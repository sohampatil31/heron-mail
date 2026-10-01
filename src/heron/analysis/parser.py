"""Turn raw RFC 5322 bytes into a plain, immutable ParsedEmail.

This is pure: bytes in, dataclass out. It never touches the database, the
network or the filesystem, so every later analysis step (IOC extraction,
rules, scoring) can be tested against a .eml fixture with no setup.

Design rules:
- Parsing never raises on hostile or broken mail. Malformed input produces
  a best-effort result plus `defects`, because phishing is often malformed
  on purpose and one bad message must not stall the worker.
- Attachments are metadata only (name, type, size, SHA-256). Content is
  hashed in memory and dropped; it is never written anywhere or executed.
- A forwarded message (message/rfc822) is one attachment. Its inner body
  is not merged into the outer body, so quoted text can't masquerade as
  the sender's own words.
- Nothing here is trusted. Display names, Reply-To, Authentication-Results
  and so on are reported as found; judging them is the rules' job.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from email import policy
from email.message import MIMEPart
from email.parser import BytesParser
from email.utils import getaddresses

# Bodies are kept in full up to this many characters. A multi-hundred-MB
# text part is a denial-of-service attempt, not something worth analysing.
MAX_BODY_CHARS = 1_000_000

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_PATH_SEPARATORS = re.compile(r"[\\/]")


@dataclass(frozen=True, slots=True)
class Address:
    display_name: str
    address: str  # domain lowercased, local part untouched; "" if none

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2] if "@" in self.address else ""


@dataclass(frozen=True, slots=True)
class AttachmentInfo:
    filename: str | None  # sanitised: control characters and any path removed
    content_type: str
    size: int
    sha256: str
    disposition: str | None  # "attachment", "inline" or None
    content_id: str | None  # without the angle brackets

    @property
    def extensions(self) -> tuple[str, ...]:
        """Every dot-suffix, lowercased: "invoice.pdf.exe" -> ("pdf", "exe")."""
        if not self.filename or "." not in self.filename.strip("."):
            return ()
        return tuple(self.filename.strip(".").lower().split(".")[1:])

    @property
    def extension(self) -> str:
        return self.extensions[-1] if self.extensions else ""


@dataclass(frozen=True, slots=True)
class ParsedEmail:
    subject: str
    from_addresses: tuple[Address, ...]
    reply_to: tuple[Address, ...]
    to: tuple[Address, ...]
    cc: tuple[Address, ...]
    return_path: Address | None
    message_id: str | None
    date_header: str | None  # raw text; display only, never trusted
    headers: tuple[tuple[str, str], ...]  # every header, in order, decoded
    body_text: str
    body_html: str
    body_truncated: bool
    attachments: tuple[AttachmentInfo, ...]
    defects: tuple[str, ...]  # names of RFC violations the parser noticed

    @property
    def from_address(self) -> Address | None:
        return self.from_addresses[0] if self.from_addresses else None

    def header_values(self, name: str) -> tuple[str, ...]:
        """All values of a header, case-insensitive, in message order."""
        wanted = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == wanted)


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse a raw message. Never raises on malformed input."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []
    defects: list[str] = [type(defect).__name__ for defect in msg.defects]

    for leaf in _iter_leaves(msg):
        defects.extend(type(defect).__name__ for defect in leaf.defects)
        if _is_body(leaf):
            target = html_parts if leaf.get_content_type() == "text/html" else text_parts
            target.append(_decode_text(leaf))
        else:
            attachments.append(_attachment_info(leaf))

    body_text, text_cut = _join_capped(text_parts)
    body_html, html_cut = _join_capped(html_parts)

    return ParsedEmail(
        subject=_header_text(msg.get("Subject")),
        from_addresses=_addresses(msg, "From"),
        reply_to=_addresses(msg, "Reply-To"),
        to=_addresses(msg, "To"),
        cc=_addresses(msg, "Cc"),
        return_path=next(iter(_addresses(msg, "Return-Path")), None),
        message_id=_header_text(msg.get("Message-ID")) or None,
        date_header=_header_text(msg.get("Date")) or None,
        headers=tuple((key, _header_text(value)) for key, value in msg.items()),
        body_text=body_text,
        body_html=body_html,
        body_truncated=text_cut or html_cut,
        attachments=tuple(attachments),
        defects=tuple(dict.fromkeys(defects)),  # unique, order kept
    )


def _iter_leaves(part: MIMEPart) -> Iterator[MIMEPart]:
    """Yield the non-container parts, treating message/rfc822 as one leaf."""
    if part.get_content_type().startswith("message/"):
        yield part
    elif part.is_multipart():
        for child in part.iter_parts():
            yield from _iter_leaves(child)
    else:
        yield part


def _is_body(leaf: MIMEPart) -> bool:
    if leaf.get_content_type() not in ("text/plain", "text/html"):
        return False
    if leaf.get_content_disposition() == "attachment":
        return False
    return leaf.get_filename() is None


def _decode_text(leaf: MIMEPart) -> str:
    try:
        return str(leaf.get_content())
    except (LookupError, UnicodeError, ValueError, KeyError):
        # Unknown charset or undecodable bytes: fall back rather than fail.
        payload = leaf.get_payload(decode=True)
        data = payload if isinstance(payload, bytes) else b""
        try:
            return data.decode(leaf.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            return data.decode("utf-8", errors="replace")


def _join_capped(parts: list[str]) -> tuple[str, bool]:
    joined = "\n".join(parts)
    if len(joined) > MAX_BODY_CHARS:
        return joined[:MAX_BODY_CHARS], True
    return joined, False


def _attachment_info(leaf: MIMEPart) -> AttachmentInfo:
    data = _leaf_bytes(leaf)
    content_id = _header_text(leaf.get("Content-ID")).strip("<>") or None
    return AttachmentInfo(
        filename=_clean_filename(leaf.get_filename()),
        content_type=leaf.get_content_type(),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        disposition=leaf.get_content_disposition(),
        content_id=content_id,
    )


def _leaf_bytes(leaf: MIMEPart) -> bytes:
    try:
        if leaf.is_multipart():  # message/rfc822: the embedded message
            inner = leaf.get_payload(0)
            return inner.as_bytes() if inner is not None else b""
        payload = leaf.get_payload(decode=True)
        return payload if isinstance(payload, bytes) else b""
    except (ValueError, LookupError, UnicodeError, TypeError, IndexError):
        return b""


def _clean_filename(name: str | None) -> str | None:
    """Drop control characters and any directory part a sender tucked in."""
    if name is None:
        return None
    cleaned = _PATH_SEPARATORS.split(_CONTROL_CHARS.sub("", name))[-1].strip()
    return cleaned or None


def _header_text(value: object) -> str:
    if value is None:
        return ""
    try:
        return str(value).strip()
    except (ValueError, LookupError, UnicodeError):
        return ""


def _addresses(msg: MIMEPart, name: str) -> tuple[Address, ...]:
    found: list[Address] = []
    for header in msg.get_all(name, []):
        try:
            pairs = [(a.display_name, a.addr_spec) for a in header.addresses]
        except AttributeError:  # not an address header object; parse the text
            pairs = list(getaddresses([_header_text(header)]))
        for display_name, spec in pairs:
            address = _lower_domain(spec.strip())
            if address or display_name:
                found.append(Address(display_name=display_name.strip(), address=address))
    return tuple(found)


def _lower_domain(address: str) -> str:
    local, at, domain = address.rpartition("@")
    return f"{local}@{domain.lower()}" if at else address
