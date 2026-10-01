"""Pull indicators of compromise (IOCs) out of a ParsedEmail, and defang them.

Pure, like the parser: ParsedEmail in, Iocs out. Nothing is fetched,
resolved or looked up. Extraction only reports what the message contains;
deciding whether a link is suspicious is the rules' job.

What it finds:
- URLs from the plain-text body (including bare "www." links and URLs
  already defanged as hxxp / [.]), and from the HTML: <a href>, src and
  action attributes, <meta refresh>, plus URLs in the visible HTML text.
  Each URL carries the anchor text that pointed at it, for the later
  "link text vs target" rule.
- IPs from bodies, URL hosts and the Received chain. Obfuscated IPv4 hosts
  that a browser would still open (decimal, hex, octal) are normalised.
- Domains from URL hosts, sender-side addresses (From, Reply-To,
  Return-Path) and addresses written in the body. Recipients are never
  domain IOCs: To and Cc are the victim's side.
- Hashes: MD5/SHA-1/SHA-256 written in the body, plus the SHA-256 of every
  non-empty attachment.

Defanging makes an indicator safe to paste into a report or chat: it
cannot be clicked, auto-linked or resolved by accident.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

from heron.analysis.parser import ParsedEmail

# A message with thousands of links is spam or an attack on the analyser.
# Each kind of indicator is capped, and `truncated` says when that happened.
MAX_PER_KIND = 1000

_MAX_LINK_TEXT = 200

_URL_RE = re.compile(
    r"(?i)(?<![\w/])(?:(?:https?|ftp)://|www\.)[^\s<>\"\x00-\x1f]+",
)
_EMAIL_RE = re.compile(
    r"(?<![\w/%+.:-])[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63})",
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_IPV6_RE = re.compile(
    r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:.])",
)
_HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])",
)
_HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})",
)
_META_REFRESH_RE = re.compile(r"(?i)url\s*=\s*['\"]?([^'\";\s]+)")
_WHITESPACE_RE = re.compile(r"\s+")

_HREF_TAGS = {"a", "area", "link", "base"}
_SRC_TAGS = {"img", "iframe", "frame", "script", "embed", "source", "video", "audio", "track"}
_ALLOWED_SCHEMES = ("http://", "https://", "ftp://")


# ---------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class ExtractedUrl:
    url: str  # refanged, scheme lowercased, trailing punctuation removed
    scheme: str
    host: str  # lowercased, IDN in punycode, "" if the URL would not parse
    ip: str | None  # normalised address when the host is an IP in any notation
    has_userinfo: bool  # http://trusted.example@evil.invalid/ style
    sources: tuple[str, ...]  # text, html-text, href, src, form, meta-refresh
    link_texts: tuple[str, ...]  # visible text of <a> tags that pointed here

    @property
    def defanged(self) -> str:
        return defang_url(self.url)


@dataclass(frozen=True, slots=True)
class ExtractedIp:
    address: str  # normalised
    sources: tuple[str, ...]  # text, url, received
    is_global: bool  # False for private, loopback, documentation ranges, etc.

    @property
    def defanged(self) -> str:
        return defang_ip(self.address)


@dataclass(frozen=True, slots=True)
class ExtractedDomain:
    domain: str
    sources: tuple[str, ...]  # url, from, reply-to, return-path, text-email

    @property
    def defanged(self) -> str:
        return defang_domain(self.domain)


@dataclass(frozen=True, slots=True)
class ExtractedHash:
    algorithm: str  # md5, sha1, sha256
    value: str  # lowercase hex
    sources: tuple[str, ...]  # text, attachment
    filenames: tuple[str, ...]  # attachment names, when the hash came from one


@dataclass(frozen=True, slots=True)
class Iocs:
    urls: tuple[ExtractedUrl, ...]
    ips: tuple[ExtractedIp, ...]
    domains: tuple[ExtractedDomain, ...]
    hashes: tuple[ExtractedHash, ...]
    truncated: bool  # some kind hit MAX_PER_KIND and the rest was dropped


# --------------------------------------------------------------- defanging


def defang_url(url: str) -> str:
    """hxxps[://]host[.]example/path - not clickable, not auto-linked."""
    out = re.sub(r"(?i)http", "hxxp", url)
    out = re.sub(r"(?i)^ftp(?=://)", "fxp", out)
    out = out.replace("://", "[://]")
    # Dots and @ only inside the authority (before the first / ? #).
    prefix, sep, rest = out.partition("[://]")
    if not sep:
        prefix, rest = "", out
    boundary = len(rest)
    for char in "/?#":
        position = rest.find(char)
        if position != -1:
            boundary = min(boundary, position)
    authority = rest[:boundary].replace(".", "[.]").replace("@", "[@]")
    return f"{prefix}{sep}{authority}{rest[boundary:]}"


def defang_ip(address: str) -> str:
    return address.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def refang(text: str) -> str:
    """Undo common defanging so an already-defanged indicator is still found."""
    out = re.sub(r"(?i)\bhxxp(s?)(?=:|\[:)", r"http\1", text)
    out = re.sub(r"(?i)\bfxp(?=:|\[:)", "ftp", out)
    out = out.replace("[://]", "://").replace("[:]", ":")
    for wrapped in ("[.]", "(.)", "{.}"):
        out = out.replace(wrapped, ".")
    return out.replace("[@]", "@").replace("[at]", "@")


# -------------------------------------------------------------- extraction


def extract_iocs(email: ParsedEmail) -> Iocs:
    urls: dict[str, _UrlBuilder] = {}
    ips: dict[str, _Sources] = {}
    domains: dict[str, _Sources] = {}
    hashes: dict[tuple[str, str], _HashBuilder] = {}

    html = _HtmlCollector()
    html.collect(email.body_html)

    # URLs. Plain text first, then HTML, so "first seen" matches reading order.
    for raw in _find_url_candidates(email.body_text):
        _add_url(urls, raw, "text", None)
    for raw in _find_url_candidates(html.visible_text):
        _add_url(urls, raw, "html-text", None)
    for link in html.links:
        _add_url(urls, link.target, link.source, link.text)

    # Indicators that come from the URLs themselves.
    for builder in urls.values():
        if builder.ip:
            _note(ips, builder.ip, "url")
        elif builder.host and _is_domain(builder.host):
            _note(domains, builder.host, "url")

    # IPs written in the message and in routing headers.
    for text, source in ((email.body_text, "text"), (html.visible_text, "text")):
        for address in _find_ips(refang(text)):
            _note(ips, address, source)
    for name in ("Received", "X-Originating-IP"):
        for value in email.header_values(name):
            for address in _find_ips(re.sub(r"(?i)IPv6:", " ", value)):
                _note(ips, address, "received")

    # Sender-side domains. Recipients are deliberately left out.
    for label, addresses in (
        ("from", email.from_addresses),
        ("reply-to", email.reply_to),
        ("return-path", (email.return_path,) if email.return_path else ()),
    ):
        for address in addresses:
            domain = address.domain.lower().rstrip(".")
            if _is_domain(domain):
                _note(domains, domain, label)
    for text in (email.body_text, html.visible_text):
        for match in _EMAIL_RE.finditer(refang(text)):
            domain = match.group(1).lower()
            if _is_domain(domain):
                _note(domains, domain, "text-email")

    # Hashes: written in the body, and the digest of each attachment.
    for text in (email.body_text, html.visible_text):
        for match in _HASH_RE.finditer(text):
            value = match.group(0).lower()
            if _looks_like_hash(value):
                _hash_builder(hashes, value).sources.add("text")
    for attachment in email.attachments:
        if attachment.size > 0:
            builder = _hash_builder(hashes, attachment.sha256)
            builder.sources.add("attachment")
            if attachment.filename:
                builder.filenames.add(attachment.filename)

    truncated = any(len(bucket) > MAX_PER_KIND for bucket in (urls, ips, domains, hashes))
    return Iocs(
        urls=tuple(builder.build() for builder in list(urls.values())[:MAX_PER_KIND]),
        ips=tuple(_build_ip(a, s) for a, s in list(ips.items())[:MAX_PER_KIND]),
        domains=tuple(
            ExtractedDomain(d, tuple(s)) for d, s in list(domains.items())[:MAX_PER_KIND]
        ),
        hashes=tuple(b.build() for b in list(hashes.values())[:MAX_PER_KIND]),
        truncated=truncated,
    )


# ------------------------------------------------------------------- URLs


class _Sources(dict[str, None]):
    """An insertion-ordered set of source labels."""

    def add(self, label: str) -> None:
        self[label] = None


class _UrlBuilder:
    def __init__(self, url: str) -> None:
        self.url = url
        self.scheme, self.host, self.ip, self.has_userinfo = _describe_url(url)
        self.sources = _Sources()
        self.link_texts = _Sources()

    def build(self) -> ExtractedUrl:
        return ExtractedUrl(
            url=self.url,
            scheme=self.scheme,
            host=self.host,
            ip=self.ip,
            has_userinfo=self.has_userinfo,
            sources=tuple(self.sources),
            link_texts=tuple(self.link_texts),
        )


def _find_url_candidates(text: str) -> Iterable[str]:
    for match in _URL_RE.finditer(refang(text)):
        yield match.group(0)


def _add_url(urls: dict[str, _UrlBuilder], raw: str, source: str, link_text: str | None) -> None:
    url = _normalise_url(raw)
    if url is None:
        return
    builder = urls.get(url)
    if builder is None:
        if len(urls) > MAX_PER_KIND:  # past the cap: keep counting, stop storing
            return
        builder = urls[url] = _UrlBuilder(url)
    builder.sources.add(source)
    if link_text:
        builder.link_texts.add(link_text)


def _normalise_url(raw: str) -> str | None:
    # Browsers ignore tabs and newlines inside a URL; so do we.
    url = re.sub(r"[\t\r\n\x00]", "", raw).strip()
    url = _strip_trailing_punctuation(url)
    if url.lower().startswith("www."):
        url = "http://" + url
    lowered = url.lower()
    scheme = next((s for s in _ALLOWED_SCHEMES if lowered.startswith(s)), None)
    if scheme is None or len(url) == len(scheme):
        return None
    return scheme + url[len(scheme) :]


def _strip_trailing_punctuation(url: str) -> str:
    pairs = {")": "(", "]": "[", "}": "{", ">": "<"}
    while url:
        last = url[-1]
        if last in ".,;:!?'\"":
            url = url[:-1]
        elif last in pairs and url.count(last) > url.count(pairs[last]):
            url = url[:-1]  # a closing bracket that nothing in the URL opened
        else:
            break
    return url


def _describe_url(url: str) -> tuple[str, str, str | None, bool]:
    scheme = url.partition("://")[0].lower()
    try:
        parts = urlsplit(url)
        hostname = parts.hostname or ""
        has_userinfo = "@" in parts.netloc
    except ValueError:  # e.g. an unbalanced [ in the authority
        return scheme, "", None, False
    host = _ascii_host(hostname)
    return scheme, host, _normalise_ip_host(host), has_userinfo


def _ascii_host(hostname: str) -> str:
    host = hostname.lower().rstrip(".")
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")  # punycode, so homographs show up
    except UnicodeError:
        return host


# ------------------------------------------------------------------- HTML


@dataclass(frozen=True, slots=True)
class _Link:
    target: str
    source: str
    text: str | None


class _HtmlCollector(HTMLParser):
    """Collects link targets, anchor text and visible text from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[_Link] = []
        self._text: list[str] = []
        self._skip_depth = 0  # inside <script> or <style>
        self._anchor_target: str | None = None
        self._anchor_text: list[str] = []

    @property
    def visible_text(self) -> str:
        return " ".join(self._text)

    def collect(self, html: str) -> None:
        if not html:
            return
        try:
            self.feed(html)
            self.close()
        except (ValueError, AssertionError):
            pass  # keep whatever was collected before the parser gave up
        self._finish_anchor()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value for name, value in attrs if value is not None}
        if tag in ("script", "style"):
            self._skip_depth += 1
        if tag == "a":
            self._finish_anchor()
            href = values.get("href")
            if href and _is_web_link(href):
                self._anchor_target, self._anchor_text = href, []
        if tag in _HREF_TAGS and tag != "a" and "href" in values:
            self._add(values["href"], "href")
        if tag in _SRC_TAGS and "src" in values:
            self._add(values["src"], "src")
        if tag == "form" and "action" in values:
            self._add(values["action"], "form")
        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            match = _META_REFRESH_RE.search(values.get("content", ""))
            if match:
                self._add(match.group(1), "meta-refresh")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        if tag == "a":
            self._finish_anchor()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self._text.append(data)
        if self._anchor_target is not None:
            self._anchor_text.append(data)

    def _add(self, target: str, source: str, text: str | None = None) -> None:
        if _is_web_link(target):
            self.links.append(_Link(target.strip(), source, text))

    def _finish_anchor(self) -> None:
        if self._anchor_target is None:
            return
        text = _WHITESPACE_RE.sub(" ", "".join(self._anchor_text)).strip()[:_MAX_LINK_TEXT]
        self._add(self._anchor_target, "href", text or None)
        self._anchor_target = None
        self._anchor_text = []


def _is_web_link(value: str) -> bool:
    cleaned = re.sub(r"[\t\r\n\x00]", "", value).strip().lower()
    return cleaned.startswith((*_ALLOWED_SCHEMES, "www."))


# -------------------------------------------------------------------- IPs


def _note(bucket: dict[str, _Sources], key: str, source: str) -> None:
    if key not in bucket and len(bucket) > MAX_PER_KIND:
        return
    bucket.setdefault(key, _Sources()).add(source)


def _build_ip(address: str, sources: _Sources) -> ExtractedIp:
    return ExtractedIp(
        address=address,
        sources=tuple(sources),
        is_global=ipaddress.ip_address(address).is_global,
    )


def _find_ips(text: str) -> Iterable[str]:
    for match in _IPV4_RE.finditer(text):
        try:
            yield str(ipaddress.IPv4Address(match.group(0)))
        except ValueError:  # 999.1.1.1, or an octet with a leading zero
            continue
    for match in _IPV6_RE.finditer(text):
        try:
            address = ipaddress.IPv6Address(match.group(0))
        except ValueError:  # times like 12:30:45, MAC addresses, and so on
            continue
        if not address.is_unspecified:
            yield str(address)


def _normalise_ip_host(host: str) -> str | None:
    """Return the address a browser would connect to, or None for a name."""
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    value = _parse_loose_ipv4(host)
    return str(ipaddress.IPv4Address(value)) if value is not None else None


def _parse_loose_ipv4(host: str) -> int | None:
    """inet_aton-style: 3232236033, 0xC0.0xA8.2.1 and 0300.0250.2.1 all work."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    numbers = [_parse_ip_number(part) for part in parts]
    if any(number is None for number in numbers):
        return None
    *head, last = (number for number in numbers if number is not None)
    if any(number > 255 for number in head) or last >= 256 ** (5 - len(parts)):
        return None
    return last + sum(number << (24 - 8 * index) for index, number in enumerate(head))


def _parse_ip_number(part: str) -> int | None:
    if re.fullmatch(r"0[xX][0-9a-fA-F]*", part):
        return int(part[2:] or "0", 16)
    if re.fullmatch(r"0[0-7]+", part):
        return int(part, 8)
    if re.fullmatch(r"[0-9]+", part):
        return int(part)
    return None


# ----------------------------------------------------------- domains, hashes


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.fullmatch(value))


def _looks_like_hash(value: str) -> bool:
    # Needs a letter: a bare 32-digit number is an ID or an account number.
    return any(char in "abcdef" for char in value)


class _HashBuilder:
    def __init__(self, algorithm: str, value: str) -> None:
        self.algorithm = algorithm
        self.value = value
        self.sources = _Sources()
        self.filenames = _Sources()

    def build(self) -> ExtractedHash:
        return ExtractedHash(self.algorithm, self.value, tuple(self.sources), tuple(self.filenames))


def _hash_builder(hashes: dict[tuple[str, str], _HashBuilder], value: str) -> _HashBuilder:
    algorithm = _HASH_ALGORITHMS[len(value)]
    key = (algorithm, value)
    if key not in hashes:
        hashes[key] = _HashBuilder(algorithm, value)
    return hashes[key]
