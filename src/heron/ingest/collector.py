"""Fetch mail for one account/folder/date-range and store it in the vault.

This is where the pieces from earlier days meet:
- core.timeutil's DateRange and widened_for_imap_search() (Day 3)
- core.crypto.SecretBox, to decrypt the stored app password (Day 4)
- core.storage.insert_email_if_new(), for deduplicated writes (Day 5)
- ingest.imap_client.ImapClient, for the actual IMAP conversation (Day 6)

Raw messages are written to disk once, named by content hash, so re-fetching
the same message is a cheap no-op rather than a second copy (see
ARCHITECTURE.md - "raw mail is stored once").
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header
from email.message import Message
from pathlib import Path
from typing import Any

from sqlalchemy.engine import Engine

from heron.core.crypto import SecretBox
from heron.core.storage import insert_email_if_new
from heron.core.timeutil import DateRange, parse_email_date_header
from heron.ingest.imap_client import ImapClient


@dataclass(frozen=True, slots=True)
class CollectorResult:
    """Summary of one fetch-and-store run, for logging and job status."""

    fetched: int  # messages returned by IMAP for the (widened) search
    stored_new: int  # of those, how many were new rows in the vault
    stored_duplicate: int  # of those, how many already existed (re-fetch)
    outside_range: int  # of those, how many fell outside the exact range

    @property
    def total_in_range(self) -> int:
        return self.stored_new + self.stored_duplicate


def fetch_and_store_range(
    engine: Engine,
    secret_box: SecretBox,
    account: dict[str, Any],
    folder: str,
    date_range: DateRange,
    *,
    eml_dir: Path,
) -> CollectorResult:
    """Fetch mail from `folder` within `date_range` and store new messages.

    `account` is a row as returned by core.storage.get_account(): its
    encrypted_password is decrypted here, in memory, only for the duration
    of the IMAP login.
    """
    password = secret_box.decrypt(account["encrypted_password"])
    wide_range = date_range.widened_for_imap_search()

    with ImapClient(account["imap_host"], account["email_address"], password) as client:
        folder_info = client.select_folder_readonly(folder)
        criteria = [
            "SINCE",
            _imap_date_string(wide_range.start),
            "BEFORE",
            _imap_date_string(wide_range.end),
        ]
        uids = client.search_uids(criteria)
        fetched = client.fetch_messages(uids)

    stored_new = 0
    stored_duplicate = 0
    outside_range = 0

    for uid, message in fetched.items():
        # IMAP's SINCE/BEFORE compares calendar dates with no time-of-day or
        # timezone component, so the widened search can return messages
        # just outside the exact range. This is the precise filter that
        # widened_for_imap_search()'s docstring promises.
        if not date_range.contains(message.internal_date):
            outside_range += 1
            continue

        parsed = message_from_bytes(message.raw_bytes)
        content_hash = hashlib.sha256(message.raw_bytes).hexdigest()
        eml_path = _store_raw_message(eml_dir, content_hash, message.raw_bytes)

        _row_id, inserted = insert_email_if_new(
            engine,
            account_id=account["id"],
            folder=folder,
            uidvalidity=folder_info.uidvalidity,
            uid=uid,
            content_hash=content_hash,
            internal_date=message.internal_date,
            eml_path=str(eml_path),
            message_id=_decode_header(parsed, "Message-Id"),
            header_date=parse_email_date_header(parsed.get("Date")),
            subject=_decode_header(parsed, "Subject"),
            from_address=_decode_header(parsed, "From"),
        )
        if inserted:
            stored_new += 1
        else:
            stored_duplicate += 1

    return CollectorResult(
        fetched=len(fetched),
        stored_new=stored_new,
        stored_duplicate=stored_duplicate,
        outside_range=outside_range,
    )


def _imap_date_string(ts: datetime) -> str:
    """Format a UTC datetime as an IMAP search date, e.g. '01-Jun-2026' (RFC 3501)."""
    return ts.strftime("%d-%b-%Y")


def _store_raw_message(eml_dir: Path, content_hash: str, raw_bytes: bytes) -> Path:
    """Write the raw message under eml_dir, sharded by hash prefix, and return its relative path.

    Sharding into two-character subdirectories (as content_hash[:2]/...) keeps
    any single directory from accumulating tens of thousands of files, which
    slows down some filesystems. Writing is idempotent: since the filename is
    the content hash, a re-fetch of the same message writes the same bytes to
    the same path.
    """
    relative_path = Path(content_hash[:2]) / f"{content_hash}.eml"
    full_path = eml_dir / relative_path
    if not full_path.exists():
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(raw_bytes)
    return relative_path


def _decode_header(message: Message, name: str) -> str | None:
    """Return a header value with RFC 2047 encoded-words decoded, e.g. '=?UTF-8?B?...?='.

    Malformed encoding falls back to the raw header text rather than raising,
    since a hostile or broken header must never stop ingestion (see
    ARCHITECTURE.md - "email is hostile input").
    """
    raw_value = message.get(name)
    if raw_value is None:
        return None
    try:
        parts = decode_header(raw_value)
        decoded = "".join(
            part.decode(encoding or "ascii", errors="replace") if isinstance(part, bytes) else part
            for part, encoding in parts
        )
        return decoded
    except (UnicodeDecodeError, LookupError, ValueError):
        return raw_value
