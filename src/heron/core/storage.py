"""Reading and writing accounts and emails, with deduplication.

Two design decisions from ARCHITECTURE.md live here:

- Emails are deduplicated on (account_id, folder, uidvalidity, uid), never
  on Message-ID, which is sender-controlled and sometimes missing.
- Range queries filter on `internal_date` (from IMAP's INTERNALDATE), never
  on the sender-controlled Date header.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine

from heron.core.crypto import SecretBox
from heron.core.models import accounts, emails
from heron.core.timeutil import DateRange, to_utc_storage_string


def create_account(
    engine: Engine,
    secret_box: SecretBox,
    *,
    email_address: str,
    imap_host: str,
    password: str,
    imap_port: int = 993,
    now: datetime | None = None,
) -> int:
    """Store a new mailbox account. The password is encrypted before it is written.

    Raises sqlalchemy.exc.IntegrityError if email_address is already registered
    (accounts.email_address is UNIQUE - see models.py).
    """
    created_at = to_utc_storage_string(now) if now else _now_string()
    stmt = (
        accounts.insert()
        .values(
            email_address=email_address,
            imap_host=imap_host,
            imap_port=imap_port,
            encrypted_password=secret_box.encrypt(password),
            created_at=created_at,
        )
        .returning(accounts.c.id)
    )
    with engine.begin() as connection:
        return connection.execute(stmt).scalar_one()


def get_account(engine: Engine, account_id: int) -> dict[str, Any] | None:
    """Fetch one account by id, or None if it does not exist."""
    stmt = select(accounts).where(accounts.c.id == account_id)
    with engine.connect() as connection:
        row = connection.execute(stmt).mappings().first()
    return dict(row) if row else None


def insert_email_if_new(
    engine: Engine,
    *,
    account_id: int,
    folder: str,
    uidvalidity: int,
    uid: int,
    content_hash: str,
    internal_date: datetime,
    eml_path: str,
    message_id: str | None = None,
    header_date: datetime | None = None,
    subject: str | None = None,
    from_address: str | None = None,
    now: datetime | None = None,
) -> tuple[int, bool]:
    """Insert an email, doing nothing if its (account, folder, uidvalidity, uid) already exists.

    Returns (row_id, inserted): inserted is False when the email was already
    present, so a re-ingested mailbox never creates duplicate rows and the
    caller can tell whether new work actually happened.
    """
    values = {
        "account_id": account_id,
        "folder": folder,
        "uidvalidity": uidvalidity,
        "uid": uid,
        "message_id": message_id,
        "content_hash": content_hash,
        "internal_date": to_utc_storage_string(internal_date),
        "header_date": to_utc_storage_string(header_date) if header_date else None,
        "subject": subject,
        "from_address": from_address,
        "eml_path": eml_path,
        "created_at": to_utc_storage_string(now) if now else _now_string(),
    }
    dedup_key = ("account_id", "folder", "uidvalidity", "uid")
    insert_stmt = (
        sqlite_insert(emails).values(**values).on_conflict_do_nothing(index_elements=dedup_key)
    )
    select_stmt = select(emails.c.id).where(*(emails.c[col] == values[col] for col in dedup_key))
    with engine.begin() as connection:
        result = connection.execute(insert_stmt)
        inserted = result.rowcount == 1
        row_id = connection.execute(select_stmt).scalar_one()
    return row_id, inserted


def get_emails_in_range(
    engine: Engine, account_id: int, date_range: DateRange
) -> list[dict[str, Any]]:
    """Return emails for one account whose internal_date falls in date_range, oldest first.

    internal_date is stored as a UTC storage string ("YYYY-MM-DD HH:MM:SS"),
    which sorts and compares correctly as plain text - no per-row parsing
    needed.
    """
    start = to_utc_storage_string(date_range.start)
    end = to_utc_storage_string(date_range.end)
    stmt = (
        select(emails)
        .where(
            emails.c.account_id == account_id,
            emails.c.internal_date >= start,
            emails.c.internal_date < end,
        )
        .order_by(emails.c.internal_date)
    )
    with engine.connect() as connection:
        rows = connection.execute(stmt).mappings().all()
    return [dict(row) for row in rows]


def _now_string() -> str:
    from datetime import UTC

    return to_utc_storage_string(datetime.now(UTC))
