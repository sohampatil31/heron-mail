"""Table definitions for the storage vault.

These use SQLAlchemy Core (`Table`, not the ORM), matching how `db.py` and
`storage.py` already talk to SQLite: as explicit statements, not a session
of tracked objects. Migrations in `migrations/versions/` are still written
by hand and are the actual source of truth for the schema on disk; this
module exists so application code (`storage.py`) and Alembic's
`--autogenerate` (as a diffing aid, not something this project relies on)
share one definition of "what an emails row looks like" instead of two.
"""

from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
)

# A naming convention keeps constraint names stable across SQLite's
# regenerate-the-whole-table approach to ALTER, which matters once we start
# writing migrations that touch existing constraints.
metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)

accounts = Table(
    "accounts",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email_address", Text, nullable=False, unique=True),
    Column("imap_host", Text, nullable=False),
    Column("imap_port", Integer, nullable=False, server_default="993"),
    # Fernet ciphertext from core.crypto.SecretBox.encrypt() - never plaintext.
    Column("encrypted_password", Text, nullable=False),
    # UTC storage strings ("YYYY-MM-DD HH:MM:SS"), per core.timeutil.
    Column("created_at", Text, nullable=False),
)

emails = Table(
    "emails",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("account_id", Integer, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False),
    Column("folder", Text, nullable=False),
    # IMAP identity: a (folder, uid) pair is only unique as long as the
    # server's UIDVALIDITY for that folder hasn't changed, so all three are
    # part of the dedup key (see ARCHITECTURE.md).
    Column("uidvalidity", Integer, nullable=False),
    Column("uid", Integer, nullable=False),
    # Sender-controlled, sometimes missing or reused - stored for reference
    # and future lookups, but never trusted for deduplication.
    Column("message_id", Text, nullable=True),
    # SHA-256 of the raw message, for integrity checks and future
    # cross-account duplicate detection - also not the dedup key.
    Column("content_hash", Text, nullable=False),
    # IMAP INTERNALDATE, converted to a UTC storage string. This - not the
    # sender-controlled Date header - is what range filtering uses.
    Column("internal_date", Text, nullable=False),
    # Parsed 'Date:' header, UTC storage string. Display only; never trusted.
    Column("header_date", Text, nullable=True),
    Column("subject", Text, nullable=True),
    Column("from_address", Text, nullable=True),
    # Path to the immutable raw .eml file on disk, relative to eml_dir.
    Column("eml_path", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    UniqueConstraint("account_id", "folder", "uidvalidity", "uid"),
    Index("ix_emails_account_internal_date", "account_id", "internal_date"),
)

jobs = Table(
    "jobs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("account_id", Integer, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False),
    Column("folder", Text, nullable=False),
    # The requested range, as UTC storage strings - see core.timeutil.DateRange.
    Column("range_start", Text, nullable=False),
    Column("range_end", Text, nullable=False),
    Column("status", Text, nullable=False, server_default="pending"),
    # The highest IMAP UID successfully stored so far. On a crash mid-run,
    # the worker resumes by skipping UIDs at or below this value instead of
    # re-fetching the whole range from the server (see worker/runner.py).
    Column("checkpoint_uid", Integer, nullable=True),
    Column("error", Text, nullable=True),
    Column("created_at", Text, nullable=False),
    Column("started_at", Text, nullable=True),
    Column("finished_at", Text, nullable=True),
    CheckConstraint("status IN ('pending', 'running', 'done', 'failed')", name="ck_jobs_status"),
    Index("ix_jobs_status", "status", "id"),
)
