"""accounts and emails tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "accounts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email_address", sa.Text, nullable=False, unique=True),
        sa.Column("imap_host", sa.Text, nullable=False),
        sa.Column("imap_port", sa.Integer, nullable=False, server_default="993"),
        sa.Column("encrypted_password", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    op.create_table(
        "emails",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "account_id",
            sa.Integer,
            sa.ForeignKey("accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("folder", sa.Text, nullable=False),
        sa.Column("uidvalidity", sa.Integer, nullable=False),
        sa.Column("uid", sa.Integer, nullable=False),
        sa.Column("message_id", sa.Text, nullable=True),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("internal_date", sa.Text, nullable=False),
        sa.Column("header_date", sa.Text, nullable=True),
        sa.Column("subject", sa.Text, nullable=True),
        sa.Column("from_address", sa.Text, nullable=True),
        sa.Column("eml_path", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.UniqueConstraint("account_id", "folder", "uidvalidity", "uid"),
    )
    op.create_index(
        "ix_emails_account_internal_date",
        "emails",
        ["account_id", "internal_date"],
    )


def downgrade() -> None:
    op.drop_index("ix_emails_account_internal_date", table_name="emails")
    op.drop_table("emails")
    op.drop_table("accounts")
