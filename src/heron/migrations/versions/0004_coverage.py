"""coverage table

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "coverage",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "account_id",
            sa.Integer,
            sa.ForeignKey("accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("folder", sa.Text, nullable=False),
        sa.Column("range_start", sa.Text, nullable=False),
        sa.Column("range_end", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )
    op.create_index(
        "ix_coverage_account_folder", "coverage", ["account_id", "folder", "range_start"]
    )


def downgrade() -> None:
    op.drop_index("ix_coverage_account_folder", table_name="coverage")
    op.drop_table("coverage")
