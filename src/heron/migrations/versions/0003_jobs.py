"""jobs table

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "jobs",
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
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("checkpoint_uid", sa.Integer, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("started_at", sa.Text, nullable=True),
        sa.Column("finished_at", sa.Text, nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'done', 'failed')", name="ck_jobs_status"
        ),
    )
    op.create_index("ix_jobs_status", "jobs", ["status", "id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_status", table_name="jobs")
    op.drop_table("jobs")
