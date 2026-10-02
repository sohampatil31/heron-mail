"""analyses and alerts tables

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "email_id",
            sa.Integer,
            sa.ForeignKey("emails.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("score", sa.Integer, nullable=False),
        sa.Column("verdict", sa.Text, nullable=False),
        sa.Column("rules_version", sa.Text, nullable=False),
        sa.Column("complete", sa.Integer, nullable=False, server_default="1"),
        sa.Column("rule_errors", sa.Text, nullable=True),
        sa.Column("analyzed_at", sa.Text, nullable=False),
        sa.UniqueConstraint("email_id", name="uq_analyses_email_id"),
        sa.CheckConstraint(
            "verdict IN ('clean', 'suspicious', 'phishing')", name="ck_analyses_verdict"
        ),
        sa.CheckConstraint("complete IN (0, 1)", name="ck_analyses_complete"),
    )
    op.create_index("ix_analyses_rules_version", "analyses", ["rules_version"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "email_id",
            sa.Integer,
            sa.ForeignKey("emails.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.Text, nullable=False, server_default="open"),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("verdict", sa.Text, nullable=False),
        sa.Column("score", sa.Integer, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("details_json", sa.Text, nullable=False),
        sa.Column("rules_version", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("updated_at", sa.Text, nullable=False),
        sa.Column("acknowledged_at", sa.Text, nullable=True),
        sa.Column("closed_at", sa.Text, nullable=True),
        sa.UniqueConstraint("email_id", name="uq_alerts_email_id"),
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved', 'false_positive')",
            name="ck_alerts_status",
        ),
        sa.CheckConstraint("severity IN ('medium', 'high')", name="ck_alerts_severity"),
        sa.CheckConstraint("verdict IN ('suspicious', 'phishing')", name="ck_alerts_verdict"),
    )
    op.create_index("ix_alerts_status", "alerts", ["status", "id"])


def downgrade() -> None:
    op.drop_index("ix_alerts_status", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_analyses_rules_version", table_name="analyses")
    op.drop_table("analyses")
