"""baseline (empty)

Revision ID: 0001
Revises:
Create Date: 2026-09-21
"""

from collections.abc import Sequence

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Empty baseline. The first real tables arrive on Day 5."""


def downgrade() -> None:
    """Nothing to undo."""
