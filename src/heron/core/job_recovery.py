"""Cleaning up after a restart.

Fetch jobs run inside the API process. If that process stops (a crash, Ctrl-C,
a redeploy) while a job is "running", nothing will ever finish it, and the
Fetch mail page would refuse to start a new fetch for that mailbox forever.

So at startup every job still marked "running" is known to be orphaned and is
marked failed. Nothing is lost: coverage is only recorded when a job finishes,
so the same range is simply fetched again, and mail already stored is skipped
by its IMAP identity.

This assumes one API process. If several workers shared one database, a
restarting one would fail the others' live jobs; that case needs a real
worker with heartbeats, not this.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import update
from sqlalchemy.engine import Engine

from heron.core.models import jobs

INTERRUPTED_MESSAGE = "Interrupted by a restart. Fetch again to resume."


def fail_interrupted_jobs(engine: Engine, *, now: datetime | None = None) -> int:
    """Mark every 'running' job as failed. Returns how many were changed."""
    moment = now or datetime.now(UTC)
    stamp = moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")
    with engine.begin() as connection:
        result = connection.execute(
            update(jobs)
            .where(jobs.c.status == "running")
            .values(status="failed", error=INTERRUPTED_MESSAGE, finished_at=stamp)
        )
    return int(result.rowcount)
