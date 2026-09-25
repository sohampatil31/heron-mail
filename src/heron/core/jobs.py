"""The jobs table: a queue lived inside the vault, not a separate service.

A job represents "scan this account's folder for this date range". Status
moves pending -> running -> (done | failed). checkpoint_uid lets a crashed
run resume without re-fetching everything already stored - see
worker/runner.py, which is what actually advances it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.engine import Engine

from heron.core.models import jobs
from heron.core.timeutil import DateRange, to_utc_storage_string


def create_job(
    engine: Engine,
    *,
    account_id: int,
    folder: str,
    date_range: DateRange,
    now: datetime | None = None,
) -> int:
    """Queue a job to scan `folder` for `date_range`. Returns the new job's id."""
    created_at = _timestamp(now)
    stmt = (
        jobs.insert()
        .values(
            account_id=account_id,
            folder=folder,
            range_start=to_utc_storage_string(date_range.start),
            range_end=to_utc_storage_string(date_range.end),
            status="pending",
            created_at=created_at,
        )
        .returning(jobs.c.id)
    )
    with engine.begin() as connection:
        return connection.execute(stmt).scalar_one()


def get_job(engine: Engine, job_id: int) -> dict[str, Any] | None:
    """Fetch one job by id, or None if it does not exist."""
    stmt = select(jobs).where(jobs.c.id == job_id)
    with engine.connect() as connection:
        row = connection.execute(stmt).mappings().first()
    return dict(row) if row else None


def claim_next_job(engine: Engine, *, now: datetime | None = None) -> dict[str, Any] | None:
    """Atomically claim the oldest pending job, marking it running. None if the queue is empty.

    The claim is a single UPDATE ... WHERE id = (correlated SELECT) ...
    RETURNING statement, so "pick a job" and "mark it running" happen as one
    database operation - two workers racing to claim would never both get
    the same job, even though Heron ships with only one worker process.
    """
    started_at = _timestamp(now)
    next_pending_id = (
        select(jobs.c.id).where(jobs.c.status == "pending").order_by(jobs.c.id).limit(1)
    ).scalar_subquery()
    stmt = (
        jobs.update()
        .where(jobs.c.id == next_pending_id)
        .values(status="running", started_at=started_at)
        .returning(*jobs.c)
    )
    with engine.begin() as connection:
        row = connection.execute(stmt).mappings().first()
    return dict(row) if row else None


def update_checkpoint(engine: Engine, job_id: int, uid: int) -> None:
    """Record the highest UID successfully stored so far for this job."""
    stmt = jobs.update().where(jobs.c.id == job_id).values(checkpoint_uid=uid)
    with engine.begin() as connection:
        connection.execute(stmt)


def mark_done(engine: Engine, job_id: int, *, now: datetime | None = None) -> None:
    """Mark a job as finished successfully."""
    stmt = (
        jobs.update().where(jobs.c.id == job_id).values(status="done", finished_at=_timestamp(now))
    )
    with engine.begin() as connection:
        connection.execute(stmt)


def mark_failed(engine: Engine, job_id: int, error: str, *, now: datetime | None = None) -> None:
    """Mark a job as failed. checkpoint_uid, if any, is left in place for a retry."""
    stmt = (
        jobs.update()
        .where(jobs.c.id == job_id)
        .values(status="failed", error=error, finished_at=_timestamp(now))
    )
    with engine.begin() as connection:
        connection.execute(stmt)


def retry_job(engine: Engine, job_id: int) -> None:
    """Reset a failed job to pending, keeping its checkpoint so it resumes rather than restarts.

    Heron does not retry automatically yet; this is the building block for
    a "retry" button (or a future auto-retry policy) once the dashboard and
    API exist.
    """
    stmt = (
        jobs.update()
        .where(jobs.c.id == job_id)
        .values(status="pending", error=None, started_at=None, finished_at=None)
    )
    with engine.begin() as connection:
        connection.execute(stmt)


def _timestamp(now: datetime | None) -> str:
    if now is not None:
        return to_utc_storage_string(now)
    from datetime import UTC

    return to_utc_storage_string(datetime.now(UTC))
