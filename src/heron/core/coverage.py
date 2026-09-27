"""Tracking which date ranges of a mailbox have already been fully ingested.

This is what lets the date-range picker (per the project brief) queue jobs
only for the gaps in a requested range, instead of re-scanning a mailbox
every time it is opened.

Two pieces:

- record_coverage() writes a segment, merging it with any existing segment
  for the same account/folder that it overlaps or touches. This keeps the
  coverage table small: a mailbox ingested daily for a year ends up as one
  row, not 365, as long as the days are contiguous.
- compute_gaps() is a pure function: given a requested range and a list of
  covered ranges, it returns the sub-ranges of the request not covered by
  any of them. It does not touch the database, which is what makes it easy
  to test exhaustively (see test_coverage.py's overlapping/adjacent/partial
  cases) independent of storage.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.engine import Engine

from heron.core.models import coverage
from heron.core.timeutil import DateRange, from_utc_storage_string, to_utc_storage_string


def record_coverage(
    engine: Engine,
    *,
    account_id: int,
    folder: str,
    date_range: DateRange,
    now: datetime | None = None,
) -> None:
    """Record that `date_range` has been fully ingested for this account/folder.

    Any existing segment that overlaps or is adjacent to `date_range` (their
    boundaries touch exactly, with no gap between them) is merged into one
    consolidated segment rather than left as a separate row. Typically
    called by the worker once a job finishes successfully.
    """
    start, end = date_range.start, date_range.end

    with engine.begin() as connection:
        existing_rows = (
            connection.execute(
                select(coverage).where(
                    coverage.c.account_id == account_id, coverage.c.folder == folder
                )
            )
            .mappings()
            .all()
        )

        merged_ids: list[int] = []
        for row in existing_rows:
            row_start = from_utc_storage_string(row["range_start"])
            row_end = from_utc_storage_string(row["range_end"])
            # Overlapping (row_start < end and row_end > start) or exactly
            # adjacent (row_end == start or row_end == end's counterpart) -
            # row_start <= end and row_end >= start covers both, since these
            # are half-open ranges that touch at a shared boundary point.
            if row_start <= end and row_end >= start:
                start = min(start, row_start)
                end = max(end, row_end)
                merged_ids.append(row["id"])

        if merged_ids:
            connection.execute(coverage.delete().where(coverage.c.id.in_(merged_ids)))

        connection.execute(
            coverage.insert().values(
                account_id=account_id,
                folder=folder,
                range_start=to_utc_storage_string(start),
                range_end=to_utc_storage_string(end),
                created_at=to_utc_storage_string(now) if now else _now_string(),
            )
        )


def get_coverage(engine: Engine, account_id: int, folder: str) -> list[DateRange]:
    """Return the covered segments for this account/folder, oldest first.

    Under normal use (all writes going through record_coverage) these are
    already merged and non-overlapping; compute_gaps() does not rely on that
    invariant, but get_coverage() gives it to callers as a courtesy.
    """
    stmt = (
        select(coverage)
        .where(coverage.c.account_id == account_id, coverage.c.folder == folder)
        .order_by(coverage.c.range_start)
    )
    with engine.connect() as connection:
        rows = connection.execute(stmt).mappings().all()
    return [
        DateRange(
            from_utc_storage_string(row["range_start"]),
            from_utc_storage_string(row["range_end"]),
        )
        for row in rows
    ]


def compute_gaps(requested: DateRange, covered: Sequence[DateRange]) -> list[DateRange]:
    """Return the sub-ranges of `requested` not covered by any range in `covered`.

    A sweep from requested.start to requested.end, advancing past each
    covered segment that overlaps the request (segments are sorted here, so
    the caller need not pre-sort or pre-merge them). Every uncovered span
    encountered along the way becomes one gap.
    """
    gaps: list[DateRange] = []
    cursor = requested.start

    for segment in sorted(covered, key=lambda seg: seg.start):
        segment_start = max(segment.start, requested.start)
        segment_end = min(segment.end, requested.end)
        if segment_start >= segment_end:
            continue  # this segment does not overlap the requested range at all

        if segment_start > cursor:
            gaps.append(DateRange(cursor, segment_start))
        cursor = max(cursor, segment_end)

        if cursor >= requested.end:
            break

    if cursor < requested.end:
        gaps.append(DateRange(cursor, requested.end))

    return gaps


def get_gaps(engine: Engine, account_id: int, folder: str, requested: DateRange) -> list[DateRange]:
    """Convenience: the gaps in `requested` for this account/folder, reading from the vault.

    This is what the API will call when a user picks a date range: the
    result is the exact list of sub-ranges that still need a job queued.
    """
    covered = get_coverage(engine, account_id, folder)
    return compute_gaps(requested, covered)


def _now_string() -> str:
    from datetime import UTC

    return to_utc_storage_string(datetime.now(UTC))
