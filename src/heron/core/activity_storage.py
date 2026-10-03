"""Reading the rows behind the dashboard timeline."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.engine import Engine

from heron.analysis.activity import Activity, build_activity
from heron.core.models import analyses, emails


def fetch_activity_rows(
    engine: Engine, account_id: int | None, utc_start: str, utc_end: str
) -> list[tuple[str, str | None]]:
    """(internal_date, verdict) for emails with utc_start <= internal_date < utc_end."""
    statement = (
        select(emails.c.internal_date, analyses.c.verdict)
        .select_from(emails.outerjoin(analyses, analyses.c.email_id == emails.c.id))
        .where(emails.c.internal_date >= utc_start, emails.c.internal_date < utc_end)
    )
    if account_id is not None:
        statement = statement.where(emails.c.account_id == account_id)
    with engine.connect() as connection:
        return [(row[0], row[1]) for row in connection.execute(statement)]


def activity_for(
    engine: Engine,
    account_id: int | None,
    start_date: date,
    end_date: date,
    tz_name: str,
) -> Activity:
    """Activity for local days start_date..end_date inclusive.

    The UTC window is widened by a day each side, which covers any time zone's
    offset; build_activity() then keeps exactly the messages whose local date
    is in range. That keeps daylight-saving handling in one place.
    """
    if end_date < start_date:
        raise ValueError("end_date must not be before start_date")
    utc_start = f"{start_date - timedelta(days=1):%Y-%m-%d} 00:00:00"
    utc_end = f"{end_date + timedelta(days=2):%Y-%m-%d} 00:00:00"
    rows = fetch_activity_rows(engine, account_id, utc_start, utc_end)
    return build_activity(rows, start_date, end_date, tz_name)
