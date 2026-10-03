"""Counting mail per hour or per day, for the dashboard timeline and KPIs.

Pure: rows in, an Activity out. Times are stored in UTC but people think in
local days, so every message is converted to the configured time zone before
it is assigned to a bucket. A single local day is shown by hour, anything
longer by day. Empty buckets are included so a chart has no gaps.

On a daylight-saving change day the repeated or missing local hour is simply
that wall-clock hour's bucket (the 01:00 hour holds both occurrences).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MAX_DAYS = 366
_STORAGE_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass(frozen=True, slots=True)
class Bucket:
    label: str  # "2026-10-03T14:00" (hour) or "2026-10-03" (day), local time
    emails: int
    suspicious: int
    phishing: int


@dataclass(frozen=True, slots=True)
class Activity:
    start_date: date
    end_date: date
    timezone: str
    granularity: str  # "hour" or "day"
    emails: int
    analysed: int  # emails that already have a verdict
    suspicious: int
    phishing: int
    buckets: tuple[Bucket, ...]


def build_activity(
    rows: Iterable[tuple[str, str | None]], start_date: date, end_date: date, tz_name: str
) -> Activity:
    """rows are (internal_date as a UTC storage string, verdict or None)."""
    if end_date < start_date:
        raise ValueError("end_date must not be before start_date")
    if (end_date - start_date).days + 1 > MAX_DAYS:
        raise ValueError(f"the range can be at most {MAX_DAYS} days")
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown time zone: {tz_name}") from exc

    hourly = start_date == end_date
    labels = _all_labels(start_date, end_date, hourly)
    counts = {label: [0, 0, 0] for label in labels}  # emails, suspicious, phishing
    analysed = 0

    for internal_date, verdict in rows:
        try:
            local = datetime.strptime(internal_date, _STORAGE_FORMAT).replace(tzinfo=UTC)
        except ValueError:
            continue  # a corrupt timestamp must not break the dashboard
        local = local.astimezone(tz)
        if not start_date <= local.date() <= end_date:
            continue
        label = f"{local:%Y-%m-%dT%H}:00" if hourly else f"{local:%Y-%m-%d}"
        bucket = counts[label]
        bucket[0] += 1
        if verdict is not None:
            analysed += 1
        if verdict == "suspicious":
            bucket[1] += 1
        elif verdict == "phishing":
            bucket[2] += 1

    buckets = tuple(Bucket(label, *counts[label]) for label in labels)
    return Activity(
        start_date=start_date,
        end_date=end_date,
        timezone=tz_name,
        granularity="hour" if hourly else "day",
        emails=sum(b.emails for b in buckets),
        analysed=analysed,
        suspicious=sum(b.suspicious for b in buckets),
        phishing=sum(b.phishing for b in buckets),
        buckets=buckets,
    )


def _all_labels(start_date: date, end_date: date, hourly: bool) -> list[str]:
    if hourly:
        return [f"{start_date.isoformat()}T{hour:02d}:00" for hour in range(24)]
    days = (end_date - start_date).days + 1
    return [(start_date + timedelta(days=offset)).isoformat() for offset in range(days)]
