"""Time handling: the module that fixes the original date-filter bug.

Two ideas run through this file:

1. Ranges are half-open: ``start <= ts < end``. A message exactly at
   midnight belongs to exactly one day, never two, and never zero.
2. "Today" is a *local calendar concept* (the user's timezone) but every
   timestamp stored or compared in the database is UTC. This module is the
   only place that converts between the two, so the conversion happens once
   and is tested once, instead of being re-derived (and re-broken) in the
   API, the collector, and the dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo


@dataclass(frozen=True, slots=True)
class DateRange:
    """A half-open UTC range: ``start <= ts < end``.

    Both bounds are timezone-aware and always in UTC, regardless of the
    timezone the range was built from. Storing it this way means every
    consumer (SQL query, IMAP search, dashboard label) works with the same
    unambiguous instants.
    """

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        for name, value in (("start", self.start), ("end", self.end)):
            if value.tzinfo is None:
                raise ValueError(f"DateRange.{name} must be timezone-aware")
        if self.start >= self.end:
            raise ValueError("DateRange.start must be before DateRange.end")

    def contains(self, ts: datetime) -> bool:
        """True if ``ts`` falls in this range. ``ts`` must be timezone-aware."""
        if ts.tzinfo is None:
            raise ValueError("ts must be timezone-aware")
        return self.start <= ts < self.end

    def widened_for_imap_search(self) -> DateRange:
        """Return a range padded by one day on each side.

        IMAP's SINCE/BEFORE search keys compare calendar dates on the
        server, with no time-of-day or timezone component (RFC 3501 §6.4.4).
        A local-midnight boundary can therefore fall on a different
        server-side calendar day depending on the server's own timezone, and
        a naive search can silently miss messages near the edges of a range.
        The fix used throughout Heron: ask IMAP for a slightly wider window,
        then filter precisely against this exact range using `contains()`
        once each message's real INTERNALDATE is known.
        """
        return DateRange(self.start - timedelta(days=1), self.end + timedelta(days=1))


def get_zone(tz_name: str) -> ZoneInfo:
    """Load an IANA timezone by name.

    Settings already validates ``HERON_TIMEZONE`` at startup (see
    ``core/config.py``), so callers that pass ``settings.timezone`` should
    not normally hit the ValueError this can raise; it is still validated
    here so this function is safe to call with any string.
    """
    try:
        return ZoneInfo(tz_name)
    except Exception as exc:  # noqa: BLE001 - re-raised with a clearer message
        raise ValueError(f"unknown timezone: {tz_name!r}") from exc


def local_day_range(day: date, tz_name: str) -> DateRange:
    """UTC bounds for one local calendar day, e.g. "Sept 21" in the user's timezone.

    On a daylight-saving transition day the local day is not exactly 24
    hours; this walks to local midnight of the *next* day and converts that,
    rather than adding a fixed 24-hour timedelta, so it is correct even on a
    23- or 25-hour day.
    """
    zone = get_zone(tz_name)
    start_local = datetime(day.year, day.month, day.day, tzinfo=zone)
    next_day = day + timedelta(days=1)
    end_local = datetime(next_day.year, next_day.month, next_day.day, tzinfo=zone)
    return DateRange(start_local.astimezone(ZoneInfo("UTC")), end_local.astimezone(ZoneInfo("UTC")))


def local_date_range(start_day: date, end_day: date, tz_name: str) -> DateRange:
    """UTC bounds for an inclusive local calendar range, e.g. a dashboard date picker.

    ``end_day`` is inclusive on the calendar (matches what a date-range
    picker shows the user) even though the returned DateRange is a
    half-open UTC interval ending just after the end of ``end_day``.
    """
    if end_day < start_day:
        raise ValueError("end_day must not be before start_day")
    first = local_day_range(start_day, tz_name)
    last = local_day_range(end_day, tz_name)
    return DateRange(first.start, last.end)


def today_range(tz_name: str, *, now: datetime | None = None) -> DateRange:
    """UTC bounds for "today" in the user's timezone. Used for the default dashboard view."""
    zone = get_zone(tz_name)
    now = now.astimezone(zone) if now else datetime.now(zone)
    return local_day_range(now.date(), tz_name)


def to_utc_storage_string(ts: datetime) -> str:
    """Render a timezone-aware datetime as Heron's storage format: 'YYYY-MM-DD HH:MM:SS' UTC.

    This matches the format described in the project brief so that plain
    SQL comparisons (``WHERE ts >= ? AND ts < ?``) sort and filter correctly
    without any per-row timezone conversion.
    """
    if ts.tzinfo is None:
        raise ValueError("ts must be timezone-aware")
    return ts.astimezone(ZoneInfo("UTC")).strftime("%Y-%m-%d %H:%M:%S")


def from_utc_storage_string(value: str) -> datetime:
    """Parse Heron's storage format back into a timezone-aware UTC datetime."""
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=ZoneInfo("UTC"))


def parse_email_date_header(value: str | None) -> datetime | None:
    """Best-effort parse of an RFC 2822 'Date:' header into a UTC datetime.

    The Date header is sender-controlled: it can be missing, malformed, or
    simply wrong (see ARCHITECTURE.md - INTERNALDATE, not this header, is
    what Heron uses for filtering and storage). This is kept only as a
    secondary, displayed-but-not-trusted field. Returns None rather than
    raising, since a malformed header should never break ingestion.
    """
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        # Some malformed senders omit the UTC offset entirely; email.utils
        # returns a naive datetime in that case rather than raising.
        return None
    return parsed.astimezone(ZoneInfo("UTC"))
