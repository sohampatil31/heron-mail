from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from heron.core.timeutil import (
    DateRange,
    from_utc_storage_string,
    local_date_range,
    local_day_range,
    parse_email_date_header,
    to_utc_storage_string,
    today_range,
)

UTC = ZoneInfo("UTC")
IST = ZoneInfo("Asia/Kolkata")  # UTC+5:30, no DST - good for a fixed-offset check
NY = ZoneInfo("America/New_York")  # has DST transitions


def test_date_range_rejects_naive_datetimes():
    with pytest.raises(ValueError, match="timezone-aware"):
        DateRange(datetime(2026, 1, 1), datetime(2026, 1, 2, tzinfo=UTC))


def test_date_range_rejects_backwards_range():
    start = datetime(2026, 1, 2, tzinfo=UTC)
    end = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="before"):
        DateRange(start, end)


def test_contains_is_half_open():
    r = DateRange(datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 2, tzinfo=UTC))
    assert r.contains(datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC))  # start: included
    assert r.contains(datetime(2026, 1, 1, 23, 59, 59, tzinfo=UTC))
    assert not r.contains(datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC))  # end: excluded
    assert not r.contains(datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC))


def test_widened_for_imap_search_pads_one_day_each_side():
    r = DateRange(datetime(2026, 6, 10, tzinfo=UTC), datetime(2026, 6, 11, tzinfo=UTC))
    wide = r.widened_for_imap_search()
    assert wide.start == datetime(2026, 6, 9, tzinfo=UTC)
    assert wide.end == datetime(2026, 6, 12, tzinfo=UTC)


def test_local_day_range_fixed_offset_timezone():
    # A day in IST (UTC+5:30): local midnight is 18:30 UTC the previous day.
    r = local_day_range(date(2026, 6, 15), "Asia/Kolkata")
    assert r.start == datetime(2026, 6, 14, 18, 30, tzinfo=UTC)
    assert r.end == datetime(2026, 6, 15, 18, 30, tzinfo=UTC)


def test_local_day_range_23_hour_dst_spring_forward_day():
    # US clocks spring forward on 2026-03-08; that local day is 23 hours long.
    r = local_day_range(date(2026, 3, 8), "America/New_York")
    assert (r.end - r.start) == timedelta(hours=23)


def test_local_day_range_25_hour_dst_fall_back_day():
    # US clocks fall back on 2026-11-01; that local day is 25 hours long.
    r = local_day_range(date(2026, 11, 1), "America/New_York")
    assert (r.end - r.start) == timedelta(hours=25)


def test_local_day_range_rejects_unknown_timezone():
    with pytest.raises(ValueError, match="unknown timezone"):
        local_day_range(date(2026, 1, 1), "Mars/Olympus")


def test_local_date_range_spans_multiple_inclusive_days():
    r = local_date_range(date(2026, 1, 1), date(2026, 1, 3), "UTC")
    assert r.start == datetime(2026, 1, 1, tzinfo=UTC)
    assert r.end == datetime(2026, 1, 4, tzinfo=UTC)  # end day is inclusive on the calendar


def test_local_date_range_single_day_matches_local_day_range():
    single = local_date_range(date(2026, 5, 1), date(2026, 5, 1), "America/New_York")
    day = local_day_range(date(2026, 5, 1), "America/New_York")
    assert single == day


def test_local_date_range_rejects_end_before_start():
    with pytest.raises(ValueError, match="end_day"):
        local_date_range(date(2026, 1, 5), date(2026, 1, 1), "UTC")


def test_today_range_uses_local_calendar_date_near_midnight():
    # 00:15 local time on the 15th is still "the 15th" locally, even though
    # in UTC it may already be a different date. This is exactly the bug
    # class the original monolith had.
    now = datetime(2026, 6, 15, 0, 15, tzinfo=NY)
    r = today_range("America/New_York", now=now)
    assert r == local_day_range(date(2026, 6, 15), "America/New_York")


def test_to_utc_storage_string_converts_non_utc_input():
    ts = datetime(2026, 6, 15, 23, 45, tzinfo=IST)
    assert to_utc_storage_string(ts) == "2026-06-15 18:15:00"


def test_to_utc_storage_string_rejects_naive_datetime():
    with pytest.raises(ValueError, match="timezone-aware"):
        to_utc_storage_string(datetime(2026, 1, 1))


def test_storage_string_round_trip():
    original = datetime(2026, 6, 15, 18, 15, tzinfo=UTC)
    stored = to_utc_storage_string(original)
    assert from_utc_storage_string(stored) == original


def test_parse_email_date_header_normalizes_to_utc():
    parsed = parse_email_date_header("Mon, 15 Jun 2026 23:45:00 +0530")
    assert parsed == datetime(2026, 6, 15, 18, 15, tzinfo=UTC)


@pytest.mark.parametrize("value", [None, "", "not a date", "Mon, 32 Foo 2026"])
def test_parse_email_date_header_returns_none_for_bad_input(value):
    assert parse_email_date_header(value) is None


def test_parse_email_date_header_returns_none_for_naive_header():
    # A header with no UTC offset at all - malformed, but seen in the wild.
    assert parse_email_date_header("Mon, 15 Jun 2026 23:45:00") is None
