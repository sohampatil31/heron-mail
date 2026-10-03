from datetime import date

import pytest

from heron.analysis.activity import MAX_DAYS, build_activity

OCT3 = date(2026, 10, 3)


def counts(activity):
    return {b.label: (b.emails, b.suspicious, b.phishing) for b in activity.buckets if b.emails}


def test_a_single_day_is_shown_by_hour_with_every_hour_present():
    rows = [
        ("2026-10-03 08:05:00", None),
        ("2026-10-03 08:59:59", "clean"),
        ("2026-10-03 14:00:00", "phishing"),
    ]
    activity = build_activity(rows, OCT3, OCT3, "UTC")
    assert activity.granularity == "hour"
    assert len(activity.buckets) == 24
    assert activity.buckets[0].label == "2026-10-03T00:00"
    assert activity.buckets[23].label == "2026-10-03T23:00"
    assert counts(activity) == {"2026-10-03T08:00": (2, 0, 0), "2026-10-03T14:00": (1, 0, 1)}


def test_totals_and_verdicts():
    rows = [
        ("2026-10-03 01:00:00", "clean"),
        ("2026-10-03 02:00:00", "suspicious"),
        ("2026-10-03 03:00:00", "phishing"),
        ("2026-10-03 04:00:00", "phishing"),
        ("2026-10-03 05:00:00", None),  # not analysed yet
    ]
    activity = build_activity(rows, OCT3, OCT3, "UTC")
    assert (activity.emails, activity.analysed) == (5, 4)
    assert (activity.suspicious, activity.phishing) == (1, 2)
    assert sum(b.emails for b in activity.buckets) == activity.emails


def test_several_days_are_shown_by_day_with_empty_days_included():
    rows = [("2026-10-01 10:00:00", None), ("2026-10-03 23:59:59", "suspicious")]
    activity = build_activity(rows, date(2026, 10, 1), OCT3, "UTC")
    assert activity.granularity == "day"
    assert [b.label for b in activity.buckets] == ["2026-10-01", "2026-10-02", "2026-10-03"]
    assert counts(activity) == {"2026-10-01": (1, 0, 0), "2026-10-03": (1, 1, 0)}


def test_messages_outside_the_range_are_ignored():
    rows = [
        ("2026-10-02 23:59:59", None),
        ("2026-10-04 00:00:00", None),
        ("2026-10-03 12:00:00", None),
    ]
    assert build_activity(rows, OCT3, OCT3, "UTC").emails == 1


def test_days_are_local_days_not_utc_days():
    # Kolkata is UTC+05:30: 20:00 UTC on the 3rd is 01:30 on the 4th locally.
    rows = [("2026-10-03 20:00:00", None), ("2026-10-03 10:00:00", None)]
    third = build_activity(rows, OCT3, OCT3, "Asia/Kolkata")
    assert counts(third) == {"2026-10-03T15:00": (1, 0, 0)}  # 10:00 UTC is 15:30 local
    fourth = build_activity(rows, date(2026, 10, 4), date(2026, 10, 4), "Asia/Kolkata")
    assert counts(fourth) == {"2026-10-04T01:00": (1, 0, 0)}


def test_daylight_saving_fall_back_hour_shares_a_bucket():
    # New York ends DST on 2026-11-01: 01:30 happens twice (05:30 UTC, then 06:30 UTC).
    rows = [("2026-11-01 05:30:00", None), ("2026-11-01 06:30:00", None)]
    activity = build_activity(rows, date(2026, 11, 1), date(2026, 11, 1), "America/New_York")
    assert counts(activity) == {"2026-11-01T01:00": (2, 0, 0)}


def test_local_midnight_is_the_day_boundary():
    nov1, nov2 = date(2026, 11, 1), date(2026, 11, 2)
    rows = [("2026-11-02 04:59:59", None), ("2026-11-02 05:00:00", None)]  # EST 23:59:59, 00:00:00
    assert build_activity(rows, nov1, nov1, "America/New_York").emails == 1
    assert build_activity(rows, nov2, nov2, "America/New_York").emails == 1


def test_corrupt_timestamps_are_skipped():
    rows = [("not a date", None), ("2026-10-03", None), ("", None), ("2026-10-03 09:00:00", None)]
    assert build_activity(rows, OCT3, OCT3, "UTC").emails == 1


def test_empty_input_gives_zeroes():
    activity = build_activity([], OCT3, OCT3, "UTC")
    totals = (activity.emails, activity.analysed, activity.suspicious, activity.phishing)
    assert totals == (0, 0, 0, 0)
    assert all(b.emails == 0 for b in activity.buckets)


def test_invalid_ranges_and_time_zones_raise_valueerror():
    with pytest.raises(ValueError):
        build_activity([], date(2026, 10, 4), OCT3, "UTC")
    with pytest.raises(ValueError):
        build_activity([], date(2024, 1, 1), date(2026, 1, 1), "UTC")  # over MAX_DAYS
    with pytest.raises(ValueError):
        build_activity([], OCT3, OCT3, "Mars/Olympus")
    assert MAX_DAYS == 366
    assert build_activity([], date(2026, 1, 1), date(2026, 12, 31), "UTC").granularity == "day"
