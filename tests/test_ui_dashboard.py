"""The dashboard's data shaping. Streamlit itself is not imported here."""

import sys
from types import ModuleType

# dashboard.py imports streamlit at module level; the helpers under test don't use it.
sys.modules.setdefault("streamlit", ModuleType("streamlit"))

from heron.ui.dashboard import alert_rows, timeline_rows  # noqa: E402


def test_hourly_timeline_uses_the_clock_label_and_splits_emails_by_verdict():
    buckets = [
        {"label": "2026-10-03T08:00", "emails": 5, "suspicious": 1, "phishing": 2},
        {"label": "2026-10-03T09:00", "emails": 0, "suspicious": 0, "phishing": 0},
    ]
    rows = timeline_rows(buckets, "hour")
    assert rows[0] == {"When": "08:00", "Not flagged": 2, "Suspicious": 1, "Phishing": 2}
    assert rows[1] == {"When": "09:00", "Not flagged": 0, "Suspicious": 0, "Phishing": 0}
    assert rows[0]["Not flagged"] + rows[0]["Suspicious"] + rows[0]["Phishing"] == 5


def test_daily_timeline_keeps_the_date_label():
    day = [{"label": "2026-10-03", "emails": 3, "suspicious": 0, "phishing": 0}]
    rows = timeline_rows(day, "day")
    assert rows == [{"When": "2026-10-03", "Not flagged": 3, "Suspicious": 0, "Phishing": 0}]


def test_flagged_never_makes_the_unflagged_count_negative():
    odd = [{"label": "2026-10-03", "emails": 1, "suspicious": 2, "phishing": 0}]
    assert timeline_rows(odd, "day")[0]["Not flagged"] == 0


def test_alert_rows_pick_display_columns_and_tolerate_missing_fields():
    alerts = [
        {"title": "Likely phishing: ![x](http://t.invalid/p.gif)", "severity": "high",
         "score": 100, "from_address": "a@example.net", "internal_date": "2026-10-03 08:00:00"},
        {"title": "Suspicious message: Hi", "severity": "medium", "score": 35,
         "from_address": None},
    ]  # fmt: skip
    rows = alert_rows(alerts)
    assert rows[0]["Alert"] == "Likely phishing: ![x](http://t.invalid/p.gif)"  # untouched text
    assert rows[0]["Received (UTC)"] == "2026-10-03 08:00:00"
    assert rows[1]["From"] == ""
    assert rows[1]["Received (UTC)"] == ""
