from heron.analysis.alerts import AlertStatus, can_transition
from heron.ui.alert_logic import (
    STATUS_FILTERS,
    available_moves,
    evidence_lines,
    option_label,
    reason_summary,
    status_label,
    timeline_lines,
)


def targets(status: str) -> list[str]:
    return [move.target.value for move in available_moves(status)]


def test_open_alert_offers_the_three_working_moves():
    assert targets("open") == ["acknowledged", "resolved", "false_positive"]


def test_acknowledged_alert_can_only_be_closed():
    assert targets("acknowledged") == ["resolved", "false_positive"]


def test_closed_alerts_can_only_be_reopened():
    assert targets("resolved") == ["open"]
    assert targets("false_positive") == ["open"]


def test_the_page_never_offers_a_move_the_lifecycle_forbids():
    for status in AlertStatus:
        offered = {move.target for move in available_moves(status.value)}
        allowed = {target for target in AlertStatus if can_transition(status, target)}
        assert offered == allowed, status


def test_unknown_status_offers_nothing():
    assert available_moves("something-new") == ()


def test_only_one_button_is_primary_and_labels_are_distinct():
    moves = available_moves("open")
    assert [m.primary for m in moves].count(True) == 1
    assert len({m.label for m in moves}) == len(moves)


def test_status_filters_map_to_api_values():
    assert STATUS_FILTERS["Open"] == "open"
    assert STATUS_FILTERS["False positive"] == "false_positive"
    assert STATUS_FILTERS["All"] is None
    api_values = {v for v in STATUS_FILTERS.values() if v}
    assert api_values == {s.value for s in AlertStatus}


def test_status_labels():
    assert status_label("false_positive") == "False positive"
    assert status_label("open") == "Open"
    assert status_label("weird\x00value") == "weird value"


def test_option_label_is_cleaned_and_truncated():
    alert = {"id": 7, "severity": "high", "title": "Likely phishing: pay\r\nnow " + "x" * 200}
    label = option_label(alert)
    assert label.startswith("#7 · HIGH · Likely phishing: pay now xxx")
    assert "\r" not in label
    assert len(label) < 120


def test_timeline_for_each_state():
    base = {"created_at": "2026-10-03 08:00:00", "acknowledged_at": None, "closed_at": None}
    assert timeline_lines({**base, "status": "open"}) == ["Raised 2026-10-03 08:00:00 UTC"]
    acknowledged = {**base, "status": "acknowledged", "acknowledged_at": "2026-10-03 09:00:00"}
    assert timeline_lines(acknowledged)[1] == "Acknowledged 2026-10-03 09:00:00 UTC"
    resolved = {**acknowledged, "status": "resolved", "closed_at": "2026-10-03 10:00:00"}
    assert timeline_lines(resolved)[2] == "Resolved 2026-10-03 10:00:00 UTC"
    fp = {**base, "status": "false_positive", "closed_at": "2026-10-03 10:00:00"}
    assert timeline_lines(fp)[1] == "Marked as a false positive 2026-10-03 10:00:00 UTC"


def test_evidence_is_cleaned_but_not_escaped_because_it_is_shown_as_plain_text():
    shown = 'shows "[x](http://t.invalid)"\r\nbut goes to y'
    reason = {"evidence": ["From: a@example.net", shown]}
    assert evidence_lines(reason) == [
        "From: a@example.net",
        'shows "[x](http://t.invalid)" but goes to y',
    ]
    assert evidence_lines({}) == []


def test_reason_summary_shows_points_only_when_they_counted():
    counted = {"title": "DMARC check failed", "points": 35}
    assert reason_summary(counted) == "DMARC check failed (+35)"
    assert reason_summary({"title": "Archive attachment", "points": 0}) == "Archive attachment"
