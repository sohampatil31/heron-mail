import json
from pathlib import Path

import pytest

from heron.analysis.alerts import (
    AlertStatus,
    InvalidTransition,
    build_alert,
    can_transition,
    recommend_actions,
    should_alert,
    transition,
)
from heron.analysis.pipeline import analyze
from heron.analysis.scoring import Verdict, assess
from heron.rules.base import Finding, Severity
from heron.rules.registry import RuleResults

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def assessment_of(*findings: Finding):
    return assess(RuleResults(tuple(findings), ()))


def finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(rule_id, severity, f"title {rule_id}", "detail", ("e",))


# ---------------------------------------------------------------- lifecycle


def test_open_alert_can_go_to_any_working_state():
    for target in (AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
        assert transition(AlertStatus.OPEN, target) is target


def test_acknowledged_alert_can_be_closed_but_not_unacknowledged():
    assert can_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED)
    assert can_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.FALSE_POSITIVE)
    assert not can_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.OPEN)


def test_closed_alerts_can_only_be_reopened():
    for closed in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
        assert transition(closed, AlertStatus.OPEN) is AlertStatus.OPEN
        assert not can_transition(closed, AlertStatus.ACKNOWLEDGED)
    # Reclassifying goes through "open" so the change is a deliberate reopen.
    assert not can_transition(AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE)
    assert not can_transition(AlertStatus.FALSE_POSITIVE, AlertStatus.RESOLVED)


def test_no_status_moves_to_itself():
    for status in AlertStatus:
        assert not can_transition(status, status)


def test_invalid_transition_raises_with_a_readable_message():
    with pytest.raises(InvalidTransition) as error:
        transition(AlertStatus.RESOLVED, AlertStatus.ACKNOWLEDGED)
    assert str(error.value) == "cannot move an alert from resolved to acknowledged"
    assert isinstance(error.value, ValueError)


def test_status_values_are_stable_strings_for_storage():
    assert [s.value for s in AlertStatus] == ["open", "acknowledged", "resolved", "false_positive"]


# ------------------------------------------------------------- should alert


def test_only_flagged_messages_get_an_alert():
    clean = assessment_of(finding("a.x", Severity.LOW))
    suspicious = assessment_of(finding("a.x", Severity.HIGH))
    phishing = assessment_of(finding("a.x", Severity.HIGH), finding("b.x", Severity.HIGH))
    assert [should_alert(a) for a in (clean, suspicious, phishing)] == [False, True, True]
    assert build_alert(clean, "hello") is None


# ------------------------------------------------------------- build_alert


def test_phish_fixture_alert():
    analysis = analyze((FIXTURES / "phish_invoice.eml").read_bytes())
    alert = build_alert(analysis.assessment, analysis.email.subject)
    assert alert is not None
    assert alert.title == "Likely phishing: Action required: verify your account"
    assert alert.severity is Severity.HIGH
    assert alert.verdict is Verdict.PHISHING
    assert alert.score == 100
    assert alert.summary == analysis.assessment.headline
    assert alert.reasons == analysis.assessment.reasons
    assert alert.rules_version == analysis.assessment.rules_version
    assert alert.complete
    assert [a.id for a in alert.actions] == [
        "no_click_no_open",
        "dont_reply",
        "verify_sender",
        "check_real_address",
        "type_the_address",
        "if_credentials_entered",
        "if_attachment_opened",
        "report_and_delete",
    ]


def test_suspicious_alert_is_medium_and_gets_only_relevant_actions():
    alert = build_alert(assessment_of(finding("auth.dmarc_fail", Severity.HIGH)), "Hi")
    assert alert is not None
    assert alert.title == "Suspicious message: Hi"
    assert alert.severity is Severity.MEDIUM
    assert [a.id for a in alert.actions] == ["verify_sender", "report_and_delete"]


def test_actions_follow_the_findings_that_scored():
    reply_to = recommend_actions(assessment_of(finding("reply_to.mismatch", Severity.HIGH)))
    assert [a.id for a in reply_to] == ["dont_reply", "verify_sender", "report_and_delete"]
    attachment = recommend_actions(assessment_of(finding("attachment.executable", Severity.HIGH)))
    assert [a.id for a in attachment] == [
        "no_click_no_open",
        "if_attachment_opened",
        "report_and_delete",
    ]


def test_a_finding_that_did_not_score_adds_no_action():
    # A rule prefix with no playbook entry recommends nothing beyond the basics.
    actions = recommend_actions(assessment_of(finding("custom.thing", Severity.HIGH)))
    assert [a.id for a in actions] == ["report_and_delete"]


def test_actions_have_no_duplicates_and_are_sorted():
    analysis = analyze((FIXTURES / "phish_invoice.eml").read_bytes())
    actions = recommend_actions(analysis.assessment)
    ids = [a.id for a in actions]
    assert len(ids) == len(set(ids))
    assert [a.priority for a in actions] == sorted(a.priority for a in actions)


def test_subject_is_cleaned_for_display():
    suspicious = assessment_of(finding("auth.dmarc_fail", Severity.HIGH))
    nasty = "Pay now\r\nBcc: x\x00  \u202eexe.txt\u202c   done"
    alert = build_alert(suspicious, nasty)
    assert alert is not None
    assert alert.title == "Suspicious message: Pay now Bcc: x exe.txt done"

    long_title = build_alert(suspicious, "x" * 500)
    assert long_title is not None
    assert long_title.title == "Suspicious message: " + "x" * 99 + "…"

    blank = build_alert(suspicious, "  \t ")
    assert blank is not None
    assert blank.title == "Suspicious message: (no subject)"


def test_incomplete_analysis_is_carried_onto_the_alert():
    crashed = ("link: ValueError",)
    flagged = assess(RuleResults((finding("auth.dmarc_fail", Severity.HIGH),), crashed))
    alert = build_alert(flagged, "s")
    assert alert is not None
    assert not alert.complete


def test_to_dict_is_json_safe_and_complete():
    analysis = analyze((FIXTURES / "phish_invoice.eml").read_bytes())
    alert = build_alert(analysis.assessment, analysis.email.subject)
    assert alert is not None
    data = json.loads(json.dumps(alert.to_dict()))
    assert data["severity"] == "high"
    assert data["verdict"] == "phishing"
    assert data["score"] == 100
    assert data["reasons"][0]["rule_id"] == "auth.dmarc_fail"
    assert data["reasons"][0]["severity"] == "high"
    assert data["reasons"][0]["evidence"] == ["dmarc=fail", "reported by mx.example.org"]
    assert data["actions"][0]["id"] == "no_click_no_open"
    assert data["rules_version"] == analysis.assessment.rules_version
    assert data["complete"] is True
