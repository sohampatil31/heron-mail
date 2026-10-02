"""Tests for the analyses/alerts tables and core.analysis_storage.

Each test gets a real SQLite database built by the real migrations, so these
also prove that migration 0005 produces what the storage code expects.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import insert, inspect, text

from heron.analysis.alerts import AlertStatus, InvalidTransition
from heron.analysis.pipeline import analyze
from heron.analysis.scoring import assess
from heron.core.analysis_storage import (
    alert_counts,
    emails_missing_analysis,
    emails_with_stale_analysis,
    get_alert,
    get_analysis,
    list_alerts,
    record_assessment,
    set_alert_status,
)
from heron.core.config import Settings
from heron.core.migrate import init_database
from heron.core.models import accounts, emails
from heron.rules.base import Finding, Severity
from heron.rules.registry import RuleResults

FIXTURES = Path(__file__).parent / "fixtures" / "emails"
T1 = datetime(2026, 10, 1, 9, 0, 0, tzinfo=UTC)
T2 = datetime(2026, 10, 1, 10, 30, 0, tzinfo=UTC)
T3 = datetime(2026, 10, 1, 11, 45, 0, tzinfo=UTC)


@pytest.fixture
def engine(tmp_path):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    eng = init_database(settings)
    yield eng
    eng.dispose()


def add_account(engine, address: str = "me@example.org") -> int:
    with engine.begin() as connection:
        result = connection.execute(
            insert(accounts).values(
                email_address=address,
                imap_host="imap.example.org",
                encrypted_password="x",
                created_at="2026-10-01 00:00:00",
            )
        )
        return int(result.inserted_primary_key[0])


def add_email(engine, account_id: int, uid: int = 1, subject: str = "Hello") -> int:
    with engine.begin() as connection:
        result = connection.execute(
            insert(emails).values(
                account_id=account_id,
                folder="INBOX",
                uidvalidity=1,
                uid=uid,
                message_id=None,
                content_hash=f"hash{uid}",
                internal_date="2026-10-01 08:00:00",
                header_date=None,
                subject=subject,
                from_address="a@example.net",
                eml_path=f"ab/hash{uid}.eml",
                created_at="2026-10-01 08:00:01",
            )
        )
        return int(result.inserted_primary_key[0])


def phishing_analysis():
    return analyze((FIXTURES / "phish_invoice.eml").read_bytes())


def clean_assessment():
    return assess(RuleResults((), ()))


def one_high_assessment():
    return assess(RuleResults((Finding("auth.dmarc_fail", Severity.HIGH, "t", "d", ("e",)),), ()))


def test_migration_creates_the_new_tables(engine):
    tables = set(inspect(engine).get_table_names())
    assert {"analyses", "alerts"} <= tables


def test_clean_message_saves_an_analysis_and_no_alert(engine):
    email_id = add_email(engine, add_account(engine))
    alert_id = record_assessment(engine, email_id, clean_assessment(), "Hello", now=T1)
    assert alert_id is None

    analysis = get_analysis(engine, email_id)
    assert analysis is not None
    assert (analysis["score"], analysis["verdict"]) == (0, "clean")
    assert analysis["complete"] is True
    assert analysis["rule_errors"] == []
    assert analysis["analyzed_at"] == "2026-10-01 09:00:00"
    assert list_alerts(engine) == []


def test_flagged_message_creates_an_open_alert_with_full_details(engine):
    account_id = add_account(engine)
    email_id = add_email(engine, account_id, uid=7, subject="Action required")
    analysis = phishing_analysis()

    alert_id = record_assessment(
        engine, email_id, analysis.assessment, analysis.email.subject, now=T1
    )
    assert alert_id is not None

    alert = get_alert(engine, alert_id)
    assert alert is not None
    assert alert["status"] == "open"
    assert alert["severity"] == "high"
    assert alert["verdict"] == "phishing"
    assert alert["score"] == 100
    assert alert["title"] == "Likely phishing: Action required: verify your account"
    assert alert["created_at"] == alert["updated_at"] == "2026-10-01 09:00:00"
    assert alert["acknowledged_at"] is None
    assert alert["closed_at"] is None
    assert (alert["account_id"], alert["email_subject"]) == (account_id, "Action required")
    assert alert["details"]["reasons"][0]["rule_id"] == "auth.dmarc_fail"
    assert alert["details"]["actions"][0]["id"] == "no_click_no_open"
    assert "details_json" not in alert


def test_unknown_alert_and_analysis_are_none(engine):
    assert get_alert(engine, 999) is None
    assert get_analysis(engine, 999) is None


def test_saving_twice_keeps_one_analysis_and_one_alert(engine):
    email_id = add_email(engine, add_account(engine))
    first = record_assessment(engine, email_id, one_high_assessment(), "Hi", now=T1)
    second = record_assessment(engine, email_id, one_high_assessment(), "Hi", now=T2)
    assert first == second
    assert len(list_alerts(engine)) == 1
    with engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM analyses")).scalar_one() == 1


def test_rescoring_refreshes_content_but_keeps_status_and_created_at(engine):
    email_id = add_email(engine, add_account(engine))
    alert_id = record_assessment(engine, email_id, one_high_assessment(), "Hi", now=T1)
    assert alert_id is not None
    set_alert_status(engine, alert_id, AlertStatus.FALSE_POSITIVE, now=T2)

    analysis = phishing_analysis()
    record_assessment(engine, email_id, analysis.assessment, "Hi", now=T3)

    alert = get_alert(engine, alert_id)
    assert alert is not None
    assert alert["status"] == "false_positive"  # a person's decision survives
    assert alert["closed_at"] == "2026-10-01 10:30:00"
    assert alert["created_at"] == "2026-10-01 09:00:00"
    assert alert["updated_at"] == "2026-10-01 11:45:00"
    assert alert["score"] == 100  # but the content is current
    assert alert["verdict"] == "phishing"


def test_rescoring_to_clean_leaves_an_existing_alert_alone(engine):
    email_id = add_email(engine, add_account(engine))
    alert_id = record_assessment(engine, email_id, one_high_assessment(), "Hi", now=T1)
    assert alert_id is not None

    assert record_assessment(engine, email_id, clean_assessment(), "Hi", now=T2) is None

    alert = get_alert(engine, alert_id)
    assert alert is not None
    assert alert["status"] == "open"
    analysis = get_analysis(engine, email_id)
    assert analysis is not None
    assert analysis["verdict"] == "clean"


def test_incomplete_analysis_is_recorded(engine):
    email_id = add_email(engine, add_account(engine))
    crashed = assess(RuleResults((), ("link: ValueError",)))
    record_assessment(engine, email_id, crashed, "Hi", now=T1)
    analysis = get_analysis(engine, email_id)
    assert analysis is not None
    assert analysis["complete"] is False
    assert analysis["rule_errors"] == ["link: ValueError"]


def test_status_lifecycle_and_timestamps(engine):
    email_id = add_email(engine, add_account(engine))
    alert_id = record_assessment(engine, email_id, one_high_assessment(), "Hi", now=T1)
    assert alert_id is not None

    acknowledged = set_alert_status(engine, alert_id, AlertStatus.ACKNOWLEDGED, now=T2)
    assert acknowledged is not None
    assert acknowledged["status"] == "acknowledged"
    assert acknowledged["acknowledged_at"] == "2026-10-01 10:30:00"
    assert acknowledged["closed_at"] is None

    resolved = set_alert_status(engine, alert_id, AlertStatus.RESOLVED, now=T3)
    assert resolved is not None
    assert resolved["status"] == "resolved"
    assert resolved["closed_at"] == "2026-10-01 11:45:00"
    assert resolved["acknowledged_at"] == "2026-10-01 10:30:00"

    reopened = set_alert_status(engine, alert_id, AlertStatus.OPEN, now=T3)
    assert reopened is not None
    assert reopened["status"] == "open"
    assert reopened["acknowledged_at"] is None
    assert reopened["closed_at"] is None


def test_invalid_status_changes_are_rejected_and_change_nothing(engine):
    email_id = add_email(engine, add_account(engine))
    alert_id = record_assessment(engine, email_id, one_high_assessment(), "Hi", now=T1)
    assert alert_id is not None
    set_alert_status(engine, alert_id, AlertStatus.RESOLVED, now=T2)

    with pytest.raises(InvalidTransition):
        set_alert_status(engine, alert_id, AlertStatus.ACKNOWLEDGED, now=T3)
    alert = get_alert(engine, alert_id)
    assert alert is not None
    assert alert["status"] == "resolved"
    assert alert["updated_at"] == "2026-10-01 10:30:00"


def test_setting_status_on_a_missing_alert_returns_none(engine):
    assert set_alert_status(engine, 999, AlertStatus.RESOLVED) is None


def test_list_alerts_filters_orders_and_pages(engine):
    first_account = add_account(engine, "one@example.org")
    second_account = add_account(engine, "two@example.org")
    ids = []
    for uid, account_id in ((1, first_account), (2, second_account), (3, first_account)):
        email_id = add_email(engine, account_id, uid=uid, subject=f"s{uid}")
        ids.append(record_assessment(engine, email_id, one_high_assessment(), f"s{uid}", now=T1))
    set_alert_status(engine, ids[0], AlertStatus.ACKNOWLEDGED, now=T2)

    assert [a["id"] for a in list_alerts(engine)] == [ids[2], ids[1], ids[0]]  # newest first
    assert [a["id"] for a in list_alerts(engine, account_id=first_account)] == [ids[2], ids[0]]
    assert [a["id"] for a in list_alerts(engine, status=AlertStatus.ACKNOWLEDGED)] == [ids[0]]
    assert [a["id"] for a in list_alerts(engine, status="open", account_id=first_account)] == [
        ids[2]
    ]
    assert [a["id"] for a in list_alerts(engine, limit=1, offset=1)] == [ids[1]]
    with pytest.raises(ValueError):
        list_alerts(engine, status="bogus")


def test_alert_counts_include_every_status(engine):
    assert alert_counts(engine) == {
        "open": 0,
        "acknowledged": 0,
        "resolved": 0,
        "false_positive": 0,
    }
    account_id = add_account(engine)
    ids = []
    for uid in (1, 2, 3):
        email_id = add_email(engine, account_id, uid=uid)
        ids.append(record_assessment(engine, email_id, one_high_assessment(), "s", now=T1))
    set_alert_status(engine, ids[0], AlertStatus.ACKNOWLEDGED, now=T2)
    set_alert_status(engine, ids[1], AlertStatus.FALSE_POSITIVE, now=T2)

    counts = alert_counts(engine)
    assert counts == {"open": 1, "acknowledged": 1, "resolved": 0, "false_positive": 1}
    assert alert_counts(engine, account_id=account_id) == counts
    assert sum(alert_counts(engine, account_id=add_account(engine, "x@example.org")).values()) == 0


def test_emails_missing_analysis_pages_by_id(engine):
    account_id = add_account(engine)
    email_ids = [add_email(engine, account_id, uid=uid) for uid in (1, 2, 3)]
    record_assessment(engine, email_ids[1], clean_assessment(), "s", now=T1)

    missing = emails_missing_analysis(engine)
    assert [row["id"] for row in missing] == [email_ids[0], email_ids[2]]
    assert missing[0]["eml_path"] == "ab/hash1.eml"
    assert [r["id"] for r in emails_missing_analysis(engine, limit=1)] == [email_ids[0]]
    assert [r["id"] for r in emails_missing_analysis(engine, after_id=email_ids[0])] == [
        email_ids[2]
    ]


def test_emails_with_stale_analysis_compares_rules_versions(engine):
    account_id = add_account(engine)
    fresh, old = (add_email(engine, account_id, uid=uid) for uid in (1, 2))
    current = clean_assessment()
    record_assessment(engine, fresh, current, "s", now=T1)
    record_assessment(engine, old, current, "s", now=T1)
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE analyses SET rules_version = 'old' WHERE email_id = :id"), {"id": old}
        )

    stale = emails_with_stale_analysis(engine, current.rules_version)
    assert [row["id"] for row in stale] == [old]
    assert emails_with_stale_analysis(engine, "old") == [{"id": fresh, "eml_path": "ab/hash1.eml"}]
