"""API tests for /alerts. Alerts are seeded straight into the real test database."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert

from heron.analysis.pipeline import analyze
from heron.analysis.scoring import assess
from heron.api.app import create_app
from heron.core.analysis_storage import record_assessment
from heron.core.config import Settings
from heron.core.models import emails
from heron.rules.base import Finding, Severity
from heron.rules.registry import RuleResults

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
FIXTURES = Path(__file__).parent / "fixtures" / "emails"
BASE = "/api/v1/alerts"


@pytest.fixture
def client(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token=TOKEN)
    with TestClient(create_app(settings), headers=AUTH) as c:
        yield c


def make_mailbox(client, address: str) -> int:
    response = client.post(
        "/api/v1/mailboxes",
        json={"email_address": address, "imap_host": "imap.example.org", "password": "hunter2"},
    )
    assert response.status_code in (200, 201)
    return response.json()["id"]


def seed_alert(client, mailbox_id: int, uid: int, *, phishing: bool = True) -> int:
    """Store an email for the mailbox and record an alert for it; return the alert id."""
    engine = client.app.state.engine
    with engine.begin() as connection:
        email_id = int(
            connection.execute(
                insert(emails).values(
                    account_id=mailbox_id,
                    folder="INBOX",
                    uidvalidity=1,
                    uid=uid,
                    message_id=None,
                    content_hash=f"hash{uid}",
                    internal_date="2026-10-01 08:00:00",
                    header_date=None,
                    subject=f"Seed {uid}",
                    from_address="a@example.net",
                    eml_path=f"ab/hash{uid}.eml",
                    created_at="2026-10-01 08:00:01",
                )
            ).inserted_primary_key[0]
        )
    if phishing:
        analysis = analyze((FIXTURES / "phish_invoice.eml").read_bytes())
        assessment, subject = analysis.assessment, analysis.email.subject
    else:
        finding = Finding("auth.dmarc_fail", Severity.HIGH, "t", "d", ("dmarc=fail",))
        assessment, subject = assess(RuleResults((finding,), ())), f"Seed {uid}"
    alert_id = record_assessment(engine, email_id, assessment, subject)
    assert alert_id is not None
    return alert_id


def ids(response) -> list[int]:
    assert response.status_code == 200
    return [alert["id"] for alert in response.json()]


def test_every_alert_route_requires_the_token(client):
    bad = {"Authorization": "Bearer wrong"}
    assert client.get(BASE, headers=bad).status_code in (401, 403)
    assert client.get(f"{BASE}/counts", headers=bad).status_code in (401, 403)
    assert client.get(f"{BASE}/1", headers=bad).status_code in (401, 403)
    response = client.post(f"{BASE}/1/status", json={"status": "resolved"}, headers=bad)
    assert response.status_code in (401, 403)


def test_empty_database(client):
    assert client.get(BASE).json() == []
    assert client.get(f"{BASE}/counts").json() == {
        "open": 0,
        "acknowledged": 0,
        "resolved": 0,
        "false_positive": 0,
    }


def test_list_fields_order_filters_and_paging(client):
    first = make_mailbox(client, "one@example.org")
    second = make_mailbox(client, "two@example.org")
    a = seed_alert(client, first, 1)
    b = seed_alert(client, first, 2, phishing=False)
    c = seed_alert(client, second, 3, phishing=False)

    listing = client.get(BASE)
    assert ids(listing) == [c, b, a]  # newest first
    summary = listing.json()[2]
    assert summary["severity"] == "high"
    assert summary["verdict"] == "phishing"
    assert summary["score"] == 100
    assert summary["status"] == "open"
    assert summary["account_id"] == first
    assert summary["email_subject"] == "Seed 1"
    assert summary["title"].startswith("Likely phishing:")
    assert "reasons" not in summary  # the list stays light

    assert ids(client.get(BASE, params={"mailbox_id": first})) == [b, a]
    assert ids(client.get(BASE, params={"limit": 1, "offset": 1})) == [b]

    client.post(f"{BASE}/{a}/status", json={"status": "acknowledged"})
    assert ids(client.get(BASE, params={"status": "acknowledged"})) == [a]
    assert ids(client.get(BASE, params={"status": "open", "mailbox_id": first})) == [b]


def test_list_validates_its_parameters(client):
    assert client.get(BASE, params={"status": "bogus"}).status_code == 422
    assert client.get(BASE, params={"limit": 0}).status_code == 422
    assert client.get(BASE, params={"limit": 500}).status_code == 422
    assert client.get(BASE, params={"offset": -1}).status_code == 422
    assert client.get(BASE, params={"mailbox_id": 999}).status_code == 404


def test_counts_with_and_without_a_mailbox(client):
    first = make_mailbox(client, "one@example.org")
    second = make_mailbox(client, "two@example.org")
    a = seed_alert(client, first, 1)
    seed_alert(client, first, 2, phishing=False)
    seed_alert(client, second, 3, phishing=False)
    client.post(f"{BASE}/{a}/status", json={"status": "false_positive"})

    assert client.get(f"{BASE}/counts").json() == {
        "open": 2,
        "acknowledged": 0,
        "resolved": 0,
        "false_positive": 1,
    }
    assert client.get(f"{BASE}/counts", params={"mailbox_id": second}).json() == {
        "open": 1,
        "acknowledged": 0,
        "resolved": 0,
        "false_positive": 0,
    }
    assert client.get(f"{BASE}/counts", params={"mailbox_id": 999}).status_code == 404


def test_detail_has_reasons_and_actions(client):
    alert_id = seed_alert(client, make_mailbox(client, "one@example.org"), 1)
    response = client.get(f"{BASE}/{alert_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == alert_id
    assert body["complete"] is True
    assert body["rules_version"].startswith("s1-")
    first_reason = body["reasons"][0]
    assert first_reason["rule_id"] == "auth.dmarc_fail"
    assert first_reason["severity"] == "high"
    assert first_reason["evidence"] == ["dmarc=fail", "reported by mx.example.org"]
    assert first_reason["points"] == 35
    assert body["actions"][0]["id"] == "no_click_no_open"
    assert "details" not in body
    assert "details_json" not in body


def test_unknown_alert_is_404(client):
    assert client.get(f"{BASE}/999").status_code == 404
    response = client.post(f"{BASE}/999/status", json={"status": "resolved"})
    assert response.status_code == 404


def test_counts_is_not_mistaken_for_an_alert_id(client):
    assert client.get(f"{BASE}/counts").status_code == 200
    assert client.get(f"{BASE}/not-a-number").status_code == 422


def test_status_changes_follow_the_lifecycle(client):
    alert_id = seed_alert(client, make_mailbox(client, "one@example.org"), 1)

    acknowledged = client.post(f"{BASE}/{alert_id}/status", json={"status": "acknowledged"})
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"
    assert acknowledged.json()["acknowledged_at"] is not None
    assert acknowledged.json()["closed_at"] is None
    assert acknowledged.json()["reasons"]  # the full detail comes back

    resolved = client.post(f"{BASE}/{alert_id}/status", json={"status": "resolved"})
    assert resolved.json()["status"] == "resolved"
    assert resolved.json()["closed_at"] is not None

    reopened = client.post(f"{BASE}/{alert_id}/status", json={"status": "open"})
    assert reopened.json()["status"] == "open"
    assert reopened.json()["acknowledged_at"] is None
    assert reopened.json()["closed_at"] is None


def test_illegal_moves_are_409_and_change_nothing(client):
    alert_id = seed_alert(client, make_mailbox(client, "one@example.org"), 1)
    client.post(f"{BASE}/{alert_id}/status", json={"status": "resolved"})

    response = client.post(f"{BASE}/{alert_id}/status", json={"status": "acknowledged"})
    assert response.status_code == 409
    assert response.json()["detail"] == "cannot move an alert from resolved to acknowledged"
    assert client.get(f"{BASE}/{alert_id}").json()["status"] == "resolved"

    same = client.post(f"{BASE}/{alert_id}/status", json={"status": "resolved"})
    assert same.status_code == 409


def test_bad_status_bodies_are_422(client):
    alert_id = seed_alert(client, make_mailbox(client, "one@example.org"), 1)
    url = f"{BASE}/{alert_id}/status"
    assert client.post(url, json={"status": "bogus"}).status_code == 422
    assert client.post(url, json={}).status_code == 422
    assert client.post(url).status_code == 422
