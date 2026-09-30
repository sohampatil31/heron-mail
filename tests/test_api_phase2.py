"""API tests for /ingest, /jobs, /emails and /stats.

run_job is replaced with a recorder, so no test touches IMAP.
If your Day 11 tests already have an app/client fixture, use that instead
of the ones below.
"""

import pytest
from fastapi.testclient import TestClient

from heron.api import ingest as ingest_module
from heron.api.app import create_app
from heron.core.config import Settings

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
RANGE = {"start_date": "2026-09-01", "end_date": "2026-09-03"}


@pytest.fixture
def client(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token=TOKEN)
    with TestClient(create_app(settings), headers=AUTH) as c:
        yield c


@pytest.fixture
def run_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(ingest_module, "run_job", lambda *args: calls.append(args))
    return calls


@pytest.fixture
def mailbox_id(client):
    response = client.post(
        "/api/v1/mailboxes",
        json={
            "email_address": "me@example.com",
            "imap_host": "imap.example.com",
            "password": "hunter2",
        },
    )
    assert response.status_code in (200, 201)
    return response.json()["id"]


def test_new_routes_require_the_token(client):
    for method, path in [
        ("get", "/api/v1/jobs"),
        ("get", "/api/v1/stats"),
        ("get", "/api/v1/emails"),
        ("post", "/api/v1/ingest"),
    ]:
        response = getattr(client, method)(path, headers={"Authorization": "Bearer wrong"})
        assert response.status_code in (401, 403), path


def test_ingest_unknown_mailbox_is_404(client, run_calls):
    response = client.post("/api/v1/ingest", json={"mailbox_id": 999, **RANGE})
    assert response.status_code == 404
    assert run_calls == []


def test_ingest_end_before_start_is_422(client, mailbox_id, run_calls):
    response = client.post(
        "/api/v1/ingest",
        json={"mailbox_id": mailbox_id, "start_date": "2026-09-05", "end_date": "2026-09-01"},
    )
    assert response.status_code == 422
    assert run_calls == []


def test_ingest_creates_one_claimed_job_and_schedules_it(client, mailbox_id, run_calls):
    response = client.post("/api/v1/ingest", json={"mailbox_id": mailbox_id, **RANGE})
    assert response.status_code == 200
    body = response.json()
    assert body["gaps_found"] == 1
    assert len(body["jobs"]) == 1
    # Built from the claimed-at-creation dict, so "running" even though
    # TestClient has already executed the background task.
    assert body["jobs"][0]["status"] == "running"
    assert body["jobs"][0]["account_id"] == mailbox_id
    assert len(run_calls) == 1
    assert run_calls[0][-1]["id"] == body["jobs"][0]["id"]


def test_jobs_list_and_get(client, mailbox_id, run_calls):
    job_id = client.post("/api/v1/ingest", json={"mailbox_id": mailbox_id, **RANGE}).json()["jobs"][
        0
    ]["id"]

    listed = client.get("/api/v1/jobs", params={"mailbox_id": mailbox_id}).json()
    assert [job["id"] for job in listed] == [job_id]
    assert client.get("/api/v1/jobs", params={"status": "failed"}).json() == []

    assert client.get(f"/api/v1/jobs/{job_id}").json()["id"] == job_id
    assert client.get("/api/v1/jobs/999999").status_code == 404


def test_emails_requires_mailbox_and_dates(client):
    assert client.get("/api/v1/emails").status_code == 422


def test_emails_unknown_mailbox_is_404(client):
    response = client.get("/api/v1/emails", params={"mailbox_id": 999, **RANGE})
    assert response.status_code == 404


def test_emails_end_before_start_is_422(client, mailbox_id):
    response = client.get(
        "/api/v1/emails",
        params={"mailbox_id": mailbox_id, "start_date": "2026-09-05", "end_date": "2026-09-01"},
    )
    assert response.status_code == 422


def test_emails_empty_mailbox_returns_empty_list(client, mailbox_id):
    response = client.get("/api/v1/emails", params={"mailbox_id": mailbox_id, **RANGE})
    assert response.status_code == 200
    assert response.json() == []


def test_stats_empty_and_unknown_mailbox(client, mailbox_id):
    overall = client.get("/api/v1/stats").json()
    assert overall["total_emails"] == 0
    assert overall["emails_last_24h"] == 0
    assert overall["oldest_internal_date"] is None

    assert client.get("/api/v1/stats", params={"mailbox_id": mailbox_id}).status_code == 200
    assert client.get("/api/v1/stats", params={"mailbox_id": 999}).status_code == 404
