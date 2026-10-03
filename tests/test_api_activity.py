from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert

from heron.api.app import create_app
from heron.core.config import Settings
from heron.core.models import emails

TOKEN = "test-token"
URL = "/api/v1/stats/activity"


@pytest.fixture
def client(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token=TOKEN)
    with TestClient(create_app(settings), headers={"Authorization": f"Bearer {TOKEN}"}) as c:
        yield c


def make_mailbox(client, address="me@example.org") -> int:
    response = client.post(
        "/api/v1/mailboxes",
        json={"email_address": address, "imap_host": "imap.example.org", "password": "x"},
    )
    assert response.status_code in (200, 201)
    return response.json()["id"]


def add_email(client, mailbox_id: int, uid: int, internal_date: str) -> None:
    with client.app.state.engine.begin() as connection:
        connection.execute(
            insert(emails).values(
                account_id=mailbox_id, folder="INBOX", uidvalidity=1, uid=uid,
                message_id=None, content_hash=f"h{uid}", internal_date=internal_date,
                header_date=None, subject=None, from_address=None,
                eml_path=f"ab/h{uid}.eml", created_at="2026-10-01 00:00:00",
            )
        )  # fmt: skip


def test_requires_the_token(client):
    assert client.get(URL, headers={"Authorization": "Bearer nope"}).status_code in (401, 403)


def test_explicit_day_returns_hourly_buckets(client):
    box = make_mailbox(client)
    add_email(client, box, 1, "2026-10-03 08:10:00")
    add_email(client, box, 2, "2026-10-03 08:50:00")

    response = client.get(URL, params={"start_date": "2026-10-03", "end_date": "2026-10-03"})
    assert response.status_code == 200
    body = response.json()
    assert body["granularity"] == "hour"
    assert body["timezone"] == "UTC"
    assert (body["start_date"], body["end_date"]) == ("2026-10-03", "2026-10-03")
    assert body["emails"] == 2
    assert len(body["buckets"]) == 24
    eight = {"label": "2026-10-03T08:00", "emails": 2, "suspicious": 0, "phishing": 0}
    assert eight in body["buckets"]


def test_multi_day_range_and_mailbox_filter(client):
    first = make_mailbox(client, "one@example.org")
    second = make_mailbox(client, "two@example.org")
    add_email(client, first, 1, "2026-10-01 08:00:00")
    add_email(client, second, 2, "2026-10-02 08:00:00")
    params = {"start_date": "2026-10-01", "end_date": "2026-10-03"}

    both = client.get(URL, params=params).json()
    assert both["granularity"] == "day"
    assert [b["emails"] for b in both["buckets"]] == [1, 1, 0]
    only_first = client.get(URL, params={**params, "mailbox_id": first}).json()
    assert [b["emails"] for b in only_first["buckets"]] == [1, 0, 0]


def test_default_is_today_and_days_widens_it(client):
    box = make_mailbox(client)
    add_email(client, box, 1, datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"))

    today = client.get(URL).json()
    assert today["start_date"] == today["end_date"]
    assert today["granularity"] == "hour"
    week = client.get(URL, params={"days": 7}).json()
    assert week["granularity"] == "day"
    assert len(week["buckets"]) == 7
    assert week["emails"] == 1


def test_bad_requests(client):
    assert client.get(URL, params={"mailbox_id": 999}).status_code == 404
    assert client.get(URL, params={"days": 0}).status_code == 422
    assert client.get(URL, params={"days": 400}).status_code == 422
    assert client.get(URL, params={"start_date": "2026-10-03"}).status_code == 422
    assert client.get(URL, params={"end_date": "2026-10-03"}).status_code == 422
    backwards = client.get(URL, params={"start_date": "2026-10-04", "end_date": "2026-10-03"})
    assert backwards.status_code == 422
    assert "end_date" in backwards.json()["detail"]
