"""Tests for the mailbox endpoints.

The IMAP side is faked (heron.ingest.imap_client.IMAPClient is monkeypatched),
so the "test connection" endpoints exercise Heron's own logic without a real
server.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from imapclient.exceptions import IMAPClientError
from sqlalchemy import text

from heron.api.app import create_app
from heron.api.mailboxes import CONNECT_TEST_TIMEOUT_SECONDS
from heron.core.config import Settings
from heron.core.storage import get_account, insert_email_if_new

TOKEN = "test-token-do-not-use-in-production"
PASSWORD = "an-app-password"
BASE = "/api/v1/mailboxes"


class FakeIMAPClient:
    fail_connect = False
    fail_login = False
    last_connect = None
    last_login = None

    def __init__(self, host, port=993, ssl=True, timeout=30):
        if FakeIMAPClient.fail_connect:
            raise OSError("connection refused")
        FakeIMAPClient.last_connect = (host, port, timeout)

    def login(self, email_address, password):
        if FakeIMAPClient.fail_login:
            raise IMAPClientError("LOGIN failed")
        FakeIMAPClient.last_login = (email_address, password)

    def logout(self):
        pass

    def shutdown(self):
        pass


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeIMAPClient.fail_connect = False
    FakeIMAPClient.fail_login = False
    FakeIMAPClient.last_connect = None
    FakeIMAPClient.last_login = None
    yield


@pytest.fixture(autouse=True)
def _patch_imapclient(monkeypatch):
    monkeypatch.setattr("heron.ingest.imap_client.IMAPClient", FakeIMAPClient)


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(data_dir=tmp_path / "data", api_token=TOKEN)
    with TestClient(create_app(settings)) as test_client:
        test_client.headers["Authorization"] = f"Bearer {TOKEN}"
        yield test_client


def _body(**overrides):
    body = {
        "email_address": "user@example.com",
        "imap_host": "imap.example.com",
        "password": PASSWORD,
    }
    body.update(overrides)
    return body


def _add(client, **overrides):
    response = client.post(BASE, json=_body(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


# --- auth -----------------------------------------------------------------


@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", BASE),
        ("POST", BASE),
        ("POST", f"{BASE}/test"),
        ("GET", f"{BASE}/1"),
        ("POST", f"{BASE}/1/test"),
        ("DELETE", f"{BASE}/1"),
    ],
)
def test_every_mailbox_route_requires_the_token(client, method, path):
    response = client.request(method, path, json=_body(), headers={"Authorization": ""})
    assert response.status_code == 401


# --- add ------------------------------------------------------------------


def test_add_mailbox_returns_201_and_the_new_mailbox(client):
    response = client.post(BASE, json=_body())
    assert response.status_code == 201
    body = response.json()
    assert body["email_address"] == "user@example.com"
    assert body["imap_host"] == "imap.example.com"
    assert body["imap_port"] == 993
    assert isinstance(body["id"], int)
    assert body["created_at"]


def test_add_mailbox_never_returns_any_password_field(client):
    body = _add(client)
    assert set(body) == {"id", "email_address", "imap_host", "imap_port", "created_at"}
    assert PASSWORD not in str(body)


def test_add_mailbox_stores_the_password_encrypted(client):
    mailbox_id = _add(client)["id"]
    row = get_account(client.app.state.engine, mailbox_id)
    assert row["encrypted_password"] != PASSWORD
    assert client.app.state.secret_box.decrypt(row["encrypted_password"]) == PASSWORD


def test_add_mailbox_accepts_a_custom_port(client):
    assert _add(client, imap_port=1993)["imap_port"] == 1993


def test_add_mailbox_trims_whitespace_around_address_and_host(client):
    body = _add(client, email_address="  user@example.com ", imap_host=" imap.example.com  ")
    assert body["email_address"] == "user@example.com"
    assert body["imap_host"] == "imap.example.com"


def test_add_mailbox_keeps_password_whitespace_untouched(client):
    mailbox_id = _add(client, password="abcd efgh ijkl mnop")["id"]
    row = get_account(client.app.state.engine, mailbox_id)
    assert client.app.state.secret_box.decrypt(row["encrypted_password"]) == "abcd efgh ijkl mnop"


def test_add_mailbox_rejects_a_duplicate_address(client):
    _add(client)
    response = client.post(BASE, json=_body())
    assert response.status_code == 409


@pytest.mark.parametrize(
    "overrides",
    [
        {"email_address": "not-an-email"},
        {"email_address": "@example.com"},
        {"email_address": "user@"},
        {"imap_host": ""},
        {"imap_port": 0},
        {"imap_port": 70000},
        {"password": ""},
    ],
)
def test_add_mailbox_rejects_invalid_input(client, overrides):
    response = client.post(BASE, json=_body(**overrides))
    assert response.status_code == 422


def test_validation_errors_never_echo_the_request_body(client):
    # A missing field makes FastAPI's default error include the whole body -
    # password and all. The custom handler must strip that out.
    body = _body()
    del body["imap_host"]
    body["password"] = "super-secret-value"
    response = client.post(BASE, json=body)
    assert response.status_code == 422
    assert "super-secret-value" not in response.text


# --- list and get ---------------------------------------------------------


def test_list_is_empty_at_first(client):
    response = client.get(BASE)
    assert response.status_code == 200
    assert response.json() == []


def test_list_returns_added_mailboxes_without_passwords(client):
    _add(client, email_address="a@example.com")
    _add(client, email_address="b@example.com")
    response = client.get(BASE)
    assert [m["email_address"] for m in response.json()] == ["a@example.com", "b@example.com"]
    assert PASSWORD not in response.text
    assert "encrypted_password" not in response.text


def test_get_one_mailbox(client):
    created = _add(client)
    response = client.get(f"{BASE}/{created['id']}")
    assert response.status_code == 200
    assert response.json() == created


def test_get_unknown_mailbox_is_404(client):
    assert client.get(f"{BASE}/999").status_code == 404


# --- delete ---------------------------------------------------------------


def test_delete_removes_the_mailbox(client):
    mailbox_id = _add(client)["id"]
    assert client.delete(f"{BASE}/{mailbox_id}").status_code == 204
    assert client.get(f"{BASE}/{mailbox_id}").status_code == 404
    assert client.get(BASE).json() == []


def test_delete_unknown_mailbox_is_404(client):
    assert client.delete(f"{BASE}/999").status_code == 404


def test_delete_cascades_to_the_mailboxes_emails(client):
    engine = client.app.state.engine
    mailbox_id = _add(client)["id"]
    insert_email_if_new(
        engine,
        account_id=mailbox_id,
        folder="INBOX",
        uidvalidity=1,
        uid=1,
        content_hash="a" * 64,
        internal_date=datetime(2026, 6, 15, 10, 0, tzinfo=UTC),
        eml_path="aa/aaaa.eml",
    )
    client.delete(f"{BASE}/{mailbox_id}")
    with engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM emails")).scalar_one() == 0


# --- test connection: saved mailbox ---------------------------------------


def test_saved_mailbox_connection_test_succeeds(client):
    mailbox_id = _add(client)["id"]
    response = client.post(f"{BASE}/{mailbox_id}/test")
    assert response.status_code == 200
    assert response.json() == {"ok": True, "error": None}


def test_saved_mailbox_test_logs_in_with_the_decrypted_password(client):
    mailbox_id = _add(client)["id"]
    client.post(f"{BASE}/{mailbox_id}/test")
    assert FakeIMAPClient.last_login == ("user@example.com", PASSWORD)


def test_connection_test_uses_a_short_timeout(client):
    mailbox_id = _add(client)["id"]
    client.post(f"{BASE}/{mailbox_id}/test")
    assert FakeIMAPClient.last_connect[2] == CONNECT_TEST_TIMEOUT_SECONDS


def test_saved_mailbox_test_reports_a_failed_login_without_leaking_the_password(client):
    mailbox_id = _add(client)["id"]
    FakeIMAPClient.fail_login = True
    response = client.post(f"{BASE}/{mailbox_id}/test")
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert "login failed" in response.json()["error"]
    assert PASSWORD not in response.text


def test_saved_mailbox_test_reports_an_unreachable_host(client):
    mailbox_id = _add(client)["id"]
    FakeIMAPClient.fail_connect = True
    body = client.post(f"{BASE}/{mailbox_id}/test").json()
    assert body["ok"] is False
    assert "could not reach" in body["error"]


def test_saved_mailbox_test_reports_an_undecryptable_password(client):
    mailbox_id = _add(client)["id"]
    with client.app.state.engine.begin() as connection:
        connection.execute(
            text("UPDATE accounts SET encrypted_password = 'garbage' WHERE id = :id"),
            {"id": mailbox_id},
        )
    body = client.post(f"{BASE}/{mailbox_id}/test").json()
    assert body["ok"] is False
    assert "decrypt" in body["error"]


def test_saved_mailbox_test_for_unknown_id_is_404(client):
    assert client.post(f"{BASE}/999/test").status_code == 404


# --- test connection: before saving ---------------------------------------


def test_credentials_test_succeeds_and_saves_nothing(client):
    response = client.post(f"{BASE}/test", json=_body())
    assert response.status_code == 200
    assert response.json() == {"ok": True, "error": None}
    assert FakeIMAPClient.last_login == ("user@example.com", PASSWORD)
    assert client.get(BASE).json() == []


def test_credentials_test_reports_a_failed_login(client):
    FakeIMAPClient.fail_login = True
    body = client.post(f"{BASE}/test", json=_body()).json()
    assert body["ok"] is False
    assert "login failed" in body["error"]
