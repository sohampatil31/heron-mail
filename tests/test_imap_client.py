"""Tests for the IMAP client wrapper.

These never talk to a real server: heron.ingest.imap_client.IMAPClient is
monkeypatched with FakeIMAPClient, a small stand-in that records what was
called and returns imapclient-shaped responses. This tests Heron's own
logic (EXAMINE not SELECT, BODY.PEEK not BODY, error wrapping, connection
lifecycle) rather than the imapclient library itself.
"""

from datetime import UTC, datetime

import pytest
from imapclient.exceptions import IMAPClientError

from heron.ingest.imap_client import ImapClient, ImapConnectionError


class FakeIMAPClient:
    """Stands in for imapclient.IMAPClient. Records calls; returns canned data."""

    fail_connect = False
    fail_login = False

    def __init__(self, host, port=993, ssl=True, timeout=30):
        if FakeIMAPClient.fail_connect:
            raise OSError("connection refused")
        self.host, self.port, self.ssl, self.timeout = host, port, ssl, timeout
        self.logged_in_as = None
        self.logged_out = False
        self.shutdown_called = False
        self.selected_folder = None
        self.selected_readonly = None
        self.searched_with = None
        self.fetched_uids = None
        self.fetched_items = None

    def login(self, email_address, password):
        if FakeIMAPClient.fail_login:
            raise IMAPClientError("LOGIN failed")
        self.logged_in_as = (email_address, password)

    def logout(self):
        self.logged_out = True

    def shutdown(self):
        self.shutdown_called = True

    def list_folders(self):
        return [((), b"/", "INBOX"), ((), b"/", "Archive")]

    def select_folder(self, folder, readonly=False):
        self.selected_folder = folder
        self.selected_readonly = readonly
        return {b"UIDVALIDITY": 1001, b"EXISTS": 42}

    def search(self, criteria):
        self.searched_with = criteria
        return [1, 2, 3]

    def fetch(self, uids, items):
        self.fetched_uids = list(uids)
        self.fetched_items = items
        return {
            uid: {
                b"BODY[]": f"raw message {uid}".encode(),
                b"INTERNALDATE": datetime(2026, 6, 15, tzinfo=UTC),
            }
            for uid in uids
        }


@pytest.fixture(autouse=True)
def _reset_fake_flags():
    FakeIMAPClient.fail_connect = False
    FakeIMAPClient.fail_login = False
    yield
    FakeIMAPClient.fail_connect = False
    FakeIMAPClient.fail_login = False


@pytest.fixture
def patch_imapclient(monkeypatch):
    monkeypatch.setattr("heron.ingest.imap_client.IMAPClient", FakeIMAPClient)


def test_connect_logs_in_with_given_credentials(patch_imapclient):
    client = ImapClient("imap.example.com", "user@example.com", "app-password")
    client.connect()
    assert client._conn.logged_in_as == ("user@example.com", "app-password")
    client.close()


def test_connect_is_idempotent(patch_imapclient):
    client = ImapClient("imap.example.com", "user@example.com", "app-password")
    client.connect()
    first_conn = client._conn
    client.connect()  # should not reconnect
    assert client._conn is first_conn
    client.close()


def test_connect_wraps_unreachable_host(patch_imapclient):
    FakeIMAPClient.fail_connect = True
    client = ImapClient("bad.example.com", "user@example.com", "app-password")
    with pytest.raises(ImapConnectionError, match="could not reach"):
        client.connect()


def test_connect_wraps_login_failure_and_shuts_down(patch_imapclient):
    FakeIMAPClient.fail_login = True
    client = ImapClient("imap.example.com", "user@example.com", "wrong-password")
    with pytest.raises(ImapConnectionError, match="login failed"):
        client.connect()
    # The socket opened during __init__ must not be leaked on a failed login.
    assert client._conn is None


def test_close_logs_out(patch_imapclient):
    client = ImapClient("imap.example.com", "user@example.com", "app-password")
    client.connect()
    conn = client._conn
    client.close()
    assert conn.logged_out is True
    assert client._conn is None


def test_close_before_connect_is_a_no_op(patch_imapclient):
    client = ImapClient("imap.example.com", "user@example.com", "app-password")
    client.close()  # must not raise


def test_close_is_safe_to_call_twice(patch_imapclient):
    client = ImapClient("imap.example.com", "user@example.com", "app-password")
    client.connect()
    client.close()
    client.close()  # must not raise


def test_context_manager_connects_and_closes(patch_imapclient):
    with ImapClient("imap.example.com", "user@example.com", "app-password") as client:
        assert client._conn is not None
        conn = client._conn
    assert conn.logged_out is True


def test_context_manager_closes_even_on_exception(patch_imapclient):
    conn_holder = {}
    with pytest.raises(ValueError, match="boom"):
        with ImapClient("imap.example.com", "user@example.com", "app-password") as client:
            conn_holder["conn"] = client._conn
            raise ValueError("boom")
    assert conn_holder["conn"].logged_out is True


@pytest.mark.parametrize(
    "method, args",
    [
        ("list_folders", ()),
        ("select_folder_readonly", ("INBOX",)),
        ("search_uids", (["ALL"],)),
        ("fetch_messages", ([1, 2],)),
    ],
)
def test_operations_before_connect_raise(patch_imapclient, method, args):
    client = ImapClient("imap.example.com", "user@example.com", "app-password")
    with pytest.raises(ImapConnectionError, match="not connected"):
        getattr(client, method)(*args)


def test_list_folders_returns_names_only(patch_imapclient):
    with ImapClient("imap.example.com", "user@example.com", "app-password") as client:
        assert client.list_folders() == ["INBOX", "Archive"]


def test_select_folder_readonly_uses_examine_not_select(patch_imapclient):
    with ImapClient("imap.example.com", "user@example.com", "app-password") as client:
        info = client.select_folder_readonly("INBOX")
        assert client._conn.selected_folder == "INBOX"
        # readonly=True is what makes imapclient issue EXAMINE instead of SELECT.
        assert client._conn.selected_readonly is True
        assert info.uidvalidity == 1001
        assert info.exists == 42


def test_search_uids_passes_criteria_through(patch_imapclient):
    with ImapClient("imap.example.com", "user@example.com", "app-password") as client:
        uids = client.search_uids(["SINCE", "01-Jun-2026", "BEFORE", "16-Jun-2026"])
        assert uids == [1, 2, 3]
        assert client._conn.searched_with == ["SINCE", "01-Jun-2026", "BEFORE", "16-Jun-2026"]


def test_fetch_messages_uses_body_peek(patch_imapclient):
    with ImapClient("imap.example.com", "user@example.com", "app-password") as client:
        client.fetch_messages([1, 2])
        assert "BODY.PEEK[]" in client._conn.fetched_items
        assert "BODY[]" not in client._conn.fetched_items  # would mark mail as read


def test_fetch_messages_returns_raw_bytes_and_internal_date(patch_imapclient):
    with ImapClient("imap.example.com", "user@example.com", "app-password") as client:
        messages = client.fetch_messages([1, 2])
        assert messages[1].raw_bytes == b"raw message 1"
        assert messages[1].internal_date == datetime(2026, 6, 15, tzinfo=UTC)
        assert messages[1].internal_date.tzinfo is not None


def test_fetch_messages_with_empty_uids_does_not_call_server(patch_imapclient):
    with ImapClient("imap.example.com", "user@example.com", "app-password") as client:
        result = client.fetch_messages([])
        assert result == {}
        assert client._conn.fetched_uids is None  # fetch() was never called
