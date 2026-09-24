"""Tests for the collector: fetch-and-store, header parsing, and range filtering.

Like test_imap_client.py, this never talks to a real server -
heron.ingest.imap_client.IMAPClient is monkeypatched with a fake that
returns synthetic messages built from real email bytes, so header parsing
(RFC 2047 decoding, Message-Id, Date) is exercised for real.
"""

from datetime import UTC, datetime

import pytest

from heron.core.config import Settings
from heron.core.crypto import SecretBox, generate_key
from heron.core.migrate import init_database
from heron.core.storage import create_account, get_account, get_emails_in_range
from heron.core.timeutil import local_day_range
from heron.ingest.collector import fetch_and_store_range

UTC_TZ = UTC


def _raw_email(
    uid: int,
    *,
    subject: str = "Test subject",
    from_addr: str = "sender@example.com",
    date_header: str = "Mon, 15 Jun 2026 12:00:00 +0000",
    message_id: str | None = None,
) -> bytes:
    message_id = message_id or f"<msg-{uid}@example.com>"
    return (
        f"From: {from_addr}\r\n"
        f"To: user@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {date_header}\r\n"
        f"Message-Id: {message_id}\r\n"
        "\r\n"
        f"Body of message {uid}.\r\n"
    ).encode()


class FakeIMAPClient:
    """Serves a fixed set of (uid -> (raw_bytes, internal_date)) messages."""

    messages: dict[int, tuple[bytes, datetime]] = {}
    uidvalidity = 5001

    def __init__(self, host, port=993, ssl=True, timeout=30):
        pass

    def login(self, email_address, password):
        pass

    def logout(self):
        pass

    def shutdown(self):
        pass

    def select_folder(self, folder, readonly=False):
        return {b"UIDVALIDITY": self.uidvalidity, b"EXISTS": len(self.messages)}

    def search(self, criteria):
        return list(self.messages.keys())

    def fetch(self, uids, items):
        return {
            uid: {b"BODY[]": self.messages[uid][0], b"INTERNALDATE": self.messages[uid][1]}
            for uid in uids
            if uid in self.messages
        }


@pytest.fixture(autouse=True)
def _reset_fake_messages():
    FakeIMAPClient.messages = {}
    FakeIMAPClient.uidvalidity = 5001
    yield
    FakeIMAPClient.messages = {}


@pytest.fixture
def patch_imapclient(monkeypatch):
    monkeypatch.setattr("heron.ingest.imap_client.IMAPClient", FakeIMAPClient)


@pytest.fixture
def engine(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    eng = init_database(settings)
    yield eng
    eng.dispose()


@pytest.fixture
def secret_box():
    return SecretBox(generate_key())


@pytest.fixture
def account(engine, secret_box):
    account_id = create_account(
        engine,
        secret_box,
        email_address="user@example.com",
        imap_host="imap.example.com",
        password="an-app-password",
    )
    return get_account(engine, account_id)


@pytest.fixture
def eml_dir(tmp_path):
    path = tmp_path / "eml"
    path.mkdir()
    return path


def _june_15_range():
    return local_day_range(datetime(2026, 6, 15, tzinfo=UTC_TZ).date(), "UTC")


def test_fetch_and_store_saves_new_messages(patch_imapclient, engine, secret_box, account, eml_dir):
    FakeIMAPClient.messages = {
        1: (_raw_email(1), datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ)),
        2: (_raw_email(2), datetime(2026, 6, 15, 14, 0, tzinfo=UTC_TZ)),
    }

    result = fetch_and_store_range(
        engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir
    )

    assert result.fetched == 2
    assert result.stored_new == 2
    assert result.stored_duplicate == 0
    assert result.outside_range == 0

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert len(rows) == 2


def test_reingesting_same_range_creates_no_duplicates(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.messages = {
        1: (_raw_email(1), datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ)),
    }

    first = fetch_and_store_range(
        engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir
    )
    second = fetch_and_store_range(
        engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir
    )

    assert first.stored_new == 1
    assert second.stored_new == 0
    assert second.stored_duplicate == 1

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert len(rows) == 1


def test_messages_outside_exact_range_are_excluded_despite_wide_imap_search(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    # The widened IMAP search would ask for a day on either side; the fake
    # server ignores the search criteria and returns everything it has
    # (mirroring how a real SINCE/BEFORE search can over-return near
    # midnight boundaries), so this tests the *exact* post-fetch filter.
    FakeIMAPClient.messages = {
        1: (_raw_email(1), datetime(2026, 6, 14, 23, 0, tzinfo=UTC_TZ)),  # day before
        2: (_raw_email(2), datetime(2026, 6, 15, 12, 0, tzinfo=UTC_TZ)),  # in range
        3: (_raw_email(3), datetime(2026, 6, 16, 1, 0, tzinfo=UTC_TZ)),  # day after
    }

    result = fetch_and_store_range(
        engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir
    )

    assert result.fetched == 3
    assert result.stored_new == 1
    assert result.outside_range == 2

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert len(rows) == 1
    assert rows[0]["uid"] == 2


def test_subject_is_decoded_from_rfc2047_encoded_words(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    encoded_subject = "=?UTF-8?B?UGhpc2hpbmcgYWxlcnQg8J+aqA==?="  # "Phishing alert 🚨"
    FakeIMAPClient.messages = {
        1: (
            _raw_email(1, subject=encoded_subject),
            datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ),
        ),
    }

    fetch_and_store_range(engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir)

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert rows[0]["subject"] == "Phishing alert \U0001f6a8"


def test_from_address_and_message_id_are_stored(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.messages = {
        1: (
            _raw_email(1, from_addr="attacker@evil.example", message_id="<abc123@evil.example>"),
            datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ),
        ),
    }

    fetch_and_store_range(engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir)

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert rows[0]["from_address"] == "attacker@evil.example"
    assert rows[0]["message_id"] == "<abc123@evil.example>"


def test_header_date_is_parsed_and_stored_separately_from_internal_date(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.messages = {
        1: (
            _raw_email(1, date_header="Mon, 15 Jun 2026 09:00:00 +0000"),
            datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ),  # server's INTERNALDATE differs
        ),
    }

    fetch_and_store_range(engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir)

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert rows[0]["internal_date"] == "2026-06-15 10:00:00"
    assert rows[0]["header_date"] == "2026-06-15 09:00:00"


def test_malformed_date_header_does_not_stop_ingestion(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.messages = {
        1: (
            _raw_email(1, date_header="not a real date"),
            datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ),
        ),
    }

    result = fetch_and_store_range(
        engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir
    )

    assert result.stored_new == 1
    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert rows[0]["header_date"] is None


def test_raw_message_is_written_to_disk_under_eml_dir(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    raw = _raw_email(1)
    FakeIMAPClient.messages = {1: (raw, datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ))}

    fetch_and_store_range(engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir)

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    stored_path = eml_dir / rows[0]["eml_path"]
    assert stored_path.exists()
    assert stored_path.read_bytes() == raw


def test_content_hash_is_the_sha256_of_the_raw_bytes(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    import hashlib

    raw = _raw_email(1)
    FakeIMAPClient.messages = {1: (raw, datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ))}

    fetch_and_store_range(engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir)

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert rows[0]["content_hash"] == hashlib.sha256(raw).hexdigest()


def test_uidvalidity_from_folder_is_stored_on_each_email(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.uidvalidity = 9999
    FakeIMAPClient.messages = {1: (_raw_email(1), datetime(2026, 6, 15, 10, 0, tzinfo=UTC_TZ))}

    fetch_and_store_range(engine, secret_box, account, "INBOX", _june_15_range(), eml_dir=eml_dir)

    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert rows[0]["uidvalidity"] == 9999
