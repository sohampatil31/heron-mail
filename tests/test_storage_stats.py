from datetime import UTC, datetime

import pytest

from heron.core.config import Settings
from heron.core.crypto import SecretBox, generate_key
from heron.core.migrate import init_database
from heron.core.storage import create_account, get_stats, insert_email_if_new


@pytest.fixture
def engine(tmp_path):
    eng = init_database(Settings(data_dir=tmp_path / "data"))
    yield eng
    eng.dispose()


@pytest.fixture
def account_id(engine):
    secret_box = SecretBox(generate_key())
    return create_account(
        engine, secret_box, email_address="user@example.com", imap_host="h", password="x"
    )


def _insert(engine, account_id, uid, internal_date):
    insert_email_if_new(
        engine,
        account_id=account_id,
        folder="INBOX",
        uidvalidity=1,
        uid=uid,
        content_hash=f"{uid:064d}",
        internal_date=internal_date,
        eml_path=f"aa/{uid}.eml",
    )


def test_stats_are_zero_with_no_emails(engine):
    stats = get_stats(engine)
    assert stats["total_emails"] == 0
    assert stats["emails_last_24h"] == 0
    assert stats["oldest_internal_date"] is None
    assert stats["newest_internal_date"] is None


def test_total_emails_counts_everything(engine, account_id):
    _insert(engine, account_id, 1, datetime(2026, 6, 1, tzinfo=UTC))
    _insert(engine, account_id, 2, datetime(2026, 6, 10, tzinfo=UTC))
    assert get_stats(engine)["total_emails"] == 2


def test_oldest_and_newest_internal_date(engine, account_id):
    _insert(engine, account_id, 1, datetime(2026, 6, 1, 8, 0, tzinfo=UTC))
    _insert(engine, account_id, 2, datetime(2026, 6, 10, 9, 0, tzinfo=UTC))
    stats = get_stats(engine)
    assert stats["oldest_internal_date"] == "2026-06-01 08:00:00"
    assert stats["newest_internal_date"] == "2026-06-10 09:00:00"


def test_emails_last_24h_uses_the_given_now(engine, account_id):
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    _insert(engine, account_id, 1, datetime(2026, 6, 15, 10, 0, tzinfo=UTC))  # within 24h
    _insert(engine, account_id, 2, datetime(2026, 6, 13, 10, 0, tzinfo=UTC))  # older
    stats = get_stats(engine, now=now)
    assert stats["emails_last_24h"] == 1
    assert stats["total_emails"] == 2


def test_stats_scoped_to_one_account(engine, account_id):
    secret_box = SecretBox(generate_key())
    other_account_id = create_account(
        engine, secret_box, email_address="other@example.com", imap_host="h", password="x"
    )
    _insert(engine, account_id, 1, datetime(2026, 6, 1, tzinfo=UTC))
    _insert(engine, other_account_id, 2, datetime(2026, 6, 1, tzinfo=UTC))

    assert get_stats(engine, account_id)["total_emails"] == 1
    assert get_stats(engine, other_account_id)["total_emails"] == 1
    assert get_stats(engine)["total_emails"] == 2
