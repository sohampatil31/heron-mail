from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from heron.core.config import Settings
from heron.core.crypto import SecretBox, generate_key
from heron.core.migrate import init_database
from heron.core.storage import (
    create_account,
    delete_account,
    get_account,
    insert_email_if_new,
    list_accounts,
)


@pytest.fixture
def engine(tmp_path):
    eng = init_database(Settings(data_dir=tmp_path / "data"))
    yield eng
    eng.dispose()


@pytest.fixture
def secret_box():
    return SecretBox(generate_key())


def _add(engine, secret_box, email_address):
    return create_account(
        engine,
        secret_box,
        email_address=email_address,
        imap_host="imap.example.com",
        password="an-app-password",
    )


def test_list_accounts_is_empty_at_first(engine):
    assert list_accounts(engine) == []


def test_list_accounts_returns_every_account_oldest_first(engine, secret_box):
    first = _add(engine, secret_box, "a@example.com")
    second = _add(engine, secret_box, "b@example.com")
    rows = list_accounts(engine)
    assert [row["id"] for row in rows] == [first, second]
    assert [row["email_address"] for row in rows] == ["a@example.com", "b@example.com"]


def test_delete_account_removes_it(engine, secret_box):
    account_id = _add(engine, secret_box, "a@example.com")
    assert delete_account(engine, account_id) is True
    assert get_account(engine, account_id) is None


def test_delete_account_returns_false_when_missing(engine):
    assert delete_account(engine, 999) is False


def test_delete_account_leaves_other_accounts_alone(engine, secret_box):
    keep = _add(engine, secret_box, "keep@example.com")
    drop = _add(engine, secret_box, "drop@example.com")
    delete_account(engine, drop)
    assert [row["id"] for row in list_accounts(engine)] == [keep]


def test_delete_account_cascades_to_emails(engine, secret_box):
    account_id = _add(engine, secret_box, "a@example.com")
    insert_email_if_new(
        engine,
        account_id=account_id,
        folder="INBOX",
        uidvalidity=1,
        uid=1,
        content_hash="a" * 64,
        internal_date=datetime(2026, 6, 15, 10, 0, tzinfo=UTC),
        eml_path="aa/aaaa.eml",
    )
    delete_account(engine, account_id)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM emails")).scalar_one() == 0
