from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from heron.core.config import Settings
from heron.core.crypto import SecretBox, generate_key
from heron.core.migrate import init_database
from heron.core.storage import (
    create_account,
    get_account,
    get_emails_in_range,
    insert_email_if_new,
)
from heron.core.timeutil import local_day_range

UTC = ZoneInfo("UTC")


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
def account_id(engine, secret_box):
    return create_account(
        engine,
        secret_box,
        email_address="user@example.com",
        imap_host="imap.example.com",
        password="an-app-password",
    )


def _email_kwargs(account_id, **overrides):
    kwargs = dict(
        account_id=account_id,
        folder="INBOX",
        uidvalidity=1001,
        uid=1,
        content_hash="a" * 64,
        internal_date=datetime(2026, 6, 15, 10, 0, tzinfo=UTC),
        eml_path="ab/abcdef.eml",
        subject="Test subject",
        from_address="sender@example.com",
    )
    kwargs.update(overrides)
    return kwargs


def test_create_account_stores_encrypted_password(engine, secret_box, account_id):
    row = get_account(engine, account_id)
    assert row is not None
    assert row["email_address"] == "user@example.com"
    assert row["imap_port"] == 993  # server_default applied
    assert row["encrypted_password"] != "an-app-password"
    assert secret_box.decrypt(row["encrypted_password"]) == "an-app-password"


def test_create_account_rejects_duplicate_email(engine, secret_box, account_id):
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        create_account(
            engine,
            secret_box,
            email_address="user@example.com",
            imap_host="imap.other.com",
            password="different-password",
        )


def test_get_account_returns_none_for_missing_id(engine):
    assert get_account(engine, 999) is None


def test_insert_email_if_new_first_insert_is_new(engine, account_id):
    row_id, inserted = insert_email_if_new(engine, **_email_kwargs(account_id))
    assert inserted is True
    assert row_id is not None


def test_reingesting_same_email_creates_no_duplicate(engine, account_id):
    first_id, first_inserted = insert_email_if_new(engine, **_email_kwargs(account_id))
    second_id, second_inserted = insert_email_if_new(engine, **_email_kwargs(account_id))

    assert first_inserted is True
    assert second_inserted is False
    assert first_id == second_id

    day = local_day_range(datetime(2026, 6, 15, tzinfo=UTC).date(), "UTC")
    rows = get_emails_in_range(engine, account_id, day)
    assert len(rows) == 1


def test_uidvalidity_change_is_a_different_email(engine, account_id):
    # Same folder and uid, but the server reset UIDVALIDITY - per IMAP
    # semantics this is a different message identity, not a duplicate.
    insert_email_if_new(engine, **_email_kwargs(account_id, uidvalidity=1001))
    _, inserted = insert_email_if_new(engine, **_email_kwargs(account_id, uidvalidity=1002))
    assert inserted is True

    day = local_day_range(datetime(2026, 6, 15, tzinfo=UTC).date(), "UTC")
    rows = get_emails_in_range(engine, account_id, day)
    assert len(rows) == 2


def test_same_uid_different_account_is_not_a_duplicate(engine, secret_box, account_id):
    other_account_id = create_account(
        engine,
        secret_box,
        email_address="other@example.com",
        imap_host="imap.example.com",
        password="another-app-password",
    )
    insert_email_if_new(engine, **_email_kwargs(account_id))
    _, inserted = insert_email_if_new(engine, **_email_kwargs(other_account_id))
    assert inserted is True


def test_get_emails_in_range_is_half_open_at_day_boundary(engine, account_id):
    insert_email_if_new(
        engine,
        **_email_kwargs(
            account_id, uid=1, internal_date=datetime(2026, 6, 14, 23, 59, 59, tzinfo=UTC)
        ),
    )
    insert_email_if_new(
        engine,
        **_email_kwargs(
            account_id, uid=2, internal_date=datetime(2026, 6, 15, 0, 0, 0, tzinfo=UTC)
        ),
    )
    insert_email_if_new(
        engine,
        **_email_kwargs(
            account_id, uid=3, internal_date=datetime(2026, 6, 15, 23, 59, 59, tzinfo=UTC)
        ),
    )
    insert_email_if_new(
        engine,
        **_email_kwargs(
            account_id, uid=4, internal_date=datetime(2026, 6, 16, 0, 0, 0, tzinfo=UTC)
        ),
    )

    day = local_day_range(datetime(2026, 6, 15, tzinfo=UTC).date(), "UTC")
    rows = get_emails_in_range(engine, account_id, day)

    assert [row["uid"] for row in rows] == [2, 3]  # the 14th's and 16th's mail are excluded


def test_get_emails_in_range_orders_oldest_first(engine, account_id):
    insert_email_if_new(
        engine,
        **_email_kwargs(account_id, uid=1, internal_date=datetime(2026, 6, 15, 15, tzinfo=UTC)),
    )
    insert_email_if_new(
        engine,
        **_email_kwargs(account_id, uid=2, internal_date=datetime(2026, 6, 15, 9, tzinfo=UTC)),
    )

    day = local_day_range(datetime(2026, 6, 15, tzinfo=UTC).date(), "UTC")
    rows = get_emails_in_range(engine, account_id, day)

    assert [row["uid"] for row in rows] == [2, 1]


def test_deleting_account_cascades_to_its_emails(engine, account_id):
    from sqlalchemy import text

    insert_email_if_new(engine, **_email_kwargs(account_id))
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM accounts WHERE id = :id"), {"id": account_id})
    with engine.connect() as connection:
        count = connection.execute(text("SELECT COUNT(*) FROM emails")).scalar_one()
    assert count == 0
