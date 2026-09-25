from datetime import UTC, datetime

import pytest

from heron.core.config import Settings
from heron.core.crypto import SecretBox, generate_key
from heron.core.jobs import (
    claim_next_job,
    create_job,
    get_job,
    mark_done,
    mark_failed,
    retry_job,
    update_checkpoint,
)
from heron.core.migrate import init_database
from heron.core.storage import create_account
from heron.core.timeutil import local_day_range


@pytest.fixture
def engine(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    eng = init_database(settings)
    yield eng
    eng.dispose()


@pytest.fixture
def account_id(engine):
    secret_box = SecretBox(generate_key())
    return create_account(
        engine,
        secret_box,
        email_address="user@example.com",
        imap_host="imap.example.com",
        password="an-app-password",
    )


def _range():
    return local_day_range(datetime(2026, 6, 15, tzinfo=UTC).date(), "UTC")


def test_create_job_starts_pending(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    job = get_job(engine, job_id)
    assert job["status"] == "pending"
    assert job["checkpoint_uid"] is None
    assert job["range_start"] == "2026-06-15 00:00:00"
    assert job["range_end"] == "2026-06-16 00:00:00"


def test_get_job_returns_none_for_missing_id(engine):
    assert get_job(engine, 999) is None


def test_claim_next_job_returns_none_when_queue_is_empty(engine):
    assert claim_next_job(engine) is None


def test_claim_next_job_marks_it_running(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    claimed = claim_next_job(engine)
    assert claimed["id"] == job_id
    assert claimed["status"] == "running"
    assert claimed["started_at"] is not None


def test_claim_next_job_claims_oldest_first(engine, account_id):
    first_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    create_job(engine, account_id=account_id, folder="Archive", date_range=_range())
    claimed = claim_next_job(engine)
    assert claimed["id"] == first_id


def test_claim_next_job_does_not_reclaim_a_running_job(engine, account_id):
    create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    first_claim = claim_next_job(engine)
    second_claim = claim_next_job(engine)
    assert first_claim is not None
    assert second_claim is None


def test_claim_next_job_skips_done_and_failed_jobs(engine, account_id):
    done_id = create_job(engine, account_id=account_id, folder="A", date_range=_range())
    failed_id = create_job(engine, account_id=account_id, folder="B", date_range=_range())
    pending_id = create_job(engine, account_id=account_id, folder="C", date_range=_range())
    mark_done(engine, done_id)
    mark_failed(engine, failed_id, "boom")

    claimed = claim_next_job(engine)
    assert claimed["id"] == pending_id


def test_update_checkpoint_stores_the_uid(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    claim_next_job(engine)
    update_checkpoint(engine, job_id, 42)
    job = get_job(engine, job_id)
    assert job["checkpoint_uid"] == 42
    assert job["status"] == "running"  # unchanged by a checkpoint update


def test_mark_done_sets_status_and_finished_at(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    claim_next_job(engine)
    mark_done(engine, job_id)
    job = get_job(engine, job_id)
    assert job["status"] == "done"
    assert job["finished_at"] is not None


def test_mark_failed_sets_status_and_error(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    claim_next_job(engine)
    update_checkpoint(engine, job_id, 10)
    mark_failed(engine, job_id, "IMAP login failed")
    job = get_job(engine, job_id)
    assert job["status"] == "failed"
    assert job["error"] == "IMAP login failed"
    # The checkpoint survives a failure - that is what makes a retry resumable.
    assert job["checkpoint_uid"] == 10


def test_retry_job_resets_to_pending_but_keeps_checkpoint(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    claim_next_job(engine)
    update_checkpoint(engine, job_id, 10)
    mark_failed(engine, job_id, "network blip")

    retry_job(engine, job_id)

    job = get_job(engine, job_id)
    assert job["status"] == "pending"
    assert job["error"] is None
    assert job["checkpoint_uid"] == 10  # resume point preserved


def test_retried_job_can_be_claimed_again(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    claim_next_job(engine)
    mark_failed(engine, job_id, "network blip")
    retry_job(engine, job_id)

    claimed = claim_next_job(engine)
    assert claimed["id"] == job_id
    assert claimed["status"] == "running"


def test_deleting_account_cascades_to_its_jobs(engine, account_id):
    from sqlalchemy import text

    create_job(engine, account_id=account_id, folder="INBOX", date_range=_range())
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM accounts WHERE id = :id"), {"id": account_id})
    with engine.connect() as connection:
        count = connection.execute(text("SELECT COUNT(*) FROM jobs")).scalar_one()
    assert count == 0
