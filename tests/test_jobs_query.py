"""Tests for list_jobs and claim_job, added alongside Day 8's job queue."""

from datetime import UTC, datetime

import pytest

from heron.core.config import Settings
from heron.core.crypto import SecretBox, generate_key
from heron.core.jobs import claim_job, claim_next_job, create_job, list_jobs, mark_done
from heron.core.migrate import init_database
from heron.core.storage import create_account
from heron.core.timeutil import local_day_range


@pytest.fixture
def engine(tmp_path):
    eng = init_database(Settings(data_dir=tmp_path / "data"))
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


# --- list_jobs --------------------------------------------------------------


def test_list_jobs_is_empty_at_first(engine):
    assert list_jobs(engine) == []


def test_list_jobs_returns_newest_first(engine, account_id):
    first = create_job(engine, account_id=account_id, folder="A", date_range=_range())
    second = create_job(engine, account_id=account_id, folder="B", date_range=_range())
    assert [job["id"] for job in list_jobs(engine)] == [second, first]


def test_list_jobs_filters_by_account_id(engine, account_id):
    secret_box = SecretBox(generate_key())
    other_account_id = create_account(
        engine, secret_box, email_address="other@example.com", imap_host="h", password="x"
    )
    create_job(engine, account_id=account_id, folder="A", date_range=_range())
    create_job(engine, account_id=other_account_id, folder="B", date_range=_range())

    jobs_for_account = list_jobs(engine, account_id=account_id)
    assert len(jobs_for_account) == 1
    assert jobs_for_account[0]["account_id"] == account_id


def test_list_jobs_filters_by_status(engine, account_id):
    done_id = create_job(engine, account_id=account_id, folder="A", date_range=_range())
    create_job(engine, account_id=account_id, folder="B", date_range=_range())
    claim_job(engine, done_id)
    mark_done(engine, done_id)

    pending_jobs = list_jobs(engine, status="pending")
    done_jobs = list_jobs(engine, status="done")
    assert len(pending_jobs) == 1
    assert len(done_jobs) == 1
    assert done_jobs[0]["id"] == done_id


def test_list_jobs_respects_limit(engine, account_id):
    for _ in range(5):
        create_job(engine, account_id=account_id, folder="A", date_range=_range())
    assert len(list_jobs(engine, limit=2)) == 2


# --- claim_job ----------------------------------------------------------------


def test_claim_job_claims_a_pending_job_by_id(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="A", date_range=_range())
    claimed = claim_job(engine, job_id)
    assert claimed["id"] == job_id
    assert claimed["status"] == "running"
    assert claimed["started_at"] is not None


def test_claim_job_returns_none_for_unknown_id(engine):
    assert claim_job(engine, 999) is None


def test_claim_job_returns_none_if_already_running(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="A", date_range=_range())
    claim_job(engine, job_id)
    assert claim_job(engine, job_id) is None


def test_claim_job_targets_only_the_requested_job(engine, account_id):
    # Two pending jobs exist; claim_job must claim the one asked for, not
    # whichever is oldest (that is claim_next_job's job, not this one's).
    first_id = create_job(engine, account_id=account_id, folder="A", date_range=_range())
    second_id = create_job(engine, account_id=account_id, folder="B", date_range=_range())
    claimed = claim_job(engine, second_id)
    assert claimed["id"] == second_id
    assert list_jobs(engine, status="pending")[0]["id"] == first_id


def test_claim_job_does_not_interfere_with_claim_next_job(engine, account_id):
    job_id = create_job(engine, account_id=account_id, folder="A", date_range=_range())
    claim_job(engine, job_id)
    # The only job is now running, not pending, so the queue-style claim
    # correctly finds nothing left to do.
    assert claim_next_job(engine) is None
