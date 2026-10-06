from datetime import UTC, datetime

import pytest
from sqlalchemy import insert, select

from heron.api.app import create_app
from heron.core.config import Settings
from heron.core.job_recovery import INTERRUPTED_MESSAGE, fail_interrupted_jobs
from heron.core.migrate import init_database
from heron.core.models import accounts, jobs

NOW = datetime(2026, 10, 4, 9, 30, 0, tzinfo=UTC)


@pytest.fixture
def engine(tmp_path):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    eng = init_database(settings)
    yield eng
    eng.dispose()


def add_job(engine, account_id: int, status: str) -> int:
    with engine.begin() as connection:
        return int(
            connection.execute(
                insert(jobs).values(
                    account_id=account_id,
                    folder="INBOX",
                    range_start="2026-10-04 00:00:00",
                    range_end="2026-10-05 00:00:00",
                    status=status,
                    created_at="2026-10-04 08:00:00",
                )
            ).inserted_primary_key[0]
        )


def add_account(engine) -> int:
    with engine.begin() as connection:
        return int(
            connection.execute(
                insert(accounts).values(
                    email_address="me@example.org",
                    imap_host="imap.example.org",
                    encrypted_password="x",
                    created_at="2026-10-01 00:00:00",
                )
            ).inserted_primary_key[0]
        )


def status_of(engine, job_id: int):
    with engine.connect() as connection:
        return connection.execute(select(jobs).where(jobs.c.id == job_id)).mappings().one()


def test_running_jobs_become_failed_with_a_reason_and_time(engine):
    job = add_job(engine, add_account(engine), "running")
    assert fail_interrupted_jobs(engine, now=NOW) == 1
    row = status_of(engine, job)
    assert row["status"] == "failed"
    assert row["error"] == INTERRUPTED_MESSAGE
    assert row["finished_at"] == "2026-10-04 09:30:00"


def test_other_statuses_are_left_alone(engine):
    account = add_account(engine)
    untouched = {s: add_job(engine, account, s) for s in ("pending", "done", "failed")}
    assert fail_interrupted_jobs(engine, now=NOW) == 0
    for status, job_id in untouched.items():
        assert status_of(engine, job_id)["status"] == status
        assert status_of(engine, job_id)["error"] is None


def test_running_it_twice_changes_nothing_the_second_time(engine):
    add_job(engine, add_account(engine), "running")
    assert fail_interrupted_jobs(engine) == 1
    assert fail_interrupted_jobs(engine) == 0


def test_starting_the_app_cleans_up_orphaned_jobs(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token="t")
    first = create_app(settings)
    job = add_job(first.state.engine, add_account(first.state.engine), "running")
    first.state.engine.dispose()

    second = create_app(settings)  # a restart
    try:
        assert status_of(second.state.engine, job)["status"] == "failed"
    finally:
        second.state.engine.dispose()
