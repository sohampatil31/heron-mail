"""A crash inside a fetch must end the job as failed, never leave it 'running'."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import insert, text

from heron.core.config import Settings
from heron.core.crypto import SecretBox
from heron.core.jobs import claim_job, create_job, get_job
from heron.core.migrate import init_database
from heron.core.models import accounts
from heron.core.timeutil import DateRange
from heron.ingest.imap_client import FetchedMessage, ImapConnectionError
from heron.worker import runner


@pytest.fixture
def setup(tmp_path):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    engine = init_database(settings)
    box = SecretBox.from_settings(settings.secret_key, settings.data_dir)
    with engine.begin() as connection:
        account_id = int(
            connection.execute(
                insert(accounts).values(
                    email_address="me@example.org",
                    imap_host="imap.example.org",
                    encrypted_password=box.encrypt("pw"),
                    created_at="2026-10-01 00:00:00",
                )
            ).inserted_primary_key[0]
        )
    window = DateRange(datetime(2026, 10, 4, tzinfo=UTC), datetime(2026, 10, 5, tzinfo=UTC))
    job_id = create_job(engine, account_id=account_id, folder="INBOX", date_range=window)
    job = claim_job(engine, job_id)
    assert job is not None
    yield SimpleNamespace(engine=engine, box=box, eml_dir=settings.eml_dir, job=job)
    engine.dispose()


def fake_client(**behaviour):
    class Fake:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def select_folder_readonly(self, folder):
            return SimpleNamespace(uidvalidity=1)

        def search_uids(self, criteria):
            return behaviour["search"]() if "search" in behaviour else [1]

        def fetch_messages(self, uids):
            return behaviour["fetch"]()

    return Fake


def run(setup):
    runner.run_job(setup.engine, setup.box, setup.eml_dir, setup.job)
    return get_job(setup.engine, setup.job["id"])


def coverage_rows(setup) -> int:
    with setup.engine.connect() as connection:
        return connection.execute(text("SELECT COUNT(*) FROM coverage")).scalar_one()


def test_an_unexpected_exception_fails_the_job_with_a_readable_reason(setup, monkeypatch):
    def boom():
        raise RuntimeError("boom\nwith   newlines")

    monkeypatch.setattr(runner, "ImapClient", fake_client(search=boom))
    job = run(setup)  # must not raise
    assert job["status"] == "failed"
    assert job["error"] == "Unexpected error (RuntimeError): boom with newlines"
    assert coverage_rows(setup) == 0  # a failed job must not claim the range was fetched


def test_a_naive_received_time_fails_the_job_instead_of_hanging_it(setup, monkeypatch):
    naive = datetime(2026, 10, 4, 12, 0, 0)  # what imapclient used to hand back
    message = FetchedMessage(raw_bytes=b"Subject: hi\r\n\r\nbody", internal_date=naive)
    monkeypatch.setattr(runner, "ImapClient", fake_client(fetch=lambda: {1: message}))
    job = run(setup)
    assert job["status"] == "failed"
    assert "timezone-aware" in job["error"]
    assert coverage_rows(setup) == 0


def test_known_connection_errors_keep_their_own_message(setup, monkeypatch):
    def refused():
        raise ImapConnectionError("Login failed")

    monkeypatch.setattr(runner, "ImapClient", fake_client(search=refused))
    job = run(setup)
    assert (job["status"], job["error"]) == ("failed", "Login failed")


def test_a_clean_run_still_succeeds_and_records_coverage(setup, monkeypatch):
    aware = datetime(2026, 10, 4, 12, 0, 0, tzinfo=UTC)
    message = FetchedMessage(raw_bytes=b"Subject: hi\r\n\r\nbody", internal_date=aware)
    monkeypatch.setattr(runner, "ImapClient", fake_client(fetch=lambda: {1: message}))
    job = run(setup)
    assert job["status"] == "done"
    assert coverage_rows(setup) == 1
