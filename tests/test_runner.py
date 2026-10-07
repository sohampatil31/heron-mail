"""Tests for the worker runner: batching, checkpointing, and resuming a crashed job.

Like test_collector.py, this uses a fake in place of imapclient.IMAPClient
rather than a real server.
"""

from datetime import UTC, datetime

import pytest

from heron.core.config import Settings
from heron.core.crypto import SecretBox, generate_key
from heron.core.jobs import claim_next_job, create_job, get_job
from heron.core.migrate import init_database
from heron.core.storage import create_account, get_account, get_emails_in_range
from heron.core.timeutil import local_day_range
from heron.worker.runner import run_job


def _raw_email(uid: int) -> bytes:
    return (
        f"From: sender@example.com\r\n"
        f"To: user@example.com\r\n"
        f"Subject: Message {uid}\r\n"
        f"Date: Mon, 15 Jun 2026 12:00:00 +0000\r\n"
        f"Message-Id: <msg-{uid}@example.com>\r\n"
        "\r\n"
        f"Body {uid}.\r\n"
    ).encode()


class FakeIMAPClient:
    """Serves a fixed set of UIDs, all timestamped inside June 15th, and
    records every fetch() call so tests can see how batching happened."""

    uids: list[int] = []
    uidvalidity = 7001
    fetch_calls: list[list[int]] = []
    fail_on_search = False

    def __init__(self, host, port=993, ssl=True, timeout=30):
        pass

    def login(self, email_address, password):
        pass

    def logout(self):
        pass

    def shutdown(self):
        pass

    def select_folder(self, folder, readonly=False):
        return {b"UIDVALIDITY": self.uidvalidity, b"EXISTS": len(self.uids)}

    def search(self, criteria):
        if FakeIMAPClient.fail_on_search:
            raise OSError("connection reset")
        return list(self.uids)

    def fetch(self, uids, items):
        FakeIMAPClient.fetch_calls.append(list(uids))
        return {
            uid: {
                b"BODY[]": _raw_email(uid),
                b"INTERNALDATE": datetime(2026, 6, 15, 12, 0, tzinfo=UTC),
            }
            for uid in uids
        }


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeIMAPClient.uids = []
    FakeIMAPClient.uidvalidity = 7001
    FakeIMAPClient.fetch_calls = []
    FakeIMAPClient.fail_on_search = False
    yield
    FakeIMAPClient.uids = []
    FakeIMAPClient.fetch_calls = []
    FakeIMAPClient.fail_on_search = False


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
    return local_day_range(datetime(2026, 6, 15, tzinfo=UTC).date(), "UTC")


def _new_job(engine, account):
    create_job(engine, account_id=account["id"], folder="INBOX", date_range=_june_15_range())
    return claim_next_job(engine)  # returns the job dict, status now "running"


def test_run_job_stores_all_messages_and_marks_done(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.uids = [1, 2, 3]
    job = _new_job(engine, account)

    run_job(engine, secret_box, eml_dir, job, batch_size=50)

    finished = get_job(engine, job["id"])
    assert finished["status"] == "done"
    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert len(rows) == 3


def test_run_job_processes_uids_in_batches(patch_imapclient, engine, secret_box, account, eml_dir):
    FakeIMAPClient.uids = [1, 2, 3, 4, 5]
    job = _new_job(engine, account)

    run_job(engine, secret_box, eml_dir, job, batch_size=2)

    # 5 uids in batches of 2 -> 3 fetch() calls: [1,2], [3,4], [5]
    assert FakeIMAPClient.fetch_calls == [[1, 2], [3, 4], [5]]
    finished = get_job(engine, job["id"])
    assert finished["status"] == "done"
    assert finished["checkpoint_uid"] == 5


def test_run_job_advances_checkpoint_after_each_batch(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.uids = [10, 20, 30, 40]
    job = _new_job(engine, account)

    run_job(engine, secret_box, eml_dir, job, batch_size=2)

    finished = get_job(engine, job["id"])
    assert finished["checkpoint_uid"] == 40


def test_run_job_skips_uids_at_or_below_existing_checkpoint(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    # Simulates resuming after a crash: uids 1 and 2 were already stored and
    # checkpointed by an earlier (interrupted) run of this same job.
    FakeIMAPClient.uids = [1, 2, 3, 4]
    job = _new_job(engine, account)
    run_job(engine, secret_box, eml_dir, job, batch_size=2)  # completes normally first

    # Now simulate a second job that starts with a checkpoint already set,
    # as retry_job() would leave it - only uids > checkpoint are fetched.
    resumed_job = dict(job)
    resumed_job["checkpoint_uid"] = 2
    resumed_job["id"] = job["id"]
    FakeIMAPClient.fetch_calls = []

    run_job(engine, secret_box, eml_dir, resumed_job, batch_size=2)

    assert FakeIMAPClient.fetch_calls == [[3, 4]]


def test_run_job_marks_failed_on_connection_error(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.fail_on_search = True
    job = _new_job(engine, account)

    run_job(engine, secret_box, eml_dir, job, batch_size=50)

    finished = get_job(engine, job["id"])
    assert finished["status"] == "failed"
    assert finished["error"]


def test_run_job_fails_gracefully_when_account_is_missing(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    job = _new_job(engine, account)
    missing_account_job = dict(job, account_id=999999)

    run_job(engine, secret_box, eml_dir, missing_account_job, batch_size=50)

    finished = get_job(engine, job["id"])
    assert finished["status"] == "failed"
    assert "999999" in finished["error"]


def test_run_job_does_not_store_messages_outside_the_range(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    # The fake server ignores search criteria and always returns its uids;
    # storage still filters by the exact INTERNALDATE, same as collector.py.
    class OutsideRangeFake(FakeIMAPClient):
        def fetch(self, uids, items):
            FakeIMAPClient.fetch_calls.append(list(uids))
            return {
                uid: {
                    b"BODY[]": _raw_email(uid),
                    b"INTERNALDATE": datetime(2026, 6, 20, 12, 0, tzinfo=UTC),  # outside range
                }
                for uid in uids
            }

    import heron.ingest.imap_client as imap_client_module

    original = imap_client_module.IMAPClient
    imap_client_module.IMAPClient = OutsideRangeFake
    try:
        FakeIMAPClient.uids = [1]
        job = _new_job(engine, account)
        run_job(engine, secret_box, eml_dir, job, batch_size=50)
    finally:
        imap_client_module.IMAPClient = original

    finished = get_job(engine, job["id"])
    assert finished["status"] == "done"
    rows = get_emails_in_range(engine, account["id"], _june_15_range())
    assert len(rows) == 0
