"""Confirms the worker actually records coverage on a successful job.

record_coverage() has existed since Day 9, but nothing called it outside of
its own tests until now - a real gap: without this, get_gaps() would never
see any range as covered, and every ingest would re-scan from scratch.
"""

from datetime import UTC, datetime

import pytest

from heron.core.config import Settings
from heron.core.coverage import get_coverage
from heron.core.crypto import SecretBox, generate_key
from heron.core.jobs import claim_next_job, create_job, get_job
from heron.core.migrate import init_database
from heron.core.storage import create_account, get_account
from heron.core.timeutil import local_day_range
from heron.worker.runner import run_job


class FakeIMAPClient:
    uids: list[int] = []
    fail_on_search = False

    def __init__(self, host, port=993, ssl=True, timeout=30, normalise_times=True):
        pass

    def login(self, email_address, password):
        pass

    def logout(self):
        pass

    def shutdown(self):
        pass

    def select_folder(self, folder, readonly=False):
        return {b"UIDVALIDITY": 1, b"EXISTS": len(self.uids)}

    def search(self, criteria):
        if FakeIMAPClient.fail_on_search:
            raise OSError("connection reset")
        return list(self.uids)

    def fetch(self, uids, items):
        return {
            uid: {
                b"BODY[]": f"From: a@example.com\r\nSubject: {uid}\r\n\r\nBody.\r\n".encode(),
                b"INTERNALDATE": datetime(2026, 6, 15, 12, 0, tzinfo=UTC),
            }
            for uid in uids
        }


@pytest.fixture(autouse=True)
def _reset():
    FakeIMAPClient.uids = []
    FakeIMAPClient.fail_on_search = False
    yield


@pytest.fixture
def patch_imapclient(monkeypatch):
    monkeypatch.setattr("heron.ingest.imap_client.IMAPClient", FakeIMAPClient)


@pytest.fixture
def engine(tmp_path):
    eng = init_database(Settings(data_dir=tmp_path / "data"))
    yield eng
    eng.dispose()


@pytest.fixture
def secret_box():
    return SecretBox(generate_key())


@pytest.fixture
def account(engine, secret_box):
    account_id = create_account(
        engine, secret_box, email_address="user@example.com", imap_host="h", password="x"
    )
    return get_account(engine, account_id)


@pytest.fixture
def eml_dir(tmp_path):
    path = tmp_path / "eml"
    path.mkdir()
    return path


def _june_15_range():
    return local_day_range(datetime(2026, 6, 15, tzinfo=UTC).date(), "UTC")


def test_successful_job_records_coverage(patch_imapclient, engine, secret_box, account, eml_dir):
    FakeIMAPClient.uids = [1, 2]
    create_job(engine, account_id=account["id"], folder="INBOX", date_range=_june_15_range())
    job = claim_next_job(engine)

    run_job(engine, secret_box, eml_dir, job)

    segments = get_coverage(engine, account["id"], "INBOX")
    assert segments == [_june_15_range()]


def test_failed_job_records_no_coverage(patch_imapclient, engine, secret_box, account, eml_dir):
    FakeIMAPClient.fail_on_search = True
    create_job(engine, account_id=account["id"], folder="INBOX", date_range=_june_15_range())
    job = claim_next_job(engine)

    run_job(engine, secret_box, eml_dir, job)

    assert get_job(engine, job["id"])["status"] == "failed"
    assert get_coverage(engine, account["id"], "INBOX") == []


def test_coverage_is_scoped_to_the_jobs_own_folder(
    patch_imapclient, engine, secret_box, account, eml_dir
):
    FakeIMAPClient.uids = [1]
    create_job(engine, account_id=account["id"], folder="Archive", date_range=_june_15_range())
    job = claim_next_job(engine)

    run_job(engine, secret_box, eml_dir, job)

    assert get_coverage(engine, account["id"], "Archive") == [_june_15_range()]
    assert get_coverage(engine, account["id"], "INBOX") == []
