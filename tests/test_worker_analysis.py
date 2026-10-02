"""analyze_pending / reanalyze_stale against real .eml files and a real database."""

import shutil
from pathlib import Path

import pytest
from sqlalchemy import insert, text

from heron.analysis.scoring import rules_version
from heron.core.analysis_storage import get_analysis, list_alerts
from heron.core.config import Settings
from heron.core.migrate import init_database
from heron.core.models import accounts, emails
from heron.worker import analysis as worker_analysis
from heron.worker.analysis import (
    analyze_pending,
    analyze_pending_safely,
    analyze_stored_email,
    reanalyze_stale,
)

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


@pytest.fixture
def engine(tmp_path):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    eng = init_database(settings)
    yield eng
    eng.dispose()


@pytest.fixture
def eml_dir(tmp_path):
    directory = tmp_path / "eml-store"
    directory.mkdir()
    return directory


@pytest.fixture
def account_id(engine):
    with engine.begin() as connection:
        result = connection.execute(
            insert(accounts).values(
                email_address="me@example.org",
                imap_host="imap.example.org",
                encrypted_password="x",
                created_at="2026-10-01 00:00:00",
            )
        )
        return int(result.inserted_primary_key[0])


def store(engine, account_id: int, eml_dir: Path, uid: int, fixture: str | None, path=None) -> int:
    """Insert an email row; copy a fixture to its path unless fixture is None."""
    relative = path or f"{uid:02d}/mail{uid}.eml"
    if fixture is not None:
        target = eml_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / fixture, target)
    with engine.begin() as connection:
        result = connection.execute(
            insert(emails).values(
                account_id=account_id,
                folder="INBOX",
                uidvalidity=1,
                uid=uid,
                message_id=None,
                content_hash=f"hash{uid}",
                internal_date="2026-10-01 08:00:00",
                header_date=None,
                subject=None,
                from_address=None,
                eml_path=relative,
                created_at="2026-10-01 08:00:01",
            )
        )
        return int(result.inserted_primary_key[0])


def test_analyze_pending_scores_everything_and_alerts_on_the_bad_one(engine, account_id, eml_dir):
    clean_id = store(engine, account_id, eml_dir, 1, "newsletter_alternative.eml")
    phish_id = store(engine, account_id, eml_dir, 2, "phish_invoice.eml")

    assert analyze_pending(engine, eml_dir) == 2

    clean = get_analysis(engine, clean_id)
    phish = get_analysis(engine, phish_id)
    assert clean is not None
    assert phish is not None
    assert (clean["verdict"], clean["score"]) == ("clean", 0)
    assert (phish["verdict"], phish["score"]) == ("phishing", 100)
    assert phish["rules_version"] == rules_version()
    (alert,) = list_alerts(engine)
    assert alert["email_id"] == phish_id
    assert alert["status"] == "open"


def test_analyze_pending_is_idempotent(engine, account_id, eml_dir):
    store(engine, account_id, eml_dir, 1, "plain_simple.eml")
    assert analyze_pending(engine, eml_dir) == 1
    assert analyze_pending(engine, eml_dir) == 0


def test_batches_cover_everything(engine, account_id, eml_dir):
    for uid in range(1, 6):
        store(engine, account_id, eml_dir, uid, "plain_simple.eml")
    assert analyze_pending(engine, eml_dir, batch_size=2) == 5


def test_unreadable_and_escaping_paths_are_skipped_without_looping(
    engine, account_id, eml_dir, tmp_path
):
    (tmp_path / "outside.eml").write_bytes((FIXTURES / "phish_invoice.eml").read_bytes())
    store(engine, account_id, eml_dir, 1, None, path="missing/nothing.eml")
    store(engine, account_id, eml_dir, 2, None, path="../outside.eml")
    good = store(engine, account_id, eml_dir, 3, "plain_simple.eml")

    assert analyze_pending(engine, eml_dir, batch_size=1) == 1
    assert get_analysis(engine, good) is not None
    assert list_alerts(engine) == []  # the file outside the store was never read


def test_analyze_stored_email_reports_success(engine, account_id, eml_dir):
    email_id = store(engine, account_id, eml_dir, 1, "plain_simple.eml")
    row = {"id": email_id, "eml_path": "01/mail1.eml"}
    assert analyze_stored_email(engine, eml_dir, row) is True
    assert analyze_stored_email(engine, eml_dir, {"id": email_id, "eml_path": "nope.eml"}) is False


def test_reanalyze_stale_only_touches_old_versions(engine, account_id, eml_dir):
    current = store(engine, account_id, eml_dir, 1, "newsletter_alternative.eml")
    stale = store(engine, account_id, eml_dir, 2, "phish_invoice.eml")
    analyze_pending(engine, eml_dir)
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE analyses SET rules_version = 'old', score = 0 WHERE email_id = :id"),
            {"id": stale},
        )

    assert reanalyze_stale(engine, eml_dir) == 1

    refreshed = get_analysis(engine, stale)
    untouched = get_analysis(engine, current)
    assert refreshed is not None
    assert untouched is not None
    assert refreshed["rules_version"] == rules_version()
    assert refreshed["score"] == 100
    assert reanalyze_stale(engine, eml_dir) == 0


def test_reanalyze_stale_does_not_loop_on_an_unreadable_file(engine, account_id, eml_dir):
    email_id = store(engine, account_id, eml_dir, 1, "plain_simple.eml")
    analyze_pending(engine, eml_dir)
    with engine.begin() as connection:
        connection.execute(text("UPDATE analyses SET rules_version = 'old'"))
    (eml_dir / "01" / "mail1.eml").unlink()

    assert reanalyze_stale(engine, eml_dir) == 0
    analysis = get_analysis(engine, email_id)
    assert analysis is not None
    assert analysis["rules_version"] == "old"  # untouched, and we still terminated


def test_analyze_pending_safely_swallows_failures_and_recovers_next_time(
    engine, account_id, eml_dir, monkeypatch
):
    email_id = store(engine, account_id, eml_dir, 1, "plain_simple.eml")

    def boom(*_args, **_kwargs):
        raise RuntimeError("analysis bug")

    monkeypatch.setattr(worker_analysis, "analyze_pending", boom)
    assert analyze_pending_safely(engine, eml_dir) == 0  # no exception reaches the caller
    assert get_analysis(engine, email_id) is None

    monkeypatch.undo()
    assert analyze_pending_safely(engine, eml_dir) == 1
    assert get_analysis(engine, email_id) is not None
