"""activity_for() against a real database built by the real migrations."""

from datetime import date

import pytest
from sqlalchemy import insert

from heron.analysis.scoring import assess
from heron.core.activity_storage import activity_for
from heron.core.analysis_storage import record_assessment
from heron.core.config import Settings
from heron.core.migrate import init_database
from heron.core.models import accounts, emails
from heron.rules.base import Finding, Severity
from heron.rules.registry import RuleResults

OCT3 = date(2026, 10, 3)


@pytest.fixture
def engine(tmp_path):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    eng = init_database(settings)
    yield eng
    eng.dispose()


def add_account(engine, address: str) -> int:
    with engine.begin() as connection:
        return int(
            connection.execute(
                insert(accounts).values(
                    email_address=address,
                    imap_host="imap.example.org",
                    encrypted_password="x",
                    created_at="2026-10-01 00:00:00",
                )
            ).inserted_primary_key[0]
        )


def add_email(engine, account_id: int, uid: int, internal_date: str) -> int:
    with engine.begin() as connection:
        return int(
            connection.execute(
                insert(emails).values(
                    account_id=account_id,
                    folder="INBOX",
                    uidvalidity=1,
                    uid=uid,
                    message_id=None,
                    content_hash=f"hash{uid}",
                    internal_date=internal_date,
                    header_date=None,
                    subject=None,
                    from_address=None,
                    eml_path=f"ab/hash{uid}.eml",
                    created_at="2026-10-01 08:00:01",
                )
            ).inserted_primary_key[0]
        )


def flag(engine, email_id: int, severity: Severity) -> None:
    finding = Finding("auth.dmarc_fail", severity, "t", "d", ("e",))
    record_assessment(engine, email_id, assess(RuleResults((finding,), ())), "s")


def test_counts_emails_and_verdicts_for_a_day(engine):
    account = add_account(engine, "me@example.org")
    plain = add_email(engine, account, 1, "2026-10-03 08:10:00")
    flagged = add_email(engine, account, 2, "2026-10-03 08:20:00")
    add_email(engine, account, 3, "2026-10-03 15:00:00")  # never analysed
    record_assessment(engine, plain, assess(RuleResults((), ())), "s")
    flag(engine, flagged, Severity.HIGH)  # one HIGH finding = suspicious

    activity = activity_for(engine, None, OCT3, OCT3, "UTC")
    assert (activity.emails, activity.analysed, activity.suspicious) == (3, 2, 1)
    by_label = {b.label: b for b in activity.buckets}
    assert by_label["2026-10-03T08:00"].emails == 2
    assert by_label["2026-10-03T08:00"].suspicious == 1
    assert by_label["2026-10-03T15:00"].emails == 1


def test_other_days_are_excluded_and_the_time_zone_decides_the_day(engine):
    account = add_account(engine, "me@example.org")
    add_email(engine, account, 1, "2026-10-02 23:30:00")  # Oct 3, 05:00 in Kolkata
    add_email(engine, account, 2, "2026-10-03 19:00:00")  # Oct 4, 00:30 in Kolkata
    add_email(engine, account, 3, "2026-09-20 10:00:00")

    assert activity_for(engine, None, OCT3, OCT3, "UTC").emails == 1
    kolkata = activity_for(engine, None, OCT3, OCT3, "Asia/Kolkata")
    assert kolkata.emails == 1
    assert [b.label for b in kolkata.buckets if b.emails] == ["2026-10-03T05:00"]


def test_filtering_by_mailbox(engine):
    first = add_account(engine, "one@example.org")
    second = add_account(engine, "two@example.org")
    add_email(engine, first, 1, "2026-10-03 08:00:00")
    add_email(engine, second, 2, "2026-10-03 09:00:00")
    add_email(engine, second, 3, "2026-10-03 10:00:00")

    assert activity_for(engine, None, OCT3, OCT3, "UTC").emails == 3
    assert activity_for(engine, first, OCT3, OCT3, "UTC").emails == 1
    assert activity_for(engine, second, OCT3, OCT3, "UTC").emails == 2


def test_a_multi_day_range_is_bucketed_by_day(engine):
    account = add_account(engine, "me@example.org")
    add_email(engine, account, 1, "2026-10-01 08:00:00")
    add_email(engine, account, 2, "2026-10-03 08:00:00")
    activity = activity_for(engine, None, date(2026, 10, 1), OCT3, "UTC")
    assert activity.granularity == "day"
    assert [b.emails for b in activity.buckets] == [1, 0, 1]


def test_end_before_start_is_rejected(engine):
    with pytest.raises(ValueError):
        activity_for(engine, None, OCT3, date(2026, 10, 2), "UTC")
