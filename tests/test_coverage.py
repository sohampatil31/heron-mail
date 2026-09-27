"""Tests for coverage: merge-on-insert (record_coverage) and gap calculation
(compute_gaps), including the overlapping/adjacent/partial cases the
roadmap named directly.
"""

from datetime import UTC, datetime

import pytest

from heron.core.config import Settings
from heron.core.coverage import compute_gaps, get_coverage, get_gaps, record_coverage
from heron.core.crypto import SecretBox, generate_key
from heron.core.migrate import init_database
from heron.core.storage import create_account
from heron.core.timeutil import DateRange


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


def _range(start_day: int, end_day: int) -> DateRange:
    """A UTC range from June `start_day` to June `end_day`, 2026 (end exclusive)."""
    return DateRange(
        datetime(2026, 6, start_day, tzinfo=UTC), datetime(2026, 6, end_day, tzinfo=UTC)
    )


# --- record_coverage: merging -------------------------------------------------


def test_record_coverage_stores_a_single_segment(engine, account_id):
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(1, 5))
    segments = get_coverage(engine, account_id, "INBOX")
    assert segments == [_range(1, 5)]


def test_record_coverage_merges_overlapping_segments(engine, account_id):
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(1, 10))
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(5, 15))
    segments = get_coverage(engine, account_id, "INBOX")
    assert segments == [_range(1, 15)]


def test_record_coverage_merges_adjacent_segments(engine, account_id):
    # These touch exactly at June 5th with no gap - should become one segment,
    # not two separate rows that happen to sit next to each other.
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(1, 5))
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(5, 10))
    segments = get_coverage(engine, account_id, "INBOX")
    assert segments == [_range(1, 10)]


def test_record_coverage_keeps_disjoint_segments_separate(engine, account_id):
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(1, 5))
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(10, 15))
    segments = get_coverage(engine, account_id, "INBOX")
    assert segments == [_range(1, 5), _range(10, 15)]


def test_record_coverage_merges_a_segment_fully_inside_an_existing_one(engine, account_id):
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(1, 20))
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(5, 10))
    segments = get_coverage(engine, account_id, "INBOX")
    assert segments == [_range(1, 20)]  # unchanged - the new range added nothing new


def test_record_coverage_can_bridge_two_existing_segments_at_once(engine, account_id):
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(1, 5))
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(15, 20))
    # This new range overlaps both existing segments and should merge all three into one.
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(3, 17))
    segments = get_coverage(engine, account_id, "INBOX")
    assert segments == [_range(1, 20)]


def test_record_coverage_keeps_folders_separate(engine, account_id):
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(1, 5))
    record_coverage(engine, account_id=account_id, folder="Archive", date_range=_range(1, 5))
    assert get_coverage(engine, account_id, "INBOX") == [_range(1, 5)]
    assert get_coverage(engine, account_id, "Archive") == [_range(1, 5)]


def test_record_coverage_keeps_accounts_separate(engine):
    secret_box = SecretBox(generate_key())
    account_a = create_account(
        engine, secret_box, email_address="a@example.com", imap_host="h", password="x"
    )
    account_b = create_account(
        engine, secret_box, email_address="b@example.com", imap_host="h", password="x"
    )
    record_coverage(engine, account_id=account_a, folder="INBOX", date_range=_range(1, 5))
    assert get_coverage(engine, account_a, "INBOX") == [_range(1, 5)]
    assert get_coverage(engine, account_b, "INBOX") == []


def test_get_coverage_returns_empty_list_for_unknown_folder(engine, account_id):
    assert get_coverage(engine, account_id, "Nonexistent") == []


# --- compute_gaps: pure function, no database ---------------------------------


def test_compute_gaps_with_no_coverage_is_the_whole_range():
    gaps = compute_gaps(_range(1, 10), [])
    assert gaps == [_range(1, 10)]


def test_compute_gaps_with_full_coverage_is_empty():
    gaps = compute_gaps(_range(1, 10), [_range(1, 10)])
    assert gaps == []


def test_compute_gaps_with_coverage_wider_than_request_is_empty():
    gaps = compute_gaps(_range(3, 6), [_range(1, 10)])
    assert gaps == []


def test_compute_gaps_partial_at_start():
    # Covered June 5-10; requested June 1-10 -> gap is June 1-5.
    gaps = compute_gaps(_range(1, 10), [_range(5, 10)])
    assert gaps == [_range(1, 5)]


def test_compute_gaps_partial_at_end():
    gaps = compute_gaps(_range(1, 10), [_range(1, 5)])
    assert gaps == [_range(5, 10)]


def test_compute_gaps_with_a_gap_in_the_middle():
    gaps = compute_gaps(_range(1, 20), [_range(1, 5), _range(15, 20)])
    assert gaps == [_range(5, 15)]


def test_compute_gaps_with_overlapping_covered_segments():
    # Two covered segments that overlap each other (as if recorded outside
    # record_coverage's merging) should not produce a phantom gap between them.
    gaps = compute_gaps(_range(1, 20), [_range(1, 10), _range(8, 20)])
    assert gaps == []


def test_compute_gaps_with_adjacent_covered_segments():
    gaps = compute_gaps(_range(1, 20), [_range(1, 10), _range(10, 20)])
    assert gaps == []


def test_compute_gaps_ignores_coverage_entirely_outside_the_request():
    gaps = compute_gaps(_range(10, 15), [_range(1, 5), _range(20, 25)])
    assert gaps == [_range(10, 15)]


def test_compute_gaps_does_not_require_sorted_input():
    gaps = compute_gaps(_range(1, 20), [_range(15, 20), _range(1, 5)])
    assert gaps == [_range(5, 15)]


def test_compute_gaps_with_several_disjoint_gaps():
    gaps = compute_gaps(_range(1, 25), [_range(5, 10), _range(15, 20)])
    assert gaps == [_range(1, 5), _range(10, 15), _range(20, 25)]


# --- get_gaps: the database-backed convenience wrapper -------------------------


def test_get_gaps_reflects_recorded_coverage(engine, account_id):
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(1, 10))
    gaps = get_gaps(engine, account_id, "INBOX", _range(1, 20))
    assert gaps == [_range(10, 20)]


def test_get_gaps_with_no_prior_coverage_is_the_whole_range(engine, account_id):
    gaps = get_gaps(engine, account_id, "INBOX", _range(1, 10))
    assert gaps == [_range(1, 10)]


def test_get_gaps_after_two_scans_narrows_to_the_remaining_gap(engine, account_id):
    # Simulates a user first syncing "today", then later picking a wider
    # range - only the newly-requested portion should come back as a gap.
    record_coverage(engine, account_id=account_id, folder="INBOX", date_range=_range(10, 11))
    gaps = get_gaps(engine, account_id, "INBOX", _range(1, 15))
    assert gaps == [_range(1, 10), _range(11, 15)]
