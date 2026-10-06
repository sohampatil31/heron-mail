"""Regression tests for the "ts must be timezone-aware" crash on a real fetch."""

from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import MagicMock

from heron.ingest import imap_client
from heron.ingest.imap_client import ImapClient, _as_aware


def test_the_imap_connection_asks_for_timezone_aware_times(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(imap_client, "IMAPClient", fake)
    with ImapClient("imap.example.org", "me@example.org", "pw"):
        pass
    # Without this flag imapclient returns naive local times, and the date-range
    # filter (correctly) refuses them.
    assert fake.call_args.kwargs["normalise_times"] is False


def test_a_naive_time_is_given_a_zone_instead_of_being_passed_on():
    naive = datetime(2026, 10, 4, 12, 0, 0)
    aware = _as_aware(naive)
    assert aware.tzinfo is not None
    assert aware.replace(tzinfo=None) == naive  # same wall-clock time, now with a zone


def test_an_aware_time_is_left_exactly_as_it_is():
    kolkata = timezone(timedelta(hours=5, minutes=30))
    original = datetime(2026, 10, 4, 12, 0, 0, tzinfo=kolkata)
    assert _as_aware(original) is original
    utc_time = datetime(2026, 10, 4, 12, 0, 0, tzinfo=UTC)
    assert _as_aware(utc_time) is utc_time
