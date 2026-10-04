from datetime import date, timedelta

from heron.ui.fetch_logic import (
    LONG_RANGE_DAYS,
    MAX_DAYS,
    active_job_ids,
    check_range,
    describe_ingest,
    preset_range,
    summarise_jobs,
)

TODAY = date(2026, 10, 3)


def test_presets_are_relative_to_the_servers_today():
    assert preset_range("Today", TODAY) == (TODAY, TODAY)
    assert preset_range("Yesterday", TODAY) == (date(2026, 10, 2), date(2026, 10, 2))
    assert preset_range("Last 7 days", TODAY) == (date(2026, 9, 27), TODAY)
    assert preset_range("Custom", TODAY) == (TODAY, TODAY)  # the picker supplies real dates


def test_a_valid_range_has_no_errors_or_warnings():
    check = check_range(date(2026, 10, 1), TODAY, TODAY)
    assert check.ok
    assert (check.errors, check.warnings) == ((), ())


def test_each_range_problem_is_reported():
    assert not check_range(TODAY, date(2026, 10, 2), TODAY).ok
    future = check_range(TODAY, date(2026, 10, 4), TODAY)
    assert not future.ok
    assert "future" in future.errors[0]
    too_long = check_range(date(2025, 1, 1), TODAY, TODAY)
    assert not too_long.ok
    assert str(MAX_DAYS) in too_long.errors[0]


def test_long_ranges_warn_but_are_allowed():
    assert check_range(date(2026, 10, 1), TODAY, TODAY).warnings == ()  # 3 days
    long_start = TODAY - timedelta(days=LONG_RANGE_DAYS)  # LONG_RANGE_DAYS + 1 days inclusive
    check = check_range(long_start, TODAY, TODAY)
    assert check.ok
    assert len(check.warnings) == 1


def test_summarise_jobs_counts_and_progress():
    jobs = [
        {"id": 1, "status": "done"},
        {"id": 2, "status": "running"},
        {"id": 3, "status": "pending"},
        {"id": 4, "status": "failed", "error": "IMAP login failed"},
    ]
    summary = summarise_jobs(jobs)
    assert (summary.total, summary.pending, summary.running) == (4, 1, 1)
    assert (summary.done, summary.failed) == (1, 1)
    assert summary.errors == ("IMAP login failed",)
    assert not summary.finished
    assert summary.fraction == 0.5


def test_finished_means_nothing_is_pending_or_running():
    assert summarise_jobs([{"status": "done"}, {"status": "failed"}]).finished
    assert not summarise_jobs([]).finished  # no jobs is not "finished"
    assert summarise_jobs([]).fraction == 0.0
    assert not summarise_jobs([{"status": "something-new"}]).finished  # unknown counts as active


def test_failed_jobs_without_a_message_add_no_error():
    assert summarise_jobs([{"status": "failed", "error": None}]).errors == ()


def test_describe_ingest():
    assert "already stored" in describe_ingest({"gaps_found": 0, "jobs": []})
    assert describe_ingest({"gaps_found": 1, "jobs": [{}]}) == "1 missing part found. Fetching now."
    assert describe_ingest({"gaps_found": 3, "jobs": [{}, {}, {}]}).startswith("3 missing parts")


def test_active_job_ids():
    jobs = [
        {"id": 1, "status": "done"},
        {"id": 2, "status": "running"},
        {"id": 3, "status": "pending"},
    ]
    assert active_job_ids(jobs) == [2, 3]
