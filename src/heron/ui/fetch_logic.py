"""The pure parts of the Fetch mail page: date presets, checks, and job progress."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

MAX_DAYS = 366
LONG_RANGE_DAYS = 31
PRESETS = ("Today", "Yesterday", "Last 7 days", "Custom")
ACTIVE_STATUSES = ("pending", "running")


def preset_range(preset: str, today: date) -> tuple[date, date]:
    """Dates for a preset, relative to `today` in the server's time zone."""
    if preset == "Yesterday":
        return today - timedelta(days=1), today - timedelta(days=1)
    if preset == "Last 7 days":
        return today - timedelta(days=6), today
    return today, today


@dataclass(frozen=True, slots=True)
class RangeCheck:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def check_range(start: date, end: date, today: date) -> RangeCheck:
    errors: list[str] = []
    warnings: list[str] = []
    if end < start:
        errors.append("The end date is before the start date.")
    if end > today:
        errors.append("Mail can't be fetched for dates in the future.")
    days = (end - start).days + 1
    if days > MAX_DAYS:
        errors.append(f"Choose at most {MAX_DAYS} days at a time.")
    elif days > LONG_RANGE_DAYS:
        warnings.append(f"{days} days is a lot of mail. This can take a long time.")
    return RangeCheck(tuple(errors), tuple(warnings))


@dataclass(frozen=True, slots=True)
class JobsSummary:
    total: int
    pending: int
    running: int
    done: int
    failed: int
    errors: tuple[str, ...]  # failure messages, as reported by the server

    @property
    def finished(self) -> bool:
        return self.total > 0 and self.pending + self.running == 0

    @property
    def fraction(self) -> float:
        """Share of jobs that have finished, 0.0 to 1.0. (Jobs report no item counts.)"""
        return (self.done + self.failed) / self.total if self.total else 0.0


def summarise_jobs(jobs: list[dict[str, Any]]) -> JobsSummary:
    statuses = [job.get("status") for job in jobs]
    known = {"running", "done", "failed"}
    return JobsSummary(
        total=len(jobs),
        pending=sum(1 for s in statuses if s not in known),  # pending, or anything unexpected
        running=statuses.count("running"),
        done=statuses.count("done"),
        failed=statuses.count("failed"),
        errors=tuple(
            str(job["error"]) for job in jobs if job.get("status") == "failed" and job.get("error")
        ),
    )


def describe_ingest(response: dict[str, Any]) -> str:
    gaps = response.get("gaps_found", 0)
    if gaps == 0:
        return "Everything in this range is already stored. Nothing to fetch."
    noun = "part" if gaps == 1 else "parts"
    return f"{gaps} missing {noun} found. Fetching now."


def active_job_ids(jobs: list[dict[str, Any]]) -> list[int]:
    return [job["id"] for job in jobs if job.get("status") in ACTIVE_STATUSES]
