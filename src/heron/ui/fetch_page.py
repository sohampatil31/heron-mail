"""The "Fetch mail" page: pick a mailbox and dates, fetch only what is missing.

Heron remembers which time ranges it has already stored, so asking again for a
range it has costs nothing. Fetching runs on the server in the background; this
page polls the jobs to show progress. Leaving the page does not stop it.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import date
from typing import Any

import streamlit as st

from heron.ui.api_client import HeronClient
from heron.ui.fetch_logic import (
    PRESETS,
    active_job_ids,
    check_range,
    describe_ingest,
    preset_range,
    summarise_jobs,
)
from heron.ui.safe import clean_text

POLL_SECONDS = 2.0
MAX_WAIT_SECONDS = 15 * 60


def render(client: HeronClient, call: Callable[[Callable[[], Any]], Any]) -> None:
    st.title("Fetch mail")
    st.caption("Heron only downloads what it doesn't already have, and never changes your mail.")

    mailboxes = call(client.list_mailboxes)
    if not mailboxes:
        st.info("Add a mailbox first.")
        return
    today = date.fromisoformat(call(lambda: client.get_activity(days=1))["start_date"])

    names = [box["email_address"] for box in mailboxes]
    index = st.selectbox("Mailbox", range(len(names)), format_func=lambda i: names[i])
    mailbox_id = mailboxes[index]["id"]
    folder = st.text_input("Folder", value="INBOX").strip() or "INBOX"

    preset = st.radio("Dates", list(PRESETS), horizontal=True)
    start, end = preset_range(preset, today)
    if preset == "Custom":
        picked = st.date_input("Date range", value=(today, today), max_value=today)
        if not isinstance(picked, tuple) or len(picked) != 2:
            st.info("Pick an end date to finish the range.")
            return
        start, end = picked

    check = check_range(start, end, today)
    for message in check.errors:
        st.error(message)
    for message in check.warnings:
        st.warning(message)
    st.caption(f"{start} to {end}, in the server's time zone")

    recent = call(lambda: client.list_jobs(mailbox_id=mailbox_id, limit=20))
    running = active_job_ids(recent)
    if running:
        st.warning("A fetch is already running for this mailbox.")
        _watch(client, call, mailbox_id, start, end, running)
    elif st.button("Fetch missing mail", type="primary", disabled=not check.ok):
        answer = call(lambda: client.ingest(mailbox_id, start.isoformat(), end.isoformat(), folder))
        st.info(describe_ingest(answer))
        job_ids = [job["id"] for job in answer.get("jobs", [])]
        if job_ids:
            _watch(client, call, mailbox_id, start, end, job_ids)

    _recent_jobs(call(lambda: client.list_jobs(mailbox_id=mailbox_id, limit=10)))


def _watch(
    client: HeronClient,
    call: Callable[[Callable[[], Any]], Any],
    mailbox_id: int,
    start: date,
    end: date,
    job_ids: list[int],
) -> None:
    """Poll the jobs until they finish, showing progress. Jobs keep running if we stop."""
    bar = st.progress(0.0, text="Starting...")
    started = time.monotonic()
    while True:
        jobs = [call(lambda job_id=job_id: client.get_job(job_id)) for job_id in job_ids]
        summary = summarise_jobs(jobs)
        stored = call(
            lambda: client.get_activity(
                mailbox_id=mailbox_id, start_date=start.isoformat(), end_date=end.isoformat()
            )
        )["emails"]
        bar.progress(
            summary.fraction,
            text=f"{summary.done + summary.failed} of {summary.total} parts finished "
            f"· {stored} emails stored in this range",
        )
        if summary.finished:
            break
        if time.monotonic() - started > MAX_WAIT_SECONDS:
            st.info("Still fetching in the background. Come back to this page to check.")
            return
        time.sleep(POLL_SECONDS)

    if summary.failed:
        st.error(f"{summary.failed} of {summary.total} parts failed.")
        for message in summary.errors:
            st.text(clean_text(message))
    else:
        st.success(f"Done. {stored} emails are stored for this range.")


def _recent_jobs(jobs: list[dict[str, Any]]) -> None:
    if not jobs:
        return
    st.subheader("Recent fetches")
    st.dataframe(
        [
            {
                "Job": job["id"],
                "Folder": job["folder"],
                "From (UTC)": job.get("range_start") or "",
                "To (UTC)": job.get("range_end") or "",
                "Status": job["status"],
                "Error": clean_text(job["error"]) if job.get("error") else "",
            }
            for job in jobs
        ],
        hide_index=True,
    )
