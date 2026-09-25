"""Runs a single job: fetch mail in batches, checkpointing between batches.

Unlike ingest.collector.fetch_and_store_range() (a one-shot fetch used for
quick ranges, e.g. a dashboard's initial "today" sync), run_job() processes
UIDs in bounded batches and records progress after each one. If the worker
process dies mid-job, the job is left in status "running" with
checkpoint_uid pointing at the last batch that was fully stored; a retry
(via core.jobs.retry_job) picks up after that UID instead of re-fetching
and re-processing everything from the start of the range.

Both this module and collector.py call the same
ingest.collector.store_if_in_range() for the actual per-message work, so
the two paths can never disagree about what "store a message" means.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from sqlalchemy.engine import Engine

from heron.core.crypto import SecretBox
from heron.core.jobs import mark_done, mark_failed, update_checkpoint
from heron.core.storage import get_account
from heron.core.timeutil import DateRange, from_utc_storage_string
from heron.ingest.collector import imap_date_string, store_if_in_range
from heron.ingest.imap_client import ImapClient, ImapConnectionError

DEFAULT_BATCH_SIZE = 50


def run_job(
    engine: Engine,
    secret_box: SecretBox,
    eml_dir: Path,
    job: dict[str, Any],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> None:
    """Execute a claimed job (see core.jobs.claim_next_job) to completion or failure.

    `job` must already be in status "running" - claim_next_job() sets that
    as part of claiming it. This function only ever transitions it onward to
    "done" or "failed"; it never re-claims.
    """
    account = get_account(engine, job["account_id"])
    if account is None:
        mark_failed(engine, job["id"], f"account {job['account_id']} no longer exists")
        return

    date_range = DateRange(
        from_utc_storage_string(job["range_start"]), from_utc_storage_string(job["range_end"])
    )
    wide_range = date_range.widened_for_imap_search()

    try:
        password = secret_box.decrypt(account["encrypted_password"])
        with ImapClient(account["imap_host"], account["email_address"], password) as client:
            folder_info = client.select_folder_readonly(job["folder"])
            criteria = [
                "SINCE",
                imap_date_string(wide_range.start),
                "BEFORE",
                imap_date_string(wide_range.end),
            ]
            uids = sorted(client.search_uids(criteria))
            checkpoint = job.get("checkpoint_uid")
            if checkpoint is not None:
                uids = [uid for uid in uids if uid > checkpoint]

            for batch in _chunked(uids, batch_size):
                fetched = client.fetch_messages(batch)
                for uid in batch:
                    message = fetched.get(uid)
                    if message is None:
                        # Deleted from the server between search and fetch -
                        # nothing to store, and not an error.
                        continue
                    store_if_in_range(
                        engine,
                        account_id=account["id"],
                        folder=job["folder"],
                        uidvalidity=folder_info.uidvalidity,
                        uid=uid,
                        message=message,
                        date_range=date_range,
                        eml_dir=eml_dir,
                    )
                # Committed once the whole batch is stored, so a crash never
                # leaves the checkpoint ahead of what is actually on disk
                # and in the vault.
                update_checkpoint(engine, job["id"], batch[-1])
    except ImapConnectionError as exc:
        mark_failed(engine, job["id"], str(exc))
        return

    mark_done(engine, job["id"])


def _chunked(items: Sequence[int], size: int) -> Iterator[Sequence[int]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]
