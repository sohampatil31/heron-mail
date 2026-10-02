"""Run the analysis pipeline over stored emails and save the results.

Two entry points:
- analyze_pending(): emails that have never been analysed. The ingest job
  calls this after storing mail, so new messages are scored as they arrive
  (and any older backlog is picked up once).
- reanalyze_stale(): emails analysed under an older rules_version. Run it on
  purpose after changing rules or weights; ingestion never triggers it, so a
  rules change can't suddenly slow every ingest job.

Both walk emails in id order, so a message whose file can't be read is skipped
once instead of being retried forever.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy.engine import Engine

from heron.analysis.pipeline import analyze
from heron.analysis.scoring import rules_version
from heron.core.analysis_storage import (
    emails_missing_analysis,
    emails_with_stale_analysis,
    record_assessment,
)

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 200


def analyze_stored_email(engine: Engine, eml_dir: Path, email_row: dict[str, Any]) -> bool:
    """Analyse one stored message and save the result. False if it couldn't be read."""
    path = _resolve_inside(eml_dir, str(email_row["eml_path"]))
    if path is None:
        logger.warning("email %s: eml_path escapes the eml directory; skipped", email_row["id"])
        return False
    try:
        raw = path.read_bytes()
    except OSError:
        logger.warning("email %s: could not read %s; skipped", email_row["id"], path.name)
        return False
    analysis = analyze(raw)
    record_assessment(engine, int(email_row["id"]), analysis.assessment, analysis.email.subject)
    return True


def analyze_pending(engine: Engine, eml_dir: Path, *, batch_size: int = DEFAULT_BATCH_SIZE) -> int:
    """Analyse every email that has no analysis yet. Returns how many were saved."""

    def fetch(after_id: int, limit: int) -> list[dict[str, Any]]:
        return emails_missing_analysis(engine, after_id=after_id, limit=limit)

    return _run(engine, eml_dir, batch_size, fetch)


def analyze_pending_safely(engine: Engine, eml_dir: Path) -> int:
    """analyze_pending() for the ingest job: scoring must never fail ingestion.

    Anything not analysed because of an error here has no analysis row, so the
    next call picks it up again. Returns 0 if the pass failed.
    """
    try:
        return analyze_pending(engine, eml_dir)
    except Exception:  # noqa: BLE001 - an analysis bug must not fail an ingest job
        logger.exception("analysis pass failed; unanalysed emails will be retried")
        return 0


def reanalyze_stale(engine: Engine, eml_dir: Path, *, batch_size: int = DEFAULT_BATCH_SIZE) -> int:
    """Re-score every email analysed under an older rules_version."""
    current = rules_version()

    def fetch(after_id: int, limit: int) -> list[dict[str, Any]]:
        return emails_with_stale_analysis(engine, current, after_id=after_id, limit=limit)

    return _run(engine, eml_dir, batch_size, fetch)


def _run(
    engine: Engine,
    eml_dir: Path,
    batch_size: int,
    fetch: Callable[[int, int], list[dict[str, Any]]],
) -> int:
    saved = 0
    after_id = 0
    while True:
        batch = fetch(after_id, batch_size)
        if not batch:
            return saved
        for row in batch:
            if analyze_stored_email(engine, eml_dir, row):
                saved += 1
        after_id = int(batch[-1]["id"])


def _resolve_inside(base: Path, relative: str) -> Path | None:
    """base/relative, or None if it would land outside base."""
    root = base.resolve()
    candidate = (root / relative).resolve()
    return candidate if candidate.is_relative_to(root) else None
