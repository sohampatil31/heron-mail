"""Saving analysis results and alerts, and moving alerts through their lifecycle.

Every function takes the Engine first and uses explicit Core statements, like
core.storage. Timestamps are UTC "YYYY-MM-DD HH:MM:SS" strings.

Rules this module enforces:
- One analysis and at most one alert per email. Saving again replaces the
  analysis and refreshes the alert's content, but an alert's status and
  created_at are never touched by a re-score. A person's "false positive"
  survives new rules.
- If a re-score now says an email is clean, an existing alert is left alone
  rather than silently closed. A rules change should not hide something from
  the person who owns the mailbox; they can close it.
- Status changes go through analysis.alerts.transition(), so an illegal move
  raises InvalidTransition and a concurrent change is detected, not overwritten.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.sql import Select

from heron.analysis.alerts import (
    AlertDraft,
    AlertStatus,
    InvalidTransition,
    build_alert,
    transition,
)
from heron.analysis.scoring import Assessment
from heron.core.models import alerts, analyses, emails


def _timestamp(now: datetime | None) -> str:
    moment = now or datetime.now(UTC)
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------- saving


def record_assessment(
    engine: Engine,
    email_id: int,
    assessment: Assessment,
    subject: str,
    *,
    now: datetime | None = None,
) -> int | None:
    """Save an email's analysis and, if it was flagged, its alert.

    Both writes happen in one transaction. Returns the alert id, or None when
    the message produced no alert (it was clean).
    """
    stamp = _timestamp(now)
    draft = build_alert(assessment, subject)
    with engine.begin() as connection:
        _upsert_analysis(connection, email_id, assessment, stamp)
        if draft is None:
            return None
        return _upsert_alert(connection, email_id, draft, stamp)


def _upsert_analysis(
    connection: Connection, email_id: int, assessment: Assessment, stamp: str
) -> None:
    values: dict[str, Any] = {
        "score": assessment.score,
        "verdict": assessment.verdict.value,
        "rules_version": assessment.rules_version,
        "complete": int(assessment.complete),
        "rule_errors": (
            json.dumps(list(assessment.rule_errors)) if assessment.rule_errors else None
        ),
        "analyzed_at": stamp,
    }
    statement = sqlite_insert(analyses).values(email_id=email_id, **values)
    connection.execute(statement.on_conflict_do_update(index_elements=["email_id"], set_=values))


def _upsert_alert(connection: Connection, email_id: int, draft: AlertDraft, stamp: str) -> int:
    content: dict[str, Any] = {
        "severity": draft.severity.name.lower(),
        "verdict": draft.verdict.value,
        "score": draft.score,
        "title": draft.title,
        "summary": draft.summary,
        "details_json": json.dumps(draft.to_dict(), sort_keys=True),
        "rules_version": draft.rules_version,
        "updated_at": stamp,
    }
    # status and created_at are only set on insert; the conflict branch
    # updates `content` alone, which is how a person's decision survives.
    statement = sqlite_insert(alerts).values(
        email_id=email_id, status=AlertStatus.OPEN.value, created_at=stamp, **content
    )
    connection.execute(statement.on_conflict_do_update(index_elements=["email_id"], set_=content))
    return int(
        connection.execute(select(alerts.c.id).where(alerts.c.email_id == email_id)).scalar_one()
    )


# --------------------------------------------------------------- reading


def get_analysis(engine: Engine, email_id: int) -> dict[str, Any] | None:
    with engine.connect() as connection:
        row = (
            connection.execute(select(analyses).where(analyses.c.email_id == email_id))
            .mappings()
            .first()
        )
    if row is None:
        return None
    result = dict(row)
    result["complete"] = bool(result["complete"])
    result["rule_errors"] = json.loads(result["rule_errors"]) if result["rule_errors"] else []
    return result


def _alert_select() -> Select[Any]:
    return select(
        alerts,
        emails.c.account_id,
        emails.c.subject.label("email_subject"),
        emails.c.from_address,
        emails.c.internal_date,
    ).select_from(alerts.join(emails, emails.c.id == alerts.c.email_id))


def _alert_dict(row: Any) -> dict[str, Any]:
    result = dict(row)
    result["details"] = json.loads(result.pop("details_json"))
    return result


def get_alert(engine: Engine, alert_id: int) -> dict[str, Any] | None:
    statement = _alert_select().where(alerts.c.id == alert_id)
    with engine.connect() as connection:
        row = connection.execute(statement).mappings().first()
    return _alert_dict(row) if row else None


def list_alerts(
    engine: Engine,
    *,
    account_id: int | None = None,
    status: AlertStatus | str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Newest first. `status` must be a real AlertStatus value (ValueError otherwise)."""
    statement = _alert_select().order_by(alerts.c.id.desc()).limit(limit).offset(offset)
    if account_id is not None:
        statement = statement.where(emails.c.account_id == account_id)
    if status is not None:
        statement = statement.where(alerts.c.status == AlertStatus(status).value)
    with engine.connect() as connection:
        return [_alert_dict(row) for row in connection.execute(statement).mappings()]


def alert_counts(engine: Engine, *, account_id: int | None = None) -> dict[str, int]:
    """Alerts per status, with every status present (0 when none)."""
    source = alerts.join(emails, emails.c.id == alerts.c.email_id)
    statement = select(alerts.c.status, func.count()).select_from(source)
    if account_id is not None:
        statement = statement.where(emails.c.account_id == account_id)
    with engine.connect() as connection:
        found = dict(connection.execute(statement.group_by(alerts.c.status)).all())
    return {status.value: int(found.get(status.value, 0)) for status in AlertStatus}


# ------------------------------------------------------------- lifecycle


def set_alert_status(
    engine: Engine, alert_id: int, target: AlertStatus, *, now: datetime | None = None
) -> dict[str, Any] | None:
    """Move an alert to `target`. None if it doesn't exist.

    Raises InvalidTransition for a move the lifecycle doesn't allow, or if the
    alert was changed by someone else between the check and the write.
    """
    stamp = _timestamp(now)
    with engine.begin() as connection:
        found = connection.execute(select(alerts.c.status).where(alerts.c.id == alert_id)).first()
        if found is None:
            return None
        current = AlertStatus(found[0])
        transition(current, target)

        changes: dict[str, Any] = {"status": target.value, "updated_at": stamp}
        if target is AlertStatus.ACKNOWLEDGED:
            changes["acknowledged_at"] = stamp
        elif target is AlertStatus.OPEN:  # reopened: forget the previous handling
            changes["acknowledged_at"] = None
            changes["closed_at"] = None
        else:  # resolved or false_positive
            changes["closed_at"] = stamp

        result = connection.execute(
            alerts.update()
            .where(alerts.c.id == alert_id, alerts.c.status == current.value)
            .values(**changes)
        )
        if result.rowcount != 1:
            raise InvalidTransition("the alert was changed by someone else; reload and retry")
    return get_alert(engine, alert_id)


# ------------------------------------------------- finding work to analyse


def emails_missing_analysis(
    engine: Engine, *, after_id: int = 0, limit: int = 200
) -> list[dict[str, Any]]:
    """Emails with no analysis yet, in id order, starting after `after_id`."""
    statement = (
        select(emails.c.id, emails.c.eml_path)
        .outerjoin(analyses, analyses.c.email_id == emails.c.id)
        .where(analyses.c.id.is_(None), emails.c.id > after_id)
        .order_by(emails.c.id)
        .limit(limit)
    )
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(statement).mappings()]


def emails_with_stale_analysis(
    engine: Engine, rules_version: str, *, after_id: int = 0, limit: int = 200
) -> list[dict[str, Any]]:
    """Emails analysed under a different rules_version than `rules_version`."""
    statement = (
        select(emails.c.id, emails.c.eml_path)
        .join(analyses, analyses.c.email_id == emails.c.id)
        .where(analyses.c.rules_version != rules_version, emails.c.id > after_id)
        .order_by(emails.c.id)
        .limit(limit)
    )
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(statement).mappings()]
