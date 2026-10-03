"""Alert endpoints: list, inspect, count, and move alerts through their lifecycle.

The request and response shapes live here, next to the routes that use them.

Everything an alert contains that came from an email (subject, evidence,
sender) is untrusted text. This API returns it as plain JSON strings; any
client that renders it must escape it.
"""

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from heron.analysis.alerts import AlertStatus, InvalidTransition
from heron.api.deps import EngineDep
from heron.core.analysis_storage import alert_counts, get_alert, list_alerts, set_alert_status
from heron.core.storage import get_account

router = APIRouter(prefix="/alerts", tags=["alerts"])


class ActionOut(BaseModel):
    id: str
    title: str
    detail: str


class ReasonOut(BaseModel):
    rule_id: str
    severity: str
    title: str
    detail: str
    evidence: list[str]
    points: int


class AlertOut(BaseModel):
    """One alert, as shown in a list."""

    model_config = ConfigDict(extra="ignore")

    id: int
    email_id: int
    account_id: int
    status: str
    severity: str
    verdict: str
    score: int
    title: str
    summary: str
    rules_version: str
    created_at: str
    updated_at: str
    acknowledged_at: str | None = None
    closed_at: str | None = None
    email_subject: str | None = None
    from_address: str | None = None
    internal_date: str | None = None


class AlertDetailOut(AlertOut):
    """An alert with its reasons and recommended actions."""

    reasons: list[ReasonOut]
    actions: list[ActionOut]
    complete: bool  # False if some rules crashed and findings may be missing


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


def _detail(row: dict[str, Any]) -> AlertDetailOut:
    details = row["details"]
    return AlertDetailOut.model_validate(
        {
            **row,
            "reasons": details.get("reasons", []),
            "actions": details.get("actions", []),
            "complete": details.get("complete", True),
        }
    )


def _require_mailbox(engine: EngineDep, mailbox_id: int | None) -> None:
    if mailbox_id is not None and get_account(engine, mailbox_id) is None:
        raise HTTPException(status_code=404, detail="Mailbox not found")


@router.get("", response_model=list[AlertOut])
def list_all_alerts(
    engine: EngineDep,
    mailbox_id: int | None = None,
    status: AlertStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AlertOut]:
    """Newest first. Filter by mailbox and/or status."""
    _require_mailbox(engine, mailbox_id)
    rows = list_alerts(engine, account_id=mailbox_id, status=status, limit=limit, offset=offset)
    return [AlertOut.model_validate(row) for row in rows]


# Declared before "/{alert_id}" so "counts" is never parsed as an id.
@router.get("/counts", response_model=dict[str, int])
def read_alert_counts(engine: EngineDep, mailbox_id: int | None = None) -> dict[str, int]:
    """Alerts per status; every status is present, 0 when there are none."""
    _require_mailbox(engine, mailbox_id)
    return alert_counts(engine, account_id=mailbox_id)


@router.get("/{alert_id}", response_model=AlertDetailOut)
def read_alert(alert_id: int, engine: EngineDep) -> AlertDetailOut:
    row = get_alert(engine, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _detail(row)


@router.post("/{alert_id}/status", response_model=AlertDetailOut)
def change_alert_status(
    alert_id: int, body: AlertStatusUpdate, engine: EngineDep
) -> AlertDetailOut:
    """Acknowledge, resolve, mark as a false positive, or reopen.

    409 if the alert's current status doesn't allow the move.
    """
    try:
        row = set_alert_status(engine, alert_id, body.status)
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _detail(row)
