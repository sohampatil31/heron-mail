"""Read-only email listing for a mailbox and a local calendar date range."""

from datetime import date
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query

from heron.api.deps import EngineDep, SettingsDep
from heron.api.schemas import EmailOut
from heron.core.storage import get_account, get_emails_in_range
from heron.core.timeutil import local_date_range

router = APIRouter(prefix="/emails", tags=["emails"])


@router.get("", response_model=list[EmailOut])
def list_emails(
    engine: EngineDep,
    settings: SettingsDep,
    mailbox_id: int,
    start_date: date,
    end_date: date,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[EmailOut]:
    """Emails whose internal_date falls in [start_date, end_date], local days."""
    if get_account(engine, mailbox_id) is None:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    try:
        date_range = local_date_range(start_date, end_date, tz_name=settings.timezone)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    rows = get_emails_in_range(engine, mailbox_id, date_range)
    return [EmailOut.model_validate(row) for row in rows[:limit]]
