"""GET /stats/activity: KPIs and a timeline for a period, in the configured time zone.

With no parameters it returns today. `days=7` means the last 7 days including
today. Explicit start_date and end_date (both required together) override it.
"""

from datetime import date, datetime, timedelta
from typing import Annotated
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from heron.analysis.activity import MAX_DAYS
from heron.api.deps import EngineDep, SettingsDep
from heron.core.activity_storage import activity_for
from heron.core.storage import get_account

router = APIRouter(prefix="/stats/activity", tags=["stats"])


class BucketOut(BaseModel):
    label: str
    emails: int
    suspicious: int
    phishing: int


class ActivityOut(BaseModel):
    start_date: date
    end_date: date
    timezone: str
    granularity: str
    emails: int
    analysed: int
    suspicious: int
    phishing: int
    buckets: list[BucketOut]


@router.get("", response_model=ActivityOut)
def read_activity(
    engine: EngineDep,
    settings: SettingsDep,
    mailbox_id: int | None = None,
    days: Annotated[int, Query(ge=1, le=MAX_DAYS)] = 1,
    start_date: date | None = None,
    end_date: date | None = None,
) -> ActivityOut:
    if mailbox_id is not None and get_account(engine, mailbox_id) is None:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    if (start_date is None) != (end_date is None):
        raise HTTPException(
            status_code=422, detail="Give both start_date and end_date, or neither."
        )
    if start_date is None or end_date is None:
        end_date = datetime.now(ZoneInfo(settings.timezone)).date()
        start_date = end_date - timedelta(days=days - 1)
    try:
        activity = activity_for(engine, mailbox_id, start_date, end_date, settings.timezone)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ActivityOut.model_validate(activity, from_attributes=True)
