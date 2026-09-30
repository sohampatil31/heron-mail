"""Headline counts. No severity or verdict: scoring does not exist yet."""

from fastapi import APIRouter, HTTPException

from heron.api.deps import EngineDep
from heron.api.schemas import StatsOut
from heron.core.storage import get_account, get_stats

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsOut)
def read_stats(engine: EngineDep, mailbox_id: int | None = None) -> StatsOut:
    if mailbox_id is not None and get_account(engine, mailbox_id) is None:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    return StatsOut.model_validate(get_stats(engine, account_id=mailbox_id))
