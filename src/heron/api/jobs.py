"""Read-only job endpoints: what is queued, running, done or failed."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query

from heron.api.deps import EngineDep
from heron.api.schemas import JobOut
from heron.core.jobs import get_job, list_jobs

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=list[JobOut])
def list_all_jobs(
    engine: EngineDep,
    mailbox_id: int | None = None,
    status: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[JobOut]:
    """Newest first. Filter by mailbox and/or status."""
    rows = list_jobs(engine, account_id=mailbox_id, status=status, limit=limit)
    return [JobOut.model_validate(row) for row in rows]


@router.get("/{job_id}", response_model=JobOut)
def read_job(job_id: int, engine: EngineDep) -> JobOut:
    job = get_job(engine, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobOut.model_validate(job)
