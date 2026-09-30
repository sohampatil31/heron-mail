"""POST /ingest: fetch only the parts of a date range not yet covered.

For each gap we create a job and claim it immediately, so the response can
show it as running, then hand it to a background task. The endpoint and the
task are plain sync functions, so FastAPI runs both in its threadpool and
blocking IMAP work never stalls the event loop.

Under TestClient the background task runs before .post() returns, so the
returned job shows "running" even though it has finished by then. Under real
uvicorn the response goes out first.
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException

from heron.api.deps import EngineDep, SecretBoxDep, SettingsDep
from heron.api.schemas import IngestRequest, IngestResponse, JobOut
from heron.core.coverage import get_gaps
from heron.core.jobs import claim_job, create_job
from heron.core.storage import get_account
from heron.core.timeutil import local_date_range
from heron.worker.runner import run_job

router = APIRouter(tags=["ingest"])


@router.post("/ingest", response_model=IngestResponse)
def ingest(
    body: IngestRequest,
    background_tasks: BackgroundTasks,
    engine: EngineDep,
    secret_box: SecretBoxDep,
    settings: SettingsDep,
) -> IngestResponse:
    if get_account(engine, body.mailbox_id) is None:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    try:
        date_range = local_date_range(body.start_date, body.end_date, tz_name=settings.timezone)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    gaps = get_gaps(engine, body.mailbox_id, body.folder, date_range)
    jobs: list[JobOut] = []
    for gap in gaps:
        job_id = create_job(engine, account_id=body.mailbox_id, folder=body.folder, date_range=gap)
        job = claim_job(engine, job_id)
        if job is None:  # something else claimed it first; nothing for us to run
            continue
        background_tasks.add_task(run_job, engine, secret_box, settings.eml_dir, job)
        jobs.append(JobOut.model_validate(job))
    return IngestResponse(gaps_found=len(gaps), jobs=jobs)
