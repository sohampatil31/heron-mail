"""The FastAPI application.

create_app() is a factory, not a bare module-level `app`. This is
deliberate: create_app() has real side effects (it creates the data
directory, migrates the database, and on first run writes secret.key and
api_token to disk), so those must only happen when someone actually asks for
an app - never as an import-time side effect that could fire during test
collection or any other incidental import of this module.

Run it with uvicorn's factory mode, which calls create_app() itself rather
than importing a pre-built app object:

    uvicorn heron.api.app:create_app --factory
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from heron.api import activity, alerts, emails, ingest, jobs, mailboxes, stats
from heron.api.auth import require_api_token, resolve_api_token
from heron.core.config import Settings, get_settings
from heron.core.crypto import SecretBox
from heron.core.migrate import init_database

API_V1_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_dirs()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        app.state.engine.dispose()

    app = FastAPI(
        title="Heron",
        summary="Self-hosted phishing detection for your inbox.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.api_token = resolve_api_token(settings.api_token, settings.data_dir)
    app.state.engine = init_database(settings)
    app.state.secret_box = SecretBox.from_settings(settings.secret_key, settings.data_dir)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 body echoes each failing field's `input`, and
        # for a missing field that input is the whole request body - which,
        # for POST /mailboxes, includes the password. Keep only where and why.
        errors = [
            {"type": error["type"], "loc": error["loc"], "msg": error["msg"]}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Unauthenticated liveness check, for the Docker healthcheck and monitoring.

        Returns only a fixed status - no account, mailbox, or other
        information that would make this worth protecting.
        """
        return {"status": "ok"}

    v1 = APIRouter(prefix=API_V1_PREFIX, dependencies=[Depends(require_api_token)])

    @v1.get("/ping")
    def ping() -> dict[str, bool | str]:
        """A protected smoke-test route: confirms a bearer token actually works."""
        return {"authenticated": True, "service": "heron"}

    v1.include_router(mailboxes.router)
    v1.include_router(ingest.router)
    v1.include_router(jobs.router)
    v1.include_router(emails.router)
    v1.include_router(stats.router)
    v1.include_router(alerts.router)
    v1.include_router(activity.router)
    app.include_router(v1)

    return app
