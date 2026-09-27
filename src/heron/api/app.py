"""The FastAPI application.

create_app() is a factory, not a bare module-level `app`. This is
deliberate: create_app() has real side effects (it creates the data
directory and, on first run, writes secret.key and api_token to disk), so
those must only happen when someone actually asks for an app - never as an
import-time side effect that could fire during test collection or any
other incidental import of this module.

Run it with uvicorn's factory mode, which calls create_app() itself rather
than importing a pre-built app object:

    uvicorn heron.api.app:create_app --factory
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI

from heron.api.auth import require_api_token, resolve_api_token
from heron.core.config import Settings, get_settings

API_V1_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_dirs()

    app = FastAPI(title="Heron", summary="Self-hosted phishing detection for your inbox.")
    app.state.settings = settings
    app.state.api_token = resolve_api_token(settings.api_token, settings.data_dir)

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
        """A protected smoke-test route: confirms a bearer token actually works.

        Useful for a first `curl` after setup, before any real endpoints
        (mailboxes, emails, jobs - arriving in later days) exist to test
        against.
        """
        return {"authenticated": True, "service": "heron"}

    app.include_router(v1)

    return app
