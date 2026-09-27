"""Bearer-token authentication for the API.

Heron is single-user and self-hosted, so this is deliberately simple: one
shared token, not a user/password/session system. Binding to 127.0.0.1 by
default is the primary protection (see ARCHITECTURE.md); this token is a
second layer for anyone who exposes the port on a home server or NAS.

The bootstrap mirrors core.crypto's key-file pattern: if HERON_API_TOKEN is
not set, a token is generated on first run and stored in
data_dir/api_token, so there is always a real secret guarding the API
rather than an empty or predictable default.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

TOKEN_FILENAME = "api_token"  # noqa: S105 - a filename, not a secret
_TOKEN_FILE_MODE = 0o600  # owner read/write only - as sensitive as a password

_bearer_scheme = HTTPBearer(auto_error=False)


class ApiTokenError(Exception):
    """Raised when the API token cannot be loaded or created."""


def load_or_create_token_file(data_dir: Path) -> str:
    """Return the token from `<data_dir>/api_token`, creating it on first run.

    Called only when HERON_API_TOKEN is not set in the environment (see
    resolve_api_token). Permissions are best-effort and POSIX-only, the
    same caveat as core.crypto.load_or_create_key_file.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = data_dir / TOKEN_FILENAME
    if token_path.exists():
        token = token_path.read_text(encoding="ascii").strip()
        if not token:
            raise ApiTokenError(f"{token_path} exists but is empty")
        return token

    token = secrets.token_urlsafe(32)
    token_path.write_text(token, encoding="ascii")
    try:
        token_path.chmod(_TOKEN_FILE_MODE)
    except NotImplementedError:
        pass  # chmod is a no-op on some platforms
    return token


def resolve_api_token(configured: str | None, data_dir: Path) -> str:
    """Use `configured` (from settings.api_token) if set, else the data-dir token file."""
    return configured or load_or_create_token_file(data_dir)


def require_api_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> None:
    """FastAPI dependency: reject the request unless it carries the correct bearer token.

    Reads the expected token from request.app.state.api_token, set once at
    app creation (see api.app.create_app) - so this has no state of its own
    and is trivial to use in tests with a known token.
    """
    expected = request.app.state.api_token
    if credentials is None or not secrets.compare_digest(credentials.credentials, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
