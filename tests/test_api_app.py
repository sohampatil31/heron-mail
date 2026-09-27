"""Tests for the FastAPI app: the public health check and token-protected routes.

Uses FastAPI's TestClient (via create_app()'s factory - see app.py's
docstring for why there is no bare module-level `app` to import instead).
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from heron.api.app import create_app
from heron.api.auth import TOKEN_FILENAME
from heron.core.config import Settings

KNOWN_TOKEN = "test-token-do-not-use-in-production"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path / "data", api_token=KNOWN_TOKEN)


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_is_public(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_requires_no_authorization_header(client: TestClient):
    # Explicitly re-asserts the "public" claim: no header at all still works.
    response = client.get("/health", headers={})
    assert response.status_code == 200


def test_protected_route_rejects_missing_token(client: TestClient):
    response = client.get("/api/v1/ping")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_protected_route_rejects_wrong_token(client: TestClient):
    response = client.get("/api/v1/ping", headers=_auth_headers("not-the-right-token"))
    assert response.status_code == 401


def test_protected_route_accepts_correct_token(client: TestClient):
    response = client.get("/api/v1/ping", headers=_auth_headers(KNOWN_TOKEN))
    assert response.status_code == 200
    assert response.json() == {"authenticated": True, "service": "heron"}


def test_protected_route_rejects_non_bearer_scheme(client: TestClient):
    # HTTPBearer(auto_error=False) treats a non-"Bearer" scheme the same as
    # a missing header - it yields None rather than raising itself - so
    # this still surfaces as our own 401, not a scheme-specific error.
    response = client.get("/api/v1/ping", headers={"Authorization": f"Basic {KNOWN_TOKEN}"})
    assert response.status_code == 401


def test_app_bootstraps_a_token_file_when_none_is_configured(tmp_path: Path):
    settings = Settings(data_dir=tmp_path / "data", api_token=None)
    app = create_app(settings)
    bootstrapped_token = app.state.api_token

    token_path = tmp_path / "data" / TOKEN_FILENAME
    assert token_path.exists()
    assert token_path.read_text(encoding="ascii").strip() == bootstrapped_token

    client = TestClient(app)
    response = client.get("/api/v1/ping", headers=_auth_headers(bootstrapped_token))
    assert response.status_code == 200


def test_creating_the_app_does_not_touch_a_different_data_dir(tmp_path: Path):
    # Guards against the bug of app creation having any effect outside its
    # own configured data_dir - e.g. a leftover module-level side effect.
    settings = Settings(data_dir=tmp_path / "isolated-data", api_token=KNOWN_TOKEN)
    create_app(settings)
    for sibling in tmp_path.iterdir():
        assert sibling.name == "isolated-data"
