"""Signing in: check a token against the API before keeping it."""

from __future__ import annotations

from dataclasses import dataclass

from heron.ui.api_client import ApiError, ApiUnreachable, HeronClient, Unauthorized


@dataclass(frozen=True, slots=True)
class LoginResult:
    client: HeronClient | None
    error: str | None  # a message that is safe to show; never contains the token


def login(base_url: str, token: str, *, timeout: float = 10.0) -> LoginResult:
    token = token.strip()
    if not token:
        return LoginResult(None, "Enter your API token.")
    try:
        client = HeronClient(base_url, token, timeout=timeout)
        answer = client.ping()
    except ValueError as exc:  # a bad API address
        return LoginResult(None, str(exc))
    except Unauthorized:
        return LoginResult(None, "That token wasn't accepted.")
    except ApiUnreachable as exc:
        return LoginResult(None, str(exc))
    except ApiError as exc:
        return LoginResult(None, exc.message)
    if not isinstance(answer, dict) or answer.get("service") != "heron":
        return LoginResult(None, "That address doesn't look like a Heron API.")
    return LoginResult(client, None)
