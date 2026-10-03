"""A small client for the Heron API, built on the standard library.

Design choices that matter for a tool holding a mailbox's secrets:
- Redirects are never followed. urllib would otherwise forward the
  Authorization header to wherever a redirect points.
- The token is never in an error message, a repr, or a URL.
- Every call has a timeout, and responses are size-capped.
- Failures become three clear exception types, so the UI can react
  (sign out on Unauthorized, show "can't reach the server" on ApiUnreachable).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlencode, urlsplit

from heron.ui.safe import clean_text

API_PREFIX = "/api/v1"
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_ERROR_BYTES = 64 * 1024


class ApiError(Exception):
    """The API answered, but not with success."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class Unauthorized(ApiError):
    """The token was missing, wrong, or no longer valid."""


class ApiUnreachable(Exception):
    """No usable answer: refused, timed out, or the network failed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None  # makes urllib raise HTTPError for the 3xx instead of following it


def normalise_base_url(url: str) -> str:
    """Check an API address and drop any trailing slash. Raises ValueError."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("The API address must start with http:// or https://")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("The API address must not contain credentials, a query or a fragment")
    return url.strip().rstrip("/")


class HeronClient:
    def __init__(self, base_url: str, token: str | None = None, *, timeout: float = 10.0) -> None:
        self._base = normalise_base_url(base_url)
        self._token = token
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __repr__(self) -> str:
        return f"HeronClient(base_url={self._base!r}, token=<hidden>)"

    @property
    def base_url(self) -> str:
        return self._base

    # ------------------------------------------------------------- endpoints

    def health(self) -> Any:
        return self._request("GET", "/health", authenticated=False)

    def ping(self) -> Any:
        return self._request("GET", f"{API_PREFIX}/ping")

    def list_mailboxes(self) -> Any:
        return self._request("GET", f"{API_PREFIX}/mailboxes")

    def create_mailbox(
        self, email_address: str, imap_host: str, imap_port: int, password: str
    ) -> Any:
        return self._request(
            "POST",
            f"{API_PREFIX}/mailboxes",
            json_body=_mailbox_body(email_address, imap_host, imap_port, password),
        )

    def test_mailbox_settings(
        self, email_address: str, imap_host: str, imap_port: int, password: str
    ) -> Any:
        """Try a login with these settings without saving anything: {ok, error}."""
        return self._request(
            "POST",
            f"{API_PREFIX}/mailboxes/test",
            json_body=_mailbox_body(email_address, imap_host, imap_port, password),
        )

    def test_mailbox(self, mailbox_id: int) -> Any:
        return self._request("POST", f"{API_PREFIX}/mailboxes/{int(mailbox_id)}/test")

    def delete_mailbox(self, mailbox_id: int) -> Any:
        return self._request("DELETE", f"{API_PREFIX}/mailboxes/{int(mailbox_id)}")

    def get_stats(self, mailbox_id: int | None = None) -> Any:
        return self._request("GET", f"{API_PREFIX}/stats", params={"mailbox_id": mailbox_id})

    def get_activity(
        self,
        *,
        mailbox_id: int | None = None,
        days: int | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> Any:
        """KPIs and a timeline. No dates means today (in the server's time zone)."""
        params = {
            "mailbox_id": mailbox_id,
            "days": days,
            "start_date": start_date,
            "end_date": end_date,
        }
        return self._request("GET", f"{API_PREFIX}/stats/activity", params=params)

    def alert_counts(self, mailbox_id: int | None = None) -> Any:
        return self._request(
            "GET", f"{API_PREFIX}/alerts/counts", params={"mailbox_id": mailbox_id}
        )

    def list_alerts(
        self,
        *,
        mailbox_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Any:
        params = {"mailbox_id": mailbox_id, "status": status, "limit": limit, "offset": offset}
        return self._request("GET", f"{API_PREFIX}/alerts", params=params)

    def get_alert(self, alert_id: int) -> Any:
        return self._request("GET", f"{API_PREFIX}/alerts/{int(alert_id)}")

    def set_alert_status(self, alert_id: int, status: str) -> Any:
        return self._request(
            "POST", f"{API_PREFIX}/alerts/{int(alert_id)}/status", json_body={"status": status}
        )

    # --------------------------------------------------------------- plumbing

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        authenticated: bool = True,
    ) -> Any:
        url = self._base + path
        if params:
            query = {key: value for key, value in params.items() if value is not None}
            if query:
                url += "?" + urlencode(query)
        data = json.dumps(json_body).encode() if json_body is not None else None
        request = urllib.request.Request(url, data=data, method=method)  # noqa: S310
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if authenticated and self._token:
            request.add_header("Authorization", f"Bearer {self._token}")

        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise _error_for(exc.code, exc.read(MAX_ERROR_BYTES)) from None
        except (urllib.error.URLError, OSError) as exc:  # refused, DNS, timeout, reset
            raise ApiUnreachable(f"Could not reach the Heron API at {self._base}") from exc

        if len(raw) > MAX_RESPONSE_BYTES:
            raise ApiError(502, "The API response was too large.")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            raise ApiError(502, "The API did not return JSON. Is this a Heron address?") from None


def _mailbox_body(
    email_address: str, imap_host: str, imap_port: int, password: str
) -> dict[str, Any]:
    return {
        "email_address": email_address,
        "imap_host": imap_host,
        "imap_port": imap_port,
        "password": password,
    }


def _error_for(status: int, body: bytes) -> ApiError:
    if status in (401, 403):
        return Unauthorized(status, "The API token was not accepted.")
    message = f"The API returned an error (HTTP {status})."
    try:
        detail = json.loads(body).get("detail")
    except (ValueError, AttributeError):
        detail = None
    if isinstance(detail, str) and detail:
        message = clean_text(detail)
    elif isinstance(detail, list):
        message = "The request was not valid."
    return ApiError(status, message)
