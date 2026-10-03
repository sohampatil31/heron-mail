"""HeronClient, login() and config, against a real HTTP server on localhost."""

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from heron.ui import api_client
from heron.ui.api_client import ApiError, ApiUnreachable, HeronClient, Unauthorized
from heron.ui.auth import login
from heron.ui.config import DEFAULT_API_URL, api_url

TOKEN = "s3cret-token-value"


@contextmanager
def serve(app):
    """Run `app(method, path, headers, body) -> (status, body, extra_headers)` on localhost."""
    seen: list[tuple[str, str, dict[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            seen.append((self.command, self.path, headers))
            status, payload, extra = app(self.command, self.path, headers, body)
            if not isinstance(payload, bytes):
                payload = json.dumps(payload).encode()
            self.send_response(status)
            for key, value in extra.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = _handle

    class QuietServer(ThreadingHTTPServer):
        def handle_error(self, request, client_address):  # client gave up (timeout test)
            pass

    server = QuietServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


def heron_app(method, path, headers, body):
    route = urlsplit(path).path
    if route == "/health":
        return 200, {"status": "ok"}, {}
    if headers.get("authorization") != f"Bearer {TOKEN}":
        return 401, {"detail": "Not authenticated"}, {}
    if route == "/api/v1/ping":
        return 200, {"authenticated": True, "service": "heron"}, {}
    if route == "/api/v1/mailboxes":
        return 200, [{"id": 1, "email_address": "me@example.org"}], {}
    if route == "/api/v1/alerts/1/status" and method == "POST":
        return 200, {"echo": json.loads(body)}, {}
    if route in ("/api/v1/alerts", "/api/v1/alerts/counts", "/api/v1/stats"):
        return 200, {"query": urlsplit(path).query}, {}
    return 404, {"detail": "Mailbox not found"}, {}


def test_health_needs_no_token_and_sends_none():
    with serve(heron_app) as (url, seen):
        assert HeronClient(url, TOKEN).health() == {"status": "ok"}
    assert "authorization" not in seen[0][2]


def test_authenticated_calls_send_the_bearer_token():
    with serve(heron_app) as (url, seen):
        client = HeronClient(url, TOKEN)
        assert client.ping() == {"authenticated": True, "service": "heron"}
        assert client.list_mailboxes() == [{"id": 1, "email_address": "me@example.org"}]
    assert all(h["authorization"] == f"Bearer {TOKEN}" for _, _, h in seen)


def test_wrong_token_raises_unauthorized():
    with serve(heron_app) as (url, _):
        with pytest.raises(Unauthorized) as error:
            HeronClient(url, "wrong").ping()
    assert error.value.status == 401
    assert TOKEN not in str(error.value)


def test_query_parameters_skip_none_and_are_encoded():
    with serve(heron_app) as (url, _):
        client = HeronClient(url, TOKEN)
        assert client.list_alerts(status="open", limit=5)["query"] == "status=open&limit=5&offset=0"
        assert client.alert_counts()["query"] == ""
        assert client.alert_counts(mailbox_id=3)["query"] == "mailbox_id=3"
        assert client.get_stats(mailbox_id=2)["query"] == "mailbox_id=2"


def test_post_sends_a_json_body():
    with serve(heron_app) as (url, _):
        result = HeronClient(url, TOKEN).set_alert_status(1, "resolved")
    assert result == {"echo": {"status": "resolved"}}


def test_error_detail_becomes_the_message():
    with serve(heron_app) as (url, _):
        with pytest.raises(ApiError) as error:
            HeronClient(url, TOKEN).get_alert(99)
    assert (error.value.status, error.value.message) == (404, "Mailbox not found")


def test_validation_errors_get_a_generic_message_and_server_text_is_cleaned():
    def app(*_args):
        if _args[1].endswith("/ping"):
            return 422, {"detail": [{"loc": ["body"], "msg": "x"}]}, {}
        return 409, {"detail": "bad\r\nthing\x00 here"}, {}

    with serve(app) as (url, _):
        client = HeronClient(url, TOKEN)
        with pytest.raises(ApiError) as validation:
            client.ping()
        with pytest.raises(ApiError) as conflict:
            client.list_mailboxes()
    assert validation.value.message == "The request was not valid."
    assert conflict.value.message == "bad thing here"


def test_non_json_and_oversized_responses_are_api_errors(monkeypatch):
    with serve(lambda *_: (200, b"<html>not json</html>", {})) as (url, _):
        with pytest.raises(ApiError) as error:
            HeronClient(url, TOKEN).ping()
    assert error.value.status == 502
    assert "Heron" in error.value.message

    with serve(lambda *_: (500, b"Internal Server Error", {})) as (url, _):
        with pytest.raises(ApiError) as server_error:
            HeronClient(url, TOKEN).ping()
    assert server_error.value.status == 500
    assert server_error.value.message == "The API returned an error (HTTP 500)."

    monkeypatch.setattr(api_client, "MAX_RESPONSE_BYTES", 5)
    with serve(lambda *_: (200, {"big": "response"}, {})) as (url, _):
        with pytest.raises(ApiError) as too_big:
            HeronClient(url, TOKEN).ping()
    assert too_big.value.message == "The API response was too large."


def test_unreachable_server_raises_apiunreachable():
    with serve(heron_app) as (url, _):
        pass  # the server is stopped now, so the port refuses connections
    with pytest.raises(ApiUnreachable):
        HeronClient(url, TOKEN, timeout=1).ping()


def test_slow_server_times_out():
    import time

    def slow(*_args):
        time.sleep(1.0)
        return 200, {}, {}

    with serve(slow) as (url, _):
        with pytest.raises(ApiUnreachable):
            HeronClient(url, TOKEN, timeout=0.2).ping()


def test_redirects_are_not_followed_and_the_token_is_not_forwarded():
    with serve(heron_app) as (elsewhere_url, elsewhere_seen):
        with serve(lambda *_: (302, b"", {"Location": f"{elsewhere_url}/api/v1/ping"})) as (
            url,
            _,
        ):
            with pytest.raises(ApiError) as error:
                HeronClient(url, TOKEN).ping()
    assert error.value.status == 302
    assert elsewhere_seen == []  # the redirect target never received a request


def test_repr_and_errors_hide_the_token():
    client = HeronClient("http://127.0.0.1:1", TOKEN)
    assert TOKEN not in repr(client)
    with pytest.raises(ApiUnreachable) as error:
        client.ping()
    assert TOKEN not in str(error.value)


def test_base_url_is_validated_and_normalised():
    assert HeronClient("http://localhost:8000/").base_url == "http://localhost:8000"
    for bad in ("localhost:8000", "ftp://example.org", "http://user:pw@example.org", "http://", ""):
        with pytest.raises(ValueError):
            HeronClient(bad)
    with pytest.raises(ValueError):
        HeronClient("http://example.org/?x=1")


# ------------------------------------------------------------------ login


def test_login_succeeds_with_the_right_token():
    with serve(heron_app) as (url, _):
        result = login(url, f"  {TOKEN}\n")  # pasted whitespace is trimmed
    assert result.error is None
    assert result.client is not None


def test_login_failures_have_safe_messages():
    with serve(heron_app) as (url, _):
        assert login(url, "").error == "Enter your API token."
        wrong = login(url, "nope")
        assert (wrong.client, wrong.error) == (None, "That token wasn't accepted.")
    gone = login(url, TOKEN, timeout=1)  # server has stopped
    assert gone.client is None
    assert "Could not reach" in (gone.error or "")
    assert login("not a url", TOKEN).client is None


def test_login_rejects_something_that_is_not_heron():
    with serve(lambda *_: (200, {"authenticated": True, "service": "other"}, {})) as (url, _):
        result = login(url, TOKEN)
    assert result.client is None
    assert result.error == "That address doesn't look like a Heron API."


def test_login_error_messages_never_contain_the_token():
    with serve(heron_app) as (url, _):
        assert TOKEN not in (login(url, TOKEN + "x").error or "")


# ----------------------------------------------------------------- config


def test_api_url_reads_the_environment(monkeypatch):
    monkeypatch.delenv("HERON_API_URL", raising=False)
    assert api_url() == DEFAULT_API_URL
    monkeypatch.setenv("HERON_API_URL", "http://api:8000/")
    assert api_url() == "http://api:8000"
    monkeypatch.setenv("HERON_API_URL", "javascript:alert(1)")
    with pytest.raises(ValueError):
        api_url()
