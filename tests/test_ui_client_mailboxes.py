"""The mailbox methods of HeronClient, against a real local HTTP server."""

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from heron.ui.api_client import ApiError, HeronClient

TOKEN = "tok"
SETTINGS = ("me@example.org", "imap.example.org", 993, "p@ss word")


@contextmanager
def serve(app):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            seen.append((self.command, self.path, body, self.headers.get("Authorization")))
            status, payload = app(self.command, self.path, body)
            data = b"" if payload is None else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_DELETE = _handle

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


def test_create_mailbox_posts_the_settings_as_json():
    with serve(lambda *_: (200, {"id": 7, "email_address": "me@example.org"})) as (url, seen):
        result = HeronClient(url, TOKEN).create_mailbox(*SETTINGS)
    assert result["id"] == 7
    method, path, body, auth = seen[0]
    assert (method, path, auth) == ("POST", "/api/v1/mailboxes", f"Bearer {TOKEN}")
    assert json.loads(body) == {
        "email_address": "me@example.org",
        "imap_host": "imap.example.org",
        "imap_port": 993,
        "password": "p@ss word",  # sent exactly as typed
    }


def test_test_settings_uses_the_dry_run_endpoint():
    with serve(lambda *_: (200, {"ok": False, "error": "Login failed"})) as (url, seen):
        result = HeronClient(url, TOKEN).test_mailbox_settings(*SETTINGS)
    assert result == {"ok": False, "error": "Login failed"}
    assert seen[0][:2] == ("POST", "/api/v1/mailboxes/test")


def test_test_saved_mailbox_and_delete():
    with serve(lambda m, *_: (204, None) if m == "DELETE" else (200, {"ok": True})) as (url, seen):
        client = HeronClient(url, TOKEN)
        assert client.test_mailbox(5) == {"ok": True}
        assert client.delete_mailbox(5) is None
    assert [s[:2] for s in seen] == [
        ("POST", "/api/v1/mailboxes/5/test"),
        ("DELETE", "/api/v1/mailboxes/5"),
    ]
    assert seen[0][2] == b""  # no body for the saved-mailbox test


def test_a_duplicate_mailbox_error_does_not_echo_the_password():
    def app(*_args):
        return 409, {"detail": "A mailbox with that address already exists"}

    with serve(app) as (url, _):
        with pytest.raises(ApiError) as error:
            HeronClient(url, TOKEN).create_mailbox(*SETTINGS)
    assert error.value.status == 409
    assert error.value.message == "A mailbox with that address already exists"
    assert "p@ss word" not in str(error.value)
