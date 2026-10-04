"""The ingest and jobs methods of HeronClient, against a real local HTTP server."""

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from heron.ui.api_client import HeronClient


@contextmanager
def serve(payload):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            seen.append((self.command, self.path, self.rfile.read(length) if length else b""))
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = _handle

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


def test_ingest_posts_the_range_as_iso_dates():
    with serve({"gaps_found": 1, "jobs": []}) as (url, seen):
        result = HeronClient(url, "t").ingest(4, "2026-10-01", "2026-10-03")
    assert result == {"gaps_found": 1, "jobs": []}
    method, path, body = seen[0]
    assert (method, path) == ("POST", "/api/v1/ingest")
    assert json.loads(body) == {
        "mailbox_id": 4,
        "folder": "INBOX",
        "start_date": "2026-10-01",
        "end_date": "2026-10-03",
    }


def test_ingest_can_target_another_folder():
    with serve({}) as (url, seen):
        HeronClient(url, "t").ingest(1, "2026-10-01", "2026-10-01", folder="Archive")
    assert json.loads(seen[0][2])["folder"] == "Archive"


def test_list_jobs_and_get_job():
    with serve([]) as (url, seen):
        client = HeronClient(url, "t")
        client.list_jobs(mailbox_id=2, status="running", limit=10)
        client.list_jobs()
        client.get_job(9)
    assert [s[1] for s in seen] == [
        "/api/v1/jobs?mailbox_id=2&status=running&limit=10",
        "/api/v1/jobs?limit=50",
        "/api/v1/jobs/9",
    ]
