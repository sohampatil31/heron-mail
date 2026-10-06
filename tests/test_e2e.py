"""End to end: a real API server on localhost, driven by the same client the UI uses.

Nothing is mocked except IMAP itself (messages are placed straight into the
vault, as a finished fetch would leave them) and the background fetch in the
ingest test. This is the check that Days 10 to 23 work together, not just alone.
"""

import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import uvicorn
from sqlalchemy import insert

from heron.analysis.alerts import AlertStatus
from heron.api import ingest as ingest_module
from heron.api.app import create_app
from heron.core.config import Settings
from heron.core.models import emails
from heron.ui.alert_logic import available_moves
from heron.ui.api_client import ApiError, HeronClient, Unauthorized
from heron.ui.auth import login
from heron.ui.fetch_logic import summarise_jobs
from heron.ui.safe import md_safe
from heron.worker.analysis import analyze_pending

TOKEN = "e2e-token"
FIXTURES = Path(__file__).parent / "fixtures" / "emails"
PASSWORD = "hunter2-very-secret"


@pytest.fixture
def stack(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token=TOKEN)
    app = create_app(settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="on")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("the test server did not start")
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        yield SimpleNamespace(
            base_url=base_url,
            settings=settings,
            engine=app.state.engine,
            client=HeronClient(base_url, TOKEN),
        )
    finally:
        server.should_exit = True
        thread.join(timeout=15)


def add_mailbox(stack, address="me@example.org") -> int:
    return stack.client.create_mailbox(address, "imap.example.org", 993, PASSWORD)["id"]


def seed(stack, mailbox_id: int, uid: int, fixture: str | None = None, raw: bytes | None = None):
    """Leave one message in the vault, as a finished fetch would."""
    relative = f"e2e/mail{uid}.eml"
    path = stack.settings.eml_dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw if raw is not None else (FIXTURES / fixture).read_bytes())
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    with stack.engine.begin() as connection:
        connection.execute(
            insert(emails).values(
                account_id=mailbox_id, folder="INBOX", uidvalidity=1, uid=uid,
                message_id=None, content_hash=f"e2e{uid}", internal_date=now,
                header_date=None, subject=None, from_address=None,
                eml_path=relative, created_at=now,
            )
        )  # fmt: skip


def test_login_and_token_handling(stack):
    assert login(stack.base_url, TOKEN).client is not None
    assert login(stack.base_url, "wrong").error == "That token wasn't accepted."
    assert HeronClient(stack.base_url).health() == {"status": "ok"}  # no token needed
    with pytest.raises(Unauthorized):
        HeronClient(stack.base_url, "wrong").list_alerts()


def test_the_mailbox_password_never_comes_back(stack):
    mailbox_id = add_mailbox(stack)
    listing = stack.client.list_mailboxes()
    assert [box["email_address"] for box in listing] == ["me@example.org"]
    assert PASSWORD not in repr(listing)
    assert PASSWORD not in repr(stack.client.get_stats())
    with pytest.raises(ApiError):  # a duplicate address is refused, and says why without echoing
        stack.client.create_mailbox("me@example.org", "imap.example.org", 993, PASSWORD)
    assert mailbox_id


def test_stored_mail_becomes_alerts_the_dashboard_and_detail(stack):
    client = stack.client
    mailbox_id = add_mailbox(stack)
    seed(stack, mailbox_id, 1, "newsletter_alternative.eml")
    seed(stack, mailbox_id, 2, "phish_invoice.eml")
    seed(stack, mailbox_id, 3, "plain_simple.eml")

    assert client.get_activity(mailbox_id=mailbox_id, days=2)["analysed"] == 0  # not scored yet
    assert analyze_pending(stack.engine, stack.settings.eml_dir) == 3
    assert analyze_pending(stack.engine, stack.settings.eml_dir) == 0  # idempotent

    today = client.get_activity()  # no arguments means "today"
    assert today["start_date"] == today["end_date"]
    assert today["granularity"] == "hour"
    assert (today["emails"], today["analysed"], today["phishing"]) == (3, 3, 1)

    assert client.alert_counts()["open"] == 1
    assert client.alert_counts(mailbox_id)["open"] == 1
    (alert,) = client.list_alerts(status="open")
    detail = client.get_alert(alert["id"])
    assert detail["verdict"] == "phishing"
    assert detail["title"].startswith("Likely phishing:")
    assert detail["reasons"][0]["rule_id"] == "auth.dmarc_fail"
    assert detail["actions"][0]["id"] == "no_click_no_open"
    assert detail["complete"] is True

    with pytest.raises(ApiError) as missing:
        client.get_activity(mailbox_id=999)
    assert missing.value.status == 404


def test_every_status_change_the_ui_offers_works_and_every_other_is_refused(stack):
    client = stack.client
    mailbox_id = add_mailbox(stack)
    seed(stack, mailbox_id, 1, "phish_invoice.eml")
    analyze_pending(stack.engine, stack.settings.eml_dir)
    alert_id = client.list_alerts()[0]["id"]

    current = "open"
    for next_status in ("acknowledged", "resolved", "open", "false_positive", "open"):
        offered = {move.target.value for move in available_moves(current)}
        for target in AlertStatus:
            if target.value not in offered:
                with pytest.raises(ApiError) as refused:
                    client.set_alert_status(alert_id, target.value)
                assert refused.value.status == 409, (current, target)
        assert client.get_alert(alert_id)["status"] == current  # refusals changed nothing
        assert next_status in offered
        assert client.set_alert_status(alert_id, next_status)["status"] == next_status
        current = next_status


def test_a_hostile_subject_arrives_as_text_and_is_defused_for_display(stack):
    subject = "![x](http://t.invalid/p.gif) [Click](http://evil.invalid)"
    raw = (
        "Authentication-Results: mx.example.org; spf=fail; dkim=fail; dmarc=fail\r\n"
        'From: "security@bank.test" <noreply@evil.invalid>\r\n'
        "To: me@example.org\r\n"
        f"Subject: {subject}\r\n"
        "\r\n"
        "hello\r\n"
    ).encode()
    mailbox_id = add_mailbox(stack)
    seed(stack, mailbox_id, 1, raw=raw)
    analyze_pending(stack.engine, stack.settings.eml_dir)

    (alert,) = stack.client.list_alerts()
    assert subject in alert["title"]  # the API reports it faithfully, as plain text
    safe = md_safe(alert["title"])
    assert "![" not in safe
    assert "](" not in safe


def test_ingest_makes_a_visible_job_and_bad_ranges_are_refused(stack, monkeypatch):
    monkeypatch.setattr(ingest_module, "run_job", lambda *args: None)  # no real IMAP here
    mailbox_id = add_mailbox(stack)
    today = datetime.now(UTC).date().isoformat()

    answer = stack.client.ingest(mailbox_id, today, today)
    assert answer["gaps_found"] == 1
    (job,) = answer["jobs"]
    assert job["status"] == "running"
    assert stack.client.get_job(job["id"])["id"] == job["id"]
    assert [j["id"] for j in stack.client.list_jobs(mailbox_id=mailbox_id)] == [job["id"]]
    assert not summarise_jobs([job]).finished

    with pytest.raises(ApiError) as backwards:
        stack.client.ingest(mailbox_id, "2026-10-04", "2026-10-03")
    assert backwards.value.status == 422
    with pytest.raises(ApiError) as unknown:
        stack.client.ingest(999, today, today)
    assert unknown.value.status == 404
