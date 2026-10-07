"""`python -m heron.doctor`: check that an install is healthy, without changing anything.

It opens the database read-only, never prints a secret, and never starts or
migrates anything. Run it after upgrading, or when something looks wrong, and
paste the report if you need help.

Exit status is 1 if any check FAILED, otherwise 0 (warnings don't fail it).
"""

from __future__ import annotations

import os
import re
import sqlite3
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

OK, WARN, FAIL = "ok", "warn", "fail"
REQUIRED_TABLES = (
    "accounts", "emails", "jobs", "coverage", "analyses", "alerts", "alembic_version",
)  # fmt: skip
_LABEL = {OK: "PASS", WARN: "WARN", FAIL: "FAIL"}
_SAMPLE_FILES = 25


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str
    detail: str


def latest_revision(versions_dir: Path) -> str | None:
    """The highest migration revision id found in the versions folder."""
    found = []
    for path in versions_dir.glob("*.py"):
        text = path.read_text()
        match = re.search(r'^revision(?::\s*str)?\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if match:
            found.append(match.group(1))
    return max(found) if found else None


def check_data_dir(data_dir: Path) -> Check:
    if not data_dir.is_dir():
        return Check("Data folder", WARN, f"{data_dir} doesn't exist yet (made on first start)")
    if not os.access(data_dir, os.W_OK):
        return Check("Data folder", FAIL, f"{data_dir} is not writable by this user")
    return Check("Data folder", OK, str(data_dir))


def check_secret_file(data_dir: Path, filename: str, env_var: str, label: str) -> Check:
    if os.environ.get(env_var):
        return Check(label, OK, f"set through {env_var}")
    path = data_dir / filename
    if not path.is_file():
        return Check(label, WARN, f"{filename} not found; it is created on first start")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        return Check(label, WARN, f"{filename} is readable by other users: chmod 600 {path}")
    return Check(label, OK, f"{filename} present and private")


def check_database(
    data_dir: Path, versions_dir: Path | None
) -> tuple[list[Check], sqlite3.Connection | None]:
    path = data_dir / "heron.db"
    if not path.is_file():
        return [Check("Database", WARN, "no heron.db yet (made on first start)")], None
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    sql = "SELECT name FROM sqlite_master WHERE type='table'"
    tables = {row[0] for row in connection.execute(sql)}
    missing = [table for table in REQUIRED_TABLES if table not in tables]
    if missing:
        detail = f"missing {', '.join(missing)}; start the app once to migrate"
        return [Check("Database tables", FAIL, detail)], connection

    checks = [Check("Database tables", OK, "all present")]
    mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    checks.append(Check("Journal mode", OK if mode == "wal" else WARN, f"{mode} (wal expected)"))

    row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    latest = latest_revision(versions_dir) if versions_dir and versions_dir.is_dir() else None
    if latest is None or row is None:
        checks.append(Check("Migrations", WARN, "couldn't compare database and code versions"))
    elif row[0] != latest:
        detail = f"database is at {row[0]}, code expects {latest}; start the app to migrate"
        checks.append(Check("Migrations", FAIL, detail))
    else:
        checks.append(Check("Migrations", OK, f"up to date ({latest})"))
    return checks, connection


def _scalar(connection: sqlite3.Connection, sql: str) -> int:
    return int(connection.execute(sql).fetchone()[0])


def check_contents(connection: sqlite3.Connection, eml_dir: Path) -> list[Check]:
    mailboxes = _scalar(connection, "SELECT COUNT(*) FROM accounts")
    stored = _scalar(connection, "SELECT COUNT(*) FROM emails")
    open_alerts = _scalar(connection, "SELECT COUNT(*) FROM alerts WHERE status = 'open'")
    unanalysed = _scalar(
        connection,
        "SELECT COUNT(*) FROM emails e LEFT JOIN analyses a ON a.email_id = e.id "
        "WHERE a.id IS NULL",
    )
    active = _scalar(connection, "SELECT COUNT(*) FROM jobs WHERE status IN ('pending','running')")

    summary = f"{mailboxes} mailbox(es), {stored} email(s), {open_alerts} open alert(s)"
    checks = [Check("Data", OK, summary)]
    if unanalysed:
        detail = f"{unanalysed} email(s) not analysed yet; fetch again or run analyze_pending"
        checks.append(Check("Analysis", WARN, detail))
    else:
        checks.append(Check("Analysis", OK, "every stored email has been analysed"))
    if active:
        detail = f"{active} job(s) pending or running (stuck if the server was restarted)"
        checks.append(Check("Jobs", WARN, detail))
    else:
        checks.append(Check("Jobs", OK, "none pending or running"))

    sql = "SELECT eml_path FROM emails ORDER BY id DESC LIMIT ?"
    paths = [row[0] for row in connection.execute(sql, (_SAMPLE_FILES,))]
    absent = [p for p in paths if not (eml_dir / p).is_file()]
    if absent:
        detail = f"{len(absent)} of {len(paths)} sampled .eml files missing from {eml_dir}"
        checks.append(Check("Stored messages", FAIL, detail))
    elif paths:
        checks.append(Check("Stored messages", OK, f"{len(paths)} sampled .eml files present"))
    return checks


def check_runner_hook(runner_path: Path | None) -> Check:
    if runner_path is None or not runner_path.is_file():
        return Check("Analysis hook", WARN, "couldn't find worker/runner.py")
    if "analyze_pending_safely" in runner_path.read_text():
        return Check("Analysis hook", OK, "run_job analyses new mail after each ingest")
    detail = "worker/runner.py never calls analyze_pending_safely; new mail won't be scored"
    return Check("Analysis hook", FAIL, detail)


def check_streamlit() -> Check:
    try:
        import streamlit  # noqa: F401, PLC0415
    except ImportError:
        return Check("Streamlit", FAIL, "not installed; run: pip install streamlit")
    return Check("Streamlit", OK, "installed")


def check_api(api_url: str) -> Check:
    url = api_url.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310
            ok = response.status == 200
            return Check("API", OK if ok else FAIL, f"{api_url} answered {response.status}")
    except (urllib.error.URLError, OSError):
        return Check("API", FAIL, f"couldn't reach {api_url}; is the API running?")


def run_checks(
    data_dir: Path,
    eml_dir: Path,
    *,
    versions_dir: Path | None = None,
    runner_path: Path | None = None,
    api_url: str | None = None,
) -> list[Check]:
    checks = [
        check_data_dir(data_dir),
        check_secret_file(data_dir, "secret.key", "HERON_SECRET_KEY", "Encryption key"),
        check_secret_file(data_dir, "api_token", "HERON_API_TOKEN", "API token"),
    ]
    db_checks, connection = check_database(data_dir, versions_dir)
    checks += db_checks
    if connection is not None:
        try:
            if not any(c.name == "Database tables" and c.status == FAIL for c in db_checks):
                checks += check_contents(connection, eml_dir)
        finally:
            connection.close()
    checks += [check_runner_hook(runner_path), check_streamlit()]
    if api_url:
        checks.append(check_api(api_url))
    return checks


def format_report(checks: list[Check]) -> str:
    width = max(len(c.name) for c in checks)
    lines = [f"[{_LABEL[c.status]}] {c.name.ljust(width)}  {c.detail}" for c in checks]
    failed = sum(c.status == FAIL for c in checks)
    warned = sum(c.status == WARN for c in checks)
    lines.append(f"\n{len(checks) - failed - warned} passed, {warned} warning(s), {failed} failed")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    from heron import worker  # noqa: PLC0415
    from heron.core.config import get_settings  # noqa: PLC0415

    args = argv if argv is not None else sys.argv[1:]
    api_url = args[args.index("--api-url") + 1] if "--api-url" in args else None
    settings = get_settings()
    package_dir = Path(__file__).parent
    checks = run_checks(
        settings.data_dir,
        settings.eml_dir,
        versions_dir=package_dir / "migrations" / "versions",
        runner_path=Path(worker.__file__).parent / "runner.py",
        api_url=api_url,
    )
    print(format_report(checks))
    return 1 if any(c.status == FAIL for c in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
