import os
import sqlite3
import stat

from heron.doctor import (
    FAIL,
    OK,
    WARN,
    Check,
    check_data_dir,
    check_runner_hook,
    check_secret_file,
    format_report,
    latest_revision,
    run_checks,
)


def make_versions(directory, *revisions):
    directory.mkdir()
    for revision in revisions:
        text = f'"""m"""\nrevision: str = "{revision}"\ndown_revision: str | None = None\n'
        (directory / f"{revision}_x.py").write_text(text)
    return directory


def make_db(data_dir, *, revision="0005", emails=(), analysed=(), alerts=(), jobs=(), wal=True):
    data_dir.mkdir(exist_ok=True)
    connection = sqlite3.connect(data_dir / "heron.db")
    if wal:
        connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(
        """
        CREATE TABLE accounts(id INTEGER PRIMARY KEY);
        CREATE TABLE emails(id INTEGER PRIMARY KEY, eml_path TEXT);
        CREATE TABLE jobs(id INTEGER PRIMARY KEY, status TEXT);
        CREATE TABLE coverage(id INTEGER PRIMARY KEY);
        CREATE TABLE analyses(id INTEGER PRIMARY KEY, email_id INTEGER);
        CREATE TABLE alerts(id INTEGER PRIMARY KEY, status TEXT);
        CREATE TABLE alembic_version(version_num TEXT);
        INSERT INTO accounts VALUES (1);
        """
    )
    connection.execute("INSERT INTO alembic_version VALUES (?)", (revision,))
    for index, path in enumerate(emails, start=1):
        connection.execute("INSERT INTO emails VALUES (?, ?)", (index, path))
    for email_id in analysed:
        connection.execute("INSERT INTO analyses(email_id) VALUES (?)", (email_id,))
    for status in alerts:
        connection.execute("INSERT INTO alerts(status) VALUES (?)", (status,))
    for status in jobs:
        connection.execute("INSERT INTO jobs(status) VALUES (?)", (status,))
    connection.commit()
    connection.close()


def by_name(checks):
    return {c.name: c for c in checks}


def healthy(tmp_path):
    data, eml = tmp_path / "data", tmp_path / "data" / "eml"
    (eml / "ab").mkdir(parents=True)
    (eml / "ab" / "one.eml").write_text("x")
    make_db(data, emails=["ab/one.eml"], analysed=[1], alerts=["open"])
    (data / "secret.key").write_text("k")
    (data / "api_token").write_text("t")
    os.chmod(data / "secret.key", 0o600)
    os.chmod(data / "api_token", 0o600)
    runner = tmp_path / "runner.py"
    runner.write_text("analyze_pending_safely(engine, eml_dir)\n")
    return data, eml, make_versions(tmp_path / "versions", "0004", "0005"), runner


def test_latest_revision_picks_the_highest(tmp_path):
    assert latest_revision(make_versions(tmp_path / "v", "0001", "0005", "0003")) == "0005"
    assert latest_revision(tmp_path) is None  # no migration files


def test_a_healthy_install_has_no_failures_or_warnings_except_streamlit(tmp_path, monkeypatch):
    monkeypatch.delenv("HERON_SECRET_KEY", raising=False)
    monkeypatch.delenv("HERON_API_TOKEN", raising=False)
    data, eml, versions, runner = healthy(tmp_path)
    checks = by_name(run_checks(data, eml, versions_dir=versions, runner_path=runner))
    assert checks["Database tables"].status == OK
    assert checks["Migrations"].status == OK
    assert checks["Analysis"].status == OK
    assert checks["Stored messages"].status == OK
    assert checks["Analysis hook"].status == OK
    assert checks["Data"].detail == "1 mailbox(es), 1 email(s), 1 open alert(s)"
    assert [c.name for c in checks.values() if c.status == FAIL and c.name != "Streamlit"] == []
    assert not [c.name for c in checks.values() if c.status == WARN]


def test_fresh_install_only_warns(tmp_path, monkeypatch):
    monkeypatch.delenv("HERON_SECRET_KEY", raising=False)
    monkeypatch.delenv("HERON_API_TOKEN", raising=False)
    checks = by_name(run_checks(tmp_path / "nothing", tmp_path / "eml"))
    assert checks["Data folder"].status == WARN
    assert checks["Database"].status == WARN
    assert checks["Encryption key"].status == WARN


def test_missing_tables_fail_and_skip_the_content_checks(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    connection = sqlite3.connect(data / "heron.db")
    connection.execute("CREATE TABLE accounts(id INTEGER)")
    connection.commit()
    connection.close()
    checks = by_name(run_checks(data, tmp_path / "eml"))
    assert checks["Database tables"].status == FAIL
    assert "emails" in checks["Database tables"].detail
    assert "Data" not in checks


def test_database_behind_the_code_fails(tmp_path):
    data, eml, versions, runner = healthy(tmp_path)
    connection = sqlite3.connect(data / "heron.db")
    connection.execute("UPDATE alembic_version SET version_num = '0004'")
    connection.commit()
    connection.close()
    checks = by_name(run_checks(data, eml, versions_dir=versions, runner_path=runner))
    migrations = checks["Migrations"]
    assert migrations.status == FAIL
    assert "0004" in migrations.detail
    assert "0005" in migrations.detail


def test_unanalysed_email_and_active_jobs_warn(tmp_path):
    data = tmp_path / "data"
    make_db(data, emails=["a.eml", "b.eml"], analysed=[1], jobs=["running", "done"])
    checks = by_name(run_checks(data, tmp_path / "eml"))
    assert checks["Analysis"].status == WARN
    assert "1 email(s)" in checks["Analysis"].detail
    assert checks["Jobs"].status == WARN


def test_missing_eml_files_fail(tmp_path):
    data = tmp_path / "data"
    make_db(data, emails=["ab/gone.eml"], analysed=[1])
    checks = by_name(run_checks(data, tmp_path / "eml"))
    assert checks["Stored messages"].status == FAIL
    assert "1 of 1" in checks["Stored messages"].detail


def test_non_wal_journal_mode_warns(tmp_path):
    data = tmp_path / "data"
    make_db(data, wal=False)
    assert by_name(run_checks(data, tmp_path / "eml"))["Journal mode"].status == WARN


def test_doctor_never_modifies_the_database(tmp_path):
    data = tmp_path / "data"
    make_db(data, emails=["a.eml"])
    before = (data / "heron.db").read_bytes()
    run_checks(data, tmp_path / "eml")
    assert (data / "heron.db").read_bytes() == before


def test_secret_file_permissions_and_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("HERON_API_TOKEN", raising=False)
    token = tmp_path / "api_token"
    token.write_text("t")
    os.chmod(token, 0o644)
    check = check_secret_file(tmp_path, "api_token", "HERON_API_TOKEN", "API token")
    assert check.status == WARN
    assert "chmod 600" in check.detail
    os.chmod(token, stat.S_IRUSR | stat.S_IWUSR)
    assert check_secret_file(tmp_path, "api_token", "HERON_API_TOKEN", "API token").status == OK
    monkeypatch.setenv("HERON_API_TOKEN", "from-env")
    elsewhere = tmp_path / "elsewhere"
    from_env = check_secret_file(elsewhere, "api_token", "HERON_API_TOKEN", "API token")
    assert from_env.status == OK
    assert "from-env" not in from_env.detail  # the value itself is never printed


def test_secret_values_are_never_in_the_report(tmp_path, monkeypatch):
    monkeypatch.delenv("HERON_SECRET_KEY", raising=False)
    monkeypatch.delenv("HERON_API_TOKEN", raising=False)
    data, eml, versions, runner = healthy(tmp_path)
    (data / "api_token").write_text("super-secret-token-value")
    (data / "secret.key").write_text("super-secret-key-value")
    report = format_report(run_checks(data, eml, versions_dir=versions, runner_path=runner))
    assert "super-secret" not in report


def test_runner_hook_check(tmp_path):
    runner = tmp_path / "runner.py"
    assert check_runner_hook(None).status == WARN
    assert check_runner_hook(runner).status == WARN  # file doesn't exist
    runner.write_text("mark_done(engine, job['id'])\n")
    assert check_runner_hook(runner).status == FAIL
    runner.write_text("mark_done(engine, job['id'])\nanalyze_pending_safely(engine, eml_dir)\n")
    assert check_runner_hook(runner).status == OK


def test_data_folder_check(tmp_path):
    assert check_data_dir(tmp_path).status == OK
    assert check_data_dir(tmp_path / "missing").status == WARN


def test_format_report_summarises_counts():
    checks = [Check("A", OK, "fine"), Check("Bee", WARN, "hmm"), Check("C", FAIL, "bad")]
    report = format_report(checks)
    assert "[PASS] A    fine" in report
    assert "[WARN] Bee  hmm" in report
    assert "[FAIL] C    bad" in report
    assert report.endswith("1 passed, 1 warning(s), 1 failed")
