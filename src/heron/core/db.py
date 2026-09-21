"""SQLite engine setup."""

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import URL, Engine


def create_db_engine(db_path: Path) -> Engine:
    """Create an engine for the SQLite file at ``db_path``.

    Every new connection is configured with:
    - WAL journal mode, so readers (API) and the writer (worker) do not block each other
    - foreign key enforcement, which SQLite leaves off by default
    - a busy timeout, so a briefly locked database is retried instead of failing
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(URL.create("sqlite", database=str(db_path)))

    @event.listens_for(engine, "connect")
    def _configure_connection(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    return engine
