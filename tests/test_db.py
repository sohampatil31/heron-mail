from sqlalchemy import text

from heron.core.db import create_db_engine


def test_connections_use_wal_and_foreign_keys(tmp_path):
    engine = create_db_engine(tmp_path / "test.db")
    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
        assert connection.execute(text("PRAGMA busy_timeout")).scalar() == 5000
    engine.dispose()


def test_missing_parent_directories_are_created(tmp_path):
    db_path = tmp_path / "nested" / "dir" / "test.db"
    engine = create_db_engine(db_path)
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    assert db_path.exists()
    engine.dispose()
