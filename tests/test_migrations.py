from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from heron.core.config import Settings
from heron.core.migrate import MIGRATIONS_DIR, init_database


def _current_version(engine):
    with engine.connect() as connection:
        return connection.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _latest_migration() -> str:
    """The newest revision on disk, read from the migration files themselves.

    Comparing against this instead of a hardcoded string (e.g. "0004") means
    this test never again goes stale the moment a new migration is added -
    it previously had to be hand-updated on Days 5, 8, and 9.
    """
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return ScriptDirectory.from_config(config).get_current_head()


def test_init_database_applies_all_migrations(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    engine = init_database(settings)
    assert settings.db_path.exists()
    assert _current_version(engine) == _latest_migration()
    engine.dispose()


def test_init_database_is_idempotent(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    init_database(settings).dispose()
    engine = init_database(settings)
    assert _current_version(engine) == _latest_migration()
    engine.dispose()
