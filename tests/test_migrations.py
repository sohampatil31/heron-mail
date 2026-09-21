from sqlalchemy import text

from heron.core.config import Settings
from heron.core.migrate import init_database


def _current_version(engine):
    with engine.connect() as connection:
        return connection.execute(text("SELECT version_num FROM alembic_version")).scalar()


def test_init_database_applies_baseline(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    engine = init_database(settings)
    assert settings.db_path.exists()
    assert _current_version(engine) == "0001"
    engine.dispose()


def test_init_database_is_idempotent(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    init_database(settings).dispose()
    engine = init_database(settings)
    assert _current_version(engine) == "0001"
    engine.dispose()
