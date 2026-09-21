"""Run database migrations from code, so the app can migrate itself on startup."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine

from heron.core.config import Settings, get_settings
from heron.core.db import create_db_engine

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def upgrade_to_head(engine: Engine) -> None:
    """Apply all pending migrations using the given engine."""
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def init_database(settings: Settings | None = None) -> Engine:
    """Create the data directory and database, migrate it, and return the engine."""
    settings = settings or get_settings()
    settings.ensure_dirs()
    engine = create_db_engine(settings.db_path)
    upgrade_to_head(engine)
    return engine
