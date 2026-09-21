"""Alembic environment.

Migrations run either from code (Heron passes an open connection through
``config.attributes["connection"]``) or from the CLI (``alembic upgrade head``),
in which case the database location comes from Heron's settings.
"""

from alembic import context

from heron.core.config import get_settings
from heron.core.db import create_db_engine

config = context.config

# Table metadata for autogenerate. Models arrive with the schema on Day 5.
target_metadata = None


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,  # SQLite cannot ALTER most things in place
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    engine = create_db_engine(get_settings().db_path)
    with engine.begin() as new_connection:
        _run(new_connection)
    engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("Offline (--sql) migrations are not supported.")

run_migrations_online()
