from __future__ import annotations

import re
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ---------------------------------------------------------------------------
# Alembic config object — provides access to values within alembic.ini
# ---------------------------------------------------------------------------
config = context.config

# Set up loggers as defined in alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# Import models so autogenerate can detect schema changes
# ---------------------------------------------------------------------------
import vibesafe.api.models  # noqa: F401  (registers all ORM classes with Base)
from vibesafe.api.db import Base

target_metadata = Base.metadata

# ---------------------------------------------------------------------------
# Override sqlalchemy.url from app Settings so there is a single source of
# truth.  asyncpg URLs are rewritten to psycopg2 so Alembic can use a
# synchronous connection during migration runs.
# ---------------------------------------------------------------------------

def _get_sync_url() -> str:
    """Return a *synchronous* PostgreSQL URL suitable for Alembic."""
    try:
        from vibesafe.api.config import get_settings
        url: str = get_settings().database_url
    except Exception:
        # Fall back to whatever is set in alembic.ini
        url = config.get_main_option("sqlalchemy.url", "")

    # Convert async driver (asyncpg) → sync driver (psycopg2)
    url = re.sub(r"^postgresql\+asyncpg", "postgresql+psycopg2", url)
    # Also handle plain postgresql:// → postgresql+psycopg2://
    url = re.sub(r"^postgresql://", "postgresql+psycopg2://", url)
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures context with just a URL (no live engine required).
    Calls to context.execute() emit the given string to the script output.
    """
    url = _get_sync_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates an Engine and associates a connection with the context.
    """
    # Build a config section override with our resolved URL
    cfg_section = config.get_section(config.config_ini_section) or {}
    cfg_section["sqlalchemy.url"] = _get_sync_url()

    connectable = engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
