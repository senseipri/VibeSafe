from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from vibesafe.api.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    echo=settings.environment == "development",
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, Any]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Startup DB check.

    Does NOT call ``Base.metadata.create_all``.  Alembic is the sole schema
    change path.  Run ``alembic upgrade head`` before starting the server.

    This function:
    1. Verifies the engine can reach the database.
    2. Warns (or raises in production) when the live Alembic revision does not
       match the current head(s).
    """
    # Ensure models are imported so Base has all mapped classes in scope for
    # any subsequent introspection (e.g. alembic autogenerate).
    from vibesafe.api import models  # noqa: F401

    # 1. Connectivity check — fail fast with a clear error instead of a
    #    cryptic 500 on the first real request.
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        raise RuntimeError(
            "Database is not reachable. "
            "Check DATABASE_URL and ensure the server is running."
        ) from exc

    # 2. Alembic revision guard — import alembic inline so the dependency is
    #    optional at the module level (keeps startup fast in tests that mock DB).
    try:
        from alembic.config import Config as AlembicConfig
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory

        alembic_cfg = AlembicConfig("alembic.ini")
        script_dir = ScriptDirectory.from_config(alembic_cfg)
        heads = set(script_dir.get_heads())

        async with engine.connect() as conn:
            ctx = await conn.run_sync(
                lambda sync_conn: MigrationContext.configure(sync_conn)
            )
            current_heads = set(ctx.get_current_heads())

        if current_heads != heads:
            msg = (
                "Alembic schema drift detected. "
                f"DB heads={current_heads or {'(none)'}}, "
                f"repo heads={heads}. "
                "Run `alembic upgrade head` before starting the server."
            )
            if settings.is_production:
                raise RuntimeError(msg)
            else:
                logger.warning(msg)
        else:
            logger.info("Alembic schema is current: %s", heads)

    except RuntimeError:
        raise
    except Exception as exc:  # pragma: no cover — alembic not configured in tests
        logger.warning("Could not verify Alembic revision: %s", exc)


async def check_db() -> bool:
    """Return True if DB is reachable."""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False