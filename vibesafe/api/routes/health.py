from __future__ import annotations

import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vibesafe.api.config import get_settings
from vibesafe.api.db import check_db, get_db

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/ping")
async def ping() -> dict:
    """Liveness probe — always returns OK if the process is running."""
    return {"status": "ok", "version": "1.0.0"}


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)) -> dict:
    """
    Readiness probe — checks database and Redis connectivity.
    Returns 200 with per-service status.
    """
    db_ok = await check_db()

    redis_ok = False
    try:
        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        redis_ok = True
    except Exception as exc:
        logger.warning("Redis health check failed: %s", exc)

    return {
        "status": "ok" if (db_ok and redis_ok) else "degraded",
        "services": {
            "database": "ok" if db_ok else "error",
            "redis": "ok" if redis_ok else "error",
        },
        "version": "1.0.0",
    }