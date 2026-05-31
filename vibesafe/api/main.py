from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from vibesafe.api.config import get_settings
from vibesafe.api.db import init_db
from vibesafe.api.routes.health import router as health_router
from vibesafe.api.routes.scan import router as scan_router

logger = logging.getLogger(__name__)
settings = get_settings()

# ── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.environment == "development" else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)


# ── Lifespan ─────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("VibeSafe API starting up | env=%s", settings.environment)
    await init_db()
    logger.info("Database tables ready")
    yield
    logger.info("VibeSafe API shutting down")


# ── App factory ───────────────────────────────────────────────────
app = FastAPI(
    title="VibeSafe API",
    description="AI-powered security scanner for vibe-coded apps.",
    version="1.0.0",
    lifespan=lifespan,
    # Hide /docs and /redoc in production
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
)


# ── Trusted host ─────────────────────────────────────────────────
# Prevents host-header injection attacks
if settings.is_production:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["api.vibesafe.dev", "vibesafe.dev"],
    )


# ── CORS ─────────────────────────────────────────────────────────
# Strictly restricted — NO wildcard, credentials handled via httpOnly cookies
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-ID"],
    allow_credentials=False,
    max_age=600,
)


# ── Security headers middleware ───────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next: Callable) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
    # Remove headers that leak server info
    try:
        del response.headers["Server"]
    except KeyError:
        pass
    try:
        del response.headers["X-Powered-By"]
    except KeyError:
        pass
    
    return response


# ── Request ID + structured logging middleware ───────────────────
@app.middleware("http")
async def request_logging(request: Request, call_next: Callable) -> Response:
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    t0 = time.monotonic()

    response = await call_next(request)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    logger.info(
        "req | %s %s %d | %dms | id=%s",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
        request_id,
    )
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{elapsed_ms}ms"
    return response


# ── Global exception handlers ─────────────────────────────────────
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Never expose internal details to the client
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred. Please try again."},
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "Not found."})


@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(
        status_code=405,
        content={"detail": "Method not allowed."},
    )


# ── Routers ───────────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(scan_router)


# ── Entry point ───────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "vibesafe.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.environment == "development",
        log_level="debug" if settings.environment == "development" else "info",
    )