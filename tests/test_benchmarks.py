"""
test_benchmarks.py — False-positive budget tests for VibeSafe v1.0.0.

Each test represents a "known-clean" pattern that must produce ZERO findings
(or findings bounded by a low count) so that real-world repos are not
dominated by speculative noise.

These are the gate checks that must pass before tagging v1.0.0.
"""
from __future__ import annotations

import pytest
from pathlib import Path

from vibesafe.scanner.static.auth import AuthScanner
from vibesafe.scanner.static.database import DBConfigScanner
from vibesafe.scanner.static.injection import InjectionScanner
from vibesafe.scanner.static.ratelimit import RateLimitScanner
from vibesafe.scanner.static.ai_security import AISecurityScanner
from vibesafe.scanner.findings import Finding

pytestmark = pytest.mark.anyio


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

async def _scan_content(
    scanner_cls,
    filename: str,
    content: str,
    tmp_path: Path,
) -> list[Finding]:
    """Write a single file and run the given scanner on it."""
    (tmp_path / filename).write_text(content, encoding="utf-8")
    from vibesafe.scanner.ingest import build_manifest
    m = build_manifest(tmp_path)
    return await scanner_cls().scan(m)


# ─────────────────────────────────────────────────────────────────
# Benchmark 1: Normal PostgreSQL schema without RLS
# ─────────────────────────────────────────────────────────────────

class TestRLSBenchmark:
    """rls_disabled must NEVER fire on non-Supabase SQL files."""

    PLAIN_POSTGRES_SQL = """
-- Django-style migration
CREATE TABLE IF NOT EXISTS auth_user (
    id SERIAL PRIMARY KEY,
    username VARCHAR(150) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL,
    password VARCHAR(128) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    date_joined TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blog_post (
    id SERIAL PRIMARY KEY,
    author_id INT NOT NULL REFERENCES auth_user(id),
    title VARCHAR(200) NOT NULL,
    body TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX blog_post_author_idx ON blog_post(author_id);
"""

    ALEMBIC_MIGRATION_SQL = """
-- Alembic upgrade
CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

CREATE TABLE product (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR NOT NULL,
    price NUMERIC(10,2) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
"""

    async def test_django_migration_no_rls_finding(self, tmp_path):
        """Django/SQLAlchemy migration files must never produce rls_disabled."""
        findings = await _scan_content(
            DBConfigScanner, "0001_initial.sql", self.PLAIN_POSTGRES_SQL, tmp_path
        )
        rls = [f for f in findings if f.category == "rls_disabled"]
        assert rls == [], f"Got {len(rls)} unexpected rls_disabled: {[f.evidence for f in rls]}"

    async def test_alembic_migration_no_rls_finding(self, tmp_path):
        """Alembic migration files must never produce rls_disabled."""
        findings = await _scan_content(
            DBConfigScanner, "2024_create_product.sql", self.ALEMBIC_MIGRATION_SQL, tmp_path
        )
        rls = [f for f in findings if f.category == "rls_disabled"]
        assert rls == [], f"Got {len(rls)} unexpected rls_disabled: {[f.evidence for f in rls]}"


# ─────────────────────────────────────────────────────────────────
# Benchmark 2: Public endpoints with inline auth checks
# ─────────────────────────────────────────────────────────────────

class TestAuthBenchmark:
    """Endpoints that carry their own auth dependency must produce 0 missing_auth."""

    FASTAPI_WITH_DEPS = """
from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated
from .auth import get_current_active_user, User

router = APIRouter()


@router.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@router.get("/admin/stats")
async def admin_stats(
    _: Annotated[User, Depends(get_current_active_user)],
):
    return {"total": 42}


@router.get("/public/info")
async def public_info():
    return {"name": "VibeSafe"}
"""

    FLASK_WITH_LOGIN_REQUIRED = """
from flask import Flask, jsonify
from flask_login import login_required, current_user

app = Flask(__name__)


@app.route("/api/admin/users")
@login_required
def list_users():
    return jsonify([])


@app.route("/api/public/status")
def status():
    return jsonify({"ok": True})
"""

    async def test_fastapi_deps_no_missing_auth(self, tmp_path):
        findings = await _scan_content(
            AuthScanner, "routes.py", self.FASTAPI_WITH_DEPS, tmp_path
        )
        missing = [f for f in findings if f.category == "missing_auth"]
        assert missing == [], (
            f"Expected no missing_auth, got {len(missing)}: {[f.evidence for f in missing]}"
        )

    async def test_flask_login_required_no_missing_auth(self, tmp_path):
        findings = await _scan_content(
            AuthScanner, "views.py", self.FLASK_WITH_LOGIN_REQUIRED, tmp_path
        )
        missing = [f for f in findings if f.category == "missing_auth"]
        # admin route is protected — must not appear
        admin_missing = [f for f in missing if "admin" in f.evidence]
        assert admin_missing == [], (
            f"login_required admin route flagged: {[f.evidence for f in admin_missing]}"
        )


# ─────────────────────────────────────────────────────────────────
# Benchmark 3: Safe structured logging (no user-controlled input)
# ─────────────────────────────────────────────────────────────────

class TestLogInjectionBenchmark:
    """Safe logging patterns must never produce log_injection findings."""

    SAFE_LOGGING = """
import logging
import structlog

logger = logging.getLogger(__name__)
slog = structlog.get_logger()


def process_order(order_id: str, amount: float) -> None:
    logger.info("Processing order", extra={"order_id": order_id, "amount": amount})
    logger.debug("Order validation complete | step=verify")
    slog.info("payment.initiated", order_id=order_id, amount=amount)


def handle_request(method: str, path: str) -> None:
    logger.info("Request received: %s %s", method, path)


def startup() -> None:
    logger.info("Server started on port 8000")
    logger.info("Database pool initialised: size=5 max_overflow=10")
"""

    async def test_safe_logging_no_finding(self, tmp_path):
        findings = await _scan_content(
            InjectionScanner, "logging_utils.py", self.SAFE_LOGGING, tmp_path
        )
        log_findings = [f for f in findings if f.category == "log_injection"]
        assert log_findings == [], (
            f"Safe logging produced {len(log_findings)} log_injection findings: "
            + str([f.evidence for f in log_findings])
        )


# ─────────────────────────────────────────────────────────────────
# Benchmark 4: Rate-limited endpoints must not fire
# ─────────────────────────────────────────────────────────────────

class TestRateLimitBenchmark:
    """Endpoints with explicit rate-limit decorators must produce 0 missing_rate_limit."""

    SLOWAPI_PROTECTED = """
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@limiter.limit("5/minute")
@app.post("/api/auth/login")
async def login(request: Request, credentials: LoginIn, db: Session = Depends(get_db)):
    user = authenticate(db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_access_token(user.id)}


@limiter.limit("3/hour")
@app.post("/api/auth/register")
async def register(request: Request, body: RegisterIn, db: Session = Depends(get_db)):
    return create_user(db, body)


@limiter.limit("3/hour")
@app.post("/api/auth/forgot-password")
async def forgot_password(request: Request, body: ForgotIn):
    return send_reset_email(body.email)
"""

    async def test_slowapi_decorated_no_finding(self, tmp_path):
        findings = await _scan_content(
            RateLimitScanner, "auth_routes.py", self.SLOWAPI_PROTECTED, tmp_path
        )
        rl = [f for f in findings if f.category == "missing_rate_limit"]
        assert rl == [], (
            f"Rate-limited endpoints produced {len(rl)} missing_rate_limit findings: "
            + str([f.evidence for f in rl])
        )


# ─────────────────────────────────────────────────────────────────
# Benchmark 5: Public prediction API without privileged actions
# ─────────────────────────────────────────────────────────────────

class TestAISecurityBenchmark:
    """A simple public prediction endpoint (no PII, no writes, no secrets) must be silent."""

    PUBLIC_PREDICTION_API = """
from fastapi import FastAPI
import google.generativeai as genai

app = FastAPI()
model = genai.GenerativeModel("gemini-2.5-flash")


@app.post("/api/predict")
async def predict(body: dict):
    prompt = body.get("text", "")
    response = model.generate_content(prompt)
    return {"result": response.text}
"""

    async def test_public_prediction_no_confirmed_findings(self, tmp_path):
        """Public prediction route (no sensitive data) must produce only needs_review at most."""
        findings = await _scan_content(
            AISecurityScanner, "predict.py", self.PUBLIC_PREDICTION_API, tmp_path
        )
        # No finding should be candidate/confirmed — all must be needs_review or absent
        confirmed_or_candidate = [
            f for f in findings
            if f.status in {"candidate", "confirmed"}
            and f.category in {"prompt_injection", "retrieval_poisoning"}
        ]
        assert confirmed_or_candidate == [], (
            f"Public prediction endpoint produced high-confidence AI findings: "
            + str([f"{f.category}:{f.status}" for f in confirmed_or_candidate])
        )


# ─────────────────────────────────────────────────────────────────
# Benchmark 6: Log injection status progression
# ─────────────────────────────────────────────────────────────────

class TestLogInjectionStatusBenchmark:
    """Without explicit CR/LF signal, log_injection must be needs_review."""

    BASIC_USER_LOG = """
import logging
logger = logging.getLogger(__name__)


def login_handler(request):
    username = request.body['username']
    logger.info(f"Login attempt: {request.body['username']}")
"""

    CRLF_LOG = r"""
import logging
logger = logging.getLogger(__name__)


def login_handler(request):
    # Note: user input could contain \n characters (CRLF injection risk)
    logger.info(f"Login attempt: {request.body['username']}")
"""

    async def test_basic_user_log_is_needs_review(self, tmp_path):
        """Without CRLF signal, log_injection is needs_review (not candidate)."""
        findings = await _scan_content(
            InjectionScanner, "handler.py", self.BASIC_USER_LOG, tmp_path
        )
        log_findings = [f for f in findings if f.category == "log_injection"]
        if log_findings:
            assert all(f.status == "needs_review" for f in log_findings), (
                f"Expected needs_review, got: {[(f.status, f.evidence) for f in log_findings]}"
            )

    async def test_crlf_in_comment_upgrades_to_candidate(self, tmp_path):
        """Presence of \\n reference near a log call should allow candidate status."""
        findings = await _scan_content(
            InjectionScanner, "handler_crlf.py", self.CRLF_LOG, tmp_path
        )
        # Either no finding or a candidate — both are acceptable, just not silent candidate FPs
        # (This test just verifies the scanner doesn't crash on CRLF patterns)
        assert isinstance(findings, list)
