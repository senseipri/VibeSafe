import pytest
from pathlib import Path
from vibesafe.scanner.static.secrets import SecretsScanner
from vibesafe.scanner.static.auth import AuthScanner
from vibesafe.scanner.static.injection import InjectionScanner
from vibesafe.scanner.static.cors import CORSScanner
from vibesafe.scanner.static.database import DBConfigScanner
from vibesafe.scanner.static.ratelimit import RateLimitScanner
from vibesafe.scanner.findings import Severity

pytestmark = pytest.mark.anyio


# ─────────────────────────────────────────────────────────────────
# SecretsScanner
# ─────────────────────────────────────────────────────────────────

class TestSecretsScanner:
    async def test_detects_openai_key(self, sample_manifest):
        findings = await SecretsScanner().scan(sample_manifest)
        cats = [f.category for f in findings]
        sevs = [f.severity for f in findings]
        assert "hardcoded_secret" in cats
        assert "critical" in sevs

    async def test_skips_env_var_references(self, tmp_path):
        # File with ONLY safe env var references — should find 0 secrets
        safe = tmp_path / "safe.py"
        safe.write_text('KEY = os.environ.get("OPENAI_API_KEY")\n')
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await SecretsScanner().scan(m)
        secret_findings = [f for f in findings if "openai" in f.evidence.lower()]
        assert len(secret_findings) == 0

    async def test_detects_committed_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("OPENAI_API_KEY=sk-proj-test\n")
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await SecretsScanner().scan(m)
        assert any(f.category == "committed_env_file" and f.severity == "critical" for f in findings)

    async def test_skips_placeholder_values(self, tmp_path):
        """Placeholder / example values like 'your-api-key-here' must not fire."""
        f = tmp_path / "readme_example.py"
        f.write_text(
            'API_KEY = "your-openai-api-key-here"\n'
            'SECRET = "replace-me"\n'
            'TOKEN = "changeme"\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await SecretsScanner().scan(m)
        # placeholders should not produce hardcoded_secret findings
        assert all(
            "your-" not in f.evidence and "replace-me" not in f.evidence
            for f in findings
            if f.category == "hardcoded_secret"
        )


# ─────────────────────────────────────────────────────────────────
# AuthScanner
# ─────────────────────────────────────────────────────────────────

class TestAuthScanner:
    async def test_detects_unprotected_admin_route(self, sample_manifest):
        findings = await AuthScanner().scan(sample_manifest)
        assert any(f.category == "missing_auth" and f.severity == "critical" for f in findings)

    async def test_ignores_protected_route(self, tmp_path):
        protected = tmp_path / "app.py"
        protected.write_text(
            'from fastapi import Depends\n'
            '@app.get("/api/admin/users")\n'
            'def list_users(current_user=Depends(get_current_user)): pass\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await AuthScanner().scan(m)
        assert len([f for f in findings if f.category == "missing_auth"]) == 0

    async def test_ignores_public_route_with_inline_auth_check(self, tmp_path):
        """GET /public endpoints with an inline auth guard must not produce findings."""
        f = tmp_path / "routes.py"
        f.write_text(
            'from fastapi import Depends\n'
            'from auth import get_current_user\n'
            '\n'
            '@app.get("/api/public/feed")\n'
            'def public_feed(): return []\n'
            '\n'
            '@app.get("/api/admin/dashboard")\n'
            'def dashboard(user=Depends(get_current_user)): return {}\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await AuthScanner().scan(m)
        # /api/admin/dashboard is protected — no missing_auth finding for it
        admin_missing = [
            f for f in findings
            if f.category == "missing_auth" and "dashboard" in f.evidence
        ]
        assert len(admin_missing) == 0

    async def test_public_route_not_flagged_as_critical(self, tmp_path):
        """A genuinely public route (/api/public/...) must never be critical."""
        f = tmp_path / "app.py"
        f.write_text(
            '@app.get("/api/public/health")\n'
            'def health_check(): return {"ok": True}\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await AuthScanner().scan(m)
        critical_on_public = [
            fi for fi in findings
            if fi.category == "missing_auth" and fi.severity == "critical"
            and "public" in fi.evidence.lower()
        ]
        assert len(critical_on_public) == 0


# ─────────────────────────────────────────────────────────────────
# InjectionScanner
# ─────────────────────────────────────────────────────────────────

class TestInjectionScanner:
    async def test_detects_sql_injection(self, sample_manifest):
        findings = await InjectionScanner().scan(sample_manifest)
        sql_findings = [f for f in findings if f.category == "sql_injection"]
        assert len(sql_findings) >= 1
        assert all(f.severity == "critical" for f in sql_findings)

    async def test_detects_log_injection(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('logger.info(f"Login: {request.body[\'username\']}")\n')
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await InjectionScanner().scan(m)
        assert any(f.category == "log_injection" for f in findings)

    async def test_safe_structured_logging_not_flagged(self, tmp_path):
        """Logging a fixed message (no user input) must produce zero log_injection findings."""
        f = tmp_path / "app.py"
        f.write_text(
            'import logging\n'
            'logger = logging.getLogger(__name__)\n'
            'logger.info("User logged in successfully")\n'
            'logger.info("Processing started | step=1")\n'
            'logger.debug("Database query complete")\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await InjectionScanner().scan(m)
        assert all(f.category != "log_injection" for f in findings)

    async def test_parameterised_sql_not_flagged(self, tmp_path):
        """Properly parameterised SQL (no interpolation) must not fire sql_injection."""
        f = tmp_path / "queries.py"
        f.write_text(
            'import sqlite3\n'
            'def get_user(uid):\n'
            '    conn = sqlite3.connect("db")\n'
            '    cursor = conn.cursor()\n'
            '    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))\n'
            '    return cursor.fetchone()\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await InjectionScanner().scan(m)
        assert all(f.category != "sql_injection" for f in findings)


# ─────────────────────────────────────────────────────────────────
# CORSScanner
# ─────────────────────────────────────────────────────────────────

class TestCORSScanner:
    async def test_detects_wildcard_with_credentials(self, sample_manifest):
        findings = await CORSScanner().scan(sample_manifest)
        cors_findings = [f for f in findings if f.category == "cors_wildcard_credentials"]
        assert len(cors_findings) >= 1
        assert cors_findings[0].severity == "critical"


# ─────────────────────────────────────────────────────────────────
# DBConfigScanner  (rls_disabled)
# ─────────────────────────────────────────────────────────────────

class TestDBConfigScanner:
    async def test_detects_missing_rls_in_supabase_project(self, sample_manifest):
        """fixture supabase_migration.sql has 'supabase' in filename → project detected."""
        findings = await DBConfigScanner().scan(sample_manifest)
        rls_findings = [f for f in findings if f.category == "rls_disabled"]
        assert len(rls_findings) >= 1

    async def test_plain_postgres_schema_no_rls_finding(self, tmp_path):
        """A standard PostgreSQL migration (no Supabase context) must not produce rls_disabled."""
        sql = tmp_path / "0001_create_users.sql"
        sql.write_text(
            "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT NOT NULL);\n"
            "CREATE TABLE posts (id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id));\n"
            "-- standard Alembic / Django migration, no row-level security required\n"
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await DBConfigScanner().scan(m)
        rls_findings = [f for f in findings if f.category == "rls_disabled"]
        assert len(rls_findings) == 0, (
            f"Expected 0 rls_disabled findings on plain PostgreSQL schema, got {len(rls_findings)}: "
            + str([f.evidence for f in rls_findings])
        )

    async def test_supabase_schema_rls_present_no_finding(self, tmp_path):
        """A Supabase migration that properly enables RLS must produce 0 rls_disabled findings."""
        sql = tmp_path / "supabase_migration.sql"
        sql.write_text(
            "CREATE TABLE users (id UUID PRIMARY KEY, email TEXT);\n"
            "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n"
            "CREATE POLICY select_own ON users FOR SELECT USING (auth.uid() = id);\n"
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await DBConfigScanner().scan(m)
        rls_findings = [f for f in findings if f.category == "rls_disabled"]
        assert len(rls_findings) == 0


# ─────────────────────────────────────────────────────────────────
# RateLimitScanner
# ─────────────────────────────────────────────────────────────────

class TestRateLimitScanner:
    async def test_detects_missing_rate_limit_on_login(self, tmp_path):
        f = tmp_path / "routes.py"
        f.write_text(
            '@app.post("/api/auth/login")\nasync def login(data: LoginData): pass\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await RateLimitScanner().scan(m)
        assert any(f.category == "missing_rate_limit" for f in findings)

    async def test_rate_limited_login_endpoint_not_flagged(self, tmp_path):
        """Login endpoint decorated with slowapi limiter must produce 0 findings."""
        f = tmp_path / "routes.py"
        f.write_text(
            'from slowapi import Limiter\n'
            'limiter = Limiter(key_func=get_remote_address)\n'
            '\n'
            '@limiter.limit("5/minute")\n'
            '@app.post("/api/auth/login")\n'
            'async def login(data: dict): pass\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await RateLimitScanner().scan(m)
        rl_findings = [f for f in findings if f.category == "missing_rate_limit"]
        assert len(rl_findings) == 0, (
            f"Expected 0 missing_rate_limit findings, got {len(rl_findings)}"
        )

    async def test_non_sensitive_endpoint_not_flagged(self, tmp_path):
        """Public /api/feed endpoint must not produce missing_rate_limit finding."""
        f = tmp_path / "routes.py"
        f.write_text(
            '@app.get("/api/feed")\n'
            'async def feed(): return []\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await RateLimitScanner().scan(m)
        assert all(f.category != "missing_rate_limit" for f in findings)

    async def test_missing_rate_limit_status_is_needs_review(self, tmp_path):
        """missing_rate_limit findings must be needs_review (not candidate) by default."""
        f = tmp_path / "routes.py"
        f.write_text(
            '@app.post("/api/auth/register")\nasync def register(data: dict): pass\n'
        )
        from vibesafe.scanner.ingest import build_manifest
        m = build_manifest(tmp_path)
        findings = await RateLimitScanner().scan(m)
        rl_findings = [f for f in findings if f.category == "missing_rate_limit"]
        assert all(f.status == "needs_review" for f in rl_findings), (
            "missing_rate_limit findings must start as needs_review to prevent false-positive dominance"
        )

