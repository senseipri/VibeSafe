from __future__ import annotations

import pytest

from vibesafe.scanner.ingest import build_manifest, detect_framework
from vibesafe.scanner.static.auth import AuthScanner
from vibesafe.scanner.static.ai_security import AISecurityScanner
from vibesafe.scanner.static.injection import InjectionScanner
from vibesafe.scanner.static.ratelimit import RateLimitScanner
from vibesafe.scanner.static.secrets import SecretsScanner
from vibesafe.scanner.evidence import EvidenceBuilder
from vibesafe.scanner.findings import Finding
from vibesafe.scanner.repo_context import RepoContext

pytestmark = pytest.mark.anyio


class TestNodeFrameworkDetection:
    async def test_detects_express_and_nextjs(self, tmp_path):
        (tmp_path / "package.json").write_text(
            '{\n  "dependencies": {\n    "express": "^4.0.0",\n    "next": "^15.0.0"\n  }\n}\n',
            encoding="utf-8",
        )
        (tmp_path / "next.config.js").write_text("module.exports = {}\n", encoding="utf-8")
        (tmp_path / "app").mkdir()

        manifest = build_manifest(tmp_path)
        frameworks = detect_framework(manifest)

        assert "node" in frameworks
        assert "express" in frameworks
        assert "nextjs" in frameworks


class TestNodeAuthScanner:
    async def test_detects_unauthenticated_express_admin_route(self, tmp_path):
        f = tmp_path / "server.js"
        f.write_text(
            'app.get("/api/admin/users", (req, res) => res.json([]))\n',
            encoding="utf-8",
        )
        findings = await AuthScanner().scan(build_manifest(tmp_path))
        assert any(f.category == "missing_auth" for f in findings)

    async def test_detects_unauthenticated_nextjs_api_route(self, tmp_path):
        route_dir = tmp_path / "app" / "api" / "admin" / "users"
        route_dir.mkdir(parents=True)
        (route_dir / "route.ts").write_text(
            "export async function DELETE(request: Request) {\n"
            "  return Response.json({ ok: true })\n"
            "}\n",
            encoding="utf-8",
        )
        findings = await AuthScanner().scan(build_manifest(tmp_path))
        assert any(f.category == "missing_auth" for f in findings)

    async def test_authenticated_express_admin_route_not_flagged(self, tmp_path):
        f = tmp_path / "server.js"
        f.write_text(
            'app.get("/api/admin/users", requireAuth, (req, res) => res.json([]))\n',
            encoding="utf-8",
        )
        findings = await AuthScanner().scan(build_manifest(tmp_path))
        assert all(f.category != "missing_auth" for f in findings)


class TestNodeRateLimitScanner:
    async def test_rate_limited_login_route_not_flagged(self, tmp_path):
        f = tmp_path / "auth.js"
        f.write_text(
            'const rateLimit = require("express-rate-limit")\n'
            'const limiter = rateLimit({ windowMs: 60000, max: 5 })\n'
            'app.post("/api/auth/login", limiter, (req, res) => res.json({ ok: true }))\n',
            encoding="utf-8",
        )
        findings = await RateLimitScanner().scan(build_manifest(tmp_path))
        assert all(f.category != "missing_rate_limit" for f in findings)


class TestNodeInjectionScanner:
    async def test_detects_sql_injection_in_express(self, tmp_path):
        f = tmp_path / "db.js"
        f.write_text(
            'app.get("/api/users", async (req, res) => {\n'
            '  return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)\n'
            '})\n',
            encoding="utf-8",
        )
        findings = await InjectionScanner().scan(build_manifest(tmp_path))
        assert any(f.category == "sql_injection" for f in findings)

    async def test_detects_command_injection_via_exec(self, tmp_path):
        f = tmp_path / "exec.js"
        f.write_text(
            'const { exec } = require("child_process")\n'
            'app.get("/api/admin/run", (req, res) => exec(`ls ${req.query.path}`))\n',
            encoding="utf-8",
        )
        findings = await InjectionScanner().scan(build_manifest(tmp_path))
        assert any(f.category == "command_injection" for f in findings)

    async def test_detects_path_traversal_via_fs_readfile(self, tmp_path):
        f = tmp_path / "fs.js"
        f.write_text(
            'const fs = require("fs")\n'
            'app.get("/api/files", (req, res) => fs.readFile(req.query.file, "utf8", () => {}))\n',
            encoding="utf-8",
        )
        findings = await InjectionScanner().scan(build_manifest(tmp_path))
        assert any(f.category == "path_traversal" for f in findings)

    async def test_parameterized_sql_query_not_flagged(self, tmp_path):
        f = tmp_path / "safe_db.js"
        f.write_text(
            'app.get("/api/users/:id", async (req, res) => {\n'
            '  return db.query("SELECT * FROM users WHERE id = $1", [req.params.id])\n'
            '})\n',
            encoding="utf-8",
        )
        findings = await InjectionScanner().scan(build_manifest(tmp_path))
        assert all(f.category != "sql_injection" for f in findings)

    async def test_sanitized_file_access_not_flagged(self, tmp_path):
        f = tmp_path / "safe_fs.js"
        f.write_text(
            'const fs = require("fs")\n'
            'const path = require("path")\n'
            'app.get("/api/files", (req, res) => fs.readFile(path.join(BASE_DIR, req.query.file), "utf8", () => {}))\n',
            encoding="utf-8",
        )
        findings = await InjectionScanner().scan(build_manifest(tmp_path))
        assert all(f.category != "path_traversal" for f in findings)


class TestNodeSecretsAndEngine:
    async def test_hardcoded_jwt_secret_detected(self, tmp_path):
        f = tmp_path / ".env.local"
        f.write_text('JWT_SECRET="supersecretvalue"\n', encoding="utf-8")
        findings = await SecretsScanner().scan(build_manifest(tmp_path))
        assert any(f.category in {"hardcoded_secret", "committed_env_file"} for f in findings)

    async def test_clean_node_repository_scans_clean(self, tmp_path):
        (tmp_path / "package.json").write_text(
            '{\n  "dependencies": {\n    "express": "^4.0.0"\n  }\n}\n',
            encoding="utf-8",
        )
        (tmp_path / "server.js").write_text(
            'const express = require("express")\n'
            'const app = express()\n'
            'app.get("/health", (req, res) => res.json({ ok: true }))\n',
            encoding="utf-8",
        )

        from vibesafe.scanner.engine import VibeSafeEngine

        result = await VibeSafeEngine(use_llm=False)._run_scan(tmp_path)
        assert result["risk_score"] == 0
        assert result["verdict"] == "CLEAN"
        assert "node" in result["frameworks"]


class TestNodePrecision:
    async def test_llm_secret_noise_is_suppressed_without_real_llm_context(self, tmp_path):
        f = tmp_path / "tokenizer.js"
        f.write_text(
            'const invalidPasswordErrorMessage = "Invalid password";\n'
            'const tokenizer_messages = [];\n'
            'const prompt_token_ids = [];\n',
            encoding="utf-8",
        )
        findings = await AISecurityScanner().scan(build_manifest(tmp_path))
        assert all(f.category != "llm_secret_exposure" for f in findings)

    async def test_proven_eval_injection_is_confirmed(self, tmp_path):
        f = tmp_path / "nodegoat.js"
        f.write_text(
            'app.post("/api/admin/run", (req, res) => {\n'
            '  return eval(req.body.code)\n'
            '})\n',
            encoding="utf-8",
        )
        manifest = build_manifest(tmp_path)
        finding = Finding(
            category="unsafe_dynamic_code",
            severity="high",
            file_path="nodegoat.js",
            line_number=2,
            evidence="return eval(req.body.code)",
            description="Unsafe eval usage.",
        )
        built = EvidenceBuilder(
            manifest,
            repo_context=RepoContext(kind="application", external_exposure_proven=True),
        ).build([finding])[0]

        assert built.status == "confirmed"
        assert built.proof.exploitability_proven is True
