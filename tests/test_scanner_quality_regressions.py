import asyncio
import pytest

import shutil
import tempfile
from pathlib import Path
from vibesafe.scanner.evidence import EvidenceBuilder
from vibesafe.scanner.findings import Finding, Proof, calculate_risk_score, dedupe_findings
from vibesafe.scanner.ingest import IngestError, _enumerate_files, build_manifest
from vibesafe.scanner.static.ai_security import AISecurityScanner
from vibesafe.scanner.static.auth import AuthScanner
from vibesafe.scanner.static.base import BaseScanner
from vibesafe.scanner.static.ratelimit import RateLimitScanner
from vibesafe.scanner.static.secrets import SecretsScanner

class _ScannerProbe(BaseScanner):
    async def scan(self, manifest):
        return []


def _temp_repo():
    base = Path.cwd() / ".tmp-tests"
    base.mkdir(exist_ok=True)
    return tempfile.mkdtemp(prefix="vibesafe_quality_", dir=str(base))


def test_dedupe_findings_merges_duplicates_with_strongest_signal():
    first = Finding(
        category="missing_auth",
        severity="medium",
        status="candidate",
        confidence=0.41,
        file_path="app/routes.py",
        line_number=12,
        evidence="  @app.get('/admin/users')  ",
        recommendation="Add auth",
        confirmed_by=["rule-a"],
    )
    second = Finding(
        category="missing_auth",
        severity="critical",
        status="needs_review",
        confidence=0.73,
        file_path="app/routes.py",
        line_number=12,
        evidence="@app.get('/admin/users')",
        fix="Protect route",
        confirmed_by=["rule-b"],
    )
    third = Finding(
        category="missing_auth",
        severity="high",
        status="confirmed",
        confidence=0.62,
        file_path="app/routes.py",
        line_number=12,
        evidence="@app.get('/admin/users')",
        fix_code="patch",
    )

    merged = dedupe_findings([first, second, third])

    assert len(merged) == 1
    finding = merged[0]
    assert finding.severity == "critical"
    assert finding.confidence == 0.73
    assert finding.status == "confirmed"
    assert finding.confirmed_by == ["rule-a", "rule-b"]
    assert finding.recommendation == "Add auth"
    assert finding.fix == "Protect route"
    assert finding.fix_code == "patch"


def test_source_only_budget_ignores_baggage_and_generated_assets():
    root = Path(_temp_repo())
    try:
        small_budget = 1024
        large_ignored_size = small_budget * 8
        (root / "src").mkdir()
        (root / "node_modules").mkdir()
        (root / "generated").mkdir()
        (root / "vendor").mkdir()
        (root / "dist").mkdir()

        (root / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "node_modules" / "bundle.js").write_bytes(b"x" * large_ignored_size)
        (root / "generated" / "types.d.ts").write_text("declare const x: string;\n", encoding="utf-8")
        (root / "vendor" / "vendored.py").write_text("PASSWORD='unsafe'\n", encoding="utf-8")
        (root / "dist" / "app.min.js").write_text("var x=1;\n", encoding="utf-8")

        files, stats = _enumerate_files(root, max_source_size_bytes=small_budget)
        rels = {str(path.relative_to(root)).replace("\\", "/") for path in files}

        assert rels == {"src/main.py"}
        assert stats.scanned_source_bytes < small_budget
        assert stats.ignored_size_bytes >= large_ignored_size
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_source_only_budget_rejects_with_clear_filtered_source_error():
    root = Path(_temp_repo())
    try:
        (root / "src").mkdir()
        (root / "src" / "too_big.py").write_bytes(b"x" * 2048)

        with pytest.raises(IngestError, match="Repository source code exceeds scanning limit."):
            _enumerate_files(root, max_source_size_bytes=1024)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_config_only_env_does_not_trigger_critical_secret_findings():
    root = Path(_temp_repo())
    try:
        (root / ".env").write_text(
            "API_HOST=http://localhost:3000\n"
            "API_PORT=8080\n"
            "DEBUG=true\n"
            "FEATURE_LOGIN_V2=false\n",
            encoding="utf-8",
        )
        (root / ".env.production").write_text(
            "JWT_SECRET=supersecretvalue\n"
            "API_HOST=https://api.example.com\n",
            encoding="utf-8",
        )

        findings = asyncio.run(SecretsScanner().scan(build_manifest(root)))
        by_category = [(f.category, f.file_path, f.severity) for f in findings]

        assert ("committed_env_file", ".env", "critical") not in by_category
        assert ("committed_env_file", ".env.production", "critical") in by_category
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_generated_and_vendored_paths_do_not_dominate_scanner_output():
    root = Path(_temp_repo())
    try:
        (root / "src").mkdir()
        (root / "generated").mkdir()
        (root / "vendor").mkdir()
        (root / "build").mkdir()

        (root / "src" / "agent.py").write_text(
            "prompt = request.body\n"
            "response = client.responses.create(input=prompt)\n",
            encoding="utf-8",
        )
        (root / "generated" / "agent.py").write_text(
            "prompt = request.body\n"
            "response = client.responses.create(input=prompt)\n",
            encoding="utf-8",
        )
        (root / "vendor" / "unsafe.ts").write_text("router.post('/login', handler)\n", encoding="utf-8")
        (root / "build" / "types.d.ts").write_text("declare const apiKey: string;\n", encoding="utf-8")

        manifest = build_manifest(root)
        ai_findings = asyncio.run(AISecurityScanner().scan(manifest))

        assert all("generated" not in finding.file_path.lower() for finding in ai_findings)
        assert all("vendor" not in finding.file_path.lower() for finding in ai_findings)

        probe = _ScannerProbe()
        assert probe._should_skip_path("types/generated/schema.ts") is True
        assert probe._should_skip_path("vendor/lib/index.ts") is True
        assert probe._should_skip_path("types/generated/schema.ts", allow_generated=True) is False
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_auth_and_rate_limit_uncertainty_stays_needs_review_with_project_level_coverage():
    root = Path(_temp_repo())
    try:
        (root / "middleware.py").write_text(
            "@app.middleware('http')\n"
            "async def auth_middleware(request, call_next):\n"
            "    return await call_next(request)\n",
            encoding="utf-8",
        )
        (root / "rate_limit.js").write_text(
            "app.use(rateLimit({ windowMs: 60000, max: 5 }))\n",
            encoding="utf-8",
        )
        (root / "routes.py").write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/admin/users')\n"
            "async def users():\n"
            "    return []\n",
            encoding="utf-8",
        )
        (root / "routes.js").write_text("router.post('/login', handler)\n", encoding="utf-8")

        manifest = build_manifest(root)
        auth_findings = asyncio.run(AuthScanner().scan(manifest))
        rate_findings = asyncio.run(RateLimitScanner().scan(manifest))

        assert len(auth_findings) == 1
        assert auth_findings[0].status == "needs_review"
        assert auth_findings[0].false_positive_risk == "high"
        assert auth_findings[0].status != "confirmed"

        assert len(rate_findings) == 1
        assert rate_findings[0].status == "needs_review"
        assert rate_findings[0].status != "confirmed"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_auth_missing_without_coverage_is_not_confirmed_by_evidence_builder():
    root = Path(_temp_repo())
    try:
        file_path = root / "public_api.py"
        file_path.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.delete('/api/admin/users/{id}')\n"
            "async def delete_user(user_id: int):\n"
            "    return {'deleted': user_id}\n",
            encoding="utf-8",
        )

        manifest = build_manifest(root)
        findings = asyncio.run(AuthScanner().scan(manifest))
        built = EvidenceBuilder(manifest).build(findings)

        assert len(built) == 1
        assert built[0].status == "candidate"
        assert built[0].status != "confirmed"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_ai_findings_without_exploitability_are_damped_in_status_and_score():
    root = Path(_temp_repo())
    try:
        (root / "agent.py").write_text(
            "prompt = request.body\n"
            "response = client.responses.create(input=prompt)\n",
            encoding="utf-8",
        )

        manifest = build_manifest(root)
        scanner_findings = asyncio.run(AISecurityScanner().scan(manifest))
        built = EvidenceBuilder(manifest).build(scanner_findings)

        assert built
        assert all(finding.status == "needs_review" for finding in built)
        assert all(finding.confidence <= 0.55 for finding in built)
        assert all(finding.proof.exploitability_proven is False for finding in built)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    ai_candidate = Finding(
        category="prompt_injection",
        severity="high",
        status="candidate",
        file_path="agent.py",
        line_number=1,
        evidence="prompt = request.body",
        proof=Proof(exploitability_proven=False),
    )
    ai_review = Finding(
        category="prompt_injection",
        severity="high",
        status="needs_review",
        file_path="agent.py",
        line_number=2,
        evidence="response = client.responses.create(input=prompt)",
        proof=Proof(exploitability_proven=False),
    )
    confirmed = Finding(
        category="sql_injection",
        severity="high",
        status="confirmed",
        file_path="db.py",
        line_number=3,
        evidence="cursor.execute(query)",
        proof=Proof(exploitability_proven=True),
    )

    assert calculate_risk_score([ai_candidate]) < calculate_risk_score([ai_review])
    assert calculate_risk_score([ai_review]) < calculate_risk_score([confirmed])
