from __future__ import annotations

import pytest

from vibesafe.scanner.findings import Finding, calculate_risk_score
from vibesafe.scanner.ingest import build_manifest
from vibesafe.scanner.repo_context import apply_repo_context, classify_repo

pytestmark = pytest.mark.anyio


def _finding(category: str, *, status: str = "confirmed", severity: str = "critical") -> Finding:
    return Finding(
        category=category,
        rule_id=category,
        status=status,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        confidence=0.91,
        file_path="app.py",
        line_number=12,
        evidence=f"{category} evidence",
        description=f"{category} description",
    )


class TestRepoContextClassification:
    async def test_internal_service_repo_downgrades_confirmed_auth_and_rate_limit(self, tmp_path):
        service_dir = tmp_path / "internal" / "worker"
        service_dir.mkdir(parents=True)
        (tmp_path / "pyproject.toml").write_text("[project]\nname='svc'\ndependencies=['fastapi']\n", encoding="utf-8")
        (service_dir / "app.py").write_text(
            "SERVICE_HOST = '127.0.0.1'\n"
            "@app.post('/api/admin/users')\n"
            "async def create_user(payload: dict):\n"
            "    return payload\n",
            encoding="utf-8",
        )
        manifest = build_manifest(tmp_path)
        context = classify_repo(manifest, ["python", "fastapi"])

        findings = apply_repo_context(
            [_finding("missing_auth"), _finding("missing_rate_limit", severity="high")],
            context,
        )

        assert context.kind == "internal_service"
        assert all(f.status == "needs_review" for f in findings)
        assert all(f.severity == "medium" for f in findings)
        assert all(any("external exposure not proven" in note for note in f.proof.notes) for f in findings)

    async def test_library_repo_does_not_keep_confirmed_missing_auth_by_default(self, tmp_path):
        src_dir = tmp_path / "src" / "sdk"
        src_dir.mkdir(parents=True)
        (tmp_path / "package.json").write_text(
            '{\n  "name": "@acme/sdk",\n  "exports": {".": "./src/index.js"}\n}\n',
            encoding="utf-8",
        )
        (src_dir / "index.js").write_text(
            "export function requestClient() { return 'ok'; }\n",
            encoding="utf-8",
        )
        manifest = build_manifest(tmp_path)
        context = classify_repo(manifest, ["node"])

        finding = _finding("missing_auth")
        adjusted = apply_repo_context([finding], context)

        assert context.kind == "library"
        assert adjusted[0].status == "needs_review"
        assert adjusted[0].severity == "medium"
        assert any("public API exposure and sensitive action path" in note for note in adjusted[0].proof.notes)

    async def test_framework_repo_without_sensitive_public_surface_downgrades_candidate(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='framework'\ndependencies=['fastapi']\n", encoding="utf-8")
        (tmp_path / "plugin.py").write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "def install_middleware(app):\n"
            "    return app\n",
            encoding="utf-8",
        )
        manifest = build_manifest(tmp_path)
        context = classify_repo(manifest, ["python", "fastapi"])

        finding = _finding("missing_auth", status="candidate")
        adjusted = apply_repo_context([finding], context)

        assert context.kind == "framework"
        assert adjusted[0].status == "needs_review"

    async def test_framework_and_library_projects_are_classified_correctly(self, tmp_path):
        (tmp_path / "package.json").write_text(
            '{\n  "dependencies": {\n    "express": "^4.0.0"\n  }\n}\n',
            encoding="utf-8",
        )
        (tmp_path / "routes.js").write_text("app.get('/health', () => {})\n", encoding="utf-8")
        express_context = classify_repo(build_manifest(tmp_path), ["node", "express"])
        assert express_context.kind == "framework"

        celery_dir = tmp_path / "celery_app"
        celery_dir.mkdir(exist_ok=True)
        (tmp_path / "requirements.txt").write_text("fastapi\ncelery\n", encoding="utf-8")
        (celery_dir / "worker.py").write_text("from celery import Celery\n", encoding="utf-8")
        celery_context = classify_repo(build_manifest(tmp_path), ["python", "fastapi", "celery"])
        assert celery_context.kind == "framework"

        rq_dir = tmp_path / "rq_pkg"
        rq_dir.mkdir(exist_ok=True)
        (tmp_path / "requirements.txt").write_text("rq\nsqlmodel\n", encoding="utf-8")
        (rq_dir / "__init__.py").write_text("from rq import Queue\n", encoding="utf-8")
        rq_context = classify_repo(build_manifest(tmp_path), ["python", "rq"])
        assert rq_context.kind == "library"

    async def test_application_signals_outweigh_weak_ml_hints(self, tmp_path):
        (tmp_path / "package.json").write_text(
            '{\n  "dependencies": {\n    "express": "^4.0.0"\n  }\n}\n',
            encoding="utf-8",
        )
        (tmp_path / "server.js").write_text(
            "app.post('/login', handler)\n"
            "app.post('/signup', handler)\n"
            "app.get('/account/profile', handler)\n"
            "const tokenizer_messages = []\n",
            encoding="utf-8",
        )
        context = classify_repo(build_manifest(tmp_path), ["node", "express"])
        assert context.kind == "application"


class TestRiskScoreSaturation:
    def test_repeated_categories_use_diminishing_returns(self):
        repeated = [_finding("missing_rate_limit", severity="medium", status="needs_review") for _ in range(8)]
        repeated_score = calculate_risk_score(repeated)
        naive_score = min(100, int(8 * 8 * 0.5))

        assert repeated_score < naive_score
        assert repeated_score > 0

    def test_distinct_categories_still_contribute_strongly(self):
        repeated = [_finding("missing_rate_limit", severity="medium", status="needs_review") for _ in range(4)]
        mixed = [
            _finding("missing_rate_limit", severity="medium", status="needs_review"),
            _finding("missing_auth", severity="medium", status="needs_review"),
            _finding("sql_injection", severity="medium", status="needs_review"),
            _finding("hardcoded_secret", severity="medium", status="needs_review"),
        ]

        assert calculate_risk_score(mixed) > calculate_risk_score(repeated)
