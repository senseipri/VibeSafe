import pytest

from vibesafe.scanner.evidence import EvidenceBuilder
from vibesafe.scanner.findings import Finding
from vibesafe.scanner.repo_context import RepoContext

pytestmark = pytest.mark.anyio


class TestEvidenceBuilder:
    async def test_rejects_prompt_like_secret_literal(self, tmp_path):
        file_path = tmp_path / "prompts.py"
        file_path.write_text('SYSTEM_PROMPT = "If user says $19.99, return NULL"\n')

        from vibesafe.scanner.ingest import build_manifest

        manifest = build_manifest(tmp_path)
        finding = Finding(
            category="weak_jwt",
            severity="high",
            file_path="prompts.py",
            line_number=1,
            evidence='SYSTEM_PROMPT = "If user says $19.99, return NULL"',
            description="Possible weak JWT secret.",
        )

        built = EvidenceBuilder(manifest).build([finding])[0]
        assert built.status == "rejected"
        assert any("prompt" in note.lower() or "currency" in note.lower() for note in built.proof.notes)

    async def test_rejects_log_finding_without_attacker_control(self, tmp_path):
        file_path = tmp_path / "app.py"
        file_path.write_text('logger.info(f"Created record: {record_id}")\n')

        from vibesafe.scanner.ingest import build_manifest

        manifest = build_manifest(tmp_path)
        finding = Finding(
            category="log_injection",
            severity="high",
            file_path="app.py",
            line_number=1,
            evidence='logger.info(f"Created record: {record_id}")',
            description="Possible log injection.",
        )

        built = EvidenceBuilder(manifest).build([finding])[0]
        assert built.status == "rejected"
        assert any("attacker-controlled" in note.lower() for note in built.proof.notes)

    async def test_python_internal_service_route_stays_needs_review_without_exposure_proof(self, tmp_path):
        file_path = tmp_path / "internal_api.py"
        file_path.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.post('/api/admin/users')\n"
            "async def create_user(payload: dict):\n"
            "    return payload\n"
        )

        from vibesafe.scanner.ingest import build_manifest

        manifest = build_manifest(tmp_path)
        finding = Finding(
            category="missing_auth",
            severity="critical",
            file_path="internal_api.py",
            line_number=3,
            evidence="@app.post('/api/admin/users')",
            description="Sensitive route has no auth.",
        )

        context = RepoContext(kind="internal_service", external_exposure_proven=False)
        built = EvidenceBuilder(manifest, repo_context=context).build([finding])[0]

        assert built.status == "needs_review"
        assert any("exposure not clearly proven" in note.lower() for note in built.proof.notes)

    async def test_python_public_sensitive_route_can_stay_candidate(self, tmp_path):
        file_path = tmp_path / "public_api.py"
        file_path.write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.delete('/api/admin/users/{id}')\n"
            "async def delete_user(user_id: int):\n"
            "    return {'deleted': user_id}\n"
        )

        from vibesafe.scanner.ingest import build_manifest

        manifest = build_manifest(tmp_path)
        finding = Finding(
            category="missing_auth",
            severity="critical",
            file_path="public_api.py",
            line_number=3,
            evidence="@app.delete('/api/admin/users/{id}')",
            description="Sensitive route has no auth.",
        )

        context = RepoContext(kind="application", external_exposure_proven=True)
        built = EvidenceBuilder(manifest, repo_context=context).build([finding])[0]

        assert built.status == "candidate"
        assert built.proof.source_present is True
        assert built.proof.path_present is True
