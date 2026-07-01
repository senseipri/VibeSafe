import pytest
from pathlib import Path

pytestmark = pytest.mark.anyio

class TestEngine:
    async def test_full_static_scan(self, fixtures_dir, tmp_path):
        import shutil
        for f in fixtures_dir.iterdir():
            if f.is_file():
                shutil.copy(f, tmp_path / f.name)
        from vibesafe.scanner.engine import VibeSafeEngine
        engine = VibeSafeEngine(use_llm=False)  # disable LLM to avoid real calls
        result = await engine._run_scan(tmp_path)
        assert result["risk_score"] > 50  # fixtures have multiple criticals
        assert len(result["findings"]) >= 5
        assert result["verdict"] in ("HIGH", "CRITICAL")
        assert result["files_scanned"] > 0
        assert result["repo_context"]["kind"] in {
            "application",
            "internal_service",
            "library",
            "framework",
            "ml_platform",
            "agent_platform",
            "unknown",
        }
        for f in result["findings"]:
            assert f["description"], f"Finding {f['id']} has empty description"
            assert f["severity"] in ("critical", "high", "medium", "low")

    async def test_clean_repo_scores_zero(self, tmp_path):
        # Create a file with no vulnerabilities
        safe = tmp_path / "safe.py"
        safe.write_text(
            'import os\nKEY = os.environ.get("SECRET")\n'
            'def hello(): return "world"\n'
        )
        from vibesafe.scanner.engine import VibeSafeEngine
        result = await VibeSafeEngine(use_llm=False)._run_scan(tmp_path)
        assert result["risk_score"] == 0
        assert result["verdict"] == "CLEAN"
        assert result["repo_context"]["kind"] == "unknown"
