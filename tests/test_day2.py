import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vibesafe.scanner.findings import EvidenceRef, Finding, Proof

pytestmark = pytest.mark.anyio

SAMPLE_FINDING = Finding(
    id="test-123",
    category="sql_injection",
    rule_id="sql_injection",
    severity="critical",
    status="candidate",
    confidence=0.82,
    file_path="app.py",
    line_number=10,
    evidence="cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")",
    evidence_refs=[
        EvidenceRef(
            kind="sink",
            file_path="app.py",
            line_start=10,
            line_end=10,
            quote="cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")",
        )
    ],
    proof=Proof(source_present=True, sink_present=True, path_present=True),
    description="SQL injection in login query.",
)


class TestGroqAnalyser:
    async def test_confirms_finding(self, sample_manifest):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    content='{"test-123":{"verdict":"confirmed","confidence":0.97,"proof":{"source_present":true,"sink_present":true,"path_present":true,"sanitizer_present":false,"attacker_controlled":true,"exploitability_proven":true},"attack_scenario":"Confirmed exploitability.","rationale":"quoted source reaches sink"}}'
                )
            )
        ]

        with patch("vibesafe.scanner.llm.groq_analyser.AsyncGroq") as mock_client:
            mock_client.return_value.chat.completions.create = AsyncMock(return_value=mock_response)
            from vibesafe.scanner.llm.groq_analyser import GroqAnalyser

            result = await GroqAnalyser().analyse([SAMPLE_FINDING.to_dict()], sample_manifest)

            assert "test-123" in result
            assert result["test-123"]["verdict"] == "confirmed"
            assert result["test-123"]["proof"]["exploitability_proven"] is True

    async def test_handles_api_error_gracefully(self, sample_manifest):
        with patch("vibesafe.scanner.llm.groq_analyser.AsyncGroq") as mock_client:
            mock_client.return_value.chat.completions.create = AsyncMock(side_effect=Exception("API error"))
            from vibesafe.scanner.llm.groq_analyser import GroqAnalyser

            result = await GroqAnalyser().analyse([SAMPLE_FINDING.to_dict()], sample_manifest)
            assert result == {}


class TestGPTFixer:
    async def test_generates_patch_only_for_confirmed_findings(self, sample_manifest):
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    content='{"test-123":{"status":"patch_ready","confidence":0.93,"patch":"--- a/app.py\\n+++ b/app.py\\n@@\\n-cursor.execute(f\\"SELECT * FROM users WHERE id = \'{user_id}\'\\")\\n+cursor.execute(\\"SELECT * FROM users WHERE id = ?\\", (user_id,))","explanation":"Use parameterized SQL."}}'
                )
            )
        ]

        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}, clear=False):
            with patch("vibesafe.scanner.llm.gpt_fixer.AsyncOpenAI") as mock_client:
                mock_client.return_value.chat.completions.create = AsyncMock(return_value=mock_response)
                from vibesafe.scanner.llm.gpt_fixer import GPTFixer

                confirmed = SAMPLE_FINDING.to_dict()
                confirmed["status"] = "confirmed"
                result = await GPTFixer().generate_fixes([confirmed], sample_manifest)
                assert "test-123" in result
                assert result["test-123"]["status"] == "patch_ready"
                assert "--- a/app.py" in result["test-123"]["patch"]


class TestGeminiAuditor:
    async def test_flags_nonexistent_package(self):
        mock_response = MagicMock()
        mock_response.text = (
            '[{"package":"react-auth-superhelper-lib","registry":"npm","verdict":"not_found",'
            '"confidence":0.98,"reason":"Registry lookup returned not found"}]'
        )
        from vibesafe.scanner.llm import gemini_auditor

        mock_genai = MagicMock()
        mock_genai.GenerativeModel.return_value.generate_content_async = AsyncMock(return_value=mock_response)
        with patch.object(gemini_auditor, "genai", mock_genai):
            from vibesafe.scanner.llm.gemini_auditor import GeminiPackageAuditor

            findings = await GeminiPackageAuditor().audit_packages(
                {
                    "npm": [
                        {
                            "package": "react-auth-superhelper-lib",
                            "registry": "npm",
                            "file_path": "package.json",
                            "line_number": 4,
                            "quote": '"react-auth-superhelper-lib": "^1.0.0"',
                        }
                    ],
                    "pypi": [],
                }
            )

            assert len(findings) == 1
            assert findings[0].category == "slopsquatting"
            assert findings[0].status == "confirmed"
            assert findings[0].line_number == 4

    def test_extract_packages_from_manifest(self, sample_manifest):
        from vibesafe.scanner.llm.gemini_auditor import GeminiPackageAuditor

        packages = GeminiPackageAuditor.extract_packages(sample_manifest)
        assert "npm" in packages
        assert "pypi" in packages
        assert any(pkg["package"] == "react" for pkg in packages["npm"])
        assert any(pkg["package"] == "next" for pkg in packages["npm"])
        assert all(pkg["line_number"] > 0 for pkg in packages["npm"])
