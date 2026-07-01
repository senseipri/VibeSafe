"""
GroqAnalyser - evidence-gated Qwen verifier for static findings.
"""
from __future__ import annotations

import asyncio
import json
import logging

from groq import AsyncGroq

from vibesafe.api.config import get_settings
from vibesafe.scanner.findings import Finding

logger = logging.getLogger(__name__)
settings = get_settings()

SYSTEM = """
You are a security finding verifier.

You must reason only from the supplied evidence bundle.
Never infer attacker control, data flow, sanitization absence, exploitability,
secrets, or impact unless they are explicitly proven in the provided evidence.

Rules:
- If a required proof element is missing, return "rejected" or "needs_review".
- Do not discover new findings.
- Do not output remediation.
- Do not output CVSS.
- Generate attack_scenario only when exploitability_proven is true.
- Use the quoted evidence exactly as given.

Return strict JSON only in this format:
{
  "finding-id": {
    "verdict": "confirmed|rejected|needs_review",
    "confidence": 0.0,
    "proof": {
      "source_present": true,
      "sink_present": true,
      "path_present": true,
      "sanitizer_present": false,
      "attacker_controlled": true,
      "exploitability_proven": true
    },
    "attack_scenario": "optional string or empty",
    "rationale": "one sentence grounded in supplied evidence"
  }
}
"""


class GroqAnalyser:
    def __init__(self) -> None:
        self.client = AsyncGroq(api_key=settings.groq_api_key)
        self.model = "qwen/qwen3-32b"

    async def analyse(self, findings: list[dict], manifest=None) -> dict:
        if not findings:
            return {}

        results: dict = {}
        batches = [findings[i : i + 6] for i in range(0, len(findings), 6)]
        batch_results = await asyncio.gather(
            *[self._analyse_batch(batch) for batch in batches],
            return_exceptions=True,
        )

        for result in batch_results:
            if isinstance(result, dict):
                results.update(result)
            elif isinstance(result, Exception):
                logger.warning("Groq verification batch failed: %s", result)
        return results

    async def _analyse_batch(self, batch: list[dict]) -> dict:
        payload = {"findings": [self._finding_payload(finding) for finding in batch]}

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=0.0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=True)},
                ],
            )
            content = response.choices[0].message.content or "{}"
            return json.loads(content)
        except Exception as exc:
            logger.warning("Groq _analyse_batch error: %s", exc)
            return {}

    def _finding_payload(self, finding: dict) -> dict:
        return {
            "id": finding["id"],
            "category": finding["category"],
            "severity": finding["severity"],
            "description": finding.get("description", ""),
            "file_path": finding["file_path"],
            "line_number": finding["line_number"],
            "confidence_hint": finding.get("confidence", 0.0),
            "evidence_refs": finding.get("evidence_refs", []),
            "proof": finding.get("proof", {}),
            "required_elements": self._required_elements(finding["category"]),
        }

    def _required_elements(self, category: str) -> list[str]:
        if category in {"sql_injection", "command_injection", "log_injection"}:
            return ["source_present", "sink_present", "path_present"]
        if category in {"hardcoded_secret", "weak_jwt", "slopsquatting", "committed_env_file"}:
            return ["quoted_evidence"]
        return ["quoted_evidence", "source_line"]
