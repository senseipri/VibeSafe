"""
Fix generator - Kimi K2 for confirmed findings only.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from openai import AsyncOpenAI

from vibesafe.api.config import get_settings
from vibesafe.scanner.evidence import get_context

logger = logging.getLogger(__name__)
settings = get_settings()

SYSTEM = """
You are a secure code repair engine.

You receive only confirmed findings with quoted proof.
Produce the smallest safe patch that removes the proven vulnerability without
changing unrelated behavior.

Rules:
- Return unified diffs only.
- Do not output CVSS.
- Do not claim a fix if the proof is insufficient.
- If the proof is insufficient, return status="cannot_fix" but still provide
  a recommendation and explanation so developers have actionable guidance.
- recommendation: one imperative sentence (≤80 chars) summarising the action.
- explanation: 2-4 sentences of human-readable remediation guidance.

Return strict JSON only:
{
  "finding-id": {
    "status": "patch_ready|cannot_fix",
    "confidence": 0.0,
    "patch": "unified diff text or empty string",
    "recommendation": "one-line imperative action",
    "explanation": "2-4 sentence remediation prose"
  }
}
"""


class GPTFixer:
    def __init__(self) -> None:
        groq_api_key = getattr(settings, "groq_api_key", None) or os.getenv("GROQ_API_KEY")
        if not groq_api_key:
            raise RuntimeError("GROQ_API_KEY not configured")

        self.client = AsyncOpenAI(
            api_key=groq_api_key,
            base_url="https://api.groq.com/openai/v1",
        )
        self.model = "moonshotai/kimi-k2-instruct"

    async def generate_fixes(self, findings: list[dict], manifest) -> dict[str, Any]:
        confirmed = [finding for finding in findings if finding.get("status") == "confirmed"]
        if not confirmed:
            return {}

        batches = [confirmed[i : i + 4] for i in range(0, len(confirmed), 4)]
        results = await asyncio.gather(
            *[self._fix_batch(batch, manifest) for batch in batches],
            return_exceptions=True,
        )

        merged: dict[str, Any] = {}
        for result in results:
            if isinstance(result, Exception):
                logger.exception("Fix generation batch failed", exc_info=result)
                continue
            if isinstance(result, dict):
                merged.update(result)
        return merged

    async def _fix_batch(self, batch: list[dict], manifest) -> dict[str, Any]:
        payload = {"findings": [self._build_fix_input(finding, manifest) for finding in batch]}

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=True)},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
                max_tokens=3000,
            )

            content = response.choices[0].message.content
            if not content:
                logger.warning("Kimi returned empty response")
                return {}
            parsed = json.loads(content)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            logger.exception("Kimi _fix_batch failed")
            return {}

    def _build_fix_input(self, finding: dict, manifest) -> dict:
        return {
            "id": finding["id"],
            "category": finding["category"],
            "file_path": finding["file_path"],
            "line_number": finding["line_number"],
            "severity": finding["severity"],
            "evidence_refs": finding.get("evidence_refs", []),
            "proof": finding.get("proof", {}),
            "context": [
                {"line_number": line_number, "code": code}
                for line_number, code in get_context(manifest, finding["file_path"], finding["line_number"], window=8)
            ],
            "description": finding.get("description", ""),
        }
