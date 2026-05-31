"""
GroqAnalyser — uses Qwen3 32B via Groq to confirm/demote findings,
estimate CVSS, generate attack scenarios, and surface extra LOW findings.
"""
from __future__ import annotations

import asyncio
import json
import logging

from groq import AsyncGroq

from vibesafe.api.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

SYSTEM = """
You are a senior application security engineer performing code review.

Your job is to validate static-analysis findings, estimate exploitability,
and identify additional low-severity security issues.

For each finding determine:

1. confirmed: boolean
   - true if the finding is likely a real vulnerability
   - false only if there is strong evidence it is a false positive

2. cvss: float
   - CVSS 3.1 base score between 0.0 and 10.0
   - Use realistic industry-standard scoring

3. attack_scenario: string
   - Explain exactly how an attacker would exploit the issue
   - Include attack steps
   - Include likely impact
   - Mention what data, systems, or users are affected
   - Be specific to the provided code

4. extra_low_findings: array
   - Additional LOW severity security issues found in context
   - Only include findings that are supported by evidence
   - Do not invent vulnerabilities

Each extra_low_finding must follow:

{
  "category": string,
  "file_path": string,
  "line_number": integer,
  "evidence": string,
  "description": string
}

Security Analysis Rules:

- Prefer true positives over false negatives.
- Be conservative when dismissing findings.
- Consider exploitability, impact, and exposure.
- Low-severity findings matter because they can participate in exploit chains.
- Use OWASP Top 10 and common application security practices.
- Do not recommend disabling security controls.
- Do not generate remediation code.
- Focus only on analysis and validation.

Output Rules:

- Return STRICT valid JSON.
- Return ONLY JSON.
- Do not wrap JSON in markdown.
- Do not use code fences.
- Do not include explanations outside JSON.
- Do not include commentary.
- Do not include introductory text.
- Do not include trailing text.

Expected format:

{
  "finding_id": {
    "confirmed": true,
    "cvss": 9.1,
    "attack_scenario": "An attacker can...",
    "extra_low_findings": []
  }
}
"""

class GroqAnalyser:
    def __init__(self) -> None:
        self.client = AsyncGroq(
            api_key=settings.groq_api_key
        )

    async def analyse(self, findings: list[dict], manifest) -> dict:
        """
        Analyse a list of finding dicts (from Finding.to_dict()).
        Returns a dict keyed by finding id with enrichment data.
        """
        if not findings:
            return {}

        results: dict = {}

        batches = [
            findings[i : i + 5]
            for i in range(0, len(findings), 5)
        ]

        tasks = [
            self._analyse_batch(batch, manifest)
            for batch in batches
        ]

        batch_results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        for r in batch_results:
            if isinstance(r, dict):
                results.update(r)
            elif isinstance(r, Exception):
                logger.warning(
                    "Groq batch failed: %s",
                    r,
                )

        return results

    async def _analyse_batch(
        self,
        batch: list[dict],
        manifest,
    ) -> dict:

        prompt_parts = [
            "Analyse findings and return JSON per finding_id:"
        ]

        for f in batch:
            ctx = self._get_context(
                manifest,
                f["file_path"],
                f["line_number"],
            )

            prompt_parts.append(
                f"\n---\n"
                f"ID:{f['id']}\n"
                f"Category:{f['category']}\n"
                f"Evidence:{f['evidence'][:200]}\n"
                f"Context:\n{ctx}"
            )

        try:
            response = await self.client.chat.completions.create(
                model="qwen/qwen3-32b",
                temperature=0.1,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": SYSTEM,
                    },
                    {
                        "role": "user",
                        "content": "\n".join(prompt_parts),
                    },
                ],
            )

            raw = response.choices[0].message.content.strip()

            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]

            return json.loads(raw)

        except Exception as exc:
            logger.warning(
                "Groq _analyse_batch error: %s",
                exc,
            )
            return {}

    def _get_context(
        self,
        manifest,
        file_path: str,
        line_num: int,
        window: int = 10,
    ) -> str:
        """Return ±window lines around line_num from the given file."""

        try:
            fpath = manifest.root / file_path

            fpath = fpath.resolve()

            if not str(fpath).startswith(
                str(manifest.root.resolve())
            ):
                return ""

            lines = (
                fpath.read_text(errors="replace")
                .splitlines()
            )

            start = max(
                0,
                line_num - window - 1,
            )

            end = min(
                len(lines),
                line_num + window,
            )

            return "\n".join(
                f"{i + start + 1}: {lines[i + start]}"
                for i in range(end - start)
            )

        except OSError:
            return ""