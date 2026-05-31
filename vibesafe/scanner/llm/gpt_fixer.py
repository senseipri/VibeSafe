"""
GPTFixer — uses GPT-4o to generate drop-in code fixes for each finding,
provide plain-English explanations, and estimate CVSS scores.
"""
from __future__ import annotations

import asyncio
import json
import logging

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

SYSTEM = """You are a security engineer generating exact code fixes.
For each finding, generate:
1. fix_code: str — corrected code in SAME language/framework/style as original. Drop-in replacement.
2. plain_explanation: str — 1 sentence explaining the fix for a non-technical founder
3. cvss: float — CVSS 3.1 base score estimate

Return ONLY JSON: {finding_id: {fix_code, plain_explanation, cvss}}"""
from vibesafe.api.config import get_settings

settings = get_settings()



class GPTFixer:
    def __init__(self) -> None:
        self.client = AsyncOpenAI(api_key=settings.openai_api_key)

    async def generate_fixes(self, findings: list[dict]) -> dict:
        """
        Generate fix code for a list of finding dicts (from Finding.to_dict()).
        Returns a dict keyed by finding id.
        """
        if not findings:
            return {}

        batches = [findings[i : i + 8] for i in range(0, len(findings), 8)]
        tasks = [self._fix_batch(b) for b in batches]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged: dict = {}
        for r in results:
            if isinstance(r, dict):
                merged.update(r)
            elif isinstance(r, Exception):
                logger.warning("GPT batch failed: %s", r)
        return merged

    async def _fix_batch(self, batch: list[dict]) -> dict:
        prompt_parts = ["Generate fixes. Return JSON per finding_id:"]
        for f in batch:
            prompt_parts.append(
                f"\nID:{f['id']} Category:{f['category']} "
                f"File:{f['file_path']}:{f['line_number']}\n"
                f"Evidence: {f['evidence'][:300]}"
            )
        try:
            r = await self.client.chat.completions.create(
                model="gpt-4o",
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": "\n".join(prompt_parts)},
                ],
                max_tokens=3000,
            )
            return json.loads(r.choices[0].message.content)
        except Exception as exc:
            logger.warning("GPT _fix_batch error: %s", exc)
            return {}
