from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from vibesafe.scanner.findings import Finding, calculate_risk_score, get_verdict, sort_findings
from vibesafe.scanner.ingest import (
    IngestError,
    RepoManifest,
    build_manifest,
    cleanup,
    clone_github_repo,
    detect_framework,
    extract_zip,
)
from vibesafe.scanner.static.auth import AuthScanner
from vibesafe.scanner.static.cors import CORSScanner
from vibesafe.scanner.static.database import DBConfigScanner
from vibesafe.scanner.static.injection import InjectionScanner
from vibesafe.scanner.static.ratelimit import RateLimitScanner
from vibesafe.scanner.static.secrets import SecretsScanner

logger = logging.getLogger(__name__)


class ScanError(Exception):
    pass


class VibeSafeEngine:
    """
    Orchestrates the full scan pipeline:
    1. Ingest repo (clone / extract zip)
    2. Run all static scanners concurrently (no LLM cost)
    3. Run all 3 LLM enrichment calls concurrently (Day 2)
    4. Merge, score, return report dict
    """

    def __init__(self, use_llm: bool = True) -> None:
        self.use_llm = use_llm

    # ── Public entry points ─────────────────────────────────────

    async def scan_url(self, repo_url: str, github_token: str = "") -> dict:
        tmpdir = None
        try:
            tmpdir, repo_path = clone_github_repo(repo_url, github_token)
            return await self._run_scan(repo_path, source_url=repo_url)
        except IngestError as exc:
            raise ScanError(str(exc)) from exc
        finally:
            if tmpdir:
                cleanup(tmpdir)

    async def scan_zip(self, zip_path: Path) -> dict:
        tmpdir = None
        try:
            tmpdir, repo_path = extract_zip(zip_path)
            return await self._run_scan(repo_path)
        except IngestError as exc:
            raise ScanError(str(exc)) from exc
        finally:
            if tmpdir:
                cleanup(tmpdir)

    # ── Core pipeline ────────────────────────────────────────────

    async def _run_scan(self, repo_path: Path, source_url: str = "") -> dict:
        t0 = time.monotonic()

        manifest = build_manifest(repo_path)
        frameworks = detect_framework(manifest)

        logger.info(
            "Starting scan | files=%d frameworks=%s",
            len(manifest),
            frameworks,
        )

        # ── Phase 1: static scanners (all concurrent, zero LLM cost) ──
        static_results = await asyncio.gather(
            SecretsScanner().scan(manifest),
            AuthScanner().scan(manifest),
            InjectionScanner().scan(manifest),
            CORSScanner().scan(manifest),
            DBConfigScanner().scan(manifest),
            RateLimitScanner().scan(manifest),
            return_exceptions=True,
        )

        findings: list[Finding] = []
        for result in static_results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.warning("Scanner raised exception: %s", result, exc_info=result)

        logger.info("Static scan complete | findings=%d", len(findings))

        models_used: list[str] = []

        # ── Phase 2: LLM enrichment (Day 2 — skipped if use_llm=False) ──
        if self.use_llm and findings:
            findings, models_used = await self._llm_enrich(findings, manifest)

        # ── Phase 3: finalise ──────────────────────────────────────────
        sorted_findings = sort_findings(findings)
        risk_score = calculate_risk_score(sorted_findings)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        logger.info(
            "Scan complete | risk=%d verdict=%s ms=%d",
            risk_score,
            get_verdict(risk_score),
            elapsed_ms,
        )

        return {
            "findings": [f.to_dict() for f in sorted_findings],
            "risk_score": risk_score,
            "verdict": get_verdict(risk_score),
            "files_scanned": len(manifest),
            "frameworks": frameworks,
            "scan_ms": elapsed_ms,
            "models_used": models_used,
        }

    # ── LLM enrichment ───────────────────────────────────────────

    async def _llm_enrich(
        self, findings: list[Finding], manifest: RepoManifest
    ) -> tuple[list[Finding], list[str]]:
        """
        Run Claude, GPT-4o, and Gemini concurrently.
        Each is fully optional — failures degrade gracefully.
        Returns enriched findings + list of models that responded.
        """
        from vibesafe.scanner.llm.groq_analyser import GroqAnalyser
        from vibesafe.scanner.llm.gemini_auditor import GeminiPackageAuditor
        from vibesafe.scanner.llm.gpt_fixer import GPTFixer

        findings_dicts = [f.to_dict() for f in findings]
        packages = GeminiPackageAuditor.extract_packages(manifest)

        claude_r, gpt_r, gemini_findings = await asyncio.gather(
            GroqAnalyser().analyse(findings_dicts, manifest),
            GPTFixer().generate_fixes(findings_dicts),
            GeminiPackageAuditor().audit_packages(packages),
            return_exceptions=True,
        )

        models_used: list[str] = []

        # Apply Claude results
        if isinstance(claude_r, dict) and claude_r:
            models_used.append("claude-sonnet-4-6")
            sev_order = ["low", "medium", "high", "critical"]

            for finding in findings:
                cr = claude_r.get(finding.id, {})
                if not cr:
                    continue

                if cr.get("confirmed") is False:
                    # Demote severity one step — still shown, never dropped
                    idx = sev_order.index(finding.severity)
                    finding.severity = sev_order[max(0, idx - 1)]
                    finding.false_positive_risk = "high"
                else:
                    if "claude" not in finding.confirmed_by:
                        finding.confirmed_by.append("claude")

                if cr.get("cvss"):
                    finding.cvss_score = float(cr["cvss"])

                if cr.get("attack_scenario"):
                    finding.attack_chain = str(cr["attack_scenario"])

                # Extra LOW findings Claude spotted in context
                for extra in cr.get("extra_low_findings", []):
                    try:
                        extra_finding = Finding(
                            category=extra.get("category", "misc"),
                            severity="low",
                            file_path=extra.get("file_path", ""),
                            line_number=int(extra.get("line_number", 0)),
                            evidence=str(extra.get("evidence", ""))[:200],
                            description=str(extra.get("description", "")),
                            confirmed_by=["claude"],
                        )
                        findings.append(extra_finding)
                    except Exception as e:
                        logger.debug("Could not parse extra finding from Claude: %s", e)

        elif isinstance(claude_r, Exception):
            logger.warning("Claude analyser failed: %s", claude_r)

        # Apply GPT-4o fix code
        if isinstance(gpt_r, dict) and gpt_r:
            models_used.append("gpt-4o")
            for finding in findings:
                gr = gpt_r.get(finding.id, {})
                if not gr:
                    continue
                if gr.get("fix_code"):
                    finding.fix_code = str(gr["fix_code"])
                if "gpt4o" not in finding.confirmed_by:
                    finding.confirmed_by.append("gpt4o")
                # Use GPT's CVSS if Claude didn't provide one
                if not finding.cvss_score and gr.get("cvss"):
                    finding.cvss_score = float(gr["cvss"])

        elif isinstance(gpt_r, Exception):
            logger.warning("GPT fixer failed: %s", gpt_r)

        # Add Gemini package findings
        if isinstance(gemini_findings, list) and gemini_findings:
            models_used.append("gemini-1.5-flash")
            findings.extend(gemini_findings)
        elif isinstance(gemini_findings, Exception):
            logger.warning("Gemini auditor failed: %s", gemini_findings)

        return findings, models_used