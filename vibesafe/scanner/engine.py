from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from vibesafe.api.config import get_settings
from vibesafe.scanner.analysis import build_code_index
from vibesafe.scanner.evidence import EvidenceBuilder
from vibesafe.scanner.fixes import FixVerifier
from vibesafe.scanner.findings import (
    Finding,
    Proof,
    calculate_risk_score,
    dedupe_findings,
    get_verdict,
    sort_findings,
)
from vibesafe.scanner.ingest import (
    IngestError,
    RepoManifest,
    build_manifest,
    cleanup,
    clone_github_repo,
    detect_framework,
    extract_zip,
)
from vibesafe.scanner.static.ai_security import AISecurityScanner
from vibesafe.scanner.repo_context import apply_repo_context, classify_repo
from vibesafe.scanner.static.auth import AuthScanner
from vibesafe.scanner.static.cors import CORSScanner
from vibesafe.scanner.static.database import DBConfigScanner
from vibesafe.scanner.static.injection import InjectionScanner
from vibesafe.scanner.static.ratelimit import RateLimitScanner
from vibesafe.scanner.static.secrets import SecretsScanner
from vibesafe.scanner.verdicts import apply_final_scoring, contradiction_gate
from vibesafe.scanner.llm.gemini_auditor import GeminiPackageAuditor
from vibesafe.scanner.llm.gpt_fixer import GPTFixer
from vibesafe.scanner.llm.groq_analyser import GroqAnalyser
from vibesafe.scanner.remediation import apply_static_remediation

logger = logging.getLogger(__name__)
settings = get_settings()


class ScanError(Exception):
    pass


class VibeSafeEngine:
    def __init__(self, use_llm: bool = True) -> None:
        self.use_llm = use_llm

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

    async def _run_scan(self, repo_path: Path, source_url: str = "") -> dict:
        t0 = time.monotonic()

        manifest = build_manifest(repo_path)
        frameworks = detect_framework(manifest)
        repo_context = classify_repo(manifest, frameworks)
        code_index = build_code_index(manifest)

        logger.info(
            (
                "Starting scan | files=%d frameworks=%s repo_context=%s "
                "repo_size_bytes=%d ignored_baggage_bytes=%d scanned_source_bytes=%d scanned_file_count=%d"
            ),
            len(manifest),
            frameworks,
            repo_context.kind,
            manifest.stats.repo_size_bytes,
            manifest.stats.ignored_size_bytes,
            manifest.stats.scanned_source_bytes,
            manifest.stats.scanned_file_count,
        )

        static_results = await asyncio.gather(
            SecretsScanner().scan(manifest),
            AuthScanner().scan(manifest),
            InjectionScanner().scan(manifest),
            AISecurityScanner().scan(manifest),
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

        findings = EvidenceBuilder(manifest, code_index, repo_context=repo_context).build(findings)
        models_used: list[str] = []

        if self.use_llm:
            findings, models_used = await self._llm_enrich(findings, manifest)

        findings = apply_repo_context(findings, repo_context)
        findings = dedupe_findings(findings)
        visible_findings = [apply_final_scoring(finding) for finding in findings if finding.status != "rejected"]
        sorted_findings = sort_findings(visible_findings)
        risk_score = calculate_risk_score(sorted_findings)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        logger.info(
            "Scan complete | risk=%d verdict=%s findings=%d ms=%d",
            risk_score,
            get_verdict(risk_score),
            len(sorted_findings),
            elapsed_ms,
        )

        return {
            "findings": [finding.to_dict() for finding in sorted_findings],
            "risk_score": risk_score,
            "verdict": get_verdict(risk_score),
            "files_scanned": len(manifest),
            "frameworks": frameworks,
            "repo_context": repo_context.to_dict(),
            "scan_ms": elapsed_ms,
            "models_used": models_used,
        }

    async def _llm_enrich(
        self,
        findings: list[Finding],
        manifest: RepoManifest,
    ) -> tuple[list[Finding], list[str]]:

        models_used: list[str] = []
        findings_by_id = {finding.id: finding for finding in findings if finding.status != "rejected"}
        findings_dicts = [finding.to_dict() for finding in findings_by_id.values()]
        package_records = GeminiPackageAuditor.extract_packages(manifest)

        verifier_result, package_findings = await asyncio.gather(
            self._run_groq(findings_dicts, manifest),
            self._run_gemini(package_records),
            return_exceptions=True,
        )

        if isinstance(verifier_result, dict) and verifier_result:
            models_used.append("qwen/qwen3-32b")
            for finding_id, finding in findings_by_id.items():
                verdict = verifier_result.get(finding_id)
                if not verdict:
                    if finding.status == "candidate":
                        finding.status = "needs_review"
                    continue

                finding.status = verdict.get("verdict", finding.status)
                finding.confidence = float(verdict.get("confidence", finding.confidence or 0.0))
                proof_payload = verdict.get("proof")
                if isinstance(proof_payload, dict):
                    finding.proof = Proof(**{**finding.proof.__dict__, **proof_payload})
                finding.validator = "qwen/qwen3-32b"
                if finding.status == "confirmed" and "qwen/qwen3-32b" not in finding.confirmed_by:
                    finding.confirmed_by.append("qwen/qwen3-32b")
                if finding.status == "confirmed" and finding.proof.exploitability_proven:
                    finding.attack_chain = str(verdict.get("attack_scenario", "") or "")

        elif isinstance(verifier_result, Exception):
            logger.warning("Groq verifier failed: %s", verifier_result)

        findings = contradiction_gate(findings)

        if isinstance(package_findings, list) and package_findings:
            models_used.append("gemini-2.5-flash")
            findings.extend(package_findings)
        elif isinstance(package_findings, Exception):
            logger.warning("Gemini auditor failed: %s", package_findings)

        # Collect confirmed findings AFTER Gemini package findings are merged
        # so slopsquatting findings are also eligible for the fixer pass.
        confirmed_dicts = [finding.to_dict() for finding in findings if finding.status == "confirmed"]
        if confirmed_dicts and settings.groq_api_key:
            try:
                fix_results = await GPTFixer().generate_fixes(confirmed_dicts, manifest)
            except Exception as exc:
                logger.warning("Kimi fixer failed: %s", exc)
                fix_results = {}
            else:
                if fix_results:
                    models_used.append("moonshotai/kimi-k2-instruct")

            fix_verifier = FixVerifier()
            for finding in findings:
                fix_result = fix_results.get(finding.id, {})
                if finding.status != "confirmed" or not fix_result:
                    continue

                # Always capture LLM-authored remediation prose when available
                llm_recommendation = str(fix_result.get("recommendation", "")).strip()
                llm_explanation = str(fix_result.get("explanation", "")).strip()

                patch = str(fix_result.get("patch", ""))
                if fix_result.get("status") == "patch_ready" and self._is_valid_patch(patch, finding.file_path):
                    verification = await fix_verifier.verify(finding, patch, manifest.root)
                    if verification.accepted:
                        finding.fix_code = patch
                        # Patch accepted: use LLM prose; fall back to static table below
                        if llm_recommendation:
                            finding.recommendation = llm_recommendation
                        if llm_explanation:
                            finding.fix = llm_explanation
                            finding.fix_source = "llm_kimi"
                    else:
                        finding.proof.notes.extend(
                            f"Fix rejected: {reason}" for reason in verification.reasons
                        )
                        # Patch rejected but LLM still gave guidance
                        if llm_recommendation:
                            finding.recommendation = llm_recommendation
                        if llm_explanation:
                            finding.fix = llm_explanation
                            finding.fix_source = "llm_kimi"
                else:
                    # cannot_fix or invalid patch: still capture prose
                    if llm_recommendation:
                        finding.recommendation = llm_recommendation
                    if llm_explanation:
                        finding.fix = llm_explanation
                        finding.fix_source = "llm_kimi"

        # ── Defensive remediation gate ──────────────────────────────────────────
        # Guarantee every confirmed/needs_review finding has remediation text.
        # Rejected findings (false positives) are intentionally skipped.
        for finding in findings:
            if finding.status == "rejected":
                continue
            applied = apply_static_remediation(finding)
            if applied and not finding.fix_code:
                # Static table was the source; mark as fallback only when LLM ran
                if settings.groq_api_key and confirmed_dicts:
                    finding.fix_source = "llm_fallback"
                else:
                    finding.fix_source = "static_table"

        return findings, models_used

    async def _run_groq(self, findings_dicts: list[dict], manifest) -> dict:
        """Run Groq verification; always returns a dict. Never raises."""
        if not findings_dicts or not settings.groq_api_key:
            return {}
        try:
            return await GroqAnalyser().analyse(findings_dicts, manifest)
        except Exception as exc:  # pragma: no cover
            logger.warning("Groq verifier failed: %s", exc)
            return {}

    async def _run_gemini(self, package_records: dict) -> list:
        """Run Gemini package audit; always returns a list. Never raises."""
        if not (package_records.get("npm") or package_records.get("pypi")) or not settings.google_api_key:
            return []
        try:
            return await GeminiPackageAuditor().audit_packages(package_records)
        except Exception as exc:  # pragma: no cover
            logger.warning("Gemini auditor failed: %s", exc)
            return []

    async def _done(self, value):
        return value

    def _is_valid_patch(self, patch: str, file_path: str) -> bool:
        if not patch.strip():
            return False
        has_target = file_path in patch or f"b/{file_path}" in patch or f"a/{file_path}" in patch
        has_hunk = "@@" in patch
        return has_target and has_hunk
