"""
Gemini package auditor for dependency existence and typosquatting review.
"""
from __future__ import annotations

import json
import logging
import re

from vibesafe.api.config import get_settings
from vibesafe.scanner.findings import EvidenceRef, Finding

settings = get_settings()
logger = logging.getLogger(__name__)

try:
    import google.generativeai as genai  # installed package: google-generativeai
except ImportError:  # pragma: no cover
    genai = None

SYSTEM = """You are a package-risk adjudicator.
Use only the supplied package facts.
Do not infer missing registry facts.
Do not treat popularity or freshness alone as vulnerability evidence.
A package is suspicious only when one of these is supported by the supplied facts:
1. registry lookup indicates not_found
2. the package is a likely typosquat of a supplied legitimate package candidate

Return JSON only:
[
  {
    "package": "name",
    "registry": "npm|pypi",
    "verdict": "ok|suspicious|not_found",
    "confidence": 0.0,
    "reason": "grounded explanation using supplied facts"
  }
]"""


class GeminiPackageAuditor:
    def __init__(self) -> None:
        if genai is None:
            raise RuntimeError("google-generativeai is not installed")
        genai.configure(api_key=settings.google_api_key)
        self.model = genai.GenerativeModel(
            "gemini-2.5-flash",
            tools="google_search_retrieval",
        )

    async def audit_packages(self, packages: dict) -> list[Finding]:
        package_records = packages.get("npm", []) + packages.get("pypi", [])
        if not package_records:
            return []

        prompt = SYSTEM + "\n\nPackage records:\n" + json.dumps(package_records[:50], ensure_ascii=True)
        try:
            response = await self.model.generate_content_async(
                prompt,
                generation_config={"response_mime_type": "application/json"},
            )
            results = json.loads(response.text)
        except Exception as exc:
            logger.warning("Gemini package audit failed: %s", exc)
            return []

        findings: list[Finding] = []
        lookup = {(item["registry"], item["package"]): item for item in package_records}
        for item in results:
            verdict = item.get("verdict")
            if verdict not in {"suspicious", "not_found"}:
                continue
            package_key = (item.get("registry", ""), item.get("package", ""))
            manifest_ref = lookup.get(package_key)
            if not manifest_ref:
                continue

            confidence = float(item.get("confidence", 0.0))
            status = "confirmed" if confidence >= 0.85 else "needs_review"
            findings.append(
                Finding(
                    category="slopsquatting",
                    rule_id="slopsquatting",
                    status=status,
                    severity="critical" if verdict == "not_found" else "high",
                    confidence=confidence,
                    file_path=manifest_ref["file_path"],
                    line_number=manifest_ref["line_number"],
                    evidence=manifest_ref["quote"],
                    evidence_refs=[
                        EvidenceRef(
                            kind="manifest",
                            file_path=manifest_ref["file_path"],
                            line_start=manifest_ref["line_number"],
                            line_end=manifest_ref["line_number"],
                            quote=manifest_ref["quote"],
                        )
                    ],
                    description=(
                        f"Package '{item['package']}' was flagged as {verdict}: "
                        f"{item.get('reason', 'no reason provided')}."
                    ),
                    validator="gemini-2.5-flash",
                    confirmed_by=["gemini-2.5-flash"] if status == "confirmed" else [],
                    false_positive_risk="low" if verdict == "not_found" else "medium",
                )
            )
        return findings

    @staticmethod
    def extract_packages(manifest) -> dict:
        npm_pkgs: list[dict] = []
        pypi_pkgs: list[dict] = []

        for file_path in manifest.files:
            rel = manifest.relative(file_path)
            if file_path.name == "package.json":
                npm_pkgs.extend(GeminiPackageAuditor._extract_package_json(file_path, rel))
            elif file_path.name in {"requirements.txt", "requirements-dev.txt"}:
                pypi_pkgs.extend(GeminiPackageAuditor._extract_requirements(file_path, rel))
            elif file_path.name == "pyproject.toml":
                pypi_pkgs.extend(GeminiPackageAuditor._extract_pyproject(file_path, rel))

        return {
            "npm": GeminiPackageAuditor._dedupe_records(npm_pkgs),
            "pypi": GeminiPackageAuditor._dedupe_records(pypi_pkgs),
        }

    @staticmethod
    def _extract_package_json(file_path, rel: str) -> list[dict]:
        try:
            data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []

        packages: list[dict] = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for package in data.get(section, {}).keys():
                line_number, quote = GeminiPackageAuditor._find_line(lines, f'"{package}"')
                packages.append(
                    {
                        "package": package,
                        "registry": "npm",
                        "file_path": rel,
                        "line_number": line_number,
                        "quote": quote,
                    }
                )
        return packages

    @staticmethod
    def _extract_requirements(file_path, rel: str) -> list[dict]:
        packages: list[dict] = []
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            pkg = re.split(r"[><=<!;]", stripped)[0].strip()
            if pkg:
                packages.append(
                    {
                        "package": pkg,
                        "registry": "pypi",
                        "file_path": rel,
                        "line_number": line_number,
                        "quote": stripped[:400],
                    }
                )
        return packages

    @staticmethod
    def _extract_pyproject(file_path, rel: str) -> list[dict]:
        packages: list[dict] = []
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        dep_re = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=<>!]")
        for line_number, line in enumerate(lines, start=1):
            match = dep_re.search(line)
            if match:
                packages.append(
                    {
                        "package": match.group(1),
                        "registry": "pypi",
                        "file_path": rel,
                        "line_number": line_number,
                        "quote": line.strip()[:400],
                    }
                )
        return packages

    @staticmethod
    def _find_line(lines: list[str], needle: str) -> tuple[int, str]:
        for line_number, line in enumerate(lines, start=1):
            if needle in line:
                return line_number, line.strip()[:400]
        return 1, needle

    @staticmethod
    def _dedupe_records(records: list[dict]) -> list[dict]:
        deduped: dict[tuple[str, str, str], dict] = {}
        for record in records:
            deduped[(record["registry"], record["package"], record["file_path"])] = record
        return list(deduped.values())
