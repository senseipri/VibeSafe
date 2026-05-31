"""
GeminiPackageAuditor — uses Gemini 1.5 Flash (with Google Search grounding)
to detect slopsquatting / typosquatted / non-existent packages in
package.json, requirements.txt, and pyproject.toml.
"""
from __future__ import annotations

import json
import logging
import re

import google.generativeai as genai

from vibesafe.scanner.findings import Finding
from vibesafe.api.config import get_settings
settings = get_settings()

logger = logging.getLogger(__name__)

SYSTEM = """You are a supply chain security analyst with web search access.
For the provided npm/PyPI packages, verify using web search:
1. Does this package exist on the registry right now?
2. Weekly downloads > 100?
3. Last published within 2 years?
4. Is the name suspiciously similar to a popular legitimate package (typosquat)?

Flag as suspicious if: doesn't exist, <100 weekly downloads + recently created, or is a typosquat.
Return JSON array: [{package, registry, status("ok"|"suspicious"|"not_found"), reason}]"""


class GeminiPackageAuditor:
    def __init__(self) -> None:
        genai.configure(
            api_key=settings.google_api_key
        )

        self.model = genai.GenerativeModel(
            "gemini-1.5-flash",
            tools="google_search_retrieval",
        )

    async def audit_packages(self, packages: dict) -> list[Finding]:
        """
        packages = {"npm": [...], "pypi": [...]}
        Returns a list of Finding objects for suspicious packages.
        """
        all_pkgs = [f"npm:{p}" for p in packages.get("npm", [])] + [
            f"pypi:{p}" for p in packages.get("pypi", [])
        ]
        if not all_pkgs:
            return []

        prompt = SYSTEM + "\n\nVerify these packages:\n" + "\n".join(all_pkgs[:50])
        try:
            r = await self.model.generate_content_async(
                prompt,
                generation_config={"response_mime_type": "application/json"},
            )
            results = json.loads(r.text)
        except Exception as exc:
            logger.warning("Gemini package audit failed: %s", exc)
            return []

        findings: list[Finding] = []
        for item in results:
            if item.get("status") in ("suspicious", "not_found"):
                findings.append(
                    Finding(
                        category="slopsquatting",
                        severity="high" if item["status"] == "suspicious" else "critical",
                        file_path="package.json / requirements.txt",
                        line_number=0,
                        evidence=f"{item['package']} ({item.get('registry', 'unknown')})",
                        description=(
                            f"Package '{item['package']}' {item.get('reason', 'is flagged')}. "
                            "Attackers register hallucinated package names to execute malicious code "
                            "when someone installs your dependencies."
                        ),
                        false_positive_risk="medium",
                    )
                )
        return findings

    @staticmethod
    def extract_packages(manifest) -> dict:
        """Extract npm and PyPI package names from manifest files."""
        npm_pkgs: list[str] = []
        pypi_pkgs: list[str] = []

        for f in manifest.files:
            if f.name == "package.json":
                try:
                    data = json.loads(f.read_text(errors="replace"))
                    for section in ("dependencies", "devDependencies", "peerDependencies"):
                        npm_pkgs.extend(data.get(section, {}).keys())
                except Exception:
                    pass

            elif f.name in ("requirements.txt", "requirements-dev.txt"):
                try:
                    for line in f.read_text(errors="replace").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            pkg = re.split(r"[><=<!;]", line)[0].strip()
                            if pkg:
                                pypi_pkgs.append(pkg)
                except Exception:
                    pass

            elif f.name == "pyproject.toml":
                try:
                    content = f.read_text(errors="replace")
                    matches = re.findall(r"^(\w[\w\-\.]+)\s*[=<>!]", content, re.MULTILINE)
                    pypi_pkgs.extend(matches)
                except Exception:
                    pass

        return {"npm": list(set(npm_pkgs)), "pypi": list(set(pypi_pkgs))}
