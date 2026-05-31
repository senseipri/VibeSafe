from __future__ import annotations

import logging
import re
from pathlib import Path

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.static.base import BaseScanner

logger = logging.getLogger(__name__)

# Python CORSMiddleware block patterns
PY_CORS_BLOCK = re.compile(
    r"CORSMiddleware\s*,?\s*\(([^)]*)\)",
    re.DOTALL,
)
PY_CORS_KWARGS = re.compile(
    r"add_middleware\s*\(\s*CORSMiddleware(.*?)\)",
    re.DOTALL,
)
PY_ORIGINS_WILDCARD = re.compile(r'allow_origins\s*=\s*\[\s*["\*]\*?["\*]\s*\]')
PY_CREDENTIALS_TRUE = re.compile(r"allow_credentials\s*=\s*True")

# JS cors() patterns
JS_CORS_CALL = re.compile(r"cors\s*\(\s*\{([^}]*)\}", re.DOTALL)
JS_ORIGIN_WILDCARD = re.compile(r'origin\s*:\s*["\*]\*["\*]|origin\s*:\s*true')
JS_CREDENTIALS_TRUE = re.compile(r"credentials\s*:\s*true", re.IGNORECASE)

# Next.js / generic header patterns
NEXT_CORS_WILDCARD = re.compile(
    r'["\']Access-Control-Allow-Origin["\']\s*[,:]\s*["\*]\*["\*]'
)
NEXT_CREDENTIALS = re.compile(
    r'["\']Access-Control-Allow-Credentials["\']\s*[,:]\s*["\']true["\']',
    re.IGNORECASE,
)


class CORSScanner(BaseScanner):
    """
    Detects dangerous CORS misconfigurations.
    Critical: wildcard origin + credentials=True (allows any site to make
              authenticated requests on behalf of logged-in users).
    High: wildcard origin without credentials (information disclosure risk).
    """

    async def scan(self, manifest: RepoManifest) -> list[Finding]:
        findings: list[Finding] = []

        for file_path in manifest.files:
            suffix = file_path.suffix.lower()
            rel = manifest.relative(file_path)
            content = self._read(file_path)
            if not content:
                continue

            if suffix == ".py":
                findings.extend(self._scan_python(content, rel))
            elif suffix in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
                findings.extend(self._scan_js(content, rel))

        return findings

    # ── Python (FastAPI / Starlette / Flask-CORS) ───────────────

    def _scan_python(self, content: str, rel: str) -> list[Finding]:
        findings: list[Finding] = []

        # Look for add_middleware(CORSMiddleware, ...) blocks
        for m in PY_CORS_KWARGS.finditer(content):
            block = m.group(1)
            line_num = content[: m.start()].count("\n") + 1

            has_wildcard = bool(PY_ORIGINS_WILDCARD.search(block))
            has_credentials = bool(PY_CREDENTIALS_TRUE.search(block))

            if has_wildcard and has_credentials:
                findings.append(self._make_finding(
                    category="cors_wildcard_credentials",
                    severity="critical",
                    file_path=rel,
                    line_number=line_num,
                    evidence=f"CORSMiddleware(allow_origins=['*'], allow_credentials=True)",
                    description=(
                        "CRITICAL CORS misconfiguration: wildcard origin combined with "
                        "allow_credentials=True. Any website can make authenticated API "
                        "requests on behalf of your logged-in users, enabling complete "
                        "account takeover. Fix: specify exact allowed origins."
                    ),
                    false_positive_risk="low",
                ))
            elif has_wildcard:
                findings.append(self._make_finding(
                    category="cors_wildcard",
                    severity="high",
                    file_path=rel,
                    line_number=line_num,
                    evidence="CORSMiddleware(allow_origins=['*'])",
                    description=(
                        "CORS wildcard origin (allow_origins=['*']) allows any website to "
                        "make requests to your API. While less severe without credentials, "
                        "this still exposes your API surface to cross-origin attacks. "
                        "Fix: replace '*' with your specific frontend domain."
                    ),
                    false_positive_risk="low",
                ))

        return findings

    # ── JavaScript / TypeScript (Express cors(), Next.js) ───────

    def _scan_js(self, content: str, rel: str) -> list[Finding]:
        findings: list[Finding] = []

        # Express: cors({...})
        for m in JS_CORS_CALL.finditer(content):
            block = m.group(1)
            line_num = content[: m.start()].count("\n") + 1

            has_wildcard = bool(JS_ORIGIN_WILDCARD.search(block))
            has_credentials = bool(JS_CREDENTIALS_TRUE.search(block))

            if has_wildcard and has_credentials:
                findings.append(self._make_finding(
                    category="cors_wildcard_credentials",
                    severity="critical",
                    file_path=rel,
                    line_number=line_num,
                    evidence="cors({ origin: '*', credentials: true })",
                    description=(
                        "CRITICAL CORS misconfiguration: wildcard origin with credentials:true. "
                        "Any malicious website can make authenticated requests to your API "
                        "using your users' cookies or auth tokens. "
                        "Fix: set origin to your specific domain(s)."
                    ),
                    false_positive_risk="low",
                ))
            elif has_wildcard:
                findings.append(self._make_finding(
                    category="cors_wildcard",
                    severity="high",
                    file_path=rel,
                    line_number=line_num,
                    evidence="cors({ origin: '*' })",
                    description=(
                        "CORS wildcard origin exposes your API to requests from any website. "
                        "Fix: specify exact allowed origin domains."
                    ),
                    false_positive_risk="low",
                ))

        # Next.js / generic header-based CORS
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if NEXT_CORS_WILDCARD.search(line):
                # Check nearby lines for credentials header
                nearby = "\n".join(lines[max(0, lineno - 3): min(len(lines), lineno + 3)])
                has_creds = bool(NEXT_CREDENTIALS.search(nearby))
                findings.append(self._make_finding(
                    category="cors_wildcard_credentials" if has_creds else "cors_wildcard",
                    severity="critical" if has_creds else "high",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        "Access-Control-Allow-Origin: * header set. "
                        + (
                            "Combined with Access-Control-Allow-Credentials: true this is "
                            "maximum severity — full account takeover is possible."
                            if has_creds
                            else "Any website can read responses from your API."
                        )
                    ),
                    false_positive_risk="low",
                ))

        return findings