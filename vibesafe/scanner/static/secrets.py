from __future__ import annotations

import logging
import re
from pathlib import Path

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.static.base import BaseScanner

logger = logging.getLogger(__name__)

# (pattern, severity, human_name)
VIBE_PATTERNS: list[tuple[str, str, str]] = [
    (r"sk-proj-[A-Za-z0-9_\-]{48,}", "critical", "OpenAI API key"),
    (r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{90,}", "critical", "Anthropic API key"),
    (r"sk_live_[A-Za-z0-9]{24,}", "critical", "Stripe live secret key"),
    (r"sk_test_[A-Za-z0-9]{24,}", "medium", "Stripe test secret key"),
    (
        r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "critical",
        "Supabase JWT / hardcoded JWT token",
    ),
    (r"ghp_[A-Za-z0-9]{36}", "critical", "GitHub personal access token"),
    (r"ghs_[A-Za-z0-9]{36}", "critical", "GitHub Actions token"),
    (r"re_[A-Za-z0-9]{32}", "high", "Resend API key"),
    (r"AIza[A-Za-z0-9_\-]{35}", "high", "Google / Firebase API key"),
    (
        r"(postgresql|mysql|mongodb(\+srv)?|redis)://[^:\s]+:[^@\s]+@[\w.\-]+[:/]\S+",
        "critical",
        "Database connection string with credentials",
    ),
    (
        r"(?:RAILWAY_TOKEN|RAILWAY_API_KEY)\s*=\s*[\"'][A-Za-z0-9\-]{30,}[\"']",
        "critical",
        "Railway API token",
    ),
    (
        r"(?:VERCEL_TOKEN|VERCEL_ACCESS_TOKEN)\s*=\s*[\"'][A-Za-z0-9_\-]{20,}[\"']",
        "critical",
        "Vercel access token",
    ),
    (
        r"(?:JWT_SECRET|SECRET_KEY|APP_SECRET|SESSION_SECRET)\s*=\s*[\"'](?!\$\{)[^\"']{1,30}[\"']",
        "high",
        "Weak JWT / session secret",
    ),
    (r"xoxb-[0-9A-Za-z\-]{40,}", "critical", "Slack bot token"),
    (r"xoxp-[0-9A-Za-z\-]{40,}", "critical", "Slack user token"),
    (r"AKIA[0-9A-Z]{16}", "critical", "AWS access key ID"),
]

# Compiled patterns cache
_COMPILED: list[tuple[re.Pattern, str, str]] = [
    (re.compile(pat), sev, name) for pat, sev, name in VIBE_PATTERNS
]


class SecretsScanner(BaseScanner):
    """
    Detects hardcoded credentials and secrets.
    Skips lines that safely reference environment variables.
    Also flags committed .env files as CRITICAL.
    """

    async def scan(self, manifest: RepoManifest) -> list[Finding]:
        findings: list[Finding] = []

        for file_path in manifest.files:
            rel = manifest.relative(file_path)

            # Flag committed .env file (not .env.example / .env.local / .env.test)
            if file_path.name == ".env" and not any(
                s in file_path.name for s in ["example", "local", "test", "sample", "template"]
            ):
                findings.append(
                    self._make_finding(
                        category="committed_env_file",
                        severity="critical",
                        file_path=rel,
                        line_number=0,
                        evidence=f".env file committed: {rel}",
                        description=(
                            "A .env file containing secrets has been committed to the repository. "
                            "Anyone with repo access can steal all credentials. "
                            "Add .env to .gitignore immediately and rotate all secrets."
                        ),
                        false_positive_risk="low",
                    )
                )

            content = self._read(file_path)
            if not content:
                continue

            lines = content.splitlines()
            for lineno, line in enumerate(lines, start=1):
                if self._is_comment(line):
                    continue
                if self._is_safe_reference(line):
                    continue

                for pattern, severity, name in _COMPILED:
                    match = pattern.search(line)
                    if match:
                        evidence = line.strip()[:200]
                        findings.append(
                            self._make_finding(
                                category="hardcoded_secret",
                                severity=severity,
                                file_path=rel,
                                line_number=lineno,
                                evidence=evidence,
                                description=(
                                    f"Hardcoded {name} found in {rel}:{lineno}. "
                                    "Anyone with repository access can steal this credential "
                                    "and use it to access your services or incur charges."
                                ),
                                false_positive_risk="low",
                            )
                        )
                        break  # one finding per line is enough

        return findings