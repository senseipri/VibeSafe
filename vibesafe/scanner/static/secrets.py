from __future__ import annotations

import logging
import re
from pathlib import Path

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.static.base import BaseScanner

logger = logging.getLogger(__name__)
ENV_ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
PLACEHOLDER_RE = re.compile(
    r"(?:changeme|example|dummy|sample|placeholder|your[_ -]?key|test[_ -]?key|fake|mock|null)",
    re.IGNORECASE,
)
CURRENCY_RE = re.compile(r"\$\s?\d+(?:\.\d{2})?")
PROMPTISH_RE = re.compile(
    r"\b(?:system_prompt|user_prompt|assistant_message|prompt_template|instruction|template)\b",
    re.IGNORECASE,
)
SENSITIVE_ENV_KEY_RE = re.compile(
    r"(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|jwt|client[_-]?secret|access[_-]?key|credentials?)",
    re.IGNORECASE,
)
NON_SECRET_ENV_KEY_RE = re.compile(
    r"^(?:api_host|api_port|host|port|debug|debug_mode|feature(?:_[a-z0-9_]+)?|enable(?:_[a-z0-9_]+)?|disable(?:_[a-z0-9_]+)?|flag(?:_[a-z0-9_]+)?|node_env|app_env|environment|log_level|base_url|public_url|origin|url|uri)$",
    re.IGNORECASE,
)
LOCAL_VALUE_RE = re.compile(r"(?:localhost|127\.0\.0\.1)", re.IGNORECASE)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")

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
    (
        r"(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GROQ_API_KEY)\s*=\s*[\"'][A-Za-z0-9_\-]{12,}[\"']",
        "critical",
        "LLM provider API key",
    ),
    (
        r"(?:AWS_SECRET_ACCESS_KEY)\s*=\s*[\"'][A-Za-z0-9/+=]{30,}[\"']",
        "critical",
        "AWS secret access key",
    ),
    (
        r"(?:AZURE_CLIENT_SECRET|AZURE_STORAGE_CONNECTION_STRING|AZURE_OPENAI_API_KEY)\s*=\s*[\"'][^\"']{16,}[\"']",
        "critical",
        "Azure credential",
    ),
    (
        r"(?:GCP_SERVICE_ACCOUNT|GOOGLE_APPLICATION_CREDENTIALS|private_key_id)\s*[:=]\s*[\"'][^\"']{16,}[\"']",
        "critical",
        "GCP credential",
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
            if self._should_skip_path(rel):
                continue

            # Flag committed environment files but skip examples/templates
            if file_path.name in {".env", ".env.local", ".env.production", ".env.development"} and not any(
                s in file_path.name for s in ["example", "test", "sample", "template"]
            ):
                first_secret_line = ""
                try:
                    for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
                        if self._env_line_contains_secret(line):
                            first_secret_line = line.strip()[:200]
                            break
                except Exception:
                    first_secret_line = ""
                if first_secret_line:
                    findings.append(
                        self._make_finding(
                            category="committed_env_file",
                            severity="critical",
                            file_path=rel,
                            line_number=1,
                            evidence=first_secret_line,
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
                        if name == "Weak JWT / session secret":
                            if PLACEHOLDER_RE.search(line) or CURRENCY_RE.search(line) or PROMPTISH_RE.search(line):
                                break
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

    def _env_line_contains_secret(self, line: str) -> bool:
        stripped = line.strip()
        if not stripped or self._is_comment(stripped):
            return False
        if PRIVATE_KEY_RE.search(stripped):
            return True
        if any(pattern.search(stripped) for pattern, _, _ in _COMPILED):
            return True

        match = ENV_ASSIGNMENT_RE.match(stripped)
        if not match:
            return False

        key, raw_value = match.groups()
        normalized_key = key.strip().lower()
        value = raw_value.strip().strip("\"'")
        if not value or PLACEHOLDER_RE.search(value):
            return False
        if NON_SECRET_ENV_KEY_RE.match(normalized_key):
            return False
        if LOCAL_VALUE_RE.search(value):
            return False
        if value.lower() in {"true", "false", "1", "0", "development", "dev", "test", "staging", "local"}:
            return False
        if not SENSITIVE_ENV_KEY_RE.search(normalized_key):
            return False
        if normalized_key.endswith("token") or normalized_key.endswith("secret") or "private_key" in normalized_key:
            return len(value) >= 8
        if "password" in normalized_key or "passwd" in normalized_key:
            return len(value) >= 6
        if "api_key" in normalized_key or "access_key" in normalized_key or "client_secret" in normalized_key:
            return len(value) >= 12
        if "jwt" in normalized_key or "credentials" in normalized_key:
            return len(value) >= 8
        return len(value) >= 8
