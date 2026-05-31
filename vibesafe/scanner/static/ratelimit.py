from __future__ import annotations

import logging
import re
from pathlib import Path

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.static.base import BaseScanner

logger = logging.getLogger(__name__)

AUTH_PATH_FRAGMENTS = [
    "/login", "/signin", "/sign-in",
    "/register", "/signup", "/sign-up",
    "/forgot-password", "/reset-password", "/forgot", "/reset",
    "/verify", "/verify-email", "/otp", "/mfa", "/2fa",
    "/refresh", "/token",
]

PAYMENT_PATH_FRAGMENTS = [
    "/payment", "/pay", "/charge",
    "/checkout", "/subscribe", "/subscription",
    "/billing", "/invoice",
    "/webhook/stripe", "/webhook/paypal",
]

SENSITIVE_FRAGMENTS = AUTH_PATH_FRAGMENTS + PAYMENT_PATH_FRAGMENTS

# Python rate-limiting signals
PY_RATE_LIMIT_SIGNALS = [
    "slowapi", "limiter", "RateLimiter", "@limiter.limit",
    "rate_limit", "ratelimit", "throttle", "Throttle",
    "RATELIMIT", "flask_limiter", "fastapi_limiter",
]

# JS rate-limiting signals
JS_RATE_LIMIT_SIGNALS = [
    "rateLimit", "rateLimiter", "expressRateLimit", "express-rate-limit",
    "throttle", "throttler", "rate_limit", "limiter(",
    "slowDown", "apiRateLimit", "requestLimit",
]

# Python route patterns
PY_ROUTE_RE = re.compile(
    r'@(?:\w+\.)?(?:route|get|post|put|delete|patch|head)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# JS route patterns
JS_ROUTE_RE = re.compile(
    r'(?:router|app|server)\s*\.\s*(?:get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _is_sensitive(path: str) -> tuple[bool, str]:
    """Return (is_sensitive, category) for a path."""
    pl = path.lower()
    for frag in AUTH_PATH_FRAGMENTS:
        if frag in pl:
            return True, "auth"
    for frag in PAYMENT_PATH_FRAGMENTS:
        if frag in pl:
            return True, "payment"
    return False, ""


class RateLimitScanner(BaseScanner):
    """
    Detects auth and payment endpoints that have no rate limiting configured.
    Without rate limiting: brute-force attacks on login, card-testing on payments.
    Severity: medium (serious but requires chaining to be critical).
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
            elif suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                findings.extend(self._scan_js(content, rel))

        return findings

    def _scan_python(self, content: str, rel: str) -> list[Finding]:
        findings: list[Finding] = []

        # Check if the file has any rate limiting at all
        file_has_rl = any(sig in content for sig in PY_RATE_LIMIT_SIGNALS)

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            m = PY_ROUTE_RE.search(line)
            if not m:
                continue

            route_path = m.group(1)
            sensitive, category = _is_sensitive(route_path)
            if not sensitive:
                continue

            # Check surrounding decorator lines (up to 5 lines above) for rate limit
            start = max(0, lineno - 6)
            context = "\n".join(lines[start:lineno])
            local_has_rl = any(sig in context for sig in PY_RATE_LIMIT_SIGNALS)

            if file_has_rl or local_has_rl:
                continue

            findings.append(self._make_finding(
                category="missing_rate_limit",
                severity="medium",
                file_path=rel,
                line_number=lineno,
                evidence=line.strip()[:200],
                description=self._description(route_path, category),
                false_positive_risk="medium",
            ))

        return findings

    def _scan_js(self, content: str, rel: str) -> list[Finding]:
        findings: list[Finding] = []

        file_has_rl = any(sig in content for sig in JS_RATE_LIMIT_SIGNALS)

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            m = JS_ROUTE_RE.search(line)
            if not m:
                continue

            route_path = m.group(1)
            sensitive, category = _is_sensitive(route_path)
            if not sensitive:
                continue

            # Check the route handler block (next 20 lines) for rate limit middleware
            end = min(len(lines), lineno + 20)
            context = "\n".join(lines[lineno - 1 : end])
            local_has_rl = any(sig in context for sig in JS_RATE_LIMIT_SIGNALS)

            if file_has_rl or local_has_rl:
                continue

            findings.append(self._make_finding(
                category="missing_rate_limit",
                severity="medium",
                file_path=rel,
                line_number=lineno,
                evidence=line.strip()[:200],
                description=self._description(route_path, category),
                false_positive_risk="medium",
            ))

        return findings

    @staticmethod
    def _description(route_path: str, category: str) -> str:
        if category == "payment":
            return (
                f"Payment endpoint '{route_path}' has no rate limiting. "
                "Without rate limiting, attackers can test thousands of stolen credit cards "
                "per minute (card-testing attack), generating chargebacks and potential "
                "payment processor account suspension. "
                "Fix: add rate limiting of 3-5 requests per IP per hour on payment endpoints."
            )
        return (
            f"Authentication endpoint '{route_path}' has no rate limiting. "
            "Without rate limiting, attackers can attempt millions of password combinations "
            "(brute-force) or test lists of breached credentials (credential stuffing). "
            "Fix: add rate limiting of 5 attempts per IP per 15 minutes with lockout."
        )