"""
Core Finding dataclass used across all scanners.
Low severity findings are NEVER dropped — they combine into exploit chains.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "high", "medium", "low"]

SEVERITY_WEIGHTS: dict[Severity, int] = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 2,
}

SEVERITY_ORDER: list[Severity] = ["low", "medium", "high", "critical"]

OWASP_CATEGORIES: dict[str, str] = {
    "hardcoded_secret": "A02:2021 – Cryptographic Failures",
    "committed_env_file": "A02:2021 – Cryptographic Failures",
    "missing_auth": "A01:2021 – Broken Access Control",
    "sql_injection": "A03:2021 – Injection",
    "log_injection": "A09:2021 – Security Logging Failures",
    "cors_wildcard_credentials": "A05:2021 – Security Misconfiguration",
    "cors_wildcard": "A05:2021 – Security Misconfiguration",
    "rls_disabled": "A01:2021 – Broken Access Control",
    "firebase_public": "A01:2021 – Broken Access Control",
    "missing_rate_limit": "A04:2021 – Insecure Design",
    "weak_jwt": "A02:2021 – Cryptographic Failures",
    "slopsquatting": "A06:2021 – Vulnerable Components",
    "missing_security_headers": "A05:2021 – Security Misconfiguration",
}


@dataclass
class Finding:
    """
    A single security finding from any scanner.
    All fields except fix_code, cvss_score, confirmed_by, attack_chain
    are populated by the static scanner. LLM layer enriches the rest.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""
    severity: Severity = "low"
    file_path: str = ""
    line_number: int = 0
    evidence: str = ""          # the offending code snippet (truncated to 200 chars)
    description: str = ""       # plain English — understandable by non-technical founders
    attack_chain: str = ""      # "attacker sends X → Y → data stolen" — populated by Claude
    fix_code: str | None = None   # populated by GPT-4o
    cvss_score: float | None = None
    confirmed_by: list[str] = field(default_factory=list)
    owasp_cat: str | None = None
    false_positive_risk: str = "low"  # "low" | "medium" | "high" — guides LLM confidence

    def __post_init__(self) -> None:
        if self.owasp_cat is None and self.category in OWASP_CATEGORIES:
            self.owasp_cat = OWASP_CATEGORIES[self.category]

    @property
    def severity_score(self) -> int:
        return SEVERITY_WEIGHTS[self.severity]

    @property
    def is_confirmed(self) -> bool:
        return len(self.confirmed_by) > 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "description": self.description,
            "attack_chain": self.attack_chain,
            "fix_code": self.fix_code,
            "cvss_score": self.cvss_score,
            "confirmed_by": self.confirmed_by,
            "owasp_cat": self.owasp_cat,
            "false_positive_risk": self.false_positive_risk,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity DESC, then by false_positive_risk ASC."""
    fp_order = {"low": 0, "medium": 1, "high": 2}
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f.severity), -fp_order.get(f.false_positive_risk, 0)),
        reverse=True,
    )


def calculate_risk_score(findings: list[Finding]) -> int:
    """
    Weighted risk score 0-100.
    Critical=40pts, High=20pts, Medium=8pts, Low=2pts. Capped at 100.
    """
    raw = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return min(100, raw)


def get_verdict(risk_score: int) -> str:
    if risk_score == 0:
        return "CLEAN"
    elif risk_score <= 15:
        return "LOW"
    elif risk_score <= 35:
        return "MEDIUM"
    elif risk_score <= 65:
        return "HIGH"
    else:
        return "CRITICAL"