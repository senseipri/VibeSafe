"""
Core finding models used across scanners, validators, and report generation.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Literal

Severity = Literal["critical", "high", "medium", "low"]
FindingStatus = Literal["candidate", "confirmed", "needs_review", "rejected"]
EvidenceKind = Literal["manifest", "source", "sink", "path", "sanitizer", "registry", "literal"]

SEVERITY_WEIGHTS: dict[Severity, int] = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 2,
}

SEVERITY_ORDER: list[Severity] = ["low", "medium", "high", "critical"]

OWASP_CATEGORIES: dict[str, str] = {
    "hardcoded_secret": "A02:2021 - Cryptographic Failures",
    "committed_env_file": "A02:2021 - Cryptographic Failures",
    "missing_auth": "A01:2021 - Broken Access Control",
    "sql_injection": "A03:2021 - Injection",
    "log_injection": "A09:2021 - Security Logging Failures",
    "command_injection": "A03:2021 - Injection",
    "unsafe_dynamic_code": "A03:2021 - Injection",
    "path_traversal": "A01:2021 - Broken Access Control",
    "cors_wildcard_credentials": "A05:2021 - Security Misconfiguration",
    "cors_wildcard": "A05:2021 - Security Misconfiguration",
    "rls_disabled": "A01:2021 - Broken Access Control",
    "firebase_public": "A01:2021 - Broken Access Control",
    "missing_rate_limit": "A04:2021 - Insecure Design",
    "weak_jwt": "A02:2021 - Cryptographic Failures",
    "slopsquatting": "A06:2021 - Vulnerable Components",
    "missing_security_headers": "A05:2021 - Security Misconfiguration",
    "supabase_anon_write": "A05:2021 - Security Misconfiguration",
    "prompt_injection": "LLM01 - Prompt Injection",
    "unsafe_tool_execution": "LLM06 - Excessive Agency",
    "agent_privilege_escalation": "LLM06 - Excessive Agency",
    "mcp_untrusted_server": "LLM06 - Excessive Agency",
    "llm_secret_exposure": "LLM02 - Sensitive Information Disclosure",
    "agent_memory_poisoning": "LLM04 - Data and Model Poisoning",
    "retrieval_poisoning": "LLM08 - Vector and Embedding Weaknesses",
}


@dataclass
class EvidenceRef:
    kind: EvidenceKind
    file_path: str
    line_start: int
    line_end: int
    quote: str


@dataclass
class Proof:
    source_present: bool = False
    sink_present: bool = False
    path_present: bool = False
    sanitizer_present: bool = False
    attacker_controlled: bool = False
    exploitability_proven: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    category: str = ""
    status: FindingStatus = "candidate"
    severity: Severity = "low"
    confidence: float = 0.0
    file_path: str = ""
    line_number: int = 0
    evidence: str = ""
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    proof: Proof = field(default_factory=Proof)
    description: str = ""
    attack_chain: str = ""
    fix_code: str | None = None
    # ── Remediation fields ─────────────────────────────────────
    # recommendation: short, imperative action headline.
    # fix: 2-4 sentence human-readable remediation guidance.
    # fix_source: provenance of the remediation content, one of:
    #   "static_table"  – came from the built-in category lookup
    #   "llm_kimi"      – LLM returned remediation prose (patch ready or not)
    #   "llm_fallback"  – LLM unavailable, static table used as fallback
    recommendation: str = ""
    fix: str = ""
    fix_source: str = ""
    # ────────────────────────────────────────────────────────────
    cvss_score: float | None = None
    cvss_vector: str | None = None
    confirmed_by: list[str] = field(default_factory=list)
    validator: str | None = None
    owasp_cat: str | None = None
    false_positive_risk: str = "low"

    def __post_init__(self) -> None:
        if not self.rule_id:
            self.rule_id = self.category
        if self.owasp_cat is None and self.category in OWASP_CATEGORIES:
            self.owasp_cat = OWASP_CATEGORIES[self.category]
        if self.evidence and not self.evidence_refs:
            line_number = self.line_number if self.line_number > 0 else 1
            self.evidence_refs.append(
                EvidenceRef(
                    kind="literal",
                    file_path=self.file_path,
                    line_start=line_number,
                    line_end=line_number,
                    quote=self.evidence[:400],
                )
            )

    @property
    def severity_score(self) -> int:
        return SEVERITY_WEIGHTS[self.severity]

    @property
    def is_confirmed(self) -> bool:
        return self.status == "confirmed" or len(self.confirmed_by) > 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "evidence_refs": [asdict(ref) for ref in self.evidence_refs],
            "proof": asdict(self.proof),
            "description": self.description,
            "attack_chain": self.attack_chain,
            "fix_code": self.fix_code,
            "recommendation": self.recommendation,
            "fix": self.fix,
            "fix_source": self.fix_source,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "confirmed_by": self.confirmed_by,
            "validator": self.validator,
            "owasp_cat": self.owasp_cat,
            "false_positive_risk": self.false_positive_risk,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity DESC, then confidence DESC."""
    status_order = {"confirmed": 2, "needs_review": 1, "candidate": 0, "rejected": -1}
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.index(f.severity),
            status_order.get(f.status, 0),
            round(f.confidence, 4),
        ),
        reverse=True,
    )


def calculate_risk_score(findings: list[Finding]) -> int:
    """
    Weighted risk score 0-100.
    Rejected findings do not contribute. Needs-review findings contribute at half weight.
    """
    raw = 0.0
    category_counts: dict[str, int] = {}
    for finding in findings:
        if finding.status == "rejected":
            continue
        weight = SEVERITY_WEIGHTS[finding.severity]
        category_index = category_counts.get(finding.category, 0)
        category_counts[finding.category] = category_index + 1
        saturation = _category_saturation_factor(category_index)
        if finding.status == "needs_review":
            raw += weight * 0.5 * saturation
        else:
            raw += weight * saturation
    return min(100, int(raw))


def _category_saturation_factor(category_index: int) -> float:
    """
    Apply diminishing returns to repeated findings in the same category.
    First few findings still matter, but large internal repos should not max out
    the score from one repeated detector class alone.
    """
    return max(0.2, 1.0 / (1.0 + (category_index * 0.55)))


def get_verdict(risk_score: int) -> str:
    if risk_score == 0:
        return "CLEAN"
    if risk_score <= 15:
        return "LOW"
    if risk_score <= 35:
        return "MEDIUM"
    if risk_score <= 65:
        return "HIGH"
    return "CRITICAL"
