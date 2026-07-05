"""
Core finding models used across scanners, validators, and report generation.
"""
from __future__ import annotations

import re
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
STATUS_ORDER: list[FindingStatus] = ["rejected", "candidate", "needs_review", "confirmed"]
STATUS_SCORE_MULTIPLIER: dict[FindingStatus, float] = {
    "rejected": 0.0,
    "candidate": 0.25,
    "needs_review": 0.5,
    "confirmed": 1.0,
}
AI_RISK_CATEGORIES: set[str] = {
    "prompt_injection",
    "unsafe_tool_execution",
    "agent_privilege_escalation",
    "mcp_untrusted_server",
    "llm_secret_exposure",
    "agent_memory_poisoning",
    "retrieval_poisoning",
}

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
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.index(f.severity),
            STATUS_ORDER.index(f.status),
            round(f.confidence, 4),
        ),
        reverse=True,
    )


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge duplicate findings using a stable canonical key."""
    merged: dict[tuple[str, str, int, str], Finding] = {}
    for finding in findings:
        key = (
            finding.category,
            finding.file_path,
            finding.line_number,
            _normalize_evidence(finding.evidence),
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        _merge_finding(existing, finding)
    return list(merged.values())


def calculate_risk_score(findings: list[Finding]) -> int:
    """
    Weighted risk score 0-100.
    Rejected findings do not contribute. Candidate findings contribute less than
    needs-review findings, and unproven AI findings are further damped.
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
        status_multiplier = STATUS_SCORE_MULTIPLIER.get(finding.status, 0.25)
        if finding.category in AI_RISK_CATEGORIES and not finding.proof.exploitability_proven:
            status_multiplier *= 0.35
        raw += weight * status_multiplier * saturation
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


def _normalize_evidence(evidence: str) -> str:
    return re.sub(r"\s+", " ", evidence).strip().lower()


def _merge_finding(target: Finding, incoming: Finding) -> None:
    if SEVERITY_ORDER.index(incoming.severity) > SEVERITY_ORDER.index(target.severity):
        target.severity = incoming.severity
    target.confidence = max(target.confidence, incoming.confidence)
    if STATUS_ORDER.index(incoming.status) > STATUS_ORDER.index(target.status):
        target.status = incoming.status

    target.evidence_refs = _merge_unique_evidence_refs(target.evidence_refs, incoming.evidence_refs)
    target.confirmed_by = _merge_unique_strings(target.confirmed_by, incoming.confirmed_by)

    if not target.recommendation and incoming.recommendation:
        target.recommendation = incoming.recommendation
    if not target.fix and incoming.fix:
        target.fix = incoming.fix
    if not target.fix_code and incoming.fix_code:
        target.fix_code = incoming.fix_code

    if not target.description and incoming.description:
        target.description = incoming.description
    if not target.attack_chain and incoming.attack_chain:
        target.attack_chain = incoming.attack_chain
    if not target.fix_source and incoming.fix_source:
        target.fix_source = incoming.fix_source
    if not target.validator and incoming.validator:
        target.validator = incoming.validator
    if not target.owasp_cat and incoming.owasp_cat:
        target.owasp_cat = incoming.owasp_cat
    if target.cvss_score is None and incoming.cvss_score is not None:
        target.cvss_score = incoming.cvss_score
    if target.cvss_vector is None and incoming.cvss_vector:
        target.cvss_vector = incoming.cvss_vector

    target.proof.source_present = target.proof.source_present or incoming.proof.source_present
    target.proof.sink_present = target.proof.sink_present or incoming.proof.sink_present
    target.proof.path_present = target.proof.path_present or incoming.proof.path_present
    target.proof.sanitizer_present = target.proof.sanitizer_present or incoming.proof.sanitizer_present
    target.proof.attacker_controlled = target.proof.attacker_controlled or incoming.proof.attacker_controlled
    target.proof.exploitability_proven = (
        target.proof.exploitability_proven or incoming.proof.exploitability_proven
    )
    target.proof.notes = _merge_unique_strings(target.proof.notes, incoming.proof.notes)


def _merge_unique_evidence_refs(
    current: list[EvidenceRef],
    incoming: list[EvidenceRef],
) -> list[EvidenceRef]:
    merged = list(current)
    seen = {
        (ref.kind, ref.file_path, ref.line_start, ref.line_end, ref.quote)
        for ref in merged
    }
    for ref in incoming:
        key = (ref.kind, ref.file_path, ref.line_start, ref.line_end, ref.quote)
        if key in seen:
            continue
        seen.add(key)
        merged.append(ref)
    return merged


def _merge_unique_strings(current: list[str], incoming: list[str]) -> list[str]:
    merged = list(current)
    seen = set(current)
    for value in incoming:
        if value in seen:
            continue
        seen.add(value)
        merged.append(value)
    return merged
