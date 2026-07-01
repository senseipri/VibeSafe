from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ScanReport:
    """
    Final report produced after all scan phases complete.
    to_dict() is the canonical serialisation format consumed by the API.
    """

    scan_id: str
    repo_url: str | None
    risk_score: int
    verdict: str
    findings: list[dict]
    frameworks: list[str]
    files_scanned: int
    scan_ms: int
    share_url: str
    repo_context: dict = field(default_factory=dict)
    models_used: list[str] = field(default_factory=list)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # ── Derived properties ───────────────────────────────────────

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "low")

    @property
    def total_count(self) -> int:
        return len(self.findings)

    @property
    def highest_severity(self) -> str:
        """Return the highest severity present, or 'none'."""
        for sev in ("critical", "high", "medium", "low"):
            if any(f["severity"] == sev for f in self.findings):
                return sev
        return "none"

    @property
    def summary(self) -> str:
        """2-sentence plain-English summary for non-technical founders."""
        total = self.total_count
        if total == 0:
            return (
                "No vulnerabilities found in your repository. "
                "Your codebase looks clean — keep scanning after every significant change."
            )

        parts: list[str] = []
        if self.critical_count:
            parts.append(f"{self.critical_count} critical")
        if self.high_count:
            parts.append(f"{self.high_count} high")
        if self.medium_count:
            parts.append(f"{self.medium_count} medium")
        if self.low_count:
            parts.append(f"{self.low_count} low")

        severity_str = ", ".join(parts) if parts else "low-severity"

        return (
            f"Found {total} {'vulnerability' if total == 1 else 'vulnerabilities'} "
            f"({severity_str}) with a risk score of {self.risk_score}/100. "
            f"{'Fix the critical and high issues before deploying to production.' if self.critical_count or self.high_count else 'Address these issues to improve your security posture.'}"
        )

    # ── Serialisation ────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "repo_url": self.repo_url,
            "scanned_at": self.scanned_at,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "summary": self.summary,
            "highest_severity": self.highest_severity,
            "finding_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": self.total_count,
            },
            "findings": self.findings,
            "frameworks": self.frameworks,
            "repo_context": self.repo_context,
            "files_scanned": self.files_scanned,
            "scan_ms": self.scan_ms,
            "models_used": self.models_used,
            "share_url": self.share_url,
        }

    @classmethod
    def from_engine_result(
        cls,
        scan_id: str,
        repo_url: str | None,
        result: dict,
        base_url: str = "https://vibesafe.dev",
    ) -> "ScanReport":
        """Build a ScanReport from the raw dict returned by VibeSafeEngine."""
        return cls(
            scan_id=scan_id,
            repo_url=repo_url,
            risk_score=result["risk_score"],
            verdict=result["verdict"],
            findings=result["findings"],
            frameworks=result.get("frameworks", []),
            repo_context=result.get("repo_context", {}),
            files_scanned=result.get("files_scanned", 0),
            scan_ms=result.get("scan_ms", 0),
            share_url=f"{base_url}/report/{scan_id}",
            models_used=result.get("models_used", []),
        )
