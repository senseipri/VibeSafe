from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vibesafe.api.db import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    repo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # queued | running | complete | failed
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    scan_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    frameworks: Mapped[list] = mapped_column(JSON, default=list)
    repo_context: Mapped[dict] = mapped_column(JSON, default=dict)
    models_used: Mapped[list] = mapped_column(JSON, default=list)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), onupdate=func.now(), nullable=True
    )

    findings: Mapped[list[ScanFinding]] = relationship(
        "ScanFinding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "repo_url": self.repo_url,
            "status": self.status,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "files_scanned": self.files_scanned,
            "scan_ms": self.scan_ms,
            "frameworks": self.frameworks or [],
            "repo_context": self.repo_context or {},
            "models_used": self.models_used or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    # critical | high | medium | low
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="candidate")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    line_number: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[str] = mapped_column(Text, default="")
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    proof: Mapped[dict] = mapped_column(JSON, default=dict)
    description: Mapped[str] = mapped_column(Text, default="")
    attack_chain: Mapped[str] = mapped_column(Text, default="")
    fix_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Remediation fields — populated for confirmed and needs_review findings
    recommendation: Mapped[str] = mapped_column(Text, default="", server_default="")
    fix: Mapped[str] = mapped_column(Text, default="", server_default="")
    # fix_source: "static_table" | "llm_kimi" | "llm_fallback" | ""
    fix_source: Mapped[str] = mapped_column(String(30), default="", server_default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    confirmed_by: Mapped[list] = mapped_column(JSON, default=list)
    validator: Mapped[str | None] = mapped_column(String(100), nullable=True)
    owasp_cat: Mapped[str | None] = mapped_column(String(100), nullable=True)
    false_positive_risk: Mapped[str] = mapped_column(String(20), default="low")

    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "scan_id": str(self.scan_id),
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "evidence_refs": self.evidence_refs or [],
            "proof": self.proof or {},
            "description": self.description,
            "attack_chain": self.attack_chain,
            "fix_code": self.fix_code,
            "recommendation": self.recommendation or "",
            "fix": self.fix or "",
            "fix_source": self.fix_source or "",
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "confirmed_by": self.confirmed_by or [],
            "validator": self.validator,
            "owasp_cat": self.owasp_cat,
            "false_positive_risk": self.false_positive_risk,
        }
