from __future__ import annotations

import asyncio
import logging
import re
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vibesafe.api.config import get_settings
from vibesafe.api.db import get_db
from vibesafe.api.models import Scan, ScanFinding
from vibesafe.scanner.engine import ScanError, VibeSafeEngine
from vibesafe.scanner.report import ScanReport

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["scan"])
settings = get_settings()

GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+/?$"
)
MAX_ZIP_BYTES = settings.max_repo_size_mb * 1024 * 1024


def _llm_enabled() -> bool:
    return bool(settings.google_api_key or settings.groq_api_key)


# ── Request / Response schemas ───────────────────────────────────

class GithubScanRequest(BaseModel):
    repo_url: str
    github_token: str = ""

    @field_validator("repo_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not GITHUB_URL_RE.match(v):
            raise ValueError(
                "repo_url must be a valid GitHub repository URL "
                "(e.g. https://github.com/owner/repo)"
            )
        return v


class ScanQueuedResponse(BaseModel):
    scan_id: str
    status: str
    poll_url: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    risk_score: int | None
    verdict: str | None
    files_scanned: int
    findings_count: int
    error_message: str | None


# ── Endpoints ────────────────────────────────────────────────────

@router.post(
    "/scan/github",
    response_model=ScanQueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def scan_github(
    body: GithubScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> ScanQueuedResponse:
    """
    Queue a scan for a public (or token-accessible) GitHub repository.
    Returns immediately with a scan_id. Poll /api/scan/{scan_id}/status.
    """
    scan_id = str(uuid.uuid4())
    scan = Scan(id=uuid.UUID(scan_id), repo_url=body.repo_url, status="queued")
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(
        _run_scan_task,
        scan_id=scan_id,
        repo_url=body.repo_url,
        github_token=body.github_token,
    )

    return ScanQueuedResponse(
        scan_id=scan_id,
        status="queued",
        poll_url=f"/api/scan/{scan_id}/status",
    )


@router.post(
    "/scan/upload",
    response_model=ScanQueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def scan_upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
) -> ScanQueuedResponse:
    """
    Queue a scan for an uploaded zip file.
    Validates magic bytes (PK\\x03\\x04) before accepting.
    """
    # Validate it is actually a zip by checking magic bytes
    header = await file.read(4)
    if header[:4] != b"PK\x03\x04":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a valid ZIP archive.",
        )
    await file.seek(0)

    # Stream to a temp file (avoids loading whole zip into memory)
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp_path = Path(tmp.name)
    total = 0
    try:
        while chunk := await file.read(64 * 1024):
            total += len(chunk)
            if total > MAX_ZIP_BYTES:
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"ZIP file exceeds maximum size of {settings.max_repo_size_mb}MB.",
                )
            tmp.write(chunk)
    finally:
        tmp.close()

    scan_id = str(uuid.uuid4())
    scan = Scan(id=uuid.UUID(scan_id), repo_url=None, status="queued")
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(
        _run_zip_scan_task,
        scan_id=scan_id,
        zip_path=tmp_path,
    )

    return ScanQueuedResponse(
        scan_id=scan_id,
        status="queued",
        poll_url=f"/api/scan/{scan_id}/status",
    )


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> ScanStatusResponse:
    """Poll this endpoint every 2 seconds until status == 'complete' or 'failed'."""
    scan = await _get_scan_or_404(scan_id, db)

    findings_count = 0
    if scan.status == "complete":
        result = await db.execute(
            select(ScanFinding).where(ScanFinding.scan_id == scan.id)
        )
        findings_count = len(result.scalars().all())

    return ScanStatusResponse(
        scan_id=str(scan.id),
        status=scan.status,
        risk_score=scan.risk_score,
        verdict=scan.verdict,
        files_scanned=scan.files_scanned,
        findings_count=findings_count,
        error_message=scan.error_message,
    )


@router.get("/report/{scan_id}")
async def get_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Fetch the full JSON report for a completed scan."""
    scan = await _get_scan_or_404(scan_id, db)

    if scan.status != "complete":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is not complete yet (current status: {scan.status}).",
        )

    result = await db.execute(
        select(ScanFinding)
        .where(ScanFinding.scan_id == scan.id)
        .order_by(
            # Order: critical > high > medium > low
            ScanFinding.severity.desc()
        )
    )
    findings = result.scalars().all()

    report = ScanReport(
        scan_id=str(scan.id),
        repo_url=scan.repo_url,
        risk_score=scan.risk_score or 0,
        verdict=scan.verdict or "UNKNOWN",
        findings=[f.to_dict() for f in findings],
        frameworks=scan.frameworks or [],
        repo_context=scan.repo_context or {},
        files_scanned=scan.files_scanned,
        scan_ms=scan.scan_ms or 0,
        share_url=f"https://vibesafe.dev/report/{scan_id}",
        models_used=scan.models_used or [],
    )

    return report.to_dict()


# ── Background tasks ─────────────────────────────────────────────

async def _run_scan_task(scan_id: str, repo_url: str, github_token: str) -> None:
    """Background task: run the full scan and persist results."""
    from vibesafe.api.db import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        try:
            # Mark as running
            scan = await _get_scan_by_id(scan_id, db)
            scan.status = "running"
            await db.commit()

            # Run the engine
            use_llm = _llm_enabled()
            engine = VibeSafeEngine(use_llm=use_llm)
            result = await asyncio.wait_for(
                engine.scan_url(repo_url, github_token),
                timeout=settings.scan_timeout_seconds,
            )

            # Persist findings
            await _persist_results(scan, result, db)

        except asyncio.TimeoutError:
            await _mark_failed(scan_id, db, "Scan timed out. Repository may be too large.")
        except ScanError as exc:
            await _mark_failed(scan_id, db, str(exc))
        except Exception as exc:
            logger.exception("Unexpected error during scan %s: %s", scan_id, exc)
            await _mark_failed(scan_id, db, "An unexpected error occurred during scanning.")


async def _run_zip_scan_task(scan_id: str, zip_path: Path) -> None:
    """Background task: run scan on an uploaded zip file."""
    from vibesafe.api.db import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        try:
            scan = await _get_scan_by_id(scan_id, db)
            scan.status = "running"
            await db.commit()

            engine = VibeSafeEngine(use_llm=_llm_enabled())
            result = await asyncio.wait_for(
                engine.scan_zip(zip_path),
                timeout=settings.scan_timeout_seconds,
            )

            await _persist_results(scan, result, db)

        except asyncio.TimeoutError:
            await _mark_failed(scan_id, db, "Scan timed out.")
        except ScanError as exc:
            await _mark_failed(scan_id, db, str(exc))
        except Exception as exc:
            logger.exception("Unexpected error during zip scan %s: %s", scan_id, exc)
            await _mark_failed(scan_id, db, "An unexpected error occurred.")
        finally:
            zip_path.unlink(missing_ok=True)


# ── Helpers ──────────────────────────────────────────────────────

async def _persist_results(scan: Scan, result: dict, db: AsyncSession) -> None:
    """Save findings to DB and mark scan complete."""
    scan.status = "complete"
    scan.risk_score = result["risk_score"]
    scan.verdict = result["verdict"]
    scan.files_scanned = result["files_scanned"]
    scan.scan_ms = result["scan_ms"]
    scan.frameworks = result.get("frameworks", [])
    scan.repo_context = result.get("repo_context", {})
    scan.models_used = result.get("models_used", [])

    for f_dict in result["findings"]:
        finding = ScanFinding(
            scan_id=scan.id,
            category=f_dict["category"],
            severity=f_dict["severity"],
            status=f_dict.get("status", "candidate"),
            confidence=f_dict.get("confidence", 0.0),
            file_path=f_dict["file_path"],
            line_number=f_dict["line_number"],
            evidence=f_dict["evidence"],
            evidence_refs=f_dict.get("evidence_refs", []),
            proof=f_dict.get("proof", {}),
            description=f_dict["description"],
            attack_chain=f_dict.get("attack_chain", ""),
            fix_code=f_dict.get("fix_code"),
            recommendation=f_dict.get("recommendation", ""),
            fix=f_dict.get("fix", ""),
            fix_source=f_dict.get("fix_source", ""),
            cvss_score=f_dict.get("cvss_score"),
            cvss_vector=f_dict.get("cvss_vector"),
            confirmed_by=f_dict.get("confirmed_by", []),
            validator=f_dict.get("validator"),
            owasp_cat=f_dict.get("owasp_cat"),
            false_positive_risk=f_dict.get("false_positive_risk", "low"),
        )
        db.add(finding)

    await db.commit()
    logger.info("Scan %s persisted: risk=%d findings=%d", scan.id, scan.risk_score, len(result["findings"]))


async def _mark_failed(scan_id: str, db: AsyncSession, message: str) -> None:
    try:
        scan = await _get_scan_by_id(scan_id, db)
        scan.status = "failed"
        scan.error_message = message
        await db.commit()
    except Exception as exc:
        logger.error("Could not mark scan %s as failed: %s", scan_id, exc)


async def _get_scan_or_404(scan_id: str, db: AsyncSession) -> Scan:
    try:
        uid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    result = await db.execute(select(Scan).where(Scan.id == uid))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


async def _get_scan_by_id(scan_id: str, db: AsyncSession) -> Scan:
    uid = uuid.UUID(scan_id)
    result = await db.execute(select(Scan).where(Scan.id == uid))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise RuntimeError(f"Scan {scan_id} not found in database.")
    return scan
