from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Abstract base for all static scanners.
    Each scanner receives a RepoManifest and returns a list of Findings.
    Scanners must handle all exceptions internally — a crash in one scanner
    must not stop the rest of the scan.
    """

    @abstractmethod
    async def scan(self, manifest: RepoManifest) -> list[Finding]:
        ...

    def _make_finding(self, **kwargs) -> Finding:
        return Finding(**kwargs)

    def _get_lines(self, file_path: Path) -> list[str]:
        """Read a file and return lines. Returns [] on any error."""
        try:
            return file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

    def _read(self, file_path: Path) -> str:
        """Read a file as string. Returns '' on any error."""
        try:
            return file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _is_safe_reference(self, line: str) -> bool:
        """Return True if the line is safely referencing an env var, not hardcoding."""
        safe_patterns = [
            "os.environ",
            "os.getenv",
            "process.env",
            "import.meta.env",
            "${",
            "getenv(",
            "environ.get(",
        ]
        return any(p in line for p in safe_patterns)

    def _is_comment(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*")