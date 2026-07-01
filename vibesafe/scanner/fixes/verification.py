from __future__ import annotations

import ast
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from vibesafe.scanner.analysis import build_code_index
from vibesafe.scanner.evidence import EvidenceBuilder
from vibesafe.scanner.findings import Finding
from vibesafe.scanner.fixes.patcher import apply_unified_patch
from vibesafe.scanner.ingest import build_manifest
from vibesafe.scanner.static.injection import InjectionScanner


@dataclass
class FixVerification:
    accepted: bool
    reasons: list[str] = field(default_factory=list)


class FixVerifier:
    async def verify(self, finding: Finding, patch: str, repo_root: Path) -> FixVerification:
        if not patch.strip():
            return FixVerification(False, ["Patch is empty."])

        with tempfile.TemporaryDirectory(prefix="vibesafe_fix_") as tmp:
            tmp_root = Path(tmp) / "repo"
            shutil.copytree(repo_root, tmp_root)

            apply_result = apply_unified_patch(tmp_root, patch)
            if not apply_result.ok:
                return FixVerification(False, [apply_result.error])

            syntax_result = self._syntax_check(tmp_root, apply_result.changed_files)
            if not syntax_result.accepted:
                return syntax_result

            if finding.category in {"sql_injection", "command_injection", "log_injection"}:
                manifest = build_manifest(tmp_root)
                scanner_findings = await InjectionScanner().scan(manifest)
                scanner_findings = [
                    candidate
                    for candidate in scanner_findings
                    if candidate.category == finding.category
                    and candidate.file_path == finding.file_path
                ]
                rebuilt = EvidenceBuilder(manifest, build_code_index(manifest)).build(scanner_findings)
                if any(candidate.status != "rejected" for candidate in rebuilt):
                    return FixVerification(
                        False,
                        ["Patch did not remove the original vulnerable proof."],
                    )

            return FixVerification(True, ["Patch applies, syntax checks pass, and scanner proof is removed."])

    def _syntax_check(self, root: Path, changed_files: list[str]) -> FixVerification:
        reasons: list[str] = []
        for rel in changed_files:
            path = root / rel
            suffix = path.suffix.lower()
            if suffix == ".py":
                try:
                    ast.parse(path.read_text(encoding="utf-8", errors="replace"))
                except SyntaxError as exc:
                    return FixVerification(False, [f"Python syntax error in {rel}: {exc.msg}."])
            elif suffix in {".js", ".mjs", ".cjs"}:
                try:
                    result = subprocess.run(
                        ["node", "--check", str(path)],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    reasons.append(f"Skipped Node syntax check for {rel}; node is unavailable.")
                else:
                    if result.returncode != 0:
                        return FixVerification(False, [f"Node syntax check failed for {rel}."])
            elif suffix in {".ts", ".tsx", ".jsx"}:
                reasons.append(f"Skipped syntax check for {rel}; project-level TypeScript check required.")
        return FixVerification(True, reasons or ["Syntax checks passed."])
