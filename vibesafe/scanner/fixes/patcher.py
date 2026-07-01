from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PatchApplyResult:
    ok: bool
    changed_files: list[str]
    error: str = ""


def apply_unified_patch(root: Path, patch: str) -> PatchApplyResult:
    changed_files: list[str] = []
    blocks = _split_file_blocks(patch)
    if not blocks:
        return PatchApplyResult(ok=False, changed_files=[], error="Patch has no file blocks.")

    for old_path, new_path, hunks in blocks:
        rel = _clean_patch_path(new_path or old_path)
        if not rel:
            return PatchApplyResult(ok=False, changed_files=changed_files, error="Patch target is missing.")

        target = (root / rel).resolve()
        if not str(target).startswith(str(root.resolve())):
            return PatchApplyResult(ok=False, changed_files=changed_files, error="Patch target escapes repo root.")
        if not target.exists():
            return PatchApplyResult(ok=False, changed_files=changed_files, error=f"Patch target does not exist: {rel}")

        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        next_lines = _apply_hunks(lines, hunks)
        if next_lines is None:
            return PatchApplyResult(ok=False, changed_files=changed_files, error=f"Could not apply patch to {rel}.")

        target.write_text("\n".join(next_lines) + ("\n" if lines else ""), encoding="utf-8")
        changed_files.append(rel)

    return PatchApplyResult(ok=True, changed_files=changed_files)


def _split_file_blocks(patch: str) -> list[tuple[str, str, list[list[str]]]]:
    lines = patch.splitlines()
    blocks: list[tuple[str, str, list[list[str]]]] = []
    i = 0
    while i < len(lines):
        if not lines[i].startswith("--- "):
            i += 1
            continue
        old_path = lines[i][4:].strip()
        i += 1
        if i >= len(lines) or not lines[i].startswith("+++ "):
            continue
        new_path = lines[i][4:].strip()
        i += 1
        hunks: list[list[str]] = []
        while i < len(lines) and not lines[i].startswith("--- "):
            if lines[i].startswith("@@"):
                hunk = [lines[i]]
                i += 1
                while i < len(lines) and not lines[i].startswith("@@") and not lines[i].startswith("--- "):
                    hunk.append(lines[i])
                    i += 1
                hunks.append(hunk)
            else:
                i += 1
        blocks.append((old_path, new_path, hunks))
    return blocks


def _clean_patch_path(path: str) -> str:
    path = path.split("\t", 1)[0].strip()
    if path in {"/dev/null", ""}:
        return ""
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    return path.replace("/", "\\")


def _apply_hunks(lines: list[str], hunks: list[list[str]]) -> list[str] | None:
    result = list(lines)
    offset = 0
    for hunk in hunks:
        header = hunk[0]
        match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", header)
        if not match:
            return None
        old_start = int(match.group(1)) - 1 + offset
        cursor = max(old_start, 0)

        for raw_line in hunk[1:]:
            if raw_line == "\\ No newline at end of file":
                continue
            if not raw_line:
                prefix, text = " ", ""
            else:
                prefix, text = raw_line[0], raw_line[1:]
            if prefix == " ":
                if cursor >= len(result) or result[cursor] != text:
                    found = _find_line(result, text, cursor)
                    if found is None:
                        return None
                    cursor = found
                cursor += 1
            elif prefix == "-":
                if cursor >= len(result) or result[cursor] != text:
                    found = _find_line(result, text, cursor)
                    if found is None:
                        return None
                    cursor = found
                result.pop(cursor)
                offset -= 1
            elif prefix == "+":
                result.insert(cursor, text)
                cursor += 1
                offset += 1
            else:
                return None
    return result


def _find_line(lines: list[str], text: str, start: int) -> int | None:
    for idx in range(max(start, 0), len(lines)):
        if lines[idx] == text:
            return idx
    return None
