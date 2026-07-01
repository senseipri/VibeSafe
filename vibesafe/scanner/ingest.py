"""
Repo ingestion: clone GitHub URLs or extract zip files.
All operations are sandboxed to an isolated tmpdir that is cleaned up after the scan.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

import git

# File extensions to scan (source code only)
SCAN_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
        ".go", ".rb", ".java", ".php", ".cs", ".rs", ".swift",
        ".json", ".yaml", ".yml", ".env", ".toml", ".ini", ".cfg",
        ".sql", ".sh", ".bash", ".zsh",
    }
)

# Directories to always skip
SKIP_DIRS: frozenset[str] = frozenset(
    {
        "node_modules", ".git", "__pycache__", ".pytest_cache",
        "dist", "build", ".next", ".nuxt", "out", "coverage",
        ".venv", "venv", "env", ".env", "vendor",
        ".mypy_cache", ".ruff_cache", "htmlcov",
    }
)

# Files to skip
SKIP_FILES: frozenset[str] = frozenset(
    {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "Pipfile.lock", "Gemfile.lock",
        ".DS_Store", "*.min.js", "*.min.css",
    }
)

GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?(?:/.*)?$"
)

MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # 1MB per file


class IngestError(Exception):
    pass


class RepoManifest:
    """Holds the list of source files from an ingested repo."""

    def __init__(self, root: Path, files: list[Path]) -> None:
        self.root = root
        self.files = files

    def __len__(self) -> int:
        return len(self.files)

    def read(self, file_path: Path) -> str:
        """Read a file, returning empty string on decode errors."""
        try:
            return file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def relative(self, file_path: Path) -> str:
        try:
            return str(file_path.relative_to(self.root))
        except ValueError:
            return str(file_path)
def _should_skip(path: Path) -> bool:
    """Return True if this path should be excluded from scanning."""
    for part in path.parent.parts:
        if part in SKIP_DIRS:
            return True
    if path.name in SKIP_FILES:
        return True
    is_env_variant = path.name == ".env" or path.name.startswith(".env.")
    if path.suffix.lower() not in SCAN_EXTENSIONS and not is_env_variant:
        return True
    return False
def _enumerate_files(root: Path, max_files: int = 500) -> list[Path]:
    """Walk a directory and return scannable source files."""
    files: list[Path] = []
    for entry in root.rglob("*"):
        if not entry.is_file():
            continue
        if _should_skip(entry.relative_to(root)):
            continue
        if entry.stat().st_size > MAX_FILE_SIZE_BYTES:
            continue
        files.append(entry)
        if len(files) >= max_files:
            break
    return files


def clone_github_repo(
    url: str,
    github_token: str = "",
    max_size_mb: int = 150,
) -> tuple[Path, Path]:
    """
    Clone a GitHub repo to an isolated tmpdir.
    Returns (tmpdir, repo_root) — caller MUST clean up tmpdir.
    Raises IngestError on failure.
    """
    match = GITHUB_URL_PATTERN.match(url.strip())
    if not match:
        raise IngestError(
            f"Invalid GitHub URL: {url!r}. Expected format: https://github.com/owner/repo"
        )

    owner, repo = match.group(1), match.group(2)

    # Build clone URL — inject token if provided
    if github_token:
        clone_url = f"https://{github_token}@github.com/{owner}/{repo}.git"
    else:
        clone_url = f"https://github.com/{owner}/{repo}.git"

    tmpdir = Path(tempfile.mkdtemp(prefix="vibesafe_"))
    repo_path = tmpdir / repo

    try:
        git.Repo.clone_from(
            clone_url,
            str(repo_path),
            depth=1,           # shallow clone — only latest commit
            no_single_branch=False,
        )
    except git.exc.GitCommandError as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        msg = str(e)
        if "not found" in msg.lower() or "repository" in msg.lower():
            raise IngestError(f"Repository not found or private: {owner}/{repo}") from e
        raise IngestError(f"Failed to clone repository: {msg}") from e

    # Check repo size
    total_size = sum(f.stat().st_size for f in repo_path.rglob("*") if f.is_file())
    if total_size > max_size_mb * 1024 * 1024:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise IngestError(
            f"Repository too large: {total_size / 1024 / 1024:.1f}MB "
            f"(limit: {max_size_mb}MB)"
        )

    return tmpdir, repo_path


def extract_zip(zip_path: Path, max_size_mb: int = 150) -> tuple[Path, Path]:
    """
    Extract a zip file to an isolated tmpdir.
    Returns (tmpdir, extracted_root).
    Raises IngestError on failure.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="vibesafe_zip_"))
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Security: check for zip-slip attacks
            for member in zf.namelist():
                member_path = Path(member)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise IngestError(f"Malicious zip entry detected: {member!r}")

            # Check total uncompressed size
            total = sum(info.file_size for info in zf.infolist())
            if total > max_size_mb * 1024 * 1024:
                raise IngestError(
                    f"Zip contents too large: {total / 1024 / 1024:.1f}MB "
                    f"(limit: {max_size_mb}MB)"
                )

            zf.extractall(str(tmpdir))
    except zipfile.BadZipFile as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise IngestError(f"Invalid zip file: {e}") from e
    except IngestError:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise

    # If the zip has a single top-level directory, use that as root
    top_level = [p for p in tmpdir.iterdir() if p.is_dir()]
    if len(top_level) == 1:
        repo_root = top_level[0]
    else:
        repo_root = tmpdir

    return tmpdir, repo_root


def build_manifest(repo_root: Path, max_files: int = 500) -> RepoManifest:
    """Build a RepoManifest from a repo root directory."""
    files = _enumerate_files(repo_root, max_files)
    return RepoManifest(root=repo_root, files=files)


def cleanup(tmpdir: Path) -> None:
    """Remove the temporary directory created during ingestion."""
    shutil.rmtree(tmpdir, ignore_errors=True)


def detect_framework(manifest: RepoManifest) -> list[str]:
    """
    Detect the frameworks/technologies used in the repo.
    Used to tune scanner behaviour.
    """
    detected: list[str] = []
    file_names = {f.name for f in manifest.files}
    file_paths = {manifest.relative(f) for f in manifest.files}

    # Check for Node project indicators at root
    root_files = {f.name for f in manifest.root.iterdir() if f.is_file()}
    root_dirs = {f.name for f in manifest.root.iterdir() if f.is_dir()}

    if {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"} & root_files:
        detected.append("node")
        # Read package.json to detect JS frameworks
        pkg_json = manifest.root / "package.json"
        if pkg_json.exists():
            try:
                content = pkg_json.read_text()
                if '"next"' in content or '"next":' in content:
                    detected.append("nextjs")
                if '"express"' in content:
                    detected.append("express")
                if '"fastify"' in content:
                    detected.append("fastify")
                if '"react"' in content:
                    detected.append("react")
                if '"@nestjs/core"' in content:
                    detected.append("nestjs")
            except OSError:
                pass

    if {"next.config.js", "next.config.ts"} & root_files or {"app", "pages"} & root_dirs:
        detected.append("nextjs")

    if "pyproject.toml" in root_files or "requirements.txt" in root_files:
        detected.append("python")
        # Check for Python frameworks
        for fname in ["pyproject.toml", "requirements.txt"]:
            fpath = manifest.root / fname
            if fpath.exists():
                try:
                    content = fpath.read_text()
                    if "fastapi" in content.lower():
                        detected.append("fastapi")
                    if "django" in content.lower():
                        detected.append("django")
                    if "flask" in content.lower():
                        detected.append("flask")
                    if "celery" in content.lower():
                        detected.append("celery")
                    if "rq" in content.lower():
                        detected.append("rq")
                    if "sqlmodel" in content.lower():
                        detected.append("sqlmodel")
                except OSError:
                    pass

    # Check for Supabase
    has_supabase = any(
        "supabase" in str(p).lower() for p in file_paths
    )
    if has_supabase:
        detected.append("supabase")

    # Check for Firebase
    if "firebase.json" in file_names or "firestore.rules" in file_names:
        detected.append("firebase")

    return list(set(detected))
