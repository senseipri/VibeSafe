from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.static.base import BaseScanner

logger = logging.getLogger(__name__)

# Detect CREATE TABLE in SQL files
SQL_CREATE_TABLE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"']?(\w+)[\"']?", re.IGNORECASE)
SQL_RLS_ENABLE = re.compile(r"ENABLE\s+ROW\s+LEVEL\s+SECURITY", re.IGNORECASE)
SQL_RLS_ALTER = re.compile(r"ALTER\s+TABLE\s+[\"']?(\w+)[\"']?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", re.IGNORECASE)

# Firebase / Firestore rules
FIREBASE_PUBLIC_READ_WRITE = re.compile(
    r"allow\s+read\s*,\s*write\s*:\s*if\s+true", re.IGNORECASE
)
FIREBASE_PUBLIC_READ = re.compile(r"allow\s+read\s*:\s*if\s+true", re.IGNORECASE)
FIREBASE_PUBLIC_WRITE = re.compile(r"allow\s+write\s*:\s*if\s+true", re.IGNORECASE)

# Realtime database rules  {".read": true}  or  {".write": true}
RTDB_PUBLIC = re.compile(r'"\.(?:read|write)"\s*:\s*"?true"?')

# Supabase client: createClient with anon key doing writes
SUPABASE_CLIENT = re.compile(r"createClient\s*\(")
SUPABASE_ANON_KEY = re.compile(r'["\']eyJ[A-Za-z0-9_\-]{40,}["\']')
SUPABASE_WRITE_OP = re.compile(r"\.(?:insert|update|delete|upsert)\s*\(")

# JWT/weak secret
JWT_WEAK = re.compile(
    r'(?:jwt\.sign|sign)\s*\([^,]+,\s*["\'](?!process\.env)(?!\$\{)[^"\']{1,25}["\']',
    re.IGNORECASE,
)
JWT_ALG_NONE = re.compile(r'algorithm\s*[=:]\s*["\']none["\']', re.IGNORECASE)
JWT_HS256_SHORT = re.compile(
    r'(?:jwt\.verify|verify)\s*\([^,]+,\s*["\'](?!process\.env)[^"\']{1,20}["\']'
)


class DBConfigScanner(BaseScanner):
    """
    Detects database misconfigurations:
    - Supabase: Row Level Security (RLS) not enabled on tables
    - Firebase: Permissive public read/write rules
    - JWT: weak secrets or insecure algorithms
    """

    async def scan(self, manifest: RepoManifest) -> list[Finding]:
        findings: list[Finding] = []

        for file_path in manifest.files:
            rel = manifest.relative(file_path)
            name = file_path.name
            suffix = file_path.suffix.lower()

            if suffix == ".sql":
                findings.extend(self._scan_sql(file_path, rel))

            elif name in ("firestore.rules", "storage.rules"):
                findings.extend(self._scan_firestore_rules(file_path, rel))

            elif name in ("firebase.json", "database.rules.json"):
                findings.extend(self._scan_firebase_json(file_path, rel))

            elif suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
                findings.extend(self._scan_js(file_path, rel))

            elif suffix == ".py":
                findings.extend(self._scan_py(file_path, rel))

        return findings

    # ── Supabase SQL migrations ─────────────────────────────────

    def _scan_sql(self, file_path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        content = self._read(file_path)
        if not content:
            return findings

        # Find all table names created in this file
        created_tables: dict[str, int] = {}
        for m in SQL_CREATE_TABLE.finditer(content):
            table_name = m.group(1)
            line_num = content[: m.start()].count("\n") + 1
            # Skip system / internal tables
            if table_name.lower() in ("schema_migrations", "ar_internal_metadata", "spatial_ref_sys"):
                continue
            created_tables[table_name.lower()] = line_num

        if not created_tables:
            return findings

        # Find tables that have RLS enabled
        rls_enabled: set[str] = set()
        for m in SQL_RLS_ALTER.finditer(content):
            rls_enabled.add(m.group(1).lower())

        # Also check for generic ENABLE ROW LEVEL SECURITY
        has_any_rls = bool(SQL_RLS_ENABLE.search(content))

        for table_name, lineno in created_tables.items():
            if table_name in rls_enabled:
                continue
            if has_any_rls and len(created_tables) == 1:
                # Single table with RLS somewhere — probably fine
                continue

            findings.append(self._make_finding(
                category="rls_disabled",
                severity="high",
                file_path=rel,
                line_number=lineno,
                evidence=f"CREATE TABLE {table_name} — ENABLE ROW LEVEL SECURITY not found",
                description=(
                    f"Supabase table '{table_name}' does not have Row Level Security (RLS) enabled. "
                    "Anyone with the anon/public key can read and write all rows in this table. "
                    "This was the exact vulnerability in the Moltbook breach (1.5M tokens exposed). "
                    f"Fix: ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY; "
                    f"then CREATE POLICY ... ON {table_name} ..."
                ),
                false_positive_risk="medium",
            ))

        return findings

    # ── Firestore / Storage rules ───────────────────────────────

    def _scan_firestore_rules(self, file_path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        content = self._read(file_path)
        if not content:
            return findings

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if FIREBASE_PUBLIC_READ_WRITE.search(line):
                findings.append(self._make_finding(
                    category="firebase_public",
                    severity="critical",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        "Firebase security rule 'allow read, write: if true' grants public "
                        "read AND write access to this collection. Anyone on the internet can "
                        "read all your data and overwrite or delete it. "
                        "Fix: replace with auth-based rules, e.g., 'if request.auth != null'."
                    ),
                    false_positive_risk="low",
                ))
            elif FIREBASE_PUBLIC_READ.search(line):
                findings.append(self._make_finding(
                    category="firebase_public",
                    severity="high",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        "Firebase rule 'allow read: if true' makes this collection publicly readable. "
                        "Any unauthenticated user can read all documents. "
                        "Fix: restrict to authenticated users or specific conditions."
                    ),
                    false_positive_risk="low",
                ))
            elif FIREBASE_PUBLIC_WRITE.search(line):
                findings.append(self._make_finding(
                    category="firebase_public",
                    severity="critical",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        "Firebase rule 'allow write: if true' lets anyone write to this collection. "
                        "Attackers can corrupt, delete, or inject malicious data. "
                        "Fix: require authentication and validate data structure."
                    ),
                    false_positive_risk="low",
                ))

        return findings

    def _scan_firebase_json(self, file_path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        content = self._read(file_path)
        if not content:
            return findings

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if RTDB_PUBLIC.search(line):
                key = ".read" if ".read" in line else ".write"
                findings.append(self._make_finding(
                    category="firebase_public",
                    severity="critical",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        f"Firebase Realtime Database rule '{key}: true' grants public "
                        f"{'read' if 'read' in key else 'write'} access to your entire database. "
                        "Fix: set rules to {'.read': 'auth != null', '.write': 'auth != null'}."
                    ),
                    false_positive_risk="low",
                ))

        return findings

    # ── JS/TS: Supabase anon-key writes + JWT issues ────────────

    def _scan_js(self, file_path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        content = self._read(file_path)
        if not content:
            return findings

        lines = content.splitlines()

        has_supabase_client = bool(SUPABASE_CLIENT.search(content))
        has_anon_key = bool(SUPABASE_ANON_KEY.search(content))
        has_write_op = bool(SUPABASE_WRITE_OP.search(content))

        if has_supabase_client and has_anon_key and has_write_op:
            # Find the line with createClient
            for lineno, line in enumerate(lines, start=1):
                if SUPABASE_CLIENT.search(line):
                    findings.append(self._make_finding(
                        category="supabase_anon_write",
                        severity="medium",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            "Supabase client using anon/public key is performing write operations. "
                            "If RLS is not enabled on the target tables, any user can write data. "
                            "Ensure RLS is enabled and policies restrict writes to authenticated users."
                        ),
                        false_positive_risk="medium",
                    ))
                    break

        # JWT weak secret in JS
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line) or self._is_safe_reference(line):
                continue
            if JWT_ALG_NONE.search(line):
                findings.append(self._make_finding(
                    category="weak_jwt",
                    severity="critical",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        "JWT algorithm set to 'none'. This disables signature verification — "
                        "any token will be accepted as valid regardless of its contents. "
                        "Attackers can forge tokens with any claims they want."
                    ),
                    false_positive_risk="low",
                ))
            elif JWT_WEAK.search(line):
                findings.append(self._make_finding(
                    category="weak_jwt",
                    severity="high",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        "JWT secret appears to be a short hardcoded string. "
                        "Secrets under 32 characters can be brute-forced. "
                        "Use a cryptographically random secret of at least 256 bits "
                        "and store it in an environment variable."
                    ),
                    false_positive_risk="medium",
                ))

        return findings

    # ── Python: JWT issues ──────────────────────────────────────

    def _scan_py(self, file_path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        content = self._read(file_path)
        if not content:
            return findings

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line) or self._is_safe_reference(line):
                continue

            if JWT_ALG_NONE.search(line):
                findings.append(self._make_finding(
                    category="weak_jwt",
                    severity="critical",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        "JWT algorithm='none' completely disables token signature verification. "
                        "An attacker can craft any token and it will be accepted. "
                        "Always use HS256 with a strong secret or RS256 with a key pair."
                    ),
                    false_positive_risk="low",
                ))

        return findings