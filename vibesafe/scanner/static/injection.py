from __future__ import annotations

import logging
import re
from pathlib import Path

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.static.base import BaseScanner

logger = logging.getLogger(__name__)

# ── SQL Injection patterns ───────────────────────────────────────

PY_SQL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\.execute\s*\(\s*f["\']'), "execute(f-string SQL)"),
    (re.compile(r'\.execute\s*\(\s*["\'][^"\']*%[sd]'), "execute(%-format SQL)"),
    (re.compile(r'\.execute\s*\([^)]*\+\s*\w'), "execute(string concat SQL)"),
    (re.compile(r'\.raw\s*\(\s*f["\']'), "raw(f-string SQL) — Django ORM"),
    (re.compile(r'sqlalchemy\.text\s*\(\s*f["\']'), "text(f-string) — SQLAlchemy"),
    (re.compile(r'db\.execute\s*\(\s*f["\']'), "db.execute(f-string)"),
    (re.compile(r'cursor\.execute\s*\(\s*f["\']'), "cursor.execute(f-string)"),
    (re.compile(r'query\s*=\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)', re.IGNORECASE),
     "f-string SQL query"),
    (re.compile(r'["\'].*(?:SELECT|DELETE|UPDATE|INSERT)[^"\']*["\']\s*%\s*\w', re.IGNORECASE),
     "%-format SQL string"),
]

JS_SQL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\.query\s*\(\s*`[^`]*\$\{'), "query(template literal)"),
    (re.compile(r'\.execute\s*\(\s*`[^`]*\$\{'), "execute(template literal)"),
    (re.compile(r'\.raw\s*\(\s*`[^`]*\$\{'), "raw(template literal)"),
    (re.compile(r'\.query\s*\(\s*"[^"]*"\s*\+\s*'), "query(string concat SQL)"),
    (re.compile(r"\.query\s*\(\s*'[^']*'\s*\+\s*"), "query(string concat SQL)"),
    (re.compile(r'"(?:SELECT|DELETE|UPDATE|INSERT)[^"]*"\s*\+', re.IGNORECASE),
     "string concatenation SQL"),
    (re.compile(r"'(?:SELECT|DELETE|UPDATE|INSERT)[^']*'\s*\+", re.IGNORECASE),
     "string concatenation SQL"),
]

# ── Log Injection patterns ───────────────────────────────────────

PY_LOG_PATTERNS: list[re.Pattern] = [
    re.compile(
        r'(?:logger\.\w+|logging\.\w+|print)\s*\(\s*f["\'][^"\']*'
        r'\{(?:request|req|body|data|user|input|params|args|kwargs)',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:logger\.\w+|logging\.\w+)\s*\(\s*["\'][^"\']*%[sd][^"\']*["\']'
        r'\s*%\s*(?:request|req|body|data|user|input)',
        re.IGNORECASE,
    ),
]

JS_LOG_PATTERNS: list[re.Pattern] = [
    re.compile(
        r'console\.\w+\s*\(`[^`]*\$\{(?:req|request|body|data|user|input|params)',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:logger|log|winston|bunyan)\.\w+\s*\(`[^`]*\$\{(?:req|request|body|data)',
        re.IGNORECASE,
    ),
]

# CR/LF injection signals — presence of any of these in the same line or
# an adjacent string literal dramatically increases log-injection impact
# (newline injection, log-forging, SIEM parser exploitation).
CRLF_SIGNALS_RE = re.compile(
    r'(?:\\n|\\r|%0[aAdD]|\\x0[aAdD]|newline|crlf|line.?inject)',
    re.IGNORECASE,
)

# ── Command Injection ────────────────────────────────────────────

PY_CMD_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?:subprocess\.\w+|os\.system|os\.popen)\s*\(\s*f["\']'),
    re.compile(r'(?:subprocess\.\w+|os\.system)\s*\([^)]*\+\s*\w'),
    re.compile(r'shell=True.*\+\s*\w'),
]

JS_CMD_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?:child_process\.)?exec\s*\(\s*`[^`]*\$\{', re.IGNORECASE),
    re.compile(r'(?:child_process\.)?execSync\s*\(\s*`[^`]*\$\{', re.IGNORECASE),
    re.compile(r'(?:child_process\.)?spawn(?:Sync)?\s*\([^,]+,\s*\[[^\]]*\$\{', re.IGNORECASE),
    re.compile(r'(?:child_process\.)?exec(?:Sync)?\s*\([^)]*(?:req|request)\.(?:body|query|params|headers|cookies)', re.IGNORECASE),
    re.compile(r'(?:child_process\.)?spawn(?:Sync)?\s*\([^)]*(?:req|request)\.(?:body|query|params|headers|cookies)', re.IGNORECASE),
]
JS_DYNAMIC_CODE_PATTERNS: list[re.Pattern] = [
    re.compile(r'eval\s*\([^)]*(?:req|request)\.(?:body|query|params|headers|cookies)', re.IGNORECASE),
    re.compile(r'new\s+Function\s*\([^)]*(?:req|request)\.(?:body|query|params|headers|cookies)', re.IGNORECASE),
    re.compile(r'setTimeout\s*\(\s*(?:req|request)\.(?:body|query|params)\.', re.IGNORECASE),
    re.compile(r'setInterval\s*\(\s*(?:req|request)\.(?:body|query|params)\.', re.IGNORECASE),
]
JS_PATH_TRAVERSAL_PATTERNS: list[re.Pattern] = [
    re.compile(r'fs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\([^)]*(?:req|request)\.(?:body|query|params)', re.IGNORECASE),
]
PATH_SANITIZER_RE = re.compile(r'(?:path\.join|path\.resolve|normalize|basename|whitelist|safePath|safe_path)', re.IGNORECASE)


class InjectionScanner(BaseScanner):
    """
    Detects SQL injection, Log injection, and Command injection vulnerabilities.
    Severity: SQL injection=critical, Log injection=high, Command injection=critical.
    """

    async def scan(self, manifest: RepoManifest) -> list[Finding]:
        findings: list[Finding] = []

        for file_path in manifest.files:
            suffix = file_path.suffix.lower()
            rel = manifest.relative(file_path)
            content = self._read(file_path)
            if not content:
                continue

            lines = content.splitlines()

            if suffix == ".py":
                findings.extend(self._check_py_sql(lines, rel))
                findings.extend(self._check_py_log(lines, rel))
                findings.extend(self._check_py_cmd(lines, rel))
            elif suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                findings.extend(self._check_js_sql(lines, rel))
                findings.extend(self._check_js_log(lines, rel))
                findings.extend(self._check_js_cmd(lines, rel))
                findings.extend(self._check_js_dynamic_code(lines, rel))
                findings.extend(self._check_js_path_traversal(lines, rel))

        return findings

    # ── Python checks ──────────────────────────────────────────

    def _check_py_sql(self, lines: list[str], rel: str) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            for pattern, label in PY_SQL_PATTERNS:
                if pattern.search(line):
                    findings.append(self._make_finding(
                        category="sql_injection",
                        severity="critical",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            f"SQL injection via {label} in {rel}:{lineno}. "
                            "User input is directly interpolated into a SQL query. "
                            "An attacker can submit a payload like `' OR 1=1 --` to dump "
                            "your entire database or bypass authentication."
                        ),
                        false_positive_risk="low",
                    ))
                    break
        return findings

    def _check_py_log(self, lines: list[str], rel: str) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            for pattern in PY_LOG_PATTERNS:
                if pattern.search(line):
                    f = self._make_finding(
                        category="log_injection",
                        severity="high",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            f"Log injection in {rel}:{lineno}. Raw user input is written to logs. "
                            "An attacker can inject newlines to forge fake log entries, "
                            "hide their tracks, or exploit log parsers and SIEM systems."
                        ),
                        false_positive_risk="medium",
                    )
                    # Without an explicit CR/LF or newline signal the impact is
                    # theoretical. Downgrade to needs_review to reduce noise.
                    if not CRLF_SIGNALS_RE.search(line):
                        f.status = "needs_review"
                    findings.append(f)
                    break
        return findings

    def _check_py_cmd(self, lines: list[str], rel: str) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            for pattern in PY_CMD_PATTERNS:
                if pattern.search(line):
                    findings.append(self._make_finding(
                        category="command_injection",
                        severity="critical",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            f"Command injection in {rel}:{lineno}. "
                            "User-controlled input is passed to a shell command. "
                            "An attacker can execute arbitrary OS commands on your server."
                        ),
                        false_positive_risk="low",
                    ))
                    break
        return findings

    # ── JS/TS checks ───────────────────────────────────────────

    def _check_js_sql(self, lines: list[str], rel: str) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            for pattern, label in JS_SQL_PATTERNS:
                if pattern.search(line):
                    findings.append(self._make_finding(
                        category="sql_injection",
                        severity="critical",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            f"SQL injection via {label} in {rel}:{lineno}. "
                            "Template literals or string concatenation in SQL queries allow "
                            "attackers to manipulate the query and access any data in your database."
                        ),
                        false_positive_risk="low",
                    ))
                    break
        return findings

    def _check_js_log(self, lines: list[str], rel: str) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            for pattern in JS_LOG_PATTERNS:
                if pattern.search(line):
                    f = self._make_finding(
                        category="log_injection",
                        severity="high",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            f"Log injection in {rel}:{lineno}. "
                            "User input is logged without sanitisation. "
                            "Attackers can forge log entries or break log parsers."
                        ),
                        false_positive_risk="medium",
                    )
                    if not CRLF_SIGNALS_RE.search(line):
                        f.status = "needs_review"
                    findings.append(f)
                    break
        return findings

    def _check_js_cmd(self, lines: list[str], rel: str) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            for pattern in JS_CMD_PATTERNS:
                if pattern.search(line):
                    findings.append(self._make_finding(
                        category="command_injection",
                        severity="critical",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            f"Command injection in {rel}:{lineno}. "
                            "User-controlled data reaches exec/spawn. "
                            "An attacker can run arbitrary commands on your server."
                        ),
                        false_positive_risk="low",
                    ))
                    break
        return findings

    def _check_js_dynamic_code(self, lines: list[str], rel: str) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            for pattern in JS_DYNAMIC_CODE_PATTERNS:
                if pattern.search(line):
                    findings.append(self._make_finding(
                        category="unsafe_dynamic_code",
                        severity="high",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            f"Unsafe dynamic code execution in {rel}:{lineno}. "
                            "User-controlled input appears to reach eval, Function, or a string-based timer."
                        ),
                        false_positive_risk="low",
                    ))
                    break
        return findings

    def _check_js_path_traversal(self, lines: list[str], rel: str) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue
            if PATH_SANITIZER_RE.search(line):
                continue
            for pattern in JS_PATH_TRAVERSAL_PATTERNS:
                if pattern.search(line):
                    findings.append(self._make_finding(
                        category="path_traversal",
                        severity="high",
                        file_path=rel,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        description=(
                            f"Path traversal risk in {rel}:{lineno}. "
                            "User-controlled input appears to reach filesystem access without clear validation."
                        ),
                        false_positive_risk="medium",
                    ))
                    break
        return findings
