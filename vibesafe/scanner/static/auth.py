from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.static.base import BaseScanner

logger = logging.getLogger(__name__)

HIGH_RISK_PATH_FRAGMENTS = [
    "/admin", "/user", "/users", "/account", "/accounts",
    "/settings", "/delete", "/remove", "/internal", "/dashboard",
    "/manage", "/management", "/panel", "/control",
]

AUTH_SIGNALS_PY = [
    "require_auth", "login_required", "auth_required",
    "get_current_user", "verify_token", "jwt_required",
    "token_required", "current_user", "authenticate",
    "Authorization", "Bearer", "HTTPBearer", "OAuth2",
    "Depends(", "Security(", "permission_required",
]

AUTH_SIGNALS_JS = [
    "authenticate", "requireAuth", "verifyToken", "isAuthenticated",
    "protect", "authMiddleware", "passport", "jwt.verify",
    "checkAuth", "ensureLoggedIn", "requireLogin", "auth(",
    "middleware", "authorization",
]

# Regex to find Python route decorators
PY_ROUTE_RE = re.compile(
    r'@(?:\w+\.)?(?:route|get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']'
)

# Regex to find JS/TS route definitions
JS_ROUTE_RE = re.compile(
    r'(?:router|app|server)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
)


def _is_high_risk_path(path: str) -> bool:
    path_lower = path.lower()
    return any(frag in path_lower for frag in HIGH_RISK_PATH_FRAGMENTS)


def _has_py_auth(source: str) -> bool:
    return any(sig in source for sig in AUTH_SIGNALS_PY)


def _has_js_auth(source: str) -> bool:
    return any(sig in source for sig in AUTH_SIGNALS_JS)


class AuthScanner(BaseScanner):
    """
    Detects routes/endpoints that are missing authentication middleware.
    Checks Python (FastAPI/Flask/Django) and JavaScript/TypeScript (Express).
    """

    async def scan(self, manifest: RepoManifest) -> list[Finding]:
        findings: list[Finding] = []

        for file_path in manifest.files:
            suffix = file_path.suffix.lower()
            if suffix == ".py":
                findings.extend(self._scan_python(file_path, manifest.relative(file_path)))
            elif suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                findings.extend(self._scan_js(file_path, manifest.relative(file_path)))

        return findings

    def _scan_python(self, file_path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        source = self._read(file_path)
        if not source:
            return findings

        # Quick check: does this file have any route definitions?
        if not PY_ROUTE_RE.search(source):
            return findings

        # Check if there are ANY auth signals in the whole file
        file_has_auth = _has_py_auth(source)

        # Try AST-based analysis for better accuracy
        try:
            tree = ast.parse(source)
            findings.extend(
                self._ast_check_python(tree, source, rel, file_has_auth)
            )
        except SyntaxError:
            # Fallback to regex if AST parse fails (e.g. for files with syntax errors)
            findings.extend(
                self._regex_check_python(source, rel, file_has_auth)
            )

        return findings

    def _ast_check_python(
        self, tree: ast.AST, source: str, rel: str, file_has_auth: bool
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = source.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Look for route decorators on this function
            route_path = None
            http_method = None
            func_has_auth = False

            for decorator in node.decorator_list:
                dec_src = ast.unparse(decorator) if hasattr(ast, "unparse") else ""

                # Check if this is a route decorator
                if any(
                    m in dec_src.lower()
                    for m in [".route(", ".get(", ".post(", ".put(", ".delete(", ".patch("]
                ):
                    # Extract path from decorator
                    if isinstance(decorator, ast.Call):
                        for arg in decorator.args:
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                route_path = arg.value
                        # Detect method
                        if isinstance(decorator.func, ast.Attribute):
                            http_method = decorator.func.attr.upper()

                # Check for auth signals in decorators
                if any(sig.lower() in dec_src.lower() for sig in AUTH_SIGNALS_PY):
                    func_has_auth = True

            if route_path is None:
                continue

            # Check function args for auth dependencies
            func_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if any(sig in func_src for sig in AUTH_SIGNALS_PY):
                func_has_auth = True

            if func_has_auth or file_has_auth:
                continue

            if not _is_high_risk_path(route_path):
                # Only flag medium for non-high-risk POST/PUT/DELETE
                if http_method not in ("POST", "PUT", "DELETE", "PATCH"):
                    continue
                severity = "medium"
            else:
                severity = "critical"

            findings.append(
                self._make_finding(
                    category="missing_auth",
                    severity=severity,
                    file_path=rel,
                    line_number=node.lineno,
                    evidence=f"@{http_method or 'route'}('{route_path}') — no auth",
                    description=(
                        f"Route '{route_path}' ({http_method or 'unknown method'}) has no "
                        "authentication middleware. Any unauthenticated user can access this "
                        "endpoint and read or modify protected data."
                    ),
                    false_positive_risk="medium",
                )
            )

        return findings

    def _regex_check_python(self, source: str, rel: str, file_has_auth: bool) -> list[Finding]:
        """Fallback regex-based check when AST fails."""
        if file_has_auth:
            return []

        findings: list[Finding] = []
        lines = source.splitlines()

        for lineno, line in enumerate(lines, start=1):
            m = PY_ROUTE_RE.search(line)
            if not m:
                continue
            route_path = m.group(1)

            if _is_high_risk_path(route_path):
                # Check surrounding lines (±5) for auth signals
                start = max(0, lineno - 5)
                end = min(len(lines), lineno + 5)
                context = "\n".join(lines[start:end])
                if not _has_py_auth(context):
                    findings.append(
                        self._make_finding(
                            category="missing_auth",
                            severity="critical",
                            file_path=rel,
                            line_number=lineno,
                            evidence=line.strip()[:200],
                            description=(
                                f"Route '{route_path}' appears to have no authentication. "
                                "Unprotected admin/user routes allow anyone to access sensitive data."
                            ),
                            false_positive_risk="medium",
                        )
                    )

        return findings

    def _scan_js(self, file_path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        source = self._read(file_path)
        if not source:
            return findings

        if not JS_ROUTE_RE.search(source):
            return findings

        file_has_auth = _has_js_auth(source)
        lines = source.splitlines()

        for lineno, line in enumerate(lines, start=1):
            m = JS_ROUTE_RE.search(line)
            if not m:
                continue
            route_path = m.group(1)

            if not _is_high_risk_path(route_path):
                continue

            # Check surrounding context for auth middleware
            start = max(0, lineno - 3)
            end = min(len(lines), lineno + 15)
            context = "\n".join(lines[start:end])

            if _has_js_auth(context) or file_has_auth:
                continue

            findings.append(
                self._make_finding(
                    category="missing_auth",
                    severity="critical",
                    file_path=rel,
                    line_number=lineno,
                    evidence=line.strip()[:200],
                    description=(
                        f"Route '{route_path}' has no authentication middleware. "
                        "Any unauthenticated request can access this endpoint."
                    ),
                    false_positive_risk="medium",
                )
            )

        return findings