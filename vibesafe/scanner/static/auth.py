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
    "/billing", "/payment", "/profile", "/auth", "/token",
    "/secret", "/api-key",
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

PY_ROUTER_AUTH_RE = re.compile(
    r"(?:APIRouter\s*\([^)]*dependencies\s*=|include_router\s*\([^)]*dependencies\s*=|add_middleware\s*\([^)]*(?:Auth|Security)|@app\.middleware)",
    re.IGNORECASE,
)
JS_ROUTER_AUTH_RE = re.compile(
    r"(?:router|app)\.use\([^)]*(?:auth|passport|jwt|clerk|session|protect|requireAuth)|withAuth|next-auth/middleware|clerkMiddleware",
    re.IGNORECASE,
)

PY_ROUTE_RE = re.compile(
    r'@(?:\w+\.)?(?:route|get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']'
)

JS_ROUTE_RE = re.compile(
    r'(?:router|app|server)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
)
NEXT_ROUTE_HANDLER_RE = re.compile(r'export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(', re.IGNORECASE)


def _is_high_risk_path(path: str) -> bool:
    path_lower = path.lower()
    return any(frag in path_lower for frag in HIGH_RISK_PATH_FRAGMENTS)


def _has_py_auth(source: str) -> bool:
    return any(sig in source for sig in AUTH_SIGNALS_PY)


def _has_js_auth(source: str) -> bool:
    return any(sig in source for sig in AUTH_SIGNALS_JS)


def _has_python_router_auth(source: str) -> bool:
    return bool(PY_ROUTER_AUTH_RE.search(source) or _has_py_auth(source))


def _has_js_router_auth(source: str) -> bool:
    return bool(JS_ROUTER_AUTH_RE.search(source) or _has_js_auth(source))


class AuthScanner(BaseScanner):
    """
    Detects routes/endpoints that are missing authentication middleware.
    Checks Python (FastAPI/Flask/Django) and JavaScript/TypeScript (Express).
    """

    async def scan(self, manifest: RepoManifest) -> list[Finding]:
        findings: list[Finding] = []
        project_auth_middleware = self._project_has_auth_middleware(manifest)

        for file_path in manifest.files:
            suffix = file_path.suffix.lower()
            rel = manifest.relative(file_path)
            if self._should_skip_path(rel):
                continue
            if suffix == ".py":
                findings.extend(self._scan_python(file_path, rel, project_auth_middleware))
            elif suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                findings.extend(self._scan_js(file_path, rel, project_auth_middleware))

        return findings

    def _scan_python(self, file_path: Path, rel: str, project_auth_middleware: bool) -> list[Finding]:
        findings: list[Finding] = []
        source = self._read(file_path)
        if not source or not PY_ROUTE_RE.search(source):
            return findings

        router_has_auth = _has_python_router_auth(source)

        try:
            tree = ast.parse(source)
            findings.extend(
                self._ast_check_python(tree, rel, router_has_auth, project_auth_middleware)
            )
        except SyntaxError:
            findings.extend(
                self._regex_check_python(source, rel, router_has_auth, project_auth_middleware)
            )

        return findings

    def _ast_check_python(
        self,
        tree: ast.AST,
        rel: str,
        router_has_auth: bool,
        project_auth_middleware: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_path = None
            http_method = None
            func_has_auth = False

            for decorator in node.decorator_list:
                dec_src = ast.unparse(decorator) if hasattr(ast, "unparse") else ""
                if any(
                    marker in dec_src.lower()
                    for marker in [".route(", ".get(", ".post(", ".put(", ".delete(", ".patch("]
                ):
                    if isinstance(decorator, ast.Call):
                        for arg in decorator.args:
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                route_path = arg.value
                        if isinstance(decorator.func, ast.Attribute):
                            http_method = decorator.func.attr.upper()
                if any(sig.lower() in dec_src.lower() for sig in AUTH_SIGNALS_PY):
                    func_has_auth = True

            if route_path is None:
                continue

            func_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
            route_context = "\n".join(
                [func_src] + [ast.unparse(dec) for dec in node.decorator_list if hasattr(ast, "unparse")]
            )
            if any(sig in func_src for sig in AUTH_SIGNALS_PY):
                func_has_auth = True

            if func_has_auth or _has_py_auth(route_context) or router_has_auth:
                continue

            if not _is_high_risk_path(route_path):
                if http_method not in ("POST", "PUT", "DELETE", "PATCH"):
                    continue
                severity = "medium"
                finding_status = "needs_review"
            else:
                severity = "critical"
                finding_status = "needs_review" if project_auth_middleware else "candidate"

            finding = self._make_finding(
                category="missing_auth",
                severity=severity,
                file_path=rel,
                line_number=node.lineno,
                evidence=f"@{http_method or 'route'}('{route_path}') - no auth",
                description=(
                    f"Route '{route_path}' ({http_method or 'unknown method'}) has no "
                    "authentication middleware. Any unauthenticated user can access this "
                    "endpoint and read or modify protected data."
                ),
                false_positive_risk="high" if project_auth_middleware else "medium",
            )
            finding.status = finding_status
            if project_auth_middleware:
                finding.proof.notes.append("Project-level auth middleware exists; route auth remains uncertain.")
            findings.append(finding)

        return findings

    def _regex_check_python(
        self,
        source: str,
        rel: str,
        router_has_auth: bool,
        project_auth_middleware: bool,
    ) -> list[Finding]:
        if router_has_auth:
            return []

        findings: list[Finding] = []
        lines = source.splitlines()

        for lineno, line in enumerate(lines, start=1):
            m = PY_ROUTE_RE.search(line)
            if not m:
                continue
            route_path = m.group(1)

            if not _is_high_risk_path(route_path):
                continue

            start = max(0, lineno - 5)
            end = min(len(lines), lineno + 5)
            context = "\n".join(lines[start:end])
            if _has_py_auth(context):
                continue

            f = self._make_finding(
                category="missing_auth",
                severity="critical",
                file_path=rel,
                line_number=lineno,
                evidence=line.strip()[:200],
                description=(
                    f"Route '{route_path}' appears to have no authentication. "
                    "Unprotected admin/user routes allow anyone to access sensitive data."
                ),
                false_positive_risk="high" if project_auth_middleware else "medium",
            )
            f.status = "needs_review"
            if project_auth_middleware:
                f.proof.notes.append("Project-level auth middleware exists; route auth remains uncertain.")
            findings.append(f)

        return findings

    def _scan_js(self, file_path: Path, rel: str, project_auth_middleware: bool) -> list[Finding]:
        findings: list[Finding] = []
        source = self._read(file_path)
        if not source:
            return findings

        if not JS_ROUTE_RE.search(source) and not self._is_next_route_handler(rel, source):
            return findings

        router_has_auth = _has_js_router_auth(source)
        lines = source.splitlines()

        if self._is_next_route_handler(rel, source):
            findings.extend(self._scan_next_route(rel, lines, router_has_auth, project_auth_middleware))

        for lineno, line in enumerate(lines, start=1):
            m = JS_ROUTE_RE.search(line)
            if not m:
                continue
            route_path = m.group(1)
            if not _is_high_risk_path(route_path):
                continue

            start = max(0, lineno - 3)
            end = min(len(lines), lineno + 15)
            context = "\n".join(lines[start:end])

            if _has_js_auth(context) or router_has_auth:
                continue

            f = self._make_finding(
                category="missing_auth",
                severity="critical",
                file_path=rel,
                line_number=lineno,
                evidence=line.strip()[:200],
                description=(
                    f"Route '{route_path}' has no authentication middleware. "
                    "Any unauthenticated request can access this endpoint."
                ),
                false_positive_risk="high" if project_auth_middleware else "medium",
            )
            f.status = "needs_review"
            if project_auth_middleware:
                f.proof.notes.append("Project-level auth middleware exists; route auth remains uncertain.")
            findings.append(f)

        return findings

    def _scan_next_route(
        self,
        rel: str,
        lines: list[str],
        router_has_auth: bool,
        project_auth_middleware: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        route_path = self._next_route_path(rel)
        if not route_path or not _is_high_risk_path(route_path):
            return findings

        for lineno, line in enumerate(lines, start=1):
            method_match = NEXT_ROUTE_HANDLER_RE.search(line)
            if not method_match:
                continue
            method = method_match.group(1).upper()
            end = min(len(lines), lineno + 25)
            context = "\n".join(lines[lineno - 1 : end])
            if _has_js_auth(context) or router_has_auth:
                continue
            finding = self._make_finding(
                category="missing_auth",
                severity="critical",
                file_path=rel,
                line_number=lineno,
                evidence=f"export async function {method}('{route_path}')",
                description=(
                    f"Next.js route '{route_path}' ({method}) has no authentication or authorization checks. "
                    "Any unauthenticated request can access sensitive functionality."
                ),
                false_positive_risk="high" if project_auth_middleware else "medium",
            )
            finding.status = "needs_review"
            if project_auth_middleware:
                finding.proof.notes.append("Project-level auth middleware exists; route auth remains uncertain.")
            findings.append(finding)
        return findings

    def _project_has_auth_middleware(self, manifest: RepoManifest) -> bool:
        for file_path in manifest.files:
            rel = manifest.relative(file_path)
            if self._should_skip_path(rel):
                continue
            rel_lower = rel.replace("\\", "/").lower()
            if not any(token in rel_lower for token in ("middleware", "auth", "router", "main", "app")):
                continue
            source = self._read(file_path)
            if not source:
                continue
            if _has_python_router_auth(source) or _has_js_router_auth(source):
                return True
        return False

    def _is_next_route_handler(self, rel: str, source: str) -> bool:
        rel_lower = rel.replace("\\", "/").lower()
        return rel_lower.startswith("app/api/") and rel_lower.endswith(("/route.ts", "/route.js")) and bool(
            NEXT_ROUTE_HANDLER_RE.search(source)
        )

    def _next_route_path(self, rel: str) -> str:
        rel_norm = rel.replace("\\", "/")
        if not rel_norm.startswith("app/api/"):
            return ""
        route_bits = rel_norm[len("app/api/") :].split("/")
        if route_bits and route_bits[-1] in {"route.ts", "route.js"}:
            route_bits = route_bits[:-1]
        return "/api/" + "/".join(route_bits)
