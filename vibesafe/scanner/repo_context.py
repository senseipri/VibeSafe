from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from vibesafe.scanner.findings import Finding, Severity
from vibesafe.scanner.ingest import RepoManifest

RepoKind = str

INTERNAL_PATH_PARTS = {
    "worker",
    "workers",
    "gateway",
    "gateways",
    "controller",
    "controllers",
    "scheduler",
    "schedulers",
    "internal",
    "cluster",
    "clusters",
}

LIBRARY_HINTS = {
    "src",
    "lib",
    "libs",
    "package",
    "packages",
    "sdk",
    "sdks",
}

APPLICATION_HINTS = (
    "login",
    "sign in",
    "signin",
    "sign up",
    "signup",
    "register",
    "account",
    "accounts",
    "profile",
    "session",
    "billing",
    "payment",
    "checkout",
    "order",
    "orders",
    "workflow",
    "dashboard",
    "user management",
    "auth flow",
    "password reset",
    "forgot password",
    "token",
)

FRAMEWORK_PACKAGE_HINTS = {
    "fastapi",
    "flask",
    "django",
    "express",
    "next",
    "celery",
    "rq",
    "sqlmodel",
    "@nestjs/core",
}

LIBRARY_PACKAGE_HINTS = {
    "rq",
    "sqlmodel",
}

ML_PLATFORM_HINTS = (
    "model.generate_content",
    "openai",
    "anthropic",
    "langchain",
    "crewai",
    "autogen",
    "scheduler",
    "worker",
    "inference",
    "prompt",
    "embedding",
    "vector",
    "agent",
    "tool_call",
    "tool_calling",
)

FRAMEWORK_HINTS = (
    "fastapi",
    "flask",
    "django",
    "express",
    "koa",
    "nest",
)

LOCAL_NETWORK_HINTS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    ".svc.cluster.local",
    "cluster.local",
    "kubernetes",
    "minikube",
    "kind-control-plane",
)

EXTERNAL_EXPOSURE_HINTS = (
    "0.0.0.0",
    "ingress",
    "loadbalancer",
    "public_url",
    "public-api",
    "allow_origins=[\"*\"]",
    "allow_origins = [\"*\"]",
    "cors",
)

PUBLIC_API_ROUTE_RE = re.compile(
    r'(?:"|\'|`)(/(?:api|v\d+|public|admin|users|user|auth|login|register)[^"\'`]*)'
)

SENSITIVE_ROUTE_TOKENS = (
    "/admin",
    "/users",
    "/user",
    "/account",
    "/accounts",
    "/auth",
    "/login",
    "/register",
    "/token",
    "/payment",
    "/billing",
    "/checkout",
)


@dataclass(slots=True)
class RepoContext:
    kind: RepoKind
    reasons: list[str] = field(default_factory=list)
    local_network_hints: list[str] = field(default_factory=list)
    public_api_signals: list[str] = field(default_factory=list)
    external_exposure_proven: bool = False
    sensitive_public_surface: bool = False

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "reasons": self.reasons,
            "local_network_hints": self.local_network_hints,
            "public_api_signals": self.public_api_signals,
            "external_exposure_proven": self.external_exposure_proven,
            "sensitive_public_surface": self.sensitive_public_surface,
        }


def classify_repo(manifest: RepoManifest, frameworks: list[str] | None = None) -> RepoContext:
    frameworks = frameworks or []
    path_parts = {part.lower() for file_path in manifest.files for part in file_path.parts}
    root_names = {path.name.lower() for path in manifest.root.iterdir()}
    combined_names = path_parts | root_names

    text_samples = _read_samples(manifest)
    lower_sample = "\n".join(text_samples).lower()

    reasons: list[str] = []
    local_hints = [hint for hint in LOCAL_NETWORK_HINTS if hint in lower_sample]
    public_signals = sorted(set(PUBLIC_API_ROUTE_RE.findall(lower_sample)))
    sensitive_public_surface = any(token in route.lower() for route in public_signals for token in SENSITIVE_ROUTE_TOKENS)
    external_exposure_proven = any(hint in lower_sample for hint in EXTERNAL_EXPOSURE_HINTS) and bool(public_signals)
    app_score = _application_score(manifest, lower_sample, public_signals)
    framework_score = _framework_score(frameworks, lower_sample)
    library_score = _library_score(manifest, lower_sample, frameworks)
    ml_score = _ml_platform_score(lower_sample)

    if combined_names & INTERNAL_PATH_PARTS:
        reasons.append("internal topology folder names")
    if local_hints:
        reasons.append("local-only networking hints")

    if any(name in combined_names for name in ("agent", "agents", "tooling", "tools")) and any(
        hint in lower_sample for hint in ("agent", "tool", "mcp", "memory", "workflow")
    ):
        return RepoContext(
            kind="agent_platform",
            reasons=reasons + ["agent-oriented orchestration signals"],
            local_network_hints=local_hints,
            public_api_signals=public_signals,
            external_exposure_proven=external_exposure_proven,
            sensitive_public_surface=sensitive_public_surface,
        )

    if app_score >= 2 and app_score >= ml_score + 1:
        return RepoContext(
            kind="application",
            reasons=reasons + ["application workflow and auth/session signals"],
            local_network_hints=local_hints,
            public_api_signals=public_signals,
            external_exposure_proven=external_exposure_proven or bool(public_signals),
            sensitive_public_surface=sensitive_public_surface,
        )

    if combined_names & INTERNAL_PATH_PARTS and local_hints:
        return RepoContext(
            kind="internal_service",
            reasons=reasons,
            local_network_hints=local_hints,
            public_api_signals=public_signals,
            external_exposure_proven=external_exposure_proven,
            sensitive_public_surface=sensitive_public_surface,
        )

    if framework_score > 0 and framework_score >= library_score:
        return RepoContext(
            kind="framework",
            reasons=reasons + ["framework/provider style routing"],
            local_network_hints=local_hints,
            public_api_signals=public_signals,
            external_exposure_proven=external_exposure_proven,
            sensitive_public_surface=sensitive_public_surface,
        )

    if library_score > 0:
        return RepoContext(
            kind="library",
            reasons=reasons + ["package/export oriented layout"],
            local_network_hints=local_hints,
            public_api_signals=public_signals,
            external_exposure_proven=external_exposure_proven,
            sensitive_public_surface=sensitive_public_surface,
        )

    if ml_score > 0:
        return RepoContext(
            kind="ml_platform",
            reasons=reasons + ["ML or inference platform signals"],
            local_network_hints=local_hints,
            public_api_signals=public_signals,
            external_exposure_proven=external_exposure_proven,
            sensitive_public_surface=sensitive_public_surface,
        )

    if public_signals or frameworks:
        return RepoContext(
            kind="application",
            reasons=reasons + ["public application routing signals"],
            local_network_hints=local_hints,
            public_api_signals=public_signals,
            external_exposure_proven=external_exposure_proven or bool(public_signals),
            sensitive_public_surface=sensitive_public_surface,
        )

    return RepoContext(
        kind="unknown",
        reasons=reasons,
        local_network_hints=local_hints,
        public_api_signals=public_signals,
        external_exposure_proven=external_exposure_proven,
        sensitive_public_surface=sensitive_public_surface,
    )


def apply_repo_context(findings: list[Finding], context: RepoContext) -> list[Finding]:
    adjusted: list[Finding] = []
    for finding in findings:
        if finding.category not in {"missing_auth", "missing_rate_limit"}:
            adjusted.append(finding)
            continue

        if context.kind in {"internal_service", "ml_platform"} and not context.external_exposure_proven:
            _downgrade_finding(
                finding,
                note=f"Downgraded for {context.kind}: external exposure not proven.",
                severity_cap="medium",
                status_only={"confirmed"},
            )
        elif context.kind in {"library", "framework"} and not (
            context.external_exposure_proven and context.sensitive_public_surface
        ):
            _downgrade_finding(
                finding,
                note=(
                    f"Downgraded for {context.kind}: public API exposure and sensitive action path "
                    "are not both proven."
                ),
                severity_cap="medium",
                status_only={"confirmed", "candidate"},
            )

        adjusted.append(finding)
    return adjusted


def _downgrade_finding(
    finding: Finding,
    *,
    note: str,
    severity_cap: Severity,
    status_only: set[str],
) -> None:
    if finding.status not in status_only:
        return
    finding.status = "needs_review"
    finding.confidence = min(finding.confidence or 1.0, 0.49)
    finding.false_positive_risk = "high"
    if _severity_rank(finding.severity) > _severity_rank(severity_cap):
        finding.severity = severity_cap
    if note not in finding.proof.notes:
        finding.proof.notes.append(note)


def _severity_rank(severity: Severity) -> int:
    order: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return order[severity]


def _looks_like_library(manifest: RepoManifest, lower_sample: str, names: set[str]) -> bool:
    if any(name in names for name in ("setup.py", "pyproject.toml", "package.json")) and any(
        hint in names for hint in LIBRARY_HINTS
    ):
        if not PUBLIC_API_ROUTE_RE.search(lower_sample):
            return True
    return any(phrase in lower_sample for phrase in ("export function", "module.exports", "__all__", "library"))


def _read_samples(manifest: RepoManifest, max_files: int = 40, max_chars: int = 4000) -> list[str]:
    samples: list[str] = []
    for file_path in manifest.files[:max_files]:
        text = manifest.read(file_path)
        if not text:
            continue
        samples.append(text[:max_chars])
    return samples


def _application_score(manifest: RepoManifest, lower_sample: str, public_signals: list[str]) -> int:
    score = 0
    for hint in APPLICATION_HINTS:
        if hint in lower_sample:
            score += 1
    if any(signal for signal in public_signals if any(token in signal.lower() for token in ("/login", "/signup", "/register", "/account", "/profile", "/session"))):
        score += 2
    if any(name in {path.name.lower() for path in manifest.files} for name in {"login", "signup", "register", "account", "session", "profile", "dashboard"}):
        score += 1
    return score


def _framework_score(frameworks: list[str], lower_sample: str) -> int:
    score = 0
    if any(fw in frameworks for fw in FRAMEWORK_PACKAGE_HINTS):
        score += 2
    for token in ("router", "middleware", "blueprint", "controller", "app.use(", "app.route(", "create_app", "apirouter", "next.config"):
        if token in lower_sample:
            score += 1
    return score


def _library_score(manifest: RepoManifest, lower_sample: str, frameworks: list[str]) -> int:
    score = 0
    names = {path.name.lower() for path in manifest.files}
    if any(name in names for name in ("package.json", "pyproject.toml", "setup.py")):
        score += 1
    if any(pkg in lower_sample for pkg in LIBRARY_PACKAGE_HINTS):
        score += 2
    if any(phrase in lower_sample for phrase in ("export function", "module.exports", "__all__", "plugin", "adapter", "sdk")):
        score += 1
    if any(fw in frameworks for fw in ("rq", "sqlmodel")):
        score += 1
    return score


def _ml_platform_score(lower_sample: str) -> int:
    score = 0
    for hint in ML_PLATFORM_HINTS:
        if hint in lower_sample:
            score += 1
    return score
