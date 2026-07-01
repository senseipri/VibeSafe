from __future__ import annotations

import re
from pathlib import Path

from vibesafe.scanner.analysis.index import CodeIndex
from vibesafe.scanner.findings import EvidenceRef, Finding, Proof
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.repo_context import RepoContext

ATTACKER_INPUT_RE = re.compile(
    r"(?:request|req|body|query|params|headers|cookies|form|input|argv|sys\.argv|stdin|user_input)",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(
    r"(?:changeme|example|dummy|sample|placeholder|your[_ -]?key|test[_ -]?key|fake|mock|null)",
    re.IGNORECASE,
)
CURRENCY_RE = re.compile(r"\$\s?\d+(?:\.\d{2})?")
PROMPTISH_RE = re.compile(
    r"\b(?:system_prompt|user_prompt|assistant_message|prompt_template|instruction|template)\b",
    re.IGNORECASE,
)
TEST_PATH_SEGMENTS = ("test", "tests", "fixture", "fixtures", "example", "examples", "docs", "sample", "samples")

FLOW_CATEGORIES = {"sql_injection", "command_injection", "log_injection", "path_traversal", "unsafe_dynamic_code"}
AI_SECURITY_CATEGORIES = {
    "prompt_injection",
    "unsafe_tool_execution",
    "agent_privilege_escalation",
    "mcp_untrusted_server",
    "llm_secret_exposure",
    "agent_memory_poisoning",
    "retrieval_poisoning",
}
DIRECT_PROOF_CATEGORIES = {
    "hardcoded_secret",
    "committed_env_file",
    "missing_auth",
    "cors_wildcard_credentials",
    "cors_wildcard",
    "rls_disabled",
    "firebase_public",
    "missing_rate_limit",
    "weak_jwt",
    "slopsquatting",
    "supabase_anon_write",
    *AI_SECURITY_CATEGORIES,
}
ROUTE_PROOF_CATEGORIES = {"missing_auth", "missing_rate_limit"}
PROMOTABLE_PROVEN_CATEGORIES = {"sql_injection", "command_injection", "unsafe_dynamic_code", "path_traversal"}
ROUTE_PATH_RE = re.compile(r'["\'](/[^"\']*)["\']')
ROUTE_METHOD_RE = re.compile(r"@(?:\w+\.)?(route|get|post|put|delete|patch|head|options)\b", re.IGNORECASE)
PYTHON_ROUTE_DECORATOR_RE = re.compile(r"@\s*(?:app|router|bp|blueprint)\.", re.IGNORECASE)
PYTHON_WEB_HINT_RE = re.compile(r"\b(?:FastAPI|APIRouter|Flask|Blueprint|django\.urls|path\(|re_path\()\b")
SENSITIVE_ROUTE_RE = re.compile(
    r"(?:/admin|/user|/users|/account|/accounts|/settings|/delete|/remove|/manage|/dashboard|/auth|/login|/register|/token|/billing|/payment|/checkout)",
    re.IGNORECASE,
)
INTERNAL_ONLY_ROUTE_RE = re.compile(r"(?:/health|/metrics|/ready|/live|/internal)", re.IGNORECASE)
SCANNER_PRIORS = {
    "sql_injection": 0.82,
    "command_injection": 0.82,
    "unsafe_dynamic_code": 0.72,
    "path_traversal": 0.74,
    "hardcoded_secret": 0.88,
    "committed_env_file": 0.95,
    "weak_jwt": 0.75,
    "firebase_public": 0.9,
    "cors_wildcard_credentials": 0.9,
    "cors_wildcard": 0.78,
    "rls_disabled": 0.7,
    "missing_auth": 0.72,
    "missing_rate_limit": 0.65,
    "log_injection": 0.45,
    "slopsquatting": 0.7,
    "supabase_anon_write": 0.55,
    "prompt_injection": 0.5,
    "unsafe_tool_execution": 0.72,
    "agent_privilege_escalation": 0.68,
    "mcp_untrusted_server": 0.7,
    "llm_secret_exposure": 0.76,
    "agent_memory_poisoning": 0.58,
    "retrieval_poisoning": 0.58,
}


def get_context(manifest: RepoManifest, file_path: str, line_number: int, window: int = 6) -> list[tuple[int, str]]:
    if not file_path or line_number <= 0:
        return []
    full_path = manifest.root / file_path
    try:
        resolved = full_path.resolve()
        if not str(resolved).startswith(str(manifest.root.resolve())):
            return []
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    start = max(0, line_number - window - 1)
    end = min(len(lines), line_number + window)
    return [(idx + 1, lines[idx]) for idx in range(start, end)]


class EvidenceBuilder:
    def __init__(
        self,
        manifest: RepoManifest,
        code_index: CodeIndex | None = None,
        repo_context: RepoContext | None = None,
    ) -> None:
        self.manifest = manifest
        self.code_index = code_index
        self.repo_context = repo_context

    def build(self, findings: list[Finding]) -> list[Finding]:
        built: list[Finding] = []
        for finding in findings:
            self._ensure_primary_evidence(finding)
            if not finding.evidence_refs or finding.line_number <= 0:
                finding.status = "rejected"
                finding.confidence = 0.0
                finding.proof.notes.append("Rejected: missing quoted evidence or source line.")
                built.append(finding)
                continue

            context = get_context(self.manifest, finding.file_path, finding.line_number)
            penalty_notes = self._apply_prefilters(finding, context)
            if penalty_notes:
                finding.status = "rejected"
                finding.confidence = 0.0
                finding.proof.notes.extend(penalty_notes)
                built.append(finding)
                continue

            proof = self._build_proof(finding, context)
            finding.proof = proof
            finding.confidence = round(self._score_confidence(finding), 4)

            if finding.category in FLOW_CATEGORIES:
                if proof.source_present and proof.sink_present and proof.path_present:
                    finding.status = "confirmed" if self._should_auto_confirm_flow(finding, proof) else "candidate"
                else:
                    finding.status = "rejected"
                    finding.proof.notes.append("Rejected: required source/sink/path proof is incomplete.")
                    finding.confidence = min(finding.confidence, 0.45)
            elif finding.category in ROUTE_PROOF_CATEGORIES:
                if proof.source_present and proof.path_present:
                    finding.status = "candidate"
                else:
                    finding.status = "needs_review"
                    if not proof.source_present:
                        finding.proof.notes.append(
                            "Exposure not clearly proven for this Python route; holding at needs_review."
                        )
                    if not proof.path_present:
                        finding.proof.notes.append(
                            "Sensitive action/data path is not clear enough for candidate status."
                        )
                    finding.confidence = min(finding.confidence, 0.69)
            else:
                if finding.category in DIRECT_PROOF_CATEGORIES:
                    finding.status = "candidate"
                else:
                    finding.status = "needs_review"

            built.append(finding)
        return built

    def _ensure_primary_evidence(self, finding: Finding) -> None:
        if finding.evidence_refs:
            return
        if finding.evidence:
            finding.evidence_refs.append(
                EvidenceRef(
                    kind="literal",
                    file_path=finding.file_path,
                    line_start=max(finding.line_number, 1),
                    line_end=max(finding.line_number, 1),
                    quote=finding.evidence[:400],
                )
            )

    def _apply_prefilters(self, finding: Finding, context: list[tuple[int, str]]) -> list[str]:
        lowered_path = finding.file_path.lower()
        notes: list[str] = []
        line = finding.evidence

        if any(segment in lowered_path for segment in TEST_PATH_SEGMENTS):
            notes.append("Rejected: finding is in a test/example/docs path.")

        if finding.category in {"hardcoded_secret", "weak_jwt"}:
            if PLACEHOLDER_RE.search(line):
                notes.append("Rejected: matched placeholder or example secret.")
            if CURRENCY_RE.search(line):
                notes.append("Rejected: matched currency literal, not a secret.")
            if PROMPTISH_RE.search(" ".join(text for _, text in context)):
                notes.append("Rejected: matched prompt or message template text.")

        if finding.category == "log_injection" and not ATTACKER_INPUT_RE.search(line):
            notes.append("Rejected: log statement does not quote a clearly attacker-controlled input.")

        return notes

    def _build_proof(self, finding: Finding, context: list[tuple[int, str]]) -> Proof:
        proof = Proof()
        evidence_line = finding.evidence
        context_text = "\n".join(text for _, text in context)

        if finding.category in FLOW_CATEGORIES:
            flow = self._find_taint_flow(finding)
            if flow:
                finding.evidence_refs.extend(flow.to_evidence_refs())
                proof.source_present = True
                proof.sink_present = True
                proof.path_present = True
                proof.sanitizer_present = flow.sanitized
                proof.attacker_controlled = True
                proof.exploitability_proven = (
                    finding.category in {"sql_injection", "command_injection"}
                    and not flow.sanitized
                )
                if finding.category == "log_injection":
                    proof.exploitability_proven = False
                    proof.notes.append(
                        "Exploit scenario suppressed until CR/LF or parser-impact proof is explicit."
                    )
                proof.notes.append(f"AST taint flow confidence={flow.confidence:.2f}.")
                return proof

            proof.sink_present = True
            proof.path_present = self._has_direct_interpolation(evidence_line)
            if finding.category in {"command_injection", "path_traversal", "unsafe_dynamic_code"}:
                proof.path_present = proof.path_present or bool(ATTACKER_INPUT_RE.search(evidence_line))
            proof.source_present = bool(ATTACKER_INPUT_RE.search(evidence_line))
            if not proof.source_present:
                proof.source_present = self._find_attacker_assignment(evidence_line, context)
            proof.attacker_controlled = proof.source_present
            proof.sanitizer_present = self._has_sanitizer(evidence_line, context_text, finding.category)
            if finding.category in {"sql_injection", "command_injection", "path_traversal", "unsafe_dynamic_code"}:
                proof.exploitability_proven = (
                    proof.source_present
                    and proof.sink_present
                    and proof.path_present
                    and not proof.sanitizer_present
                )
            else:
                proof.exploitability_proven = False
                if proof.source_present and proof.path_present and not proof.sanitizer_present:
                    proof.notes.append(
                        "Exploit scenario suppressed until CR/LF or parser-impact proof is explicit."
                    )
            return proof

        if finding.category in {"hardcoded_secret", "committed_env_file", "weak_jwt", "slopsquatting"}:
            proof.source_present = True
            proof.sink_present = True
            proof.path_present = True
            proof.attacker_controlled = False
            proof.exploitability_proven = finding.category in {"hardcoded_secret", "committed_env_file", "weak_jwt"}
            return proof

        if finding.category in ROUTE_PROOF_CATEGORIES:
            route_path, route_method = self._extract_route_signature(finding.evidence)
            proof.sink_present = bool(route_path)
            proof.path_present = self._has_sensitive_route_action(route_path, route_method, finding.category)
            proof.source_present = self._has_clear_route_exposure(finding, route_path, context)
            proof.attacker_controlled = proof.source_present
            proof.exploitability_proven = proof.source_present and proof.path_present
            if self.repo_context and self.repo_context.kind in {"internal_service", "ml_platform"} and not self.repo_context.external_exposure_proven:
                proof.notes.append("Internal-service style Python route requires external exposure proof before confirmation.")
            return proof

        if finding.category in AI_SECURITY_CATEGORIES:
            proof.source_present = True
            proof.sink_present = True
            proof.path_present = bool(finding.evidence_refs)
            proof.attacker_controlled = finding.category in {
                "prompt_injection",
                "unsafe_tool_execution",
                "agent_memory_poisoning",
                "retrieval_poisoning",
            }
            proof.exploitability_proven = False
            proof.notes.append("AI security candidate requires verifier confirmation before exploitability.")
            return proof

        if finding.category in DIRECT_PROOF_CATEGORIES:
            proof.source_present = True
            proof.sink_present = True
            proof.path_present = True
            proof.exploitability_proven = True
            return proof

        if context:
            proof.source_present = True
            proof.sink_present = True
            proof.path_present = True
        return proof

    def _find_taint_flow(self, finding: Finding):
        if not self.code_index:
            return None
        return self.code_index.taint_graph.find_flow(
            file_path=finding.file_path,
            sink_line=finding.line_number,
            category=finding.category,
        )

    def _find_attacker_assignment(self, evidence_line: str, context: list[tuple[int, str]]) -> bool:
        variables = self._extract_interpolated_variables(evidence_line)
        if not variables:
            return False
        for _, line in context:
            for variable in variables:
                assign_re = re.compile(rf"\b{re.escape(variable)}\b\s*=\s*.+", re.IGNORECASE)
                if assign_re.search(line) and ATTACKER_INPUT_RE.search(line):
                    return True
                param_re = re.compile(rf"(?:def|function)\s+\w+\s*\([^)]*\b{re.escape(variable)}\b", re.IGNORECASE)
                if param_re.search(line):
                    return True
        return False

    def _extract_interpolated_variables(self, line: str) -> set[str]:
        vars_found = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_\.]*)", line))
        vars_found.update(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_\.]*)", line))
        percent_match = re.search(r"%\s*([A-Za-z_][A-Za-z0-9_]*)", line)
        if percent_match:
            vars_found.add(percent_match.group(1))
        concat_matches = re.findall(r"\+\s*([A-Za-z_][A-Za-z0-9_]*)", line)
        vars_found.update(concat_matches)
        return {name.split(".")[0] for name in vars_found}

    def _has_direct_interpolation(self, line: str) -> bool:
        return any(token in line for token in ("{", "${", "%", "+"))

    def _has_sanitizer(self, evidence_line: str, context_text: str, category: str) -> bool:
        sanitizer_tokens = [".replace('\\n'", ".replace(\"\\n\"", "json.dumps", "repr(", "escape("]
        if category == "sql_injection":
            sanitizer_tokens.extend(["quote_ident(", "sanitize_sql", "escape_sql("])
        return any(token in evidence_line or token in context_text for token in sanitizer_tokens)

    def _score_confidence(self, finding: Finding) -> float:
        prior = SCANNER_PRIORS.get(finding.category, 0.55)
        proof = finding.proof
        score = 0.30 * prior
        score += 0.20 if proof.source_present else 0.0
        score += 0.20 if proof.sink_present else 0.0
        score += 0.15 if proof.path_present else 0.0
        score += 0.10 if not proof.sanitizer_present else 0.0
        score += 0.05 if len(finding.evidence_refs) > 1 else 0.0

        line = finding.evidence
        lowered_path = finding.file_path.lower()
        if PLACEHOLDER_RE.search(line):
            score -= 0.25
        if CURRENCY_RE.search(line) or PROMPTISH_RE.search(line):
            score -= 0.20
        if any(segment in lowered_path for segment in TEST_PATH_SEGMENTS):
            score -= 0.20
        if finding.category == "log_injection":
            score = min(score, 0.74)
        if finding.category in ROUTE_PROOF_CATEGORIES and finding.status == "needs_review":
            score = min(score, 0.69)

        return max(0.0, min(1.0, score))

    def _extract_route_signature(self, evidence_line: str) -> tuple[str, str]:
        path_match = ROUTE_PATH_RE.search(evidence_line)
        method_match = ROUTE_METHOD_RE.search(evidence_line)
        return (
            path_match.group(1) if path_match else "",
            method_match.group(1).upper() if method_match else "",
        )

    def _has_sensitive_route_action(self, route_path: str, route_method: str, category: str) -> bool:
        if not route_path:
            return False
        route_lower = route_path.lower()
        if INTERNAL_ONLY_ROUTE_RE.search(route_lower):
            return False
        if SENSITIVE_ROUTE_RE.search(route_lower):
            return True
        if category == "missing_rate_limit" and route_method in {"POST", "PUT", "PATCH", "DELETE"}:
            return True
        if category == "missing_auth" and route_method in {"PUT", "PATCH", "DELETE"}:
            return True
        return False

    def _has_clear_route_exposure(
        self,
        finding: Finding,
        route_path: str,
        context: list[tuple[int, str]],
    ) -> bool:
        if not route_path:
            return False
        if self.repo_context and self.repo_context.kind in {"internal_service", "ml_platform"} and not self.repo_context.external_exposure_proven:
            return False
        if self.repo_context and self.repo_context.external_exposure_proven:
            return True

        file_text = self._file_text(finding.file_path)
        context_text = "\n".join(text for _, text in context)
        combined = "\n".join(part for part in (finding.evidence, context_text, file_text[:2000]) if part)
        route_lower = route_path.lower()

        if INTERNAL_ONLY_ROUTE_RE.search(route_lower):
            return False
        if PYTHON_ROUTE_DECORATOR_RE.search(finding.evidence) and (
            route_lower.startswith("/api/")
            or route_lower.startswith("/admin")
            or route_lower.startswith("/users")
            or route_lower.startswith("/auth")
        ):
            return True
        return bool(PYTHON_WEB_HINT_RE.search(combined) and route_lower.startswith("/"))

    def _file_text(self, file_path: str) -> str:
        if not file_path:
            return ""
        return self.manifest.read(self.manifest.root / file_path)

    def _should_auto_confirm_flow(self, finding: Finding, proof: Proof) -> bool:
        return (
            finding.category in PROMOTABLE_PROVEN_CATEGORIES
            and proof.source_present
            and proof.sink_present
            and proof.path_present
            and proof.attacker_controlled
            and proof.exploitability_proven
            and not proof.sanitizer_present
        )
