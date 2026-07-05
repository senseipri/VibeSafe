from __future__ import annotations

import json
import logging
import re

from vibesafe.scanner.findings import Finding
from vibesafe.scanner.ingest import RepoManifest
from vibesafe.scanner.static.base import BaseScanner

logger = logging.getLogger(__name__)

LLM_CALL_RE = re.compile(
    r"(?:chat\.completions\.create|responses\.create|generate_content|invoke|agent\.run|llm\.)",
    re.IGNORECASE,
)
PROMPT_VAR_RE = re.compile(r"(?:system_prompt|user_prompt|prompt|messages|instructions)\s*=", re.IGNORECASE)
TOOL_EXEC_RE = re.compile(
    r"(?:subprocess\.|os\.system|exec\(|eval\(|shell=True|tool\.invoke|tools?\[.+\]\()",
    re.IGNORECASE,
)
MODEL_OUTPUT_RE = re.compile(r"(?:llm_response|model_output|assistant_message|completion|response\.choices)", re.IGNORECASE)
MEMORY_WRITE_RE = re.compile(r"(?:memory\.save|memory\.add|vectorstore\.add|add_documents|upsert|insert)\(", re.IGNORECASE)
RETRIEVAL_RE = re.compile(r"(?:similarity_search|retriever\.invoke|as_retriever|vectorstore)", re.IGNORECASE)
SECRET_IN_PROMPT_RE = re.compile(r"(?:api[_-]?key|secret|token|password).{0,80}(?:prompt|message|instruction)", re.IGNORECASE)
LLM_SECRET_SOURCE_RE = re.compile(
    r"(?:process\.env|os\.environ|os\.getenv|import\.meta\.env|dotenv|env\[|env\.|OPENAI_API_KEY|ANTHROPIC_API_KEY|GROQ_API_KEY|AWS_SECRET_ACCESS_KEY|AZURE_OPENAI_API_KEY|AZURE_CLIENT_SECRET|GCP_SERVICE_ACCOUNT|sk-[A-Za-z0-9_\-]{8,}|ghp_[A-Za-z0-9]{12,}|xox[bp]-[0-9A-Za-z\-]{12,}|AKIA[0-9A-Z]{8,})",
    re.IGNORECASE,
)

# Sensitive data signals: presence of any of these raises confidence that a
# prompt_injection or retrieval_poisoning finding has real impact.
# Without at least one of these signals the finding is downgraded to
# needs_review (public prediction endpoints without privileged access are
# low risk).
SENSITIVE_DATA_RE = re.compile(
    r"(?:"
    r"pii|email|password|credit.?card|ssn|social.?security"
    r"|admin|privileged|role|permission"
    r"|delete|write|update|insert|mutate"
    r"|api[_-]?key|secret|token|bearer"
    r")",
    re.IGNORECASE,
)


class AISecurityScanner(BaseScanner):
    """
    Candidate generator for AI/agent-specific risks.
    The evidence/proof layer decides whether these survive.
    """

    async def scan(self, manifest: RepoManifest) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in manifest.files:
            suffix = file_path.suffix.lower()
            rel = manifest.relative(file_path)
            if self._should_skip_path(rel):
                continue
            if suffix not in {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".json", ".yaml", ".yml"}:
                continue
            content = self._read(file_path)
            if not content:
                continue
            lines = content.splitlines()

            if suffix == ".json" and file_path.name.lower().endswith(".json"):
                findings.extend(self._scan_mcp_json(lines, rel))
                continue

            findings.extend(self._scan_code(lines, rel))
        return findings

    def _scan_code(self, lines: list[str], rel: str) -> list[Finding]:
        findings: list[Finding] = []
        content = "\n".join(lines)
        has_llm_call = bool(LLM_CALL_RE.search(content))
        has_retrieval = bool(RETRIEVAL_RE.search(content))
        has_sensitive = bool(SENSITIVE_DATA_RE.search(content))
        has_llm_context = has_llm_call or bool(PROMPT_VAR_RE.search(content) or MODEL_OUTPUT_RE.search(content) or has_retrieval)

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self._is_comment(stripped):
                continue

            if has_llm_call and PROMPT_VAR_RE.search(stripped) and self._line_uses_untrusted_input(stripped):
                f = self._finding(
                    "prompt_injection",
                    "medium",
                    rel,
                    lineno,
                    stripped,
                    "User or retrieved content is assembled into an LLM prompt. Verify boundaries before privileged tool use.",
                )
                # Only treat as candidate when the surrounding code handles
                # sensitive/privileged data. Public-prediction-only flows are
                # needs_review until LLM confirms exploitability.
                if not has_sensitive:
                    f.status = "needs_review"
                findings.append(f)

            if TOOL_EXEC_RE.search(stripped) and MODEL_OUTPUT_RE.search(stripped):
                findings.append(self._finding(
                    "unsafe_tool_execution",
                    "high",
                    rel,
                    lineno,
                    stripped,
                    "Model-controlled output appears to reach a tool or code execution sink.",
                ))

            if has_llm_context and self._is_real_llm_secret_exposure(stripped):
                findings.append(self._finding(
                    "llm_secret_exposure",
                    "high",
                    rel,
                    lineno,
                    stripped,
                    "Secret-like values appear to be included in an LLM prompt or message.",
                ))

            if has_llm_context and MEMORY_WRITE_RE.search(stripped) and self._line_uses_untrusted_input(stripped):
                findings.append(self._finding(
                    "agent_memory_poisoning",
                    "medium",
                    rel,
                    lineno,
                    stripped,
                    "User-controlled content is persisted to agent memory or a vector store.",
                ))

            if has_retrieval and has_llm_call and RETRIEVAL_RE.search(stripped):
                f = self._finding(
                    "retrieval_poisoning",
                    "medium",
                    rel,
                    lineno,
                    stripped,
                    "Retrieved documents are used in an LLM workflow; verify trust boundaries and source filtering.",
                )
                # Retrieval + LLM alone is not proof of abuse impact.
                # Require a sensitive-data signal to stay as candidate.
                if not has_sensitive:
                    f.status = "needs_review"
                findings.append(f)

        return findings

    def _scan_mcp_json(self, lines: list[str], rel: str) -> list[Finding]:
        content = "\n".join(lines)
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = None

        findings: list[Finding] = []
        if parsed and "mcpServers" in parsed:
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if '"command"' in stripped or '"url"' in stripped or '"env"' in stripped:
                    findings.append(self._finding(
                        "mcp_untrusted_server",
                        "high",
                        rel,
                        lineno,
                        stripped,
                        "MCP server configuration exposes executable commands, remote servers, or environment variables.",
                    ))
        return findings

    def _line_uses_untrusted_input(self, line: str) -> bool:
        return bool(re.search(r"(?:request|req|body|query|params|headers|user_input|retrieved|documents|docs)", line, re.IGNORECASE))

    def _is_real_llm_secret_exposure(self, line: str) -> bool:
        if not SECRET_IN_PROMPT_RE.search(line):
            return False
        if not LLM_SECRET_SOURCE_RE.search(line):
            return False
        if not any(token in line for token in ("prompt", "message", "instruction", "messages", "system")):
            return False
        if not any(token in line for token in ("=", ":", "`${", "{", "${")):
            return False
        return True

    def _finding(
        self,
        category: str,
        severity: str,
        rel: str,
        line_number: int,
        evidence: str,
        description: str,
    ) -> Finding:
        return self._make_finding(
            category=category,
            severity=severity,
            file_path=rel,
            line_number=line_number,
            evidence=evidence[:200],
            description=description,
            false_positive_risk="medium",
        )
