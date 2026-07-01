"""
Static remediation guidance lookup.

Returns (recommendation, fix) for every known vulnerability category.
Used as:
  1. Primary source when LLM is unavailable or Groq API key is missing.
  2. Guaranteed fallback when GPTFixer returns cannot_fix or fails.

Coverage: all 23 categories in findings.OWASP_CATEGORIES plus any extras.
fix_source tag: "static_table"

Policy:
  - Populate for confirmed AND needs_review findings.
  - Do NOT populate for rejected findings (false positives / suppressed).
"""
from __future__ import annotations

# Each entry: category -> (recommendation, fix)
# recommendation: ≤80 chars, imperative headline.
# fix: 2-4 sentences, actionable prose.

_REMEDIATION: dict[str, tuple[str, str]] = {
    # ── Secrets & credentials ────────────────────────────────────────────
    "hardcoded_secret": (
        "Move the credential to an environment variable and rotate it immediately.",
        (
            "Never embed API keys, tokens, or passwords directly in source code — "
            "they are permanently visible in version history even after deletion. "
            "Move the value to an environment variable (e.g. os.getenv / process.env) and "
            "load it at runtime. Rotate the exposed credential right away via the issuing "
            "service's dashboard, then add the variable name to .gitignore and your secrets "
            "manager (e.g. AWS Secrets Manager, Vault, Doppler, or GitHub Actions Secrets)."
        ),
    ),
    "committed_env_file": (
        "Remove the .env file from git history and rotate all secrets it contained.",
        (
            "A committed .env file exposes every credential it contains to anyone with "
            "repository read access — including if the repo ever becomes public. "
            "Run `git rm --cached .env && echo '.env' >> .gitignore && git commit` to stop "
            "tracking it. Use `git filter-repo` or BFG Repo Cleaner to purge it from history. "
            "Rotate every secret in the file immediately, as it should be treated as compromised."
        ),
    ),
    # ── Access control ───────────────────────────────────────────────────
    "missing_auth": (
        "Add authentication middleware to all sensitive routes.",
        (
            "Unauthenticated endpoints allow any caller to access or mutate protected resources. "
            "Apply an authentication guard (e.g. a FastAPI Dependency, Express middleware, or "
            "framework decorator) that validates a JWT or session token before processing the "
            "request. Confirm that the guard runs for every HTTP method the route accepts. "
            "Write an integration test that asserts a 401/403 is returned when no credentials "
            "are supplied."
        ),
    ),
    "path_traversal": (
        "Validate and canonicalize user-supplied file paths before any I/O.",
        (
            "Unsanitized path segments allow attackers to read or write arbitrary files outside "
            "the intended directory (e.g. ../../../../etc/passwd). "
            "After combining the base directory with the user-supplied component, call "
            "Path.resolve() (Python) or path.resolve() (Node.js) and assert the result still "
            "starts with the allowed base directory. Reject or sanitize any input that contains "
            "'..' or absolute path separators before the join."
        ),
    ),
    "rls_disabled": (
        "Enable Row-Level Security on every table that contains multi-tenant data.",
        (
            "Tables without RLS in Supabase / PostgreSQL allow any authenticated service-role "
            "query to read or write rows belonging to other tenants. "
            "Enable RLS with `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;` and create "
            "policies that restrict reads and writes to the owning user_id or organisation_id. "
            "Test that a session authenticated as user A cannot retrieve rows owned by user B."
        ),
    ),
    "firebase_public": (
        "Add Firestore / Realtime DB security rules that deny unauthenticated reads and writes.",
        (
            "Open Firebase security rules (`allow read, write: if true`) expose your entire "
            "database to the internet without any access control. "
            "Replace permissive rules with identity-based checks: "
            "`allow read, write: if request.auth != null && request.auth.uid == resource.data.uid`. "
            "Deploy the new rules via `firebase deploy --only firestore:rules` and run the "
            "Firebase Rules Playground to verify that anonymous requests are rejected."
        ),
    ),
    # ── Injection ────────────────────────────────────────────────────────
    "sql_injection": (
        "Replace string-formatted SQL with parameterized queries or an ORM.",
        (
            "Interpolating user input directly into SQL strings allows attackers to alter "
            "query logic, dump data, or drop tables. "
            "Use parameterized queries (`cursor.execute(sql, (param,))` in Python, "
            "`db.query(sql, [param])` in Node.js) or an ORM (SQLAlchemy, Prisma, Sequelize) "
            "that handles escaping automatically. "
            "Never use string formatting, f-strings, or concatenation to build SQL."
        ),
    ),
    "command_injection": (
        "Pass arguments as a list to subprocess/exec and never interpolate user input into shell strings.",
        (
            "Passing user-controlled strings to a shell interpreter allows attackers to inject "
            "arbitrary OS commands. "
            "Replace shell=True / exec() with a list-form call: `subprocess.run(['cmd', arg])` "
            "in Python or `execFile('cmd', [arg])` in Node.js. "
            "If a shell is truly required, allowlist every possible input and reject anything "
            "that does not match. Never concatenate user input into a shell command string."
        ),
    ),
    "log_injection": (
        "Sanitize user input before logging to prevent log forging.",
        (
            "Writing raw user input to logs allows attackers to inject fake log entries, "
            "corrupt log files, or exploit downstream log parsers. "
            "Strip or encode newline characters (\\n, \\r) from any user-controlled value before "
            "it appears in a log statement. Consider using a structured logging library "
            "(structlog, winston) that serializes values safely as JSON fields rather than "
            "interpolating them into raw strings."
        ),
    ),
    "unsafe_dynamic_code": (
        "Remove eval() / exec() on user input; use a safe alternative.",
        (
            "Evaluating user-supplied strings as code allows arbitrary code execution with "
            "the privileges of the running process. "
            "Remove all uses of eval(), exec(), Function(), or equivalent dynamic code "
            "execution on untrusted data. "
            "If dynamic dispatch is needed, use a controlled lookup table (dict / switch) that "
            "maps allowed string keys to pre-defined functions."
        ),
    ),
    # ── CORS & headers ───────────────────────────────────────────────────
    "cors_wildcard": (
        "Restrict CORS to an explicit allowlist of trusted origins.",
        (
            "A wildcard CORS policy (Access-Control-Allow-Origin: *) allows any web page on "
            "the internet to make cross-origin requests to your API. "
            "Replace the wildcard with an explicit list of approved origins and validate "
            "the incoming Origin header against that list at request time. "
            "Ensure your framework's CORS middleware is configured before any route handlers."
        ),
    ),
    "cors_wildcard_credentials": (
        "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
        (
            "This combination is rejected by browsers per the CORS spec, but some middleware "
            "silently reflects the request origin instead — allowing any site to make "
            "credentialed (cookie-bearing) cross-origin requests to your API. "
            "Set an explicit origin allowlist and only send Allow-Credentials: true for "
            "origins you trust. Audit every CORS response header to confirm the wildcard "
            "is never echoed when credentials are allowed."
        ),
    ),
    "missing_security_headers": (
        "Add Content-Security-Policy, X-Frame-Options, and HSTS response headers.",
        (
            "Missing security headers leave browsers without critical protections against "
            "XSS, clickjacking, and protocol downgrade attacks. "
            "Add at minimum: Content-Security-Policy, Strict-Transport-Security, "
            "X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and "
            "Referrer-Policy: strict-origin-when-cross-origin. "
            "Use a library (helmet for Express, secure-headers for Python) to set these "
            "automatically on every response."
        ),
    ),
    # ── Rate limiting & design ───────────────────────────────────────────
    "missing_rate_limit": (
        "Apply a rate limiter to all public-facing and auth endpoints.",
        (
            "Endpoints without rate limiting are vulnerable to brute-force, credential "
            "stuffing, and resource exhaustion attacks. "
            "Add a token-bucket or sliding-window rate limiter keyed on IP address (and "
            "user ID for authenticated endpoints) with appropriate per-minute limits. "
            "For auth routes use stricter limits (e.g. 5 attempts / 15 min) and add "
            "exponential backoff or account lockout after repeated failures."
        ),
    ),
    # ── JWT & crypto ─────────────────────────────────────────────────────
    "weak_jwt": (
        "Use a strong algorithm (RS256 / ES256) and a cryptographically random secret ≥ 32 bytes.",
        (
            "Weak JWT secrets or insecure algorithm choices (including 'none') allow attackers "
            "to forge tokens and impersonate any user. "
            "Generate your secret with a CSPRNG (`secrets.token_hex(32)` in Python, "
            "`crypto.randomBytes(32)` in Node.js) and store it in an environment variable. "
            "Set `algorithms=['HS256']` (or RS256/ES256) explicitly when verifying — never "
            "pass an empty list or allow the 'none' algorithm."
        ),
    ),
    # ── Supabase ─────────────────────────────────────────────────────────
    "supabase_anon_write": (
        "Restrict Supabase anon key to read-only operations and enforce RLS.",
        (
            "Allowing write operations via the anonymous Supabase key means any unauthenticated "
            "user can insert, update, or delete rows. "
            "Audit every table for RLS policies that allow inserts/updates from "
            "request.auth = null and remove them. "
            "Reserve mutation operations for service-role calls that run server-side, never "
            "in client-facing code that ships the anon key."
        ),
    ),
    # ── Dependency risk ──────────────────────────────────────────────────
    "slopsquatting": (
        "Verify the package exists on the official registry before shipping and pin its version.",
        (
            "AI-generated code sometimes references non-existent or typosquatted packages. "
            "Confirm the exact package name on npmjs.com or pypi.org before installing. "
            "If the package does not exist, find and use the correct legitimate alternative. "
            "Pin the exact version in your lockfile and enable Dependabot or Renovate to "
            "surface future vulnerabilities."
        ),
    ),
    # ── AI / LLM security ────────────────────────────────────────────────
    "prompt_injection": (
        "Sanitize and isolate user-supplied content from LLM system instructions.",
        (
            "Prompt injection attacks embed instructions in user input that override your "
            "system prompt, leaking data or causing the model to perform unauthorized actions. "
            "Separate trusted system instructions from untrusted user content using distinct "
            "message roles and never interpolate raw user input directly into the system prompt. "
            "Apply an input filter that rejects or escapes common injection patterns "
            "('Ignore previous instructions', 'You are now...') before forwarding to the model."
        ),
    ),
    "unsafe_tool_execution": (
        "Validate and sandbox every tool call invoked by an LLM agent.",
        (
            "LLM agents that execute tool calls without validation can be manipulated by "
            "adversarial inputs into running arbitrary code, deleting data, or exfiltrating "
            "secrets. "
            "Implement an explicit allowlist of permitted tool names and parameter shapes. "
            "Run tool execution in a sandboxed environment with minimal OS privileges. "
            "Require human-in-the-loop confirmation for any irreversible action."
        ),
    ),
    "agent_privilege_escalation": (
        "Enforce least-privilege scopes on all agent credentials and tool permissions.",
        (
            "Agents operating with broad scopes can be manipulated into escalating their "
            "effective permissions through chained tool calls or adversarial prompts. "
            "Grant each agent only the minimum set of tool permissions and API scopes needed "
            "for its specific task. "
            "Log all tool invocations and alert on any call that exercises a scope the agent "
            "has not previously used in normal operation."
        ),
    ),
    "mcp_untrusted_server": (
        "Only connect MCP agents to explicitly approved, integrity-verified server endpoints.",
        (
            "Connecting to an untrusted or dynamically resolved MCP server allows a malicious "
            "endpoint to issue arbitrary tool calls back to the agent. "
            "Maintain a static allowlist of approved MCP server URLs and verify their TLS "
            "certificates and expected response schemas on startup. "
            "Reject any server whose identity cannot be cryptographically verified."
        ),
    ),
    "llm_secret_exposure": (
        "Remove secrets from LLM context windows and redact them from logs and responses.",
        (
            "Secrets passed into an LLM prompt (via system instructions, retrieved documents, "
            "or tool results) can be leaked in model responses or logged in request traces. "
            "Scan context payloads for secret-like patterns before sending to the model and "
            "redact or replace them with placeholder tokens. "
            "Implement a response filter that rejects any completion containing known "
            "credential patterns before it reaches the caller."
        ),
    ),
    "agent_memory_poisoning": (
        "Validate and sanitize all data written to or read from agent memory stores.",
        (
            "An attacker who can influence what is stored in an agent's long-term memory can "
            "inject persistent malicious instructions that affect future interactions. "
            "Treat all externally sourced data as untrusted before writing it to a memory "
            "store. Apply content filtering on ingestion and re-validate retrieved memories "
            "against the original task intent before acting on them."
        ),
    ),
    "retrieval_poisoning": (
        "Validate retrieved vector-store documents before injecting them into LLM context.",
        (
            "Documents in a RAG pipeline can contain adversarial instructions that hijack "
            "model behavior when retrieved. "
            "Apply relevance scoring thresholds and content filtering on all retrieved chunks "
            "before they are added to the prompt context. "
            "Consider a two-stage retrieval where a lightweight classifier screens out "
            "chunks containing instruction-like content before they reach the primary model."
        ),
    ),
}


def get_static_remediation(category: str) -> tuple[str, str] | None:
    """
    Return (recommendation, fix) for a known vulnerability category, or None.

    Returns None for unknown categories so callers can distinguish
    'no entry' from 'empty string'.
    """
    return _REMEDIATION.get(category)


def apply_static_remediation(finding) -> bool:
    """
    Populate finding.recommendation, finding.fix, and finding.fix_source from
    the static lookup table if both fields are currently empty.

    Skips rejected findings (false positives).
    Returns True if remediation was applied.
    """
    # Never add remediation to rejected findings
    if finding.status == "rejected":
        return False
    # Only fill gaps — do not overwrite LLM-generated content
    if finding.recommendation and finding.fix:
        return False
    entry = get_static_remediation(finding.category)
    if not entry:
        return False
    recommendation, fix = entry
    finding.recommendation = recommendation
    finding.fix = fix
    finding.fix_source = "static_table"
    return True
