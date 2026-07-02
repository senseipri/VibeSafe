// Deterministic mock report generator. Shape matches the eventual real API response.
const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const TEMPLATES = [
  {
    severity: 'CRITICAL',
    title: 'Supabase RLS disabled — public read/write on all tables',
    owasp: 'OWASP A01',
    category: 'Public Database',
    file: 'supabase/migrations/0001_init.sql',
    line: 14,
    description:
      'Row Level Security is disabled on every table in the public schema. Any user with the anon key (which ships in your frontend bundle) can read or write any row.',
    evidence: 'ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;\nALTER TABLE public.payments DISABLE ROW LEVEL SECURITY;',
    fix_code: "-- Enable RLS and add a policy that restricts access to the row owner\nALTER TABLE public.users ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY \"users can read their own row\"\n  ON public.users FOR SELECT\n  USING (auth.uid() = id);\n\nCREATE POLICY \"users can update their own row\"\n  ON public.users FOR UPDATE\n  USING (auth.uid() = id);",
    fix_language: 'sql',
    attacker_scenario:
      "With the anon key exposed in your client bundle, an attacker queries `select * from users` directly via PostgREST and exfiltrates every email, hashed password, and Stripe customer id in your database.",
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: true },
  },
  {
    severity: 'CRITICAL',
    title: 'Hardcoded OPENAI_API_KEY in source',
    owasp: 'OWASP A02',
    category: 'Hardcoded Secrets',
    file: 'app/config/app.config.ts',
    line: 23,
    description:
      'A production OpenAI API key is committed directly to the repository. Anyone with read access (including via leaked archives or fork history) can use it to bill your account.',
    evidence: 'export const OPENAI_API_KEY = "sk-proj-Rk2hX_8aN3K9Lm...";',
    fix_code: "// Read from environment variable instead\nexport const OPENAI_API_KEY = process.env.OPENAI_API_KEY;\n\nif (!OPENAI_API_KEY) {\n  throw new Error(\"OPENAI_API_KEY is not set\");\n}\n\n// Then rotate the leaked key in the OpenAI dashboard immediately,\n// and purge it from git history with: git filter-repo --invert-paths --path app/config/app.config.ts",
    fix_language: 'typescript',
    attacker_scenario:
      "An attacker scrapes your public repo (or buys a leaked dump), finds the key, and racks up $40k in API charges before you notice.",
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: true },
  },
  {
    severity: 'HIGH',
    title: 'CORS wildcard with credentials — CSRF possible',
    owasp: 'OWASP A05',
    category: 'CORS Misconfiguration',
    file: 'server/middleware/cors.py',
    line: 11,
    description:
      'CORS is configured with allow_origins=["*"] and allow_credentials=True. Browsers normally block this combination, but misconfigured proxies and older clients can still process cross-origin requests with cookies.',
    evidence: 'app.add_middleware(\n  CORSMiddleware,\n  allow_origins=["*"],\n  allow_credentials=True,\n)',
    fix_code: "# Use an explicit allowlist and remove the wildcard\nALLOWED_ORIGINS = [\n    \"https://yourdomain.com\",\n    \"https://app.yourdomain.com\",\n]\n\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=ALLOWED_ORIGINS,\n    allow_credentials=True,\n    allow_methods=[\"GET\", \"POST\", \"PUT\", \"DELETE\"],\n    allow_headers=[\"Authorization\", \"Content-Type\"],\n)",
    fix_language: 'python',
    attacker_scenario:
      "Attacker hosts evil.com, victim visits while logged into your app. evil.com fires a credentialed cross-origin request to your API and reads the response.",
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: true },
  },
  {
    severity: 'HIGH',
    title: 'SQL injection via f-string interpolation',
    owasp: 'OWASP A03',
    category: 'SQL Injection',
    file: 'server/routes/users.py',
    line: 47,
    description:
      'User-supplied email is interpolated directly into a SQL query using an f-string. Standard tautology and UNION attacks are trivially possible.',
    evidence: 'q = f"SELECT * FROM users WHERE email = \'{user_email}\'"\ncur.execute(q)',
    fix_code: "# Use parameterised queries — the driver will escape values for you\ncur.execute(\n    \"SELECT id, email, name FROM users WHERE email = %s\",\n    (user_email,),\n)\nrow = cur.fetchone()",
    fix_language: 'python',
    attacker_scenario:
      "Attacker sends email='' OR 1=1 --. The query returns every user. With UNION SELECT they can dump any other table.",
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: true },
  },
  {
    severity: 'HIGH',
    title: 'Slopsquatting risk: package not in npm registry',
    owasp: 'OWASP A06',
    category: 'Slopsquatting',
    file: 'package.json',
    line: 18,
    description:
      'The package `react-fetch-utils` (added by an AI suggestion) does not exist in the npm registry. Attackers commonly register such hallucinated names with malicious code waiting to be installed.',
    evidence: '"dependencies": {\n  "react-fetch-utils": "^1.2.0"\n}',
    fix_code: "// Remove the hallucinated package and use a real, audited alternative\n// (e.g. native fetch, axios, or @tanstack/react-query)\n\n// package.json\n\"dependencies\": {\n  \"axios\": \"^1.7.0\"\n}\n\n// then\nimport axios from 'axios';\nconst res = await axios.get('/api/users');",
    fix_language: 'javascript',
    attacker_scenario:
      "Attacker registers the package name first with a postinstall script that steals env vars on `npm install`.",
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: true },
  },
  {
    severity: 'HIGH',
    title: 'Admin route has no auth middleware',
    owasp: 'OWASP A01',
    category: 'Missing Auth',
    file: 'app/api/admin/users/route.ts',
    line: 8,
    description:
      'The /api/admin/users endpoint returns every user record but has no authentication or authorization check.',
    evidence: 'export async function GET(req: Request) {\n  const users = await db.users.findMany();\n  return Response.json(users);\n}',
    fix_code: "import { getServerSession } from 'next-auth';\nimport { authOptions } from '@/lib/auth';\n\nexport async function GET(req: Request) {\n  const session = await getServerSession(authOptions);\n  if (!session?.user || session.user.role !== 'admin') {\n    return new Response('Unauthorized', { status: 401 });\n  }\n  const users = await db.users.findMany({\n    select: { id: true, email: true, name: true, createdAt: true },\n  });\n  return Response.json(users);\n}",
    fix_language: 'typescript',
    attacker_scenario:
      "Attacker guesses the /api/admin/users URL (or finds it in your client bundle) and downloads every user's email and PII.",
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: false },
  },
  {
    severity: 'MEDIUM',
    title: 'No rate limiting on /api/auth/login',
    owasp: 'OWASP A04',
    category: 'Rate Limiting',
    file: 'app/api/auth/login/route.ts',
    line: 4,
    description:
      'The login endpoint has no rate limiting. Credential stuffing and brute force attacks against your user base are trivially possible.',
    evidence: 'export async function POST(req: Request) {\n  const { email, password } = await req.json();\n  // ... no limiter ...\n}',
    fix_code: "import { Ratelimit } from '@upstash/ratelimit';\nimport { Redis } from '@upstash/redis';\n\nconst limiter = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(5, '15 m'),\n});\n\nexport async function POST(req: Request) {\n  const ip = req.headers.get('x-forwarded-for') ?? 'anon';\n  const { success, reset } = await limiter.limit(`login:${ip}`);\n  if (!success) {\n    return new Response('Too many attempts', {\n      status: 429,\n      headers: { 'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)) },\n    });\n  }\n  // ... existing login logic ...\n}",
    fix_language: 'typescript',
    attacker_scenario:
      "Attacker runs a credential-stuffing attack with 100k leaked credentials and successfully logs in as ~0.5% of users.",
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: true },
  },
  {
    severity: 'MEDIUM',
    title: 'Sensitive data logged to stdout',
    owasp: 'OWASP A09',
    category: 'Logging',
    file: 'server/auth.py',
    line: 62,
    description:
      'Full request bodies (including passwords and tokens) are logged on every login attempt. These end up in your log aggregator unencrypted.',
    evidence: 'print("login attempt:", request.json())',
    fix_code: "# Redact sensitive fields before logging\nSENSITIVE = {\"password\", \"token\", \"api_key\", \"secret\"}\n\ndef safe_log(payload: dict):\n    redacted = {k: (\"***\" if k in SENSITIVE else v) for k, v in payload.items()}\n    logger.info(\"login attempt: %s\", redacted)\n\nsafe_log(request.json())",
    fix_language: 'python',
    attacker_scenario:
      'Anyone with read access to your log aggregator (an oncall engineer, a leaked Datadog token) can harvest plaintext passwords.',
    confidence: 'medium',
    consensus: { claude: true, gpt4o: false, gemini: true },
  },
  {
    severity: 'MEDIUM',
    title: 'Cookies missing Secure + SameSite flags',
    owasp: 'OWASP A05',
    category: 'Session Hardening',
    file: 'server/session.py',
    line: 31,
    description:
      'Session cookies are set without HttpOnly, Secure, or SameSite. They can be read by JavaScript and sent over HTTP.',
    evidence: 'response.set_cookie("session", token)',
    fix_code: "response.set_cookie(\n    key=\"session\",\n    value=token,\n    httponly=True,\n    secure=True,\n    samesite=\"strict\",\n    max_age=60 * 60 * 24 * 7,\n)",
    fix_language: 'python',
    attacker_scenario:
      'A single XSS payload anywhere on your domain can read document.cookie and steal active sessions.',
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: true },
  },
  {
    severity: 'LOW',
    title: 'Outdated dependency: next 13.4.0',
    owasp: 'OWASP A06',
    category: 'Outdated Dependency',
    file: 'package.json',
    line: 22,
    description:
      'You are pinned to Next.js 13.4.0 which has known SSRF and middleware-bypass advisories. Upgrade to the latest 15.x.',
    evidence: '"next": "13.4.0"',
    fix_code: "# In your package.json\n\"next\": \"^15.0.0\"\n\n# then\nyarn add next@latest react@latest react-dom@latest\nyarn next-codemod upgrade",
    fix_language: 'bash',
    attacker_scenario:
      'Known CVEs in this Next.js version allow middleware bypass on protected routes.',
    confidence: 'high',
    consensus: { claude: true, gpt4o: true, gemini: true },
  },
];

function hashStr(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

export function buildMockReport(repoUrl, scanId) {
  // Pick a deterministic subset of findings based on the scan id
  const seed = hashStr(scanId + repoUrl);
  const count = 7 + (seed % 4); // 7–10 findings
  const findings = [];
  const used = new Set();
  for (let i = 0; i < count && used.size < TEMPLATES.length; i++) {
    const idx = (seed + i * 7) % TEMPLATES.length;
    if (used.has(idx)) continue;
    used.add(idx);
    const t = TEMPLATES[idx];
    findings.push({
      id: `${scanId}-${idx}`,
      ...t,
    });
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const stats = {
    critical: findings.filter((f) => f.severity === 'CRITICAL').length,
    high: findings.filter((f) => f.severity === 'HIGH').length,
    medium: findings.filter((f) => f.severity === 'MEDIUM').length,
    low: findings.filter((f) => f.severity === 'LOW').length,
    files_scanned: 30 + (seed % 80),
    packages_audited: 80 + (seed % 200),
    lines_of_code: 4000 + (seed % 20000),
    duration_seconds: 38 + (seed % 18),
  };

  // CVSS-weighted risk score
  const score = Math.min(
    100,
    stats.critical * 22 + stats.high * 12 + stats.medium * 5 + stats.low * 1.5,
  );

  return {
    scan_id: scanId,
    repo_url: repoUrl,
    status: 'complete',
    created_at: new Date().toISOString(),
    risk_score: Math.round(score),
    findings,
    stats,
    engines: {
      claude: { model: 'claude-sonnet-4.5', ran: true },
      gpt4o: { model: 'gpt-4o', ran: true },
      gemini: { model: 'gemini-2.5-pro', ran: true },
    },
  };
}

export function severityColor(s) {
  return (
    {
      CRITICAL: '#FF4B1F',
      HIGH: '#FF9500',
      MEDIUM: '#FFD60A',
      LOW: '#3B9EFF',
    }[s] || '#8099B0'
  );
}
