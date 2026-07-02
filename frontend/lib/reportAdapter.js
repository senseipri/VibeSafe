/**
 * reportAdapter.js
 * Transforms FastAPI backend report/finding data shapes
 * into the shape expected by the Next.js frontend components.
 *
 * Backend finding fields:  file_path, line_number, owasp_cat,
 *                          attack_chain, confirmed_by, false_positive_risk,
 *                          severity (lowercase)
 * Frontend finding fields: file, line, owasp, attacker_scenario,
 *                          consensus, confidence, severity (UPPERCASE), title
 */

const CATEGORY_LABELS = {
  hardcoded_secret: 'Hardcoded Secret',
  committed_env_file: 'Committed .env File',
  missing_auth: 'Missing Auth',
  sql_injection: 'SQL Injection',
  log_injection: 'Log Injection',
  cors_wildcard_credentials: 'CORS Misconfiguration',
  cors_wildcard: 'CORS Misconfiguration',
  rls_disabled: 'RLS Disabled',
  firebase_public: 'Firebase Public',
  missing_rate_limit: 'Rate Limiting',
  weak_jwt: 'Weak JWT',
  slopsquatting: 'Slopsquatting',
  missing_security_headers: 'Missing Security Headers',
};

// "A02:2021 – Cryptographic Failures" → "OWASP A02"
function owaspShort(owaspCat) {
  if (!owaspCat) return 'OWASP';
  const m = owaspCat.match(/^(A\d+)/);
  return m ? `OWASP ${m[1]}` : 'OWASP';
}

function fixLanguageFromPath(filePath) {
  if (!filePath) return 'code';
  const ext = (filePath.split('.').pop() || '').toLowerCase();
  const MAP = {
    ts: 'typescript', tsx: 'typescript',
    js: 'javascript', jsx: 'javascript',
    py: 'python', sql: 'sql',
    json: 'json', yaml: 'yaml', yml: 'yaml',
    sh: 'bash', env: 'bash', md: 'markdown',
    rb: 'ruby', go: 'go', java: 'java', rs: 'rust',
  };
  return MAP[ext] || 'code';
}

// confirmed_by: ["claude", "gpt4o"] → { claude: true, gpt4o: true, gemini: false }
function buildConsensus(confirmedBy = []) {
  const consensus = {
    claude: confirmedBy.includes('claude'),
    gpt4o: confirmedBy.includes('gpt4o'),
    gemini: confirmedBy.includes('gemini'),
  };
  // Dynamically include any other validators
  confirmedBy.forEach((model) => {
    if (model) {
      consensus[model] = true;
    }
  });
  return consensus;
}

// false_positive_risk "low" → confidence "high" (inverse)
function buildConfidence(falsePositiveRisk) {
  if (falsePositiveRisk === 'high') return 'low';
  if (falsePositiveRisk === 'medium') return 'medium';
  return 'high';
}

function buildTitle(finding) {
  const catLabel = CATEGORY_LABELS[finding.category] || finding.category;
  const filename = finding.file_path ? finding.file_path.split('/').pop() : '';
  return filename ? `${catLabel} in ${filename}` : catLabel;
}

/**
 * Adapt a single backend finding dict to the shape expected by FindingItem.jsx
 */
export function adaptFinding(f) {
  return {
    id: f.id,
    severity: (f.severity || 'low').toUpperCase(),
    owasp: owaspShort(f.owasp_cat),
    owasp_cat: f.owasp_cat || '',

    category: CATEGORY_LABELS[f.category] || f.category,

    file: f.file_path || '',
    line: f.line_number || 0,

    title: buildTitle(f),

    description: f.description || '',
    evidence: f.evidence || '',

    recommendation:
      f.recommendation ||
      f.remediation ||
      f.fix ||
      '',

    fix:
      f.fix ||
      f.remediation ||
      '',

    fix_code: f.fix_code || '',
    fix_source: f.fix_source || '',
    cvss_score: f.cvss_score ?? null,
    cvss_vector: f.cvss_vector || '',
    status: f.status || 'candidate',
    validator: f.validator || '',

    impact: f.impact || '',

    references: f.references || [],

    fix_language: fixLanguageFromPath(f.file_path),

    attacker_scenario:
      f.attack_chain ||
      'An attacker can exploit this vulnerability to compromise your application.',
  
    confidence: buildConfidence(f.false_positive_risk),

    consensus: buildConsensus(f.confirmed_by),
    confirmed_by: f.confirmed_by || [],
  };
}

/**
 * Adapt a full backend report (ScanReport.to_dict()) to the shape
 * expected by app/report/[id]/page.js
 */
export function adaptReport(backendReport) {
  const fc = backendReport.finding_counts || {};
  const findings = (backendReport.findings || []).map(adaptFinding);

  return {
    scan_id: backendReport.scan_id,
    repo_url: backendReport.repo_url || '',
    created_at: backendReport.scanned_at || new Date().toISOString(),
    risk_score: backendReport.risk_score ?? 0,
    findings,
    // Preserving all backend report properties
    summary: backendReport.summary || '',
    verdict: backendReport.verdict || '',
    highest_severity: backendReport.highest_severity || '',
    frameworks: backendReport.frameworks || [],
    repo_context: backendReport.repo_context || {},
    models_used: backendReport.models_used || [],
    share_url: backendReport.share_url || '',
    files_scanned: backendReport.files_scanned ?? 0,
    scan_ms: backendReport.scan_ms ?? 0,
    stats: {
      critical: fc.critical ?? findings.filter((f) => f.severity === 'CRITICAL').length,
      high: fc.high ?? findings.filter((f) => f.severity === 'HIGH').length,
      medium: fc.medium ?? findings.filter((f) => f.severity === 'MEDIUM').length,
      low: fc.low ?? findings.filter((f) => f.severity === 'LOW').length,
      files_scanned: backendReport.files_scanned ?? 0,
      packages_audited: 0,
      lines_of_code: 0,
      duration_seconds: Math.round((backendReport.scan_ms ?? 0) / 1000),
    },
  };
}
