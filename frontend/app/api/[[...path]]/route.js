import { NextResponse } from 'next/server';
import { checkRateLimit, recordRateLimitEvent, getClientIp, LIMITS } from '@/lib/rateLimit';
import { verifyTurnstileToken, turnstileEnabled } from '@/lib/turnstile';
import { getCollections } from '@/lib/mongo';
import { adaptReport } from '@/lib/reportAdapter';

const json = (data, init = {}) => NextResponse.json(data, init);

// ── Backend URL ─────────────────────────────────────────────────
// All real scan requests are proxied to the FastAPI backend.
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8000';

async function backendFetch(path, options = {}) {
  const url = `${BACKEND_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  return res;
}

// ── Validation helpers ──────────────────────────────────────────
const GITHUB_RE = /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\/?$/;
const LOOSE_RE =
  /^(?:https:\/\/github\.com\/|github\.com\/)?([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)\/?$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,189}\.[^\s@]{1,64}$/;

function normaliseRepo(input) {
  const v = (input || '').trim();
  if (!v) return null;
  if (GITHUB_RE.test(v)) return v.replace(/\/$/, '');
  const m = v.match(LOOSE_RE);
  if (m) return `https://github.com/${m[1]}/${m[2]}`;
  return null;
}

function tooManyRequests({ retryAfterSec, limit, label }) {
  return json(
    {
      ok: false,
      error: `Slow down — ${limit} ${label || 'requests'} per hour per IP for the free tier.`,
      retry_after_seconds: retryAfterSec,
    },
    { status: 429, headers: { 'Retry-After': String(retryAfterSec) } },
  );
}

// ── GET ─────────────────────────────────────────────────────────
export async function GET(request, { params }) {
  const path = (params?.path || []).join('/');

  // ---- GET /api/health (marketing-site health, not backend) -----
  if (path === 'health') {
    return json({
      ok: true,
      service: 'vibesafe-marketing',
      turnstile_enabled: turnstileEnabled(),
    });
  }

  // ---- GET /api/stats (static marketing numbers) ----------------
  if (path === 'stats') {
    return json({
      repos_scanned: 47000,
      vulnerabilities_found: 312000,
      savings_usd: 4200000,
    });
  }

  // ---- GET /api/scan/{id}/status → proxy to FastAPI backend -----
  const statusMatch = path.match(/^scan\/([^/]+)\/status$/);
  if (statusMatch) {
    const scanId = statusMatch[1];
    try {
      const res = await backendFetch(`/api/scan/${scanId}/status`);
      const data = await res.json();
      if (!res.ok) {
        return json({ ok: false, error: data?.detail || 'Scan not found' }, { status: res.status });
      }
      return json({ ok: true, ...data });
    } catch {
      return json({ ok: false, error: 'Backend unavailable' }, { status: 503 });
    }
  }

  // ---- GET /api/report/{id} → proxy + adapt to frontend shape ---
  const reportMatch = path.match(/^report\/([^/]+)$/);
  if (reportMatch) {
    const scanId = reportMatch[1];
    try {
      const res = await backendFetch(`/api/report/${scanId}`);
      const data = await res.json();
      if (!res.ok) {
        return json(
          { ok: false, error: data?.detail || 'Report not found' },
          { status: res.status },
        );
      }
      // Transform backend shape → frontend shape
      const adapted = adaptReport(data);
      return json({ ok: true, report: adapted });
    } catch {
      return json({ ok: false, error: 'Backend unavailable' }, { status: 503 });
    }
  }

  // ---- GET /api/rate-limit/{endpoint} → quota for caller's IP ---
  if (path.startsWith('rate-limit/')) {
    const endpoint = path.slice('rate-limit/'.length);
    if (!LIMITS[endpoint]) return json({ ok: false, error: 'Unknown endpoint' }, { status: 404 });
    const ip = getClientIp(request);
    const rl = await checkRateLimit(endpoint, ip);
    return json({
      ok: true,
      endpoint,
      limit: rl.limit,
      remaining: rl.allowed ? rl.remaining : 0,
      retry_after_seconds: rl.retryAfterSec,
    });
  }

  return json({ message: 'VibeSafe API' });
}

// ── POST ────────────────────────────────────────────────────────
export async function POST(request, { params }) {
  const path = (params?.path || []).join('/');
  const ip = getClientIp(request);

  let body = {};
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'Invalid JSON body' }, { status: 400 });
  }

  // ---- POST /api/scan/github → proxy to FastAPI backend ---------
  if (path === 'scan/github') {
    // Honeypot check
    if (body?.website) {
      return json({ ok: true, scan_id: 'ignored' });
    }

    const repo = normaliseRepo(body?.repo_url);
    if (!repo) {
      return json(
        { ok: false, error: 'Please paste a valid GitHub repository URL.' },
        { status: 400 },
      );
    }

    // Rate limit BEFORE backend call to short-circuit abusers cheaply.
    const rl = await checkRateLimit('scan/github', ip);
    if (!rl.allowed) return tooManyRequests(rl);

    // Turnstile verification.
    if (turnstileEnabled()) {
      const verdict = await verifyTurnstileToken(body?.turnstile_token, ip);
      if (!verdict.ok) return json({ ok: false, error: verdict.error }, { status: 400 });
    }

    await recordRateLimitEvent('scan/github', ip);

    // Forward to FastAPI backend
    try {
      const res = await backendFetch('/api/scan/github', {
        method: 'POST',
        body: JSON.stringify({
          repo_url: repo,
          github_token: body?.github_token || '',
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        return json(
          { ok: false, error: data?.detail || 'Failed to start scan' },
          { status: res.status },
        );
      }

      // Best-effort: log scan metadata to MongoDB (not source code).
      try {
        const { scans } = await getCollections();
        await scans.insertOne({
          scan_id: data.scan_id,
          repo_url: repo,
          ip,
          created_at: new Date(),
        });
      } catch {
        // non-fatal
      }

      return json({
        ok: true,
        scan_id: data.scan_id,
        repo_url: repo,
        estimated_duration_ms: 30000,
      });
    } catch {
      return json({ ok: false, error: 'Scan service unavailable. Please try again shortly.' }, { status: 503 });
    }
  }

  // ---- POST /api/waitlist ----------------------------------------
  if (path === 'waitlist') {
    if (body?.website) return json({ ok: true });

    const email = (body?.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email)) {
      return json({ ok: false, error: 'Please enter a valid email address.' }, { status: 400 });
    }

    const rl = await checkRateLimit('waitlist', ip);
    if (!rl.allowed) return tooManyRequests(rl);

    if (turnstileEnabled() && body?.turnstile_token) {
      const verdict = await verifyTurnstileToken(body?.turnstile_token, ip);
      if (!verdict.ok) return json({ ok: false, error: verdict.error }, { status: 400 });
    }

    await recordRateLimitEvent('waitlist', ip);

    const source = String(body?.source || 'unknown').slice(0, 64);
    try {
      const { waitlist } = await getCollections();
      await waitlist.updateOne(
        { email },
        {
          $setOnInsert: {
            email,
            created_at: new Date(),
            source,
            ip,
          },
          $set: { last_seen_at: new Date(), last_source: source },
        },
        { upsert: true },
      );
    } catch (e) {
      return json({ ok: false, error: 'Could not save email. Try again shortly.' }, { status: 500 });
    }

    return json({ ok: true, email });
  }

  return json({ message: 'ok' });
}
