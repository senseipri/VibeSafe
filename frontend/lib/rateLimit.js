import { getCollections } from './mongo';

// Free-tier limits per IP per hour. Tweak per endpoint.
export const LIMITS = {
  'scan/github': { max: 5, windowSec: 60 * 60, label: 'scans' },
  waitlist: { max: 3, windowSec: 60 * 60, label: 'waitlist signups' },
  'contact': { max: 3, windowSec: 60 * 60, label: 'messages' },
};

export function getClientIp(request) {
  const xff = request.headers.get('x-forwarded-for') || '';
  const ip = xff.split(',')[0]?.trim();
  if (ip) return ip;
  const real = request.headers.get('x-real-ip');
  if (real) return real.trim();
  return 'unknown';
}

// Returns { allowed: boolean, remaining: number, retryAfterSec: number, limit: number }
export async function checkRateLimit(endpoint, ip) {
  const cfg = LIMITS[endpoint];
  if (!cfg) return { allowed: true, remaining: Infinity, retryAfterSec: 0, limit: Infinity };
  try {
    const { rateLimitEvents } = await getCollections();
    const now = new Date();
    const windowStart = new Date(now.getTime() - cfg.windowSec * 1000);
    const recent = await rateLimitEvents
      .find({ ip, endpoint, ts: { $gte: windowStart } })
      .sort({ ts: 1 })
      .toArray();
    if (recent.length >= cfg.max) {
      const oldest = recent[0].ts;
      const resetAt = new Date(oldest.getTime() + cfg.windowSec * 1000);
      const retryAfterSec = Math.max(1, Math.ceil((resetAt.getTime() - now.getTime()) / 1000));
      return {
        allowed: false,
        remaining: 0,
        retryAfterSec,
        limit: cfg.max,
        label: cfg.label,
      };
    }
    return {
      allowed: true,
      remaining: Math.max(0, cfg.max - recent.length),
      retryAfterSec: 0,
      limit: cfg.max,
      label: cfg.label,
    };
  } catch (e) {
    // Fail-open if Mongo is unavailable so the marketing site stays usable.
    console.warn('[rate-limit] fail-open:', e?.message);
    return { allowed: true, remaining: cfg.max, retryAfterSec: 0, limit: cfg.max };
  }
}

export async function recordRateLimitEvent(endpoint, ip) {
  try {
    const { rateLimitEvents } = await getCollections();
    await rateLimitEvents.insertOne({ ip, endpoint, ts: new Date() });
  } catch (e) {
    console.warn('[rate-limit] record error:', e?.message);
  }
}
