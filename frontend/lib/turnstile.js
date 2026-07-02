const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export function turnstileEnabled() {
  return Boolean(process.env.TURNSTILE_SECRET_KEY);
}

// Returns { ok: boolean, error?: string }
export async function verifyTurnstileToken(token, remoteIp) {
  if (!turnstileEnabled()) return { ok: true };
  if (!token || typeof token !== 'string' || token.length < 8) {
    return { ok: false, error: 'Captcha not completed' };
  }
  try {
    const form = new URLSearchParams();
    form.append('secret', process.env.TURNSTILE_SECRET_KEY);
    form.append('response', token);
    if (remoteIp) form.append('remoteip', remoteIp);
    const res = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    const data = await res.json();
    if (data?.success) return { ok: true };
    return {
      ok: false,
      error: 'Captcha failed (' + (data?.['error-codes']?.join(',') || 'unknown') + ')',
    };
  } catch (e) {
    console.warn('[turnstile] verify error:', e?.message);
    return { ok: false, error: 'Captcha verification unavailable' };
  }
}
