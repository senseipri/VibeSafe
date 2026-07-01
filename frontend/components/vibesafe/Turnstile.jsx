'use client';
import { useEffect, useRef, useState } from 'react';

let scriptLoadingPromise = null;
function loadTurnstileScript() {
  if (typeof window === 'undefined') return Promise.reject(new Error('SSR'));
  if (window.turnstile) return Promise.resolve();
  if (scriptLoadingPromise) return scriptLoadingPromise;
  scriptLoadingPromise = new Promise((resolve, reject) => {
    const existing = document.querySelector('script[data-turnstile="true"]');
    if (existing) {
      existing.addEventListener('load', () => resolve());
      existing.addEventListener('error', reject);
      return;
    }
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    s.async = true;
    s.defer = true;
    s.dataset.turnstile = 'true';
    s.onload = () => resolve();
    s.onerror = reject;
    document.head.appendChild(s);
  });
  return scriptLoadingPromise;
}

export default function Turnstile({ siteKey, onToken, onExpire, theme = 'dark', size = 'normal' }) {
  const containerRef = useRef(null);
  const widgetIdRef = useRef(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    if (!siteKey) return;
    loadTurnstileScript()
      .then(() => {
        if (cancelled || !window.turnstile || !containerRef.current) return;
        try {
          widgetIdRef.current = window.turnstile.render(containerRef.current, {
            sitekey: siteKey,
            theme,
            size,
            callback: (token) => onToken?.(token),
            'expired-callback': () => onExpire?.(),
            'error-callback': () => setError('Captcha error'),
          });
        } catch (e) {
          setError(e?.message || 'Failed to render captcha');
        }
      })
      .catch(() => setError('Could not load captcha script'));
    return () => {
      cancelled = true;
      try {
        if (widgetIdRef.current && window.turnstile) {
          window.turnstile.remove(widgetIdRef.current);
        }
      } catch {}
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteKey]);

  return (
    <div>
      <div ref={containerRef} />
      {error && (
        <p className="mt-2 text-[12px] text-[#8A2BE2] font-mono">{error}</p>
      )}
    </div>
  );
}
