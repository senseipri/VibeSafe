/** @type {import('next').NextConfig} */

// Note: security headers are relaxed during local/preview development so the
// Emergent preview iframe can render the site. The strict, production-grade
// headers (X-Frame-Options: DENY, frame-ancestors 'none', COEP, etc.) should
// be re-enabled at deploy time by setting NODE_ENV=production.
const isProd = process.env.NODE_ENV === 'production' && process.env.VIBESAFE_STRICT_HEADERS === 'true';

const productionHeaders = [
  {
    key: 'Content-Security-Policy',
    value:
      "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests",
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-XSS-Protection', value: '1; mode=block' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=()',
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
];

// Preview-friendly headers: keep the safety net (XSS, sniffing, referrer,
// permissions) but allow the page to be embedded in an iframe so the
// Emergent preview tool can display it.
const previewHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-XSS-Protection', value: '1; mode=block' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=()',
  },
];

const nextConfig = {
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: isProd ? productionHeaders : previewHeaders,
      },
    ];
  },
};

module.exports = nextConfig;
