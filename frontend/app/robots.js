export default function robots() {
  const base = process.env.NEXT_PUBLIC_BASE_URL || 'https://vibesafe.dev';
  return {
    rules: [
      {
        userAgent: '*',
        allow: ['/'],
        disallow: ['/api/', '/report/', '/downloads/'],
      },
    ],
    sitemap: `${base}/sitemap.xml`,
    host: base.replace(/^https?:\/\//, ''),
  };
}
