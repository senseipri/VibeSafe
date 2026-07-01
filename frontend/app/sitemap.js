const PUBLIC_PAGES = ['/', '/scan'];

export default function sitemap() {
  const base = process.env.NEXT_PUBLIC_BASE_URL || 'https://vibesafe.dev';
  const now = new Date();
  return PUBLIC_PAGES.map((p) => ({
    url: `${base}${p === '/' ? '' : p}`,
    lastModified: now,
    changeFrequency: p === '/' ? 'weekly' : 'monthly',
    priority: p === '/' ? 1 : 0.8,
  }));
}
