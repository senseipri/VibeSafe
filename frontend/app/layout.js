import AntiGravityBackground from '@/components/vibesafe/AntiGravityBackground';
import ScrollToTop from '@/components/vibesafe/ScrollToTop';
import './globals.css';

export const metadata = {
  title: 'VibeSafe — Security is the absence of an exploit',
  description:
    'A security-first audit ecosystem for AI-generated apps. Pattern engine, semantic scanning, safety audit, and automated remediation.',
  openGraph: {
    title: 'VibeSafe — The post-hackathon moat',
    description:
      '10,000+ empirical scans of vibe-coded apps. Catch the exact vulnerabilities AI coding tools produce — before they ship.',
    type: 'website',
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#05050D] text-white antialiased selection:bg-[#8A2BE2]/30 selection:text-white">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-[100] focus:bg-[#8A2BE2] focus:text-white focus:px-4 focus:py-2 focus:rounded-md focus:outline-none"
        >
          Skip to main content
        </a>
        <AntiGravityBackground />
        <div className="relative z-10">{children}</div>
        <ScrollToTop />
      </body>
    </html>
  );
}
