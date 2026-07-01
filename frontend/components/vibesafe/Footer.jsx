import { Github, Twitter, MessageSquare } from 'lucide-react';
import WaitlistForm from './WaitlistForm';

function MiniOrb({ size = 16, color = '#8A2BE2', delay = 0, left = '20%', top = '30%' }) {
  return (
    <div
      className="absolute rounded-full plasma-morph-1 pointer-events-none"
      style={{
        left,
        top,
        width: size,
        height: size,
        background: `radial-gradient(circle at 30% 30%, #FFFFFF 0%, ${color} 30%, #2A0A55 80%, transparent 100%)`,
        boxShadow: `0 0 ${size}px ${color}80`,
        animationDelay: `${delay}s`,
      }}
    />
  );
}

const MINI_ORBS = [
  { size: 10, color: '#B967FF', left: '10%',  top: '20%', delay: 0 },
  { size: 14, color: '#8A2BE2', left: '22%',  top: '65%', delay: 1.2 },
  { size: 8,  color: '#FF00FF', left: '35%',  top: '35%', delay: 0.6 },
  { size: 12, color: '#B967FF', left: '50%',  top: '75%', delay: 2 },
  { size: 16, color: '#FF00FF', left: '63%',  top: '25%', delay: 0.3 },
  { size: 9,  color: '#00F0FF', left: '75%',  top: '55%', delay: 1.5 },
  { size: 11, color: '#8A2BE2', left: '85%',  top: '30%', delay: 2.4 },
  { size: 7,  color: '#B967FF', left: '92%',  top: '70%', delay: 0.9 },
];

export default function Footer() {
  return (
    <footer className="relative border-t border-[#1F1F3D] bg-[#070716] overflow-hidden">
      {/* Floating mini-orbs (each represents one scan) */}
      <div className="absolute inset-0 pointer-events-none">
        {MINI_ORBS.map((o, i) => (
          <MiniOrb key={i} {...o} />
        ))}
      </div>
      <div className="absolute inset-0 grid-lines opacity-20 pointer-events-none" />

      <div className="relative max-w-7xl mx-auto px-6 lg:pl-28 lg:pr-10 py-20">
        <div className="grid lg:grid-cols-12 gap-10 mb-14">
          <div className="lg:col-span-5">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-10 h-10 rounded-md border border-[#8A2BE2]/50 bg-[#05050D] flex items-center justify-center shadow-[0_0_20px_rgba(138,43,226,0.4)]">
                <span className="font-display text-[14px] tracking-wider text-[#B967FF]">VS</span>
              </div>
              <div>
                <div className="font-display text-base tracking-[0.15em] text-white uppercase">VibeSafe</div>
                <div className="font-mono text-[9px] tracking-[0.25em] text-[#5A5A7A] uppercase">Security Engine</div>
              </div>
            </div>
            <p className="text-[14px] text-[#A0A0A0] font-light leading-relaxed max-w-md mb-7">
              The post-hackathon moat. A security-first audit ecosystem for AI-generated apps.
              We never store your source code.
            </p>
            <WaitlistForm source="footer" />
          </div>

          <div className="lg:col-span-7 grid grid-cols-2 sm:grid-cols-3 gap-8">
            <FooterCol
              title="Engine"
              links={[
                { l: 'Scan', h: '/scan' },
                { l: 'How It Works', h: '#how' },
                { l: 'Catalog', h: '#docs' },
                { l: 'Pricing', h: '#pricing' },
              ]}
            />
            <FooterCol
              title="Trust"
              links={[
                { l: 'Security', h: '/.well-known/security.txt' },
                { l: 'Sitemap', h: '/sitemap.xml' },
                { l: 'Robots', h: '/robots.txt' },
                { l: 'Privacy', h: '#' },
              ]}
            />
            <FooterCol
              title="Connect"
              links={[
                { l: 'GitHub', h: '#' },
                { l: 'Discord', h: '#' },
                { l: 'Twitter', h: '#' },
                { l: 'security@vibesafe.dev', h: 'mailto:security@vibesafe.dev' },
              ]}
            />
          </div>
        </div>

        <div className="pt-8 border-t border-[#1F1F3D] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <p className="font-mono text-[10px] text-[#5A5A7A] tracking-[0.2em] uppercase">
            © 2026 VibeSafe Labs · Built with paranoia in San Francisco
          </p>
          <div className="flex items-center gap-3">
            <SocialIcon icon={Github} label="GitHub" />
            <SocialIcon icon={Twitter} label="Twitter" />
            <SocialIcon icon={MessageSquare} label="Discord" />
            <span className="ml-3 flex items-center gap-2 font-mono text-[10px] text-[#A0A0A0] tracking-[0.2em] uppercase">
              <span className="w-2 h-2 rounded-full bg-[#00F0FF] pulse-dot" />
              Engine online
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}

function FooterCol({ title, links }) {
  return (
    <div>
      <h4 className="font-mono text-[10px] tracking-[0.3em] text-[#FF00FF] uppercase mb-4">
        / {title}
      </h4>
      <ul className="space-y-2.5">
        {links.map((l) => (
          <li key={l.l}>
            <a
              href={l.h}
              className="text-[13px] text-white hover:text-[#B967FF] transition-colors font-mono tracking-[0.05em]"
            >
              {l.l}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SocialIcon({ icon: Icon, label }) {
  return (
    <a
      href="#"
      aria-label={label}
      className="hover-aura w-9 h-9 rounded-md border border-[#1F1F3D] hover:border-[#8A2BE2] flex items-center justify-center text-[#A0A0A0] hover:text-[#B967FF] transition-colors"
    >
      <Icon className="w-4 h-4" />
    </a>
  );
}
