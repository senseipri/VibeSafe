import { Github, Twitter, MessageSquare } from 'lucide-react';

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

      <div className="relative max-w-7xl mx-auto px-6 lg:pl-28 lg:pr-10 py-10">
        <div className="mb-6">
          <div className="max-w-md">
            <div className="flex items-center gap-3 mb-3">
              <div className="relative w-10 h-10 rounded-md border border-[#8A2BE2]/50 bg-[#05050D] flex items-center justify-center shadow-[0_0_20px_rgba(138,43,226,0.4)] overflow-hidden">
                <img src="/vibesafe-icon.svg" alt="VibeSafe Logo" className="w-6 h-6 object-contain" />
              </div>
              <div>
                <div className="font-display text-base tracking-[0.15em] text-white uppercase">VibeSafe</div>
                <div className="font-mono text-[9px] tracking-[0.25em] text-[#5A5A7A] uppercase">Be Secured</div>
              </div>
            </div>
            <p className="text-[14px] text-[#A0A0A0] font-light leading-relaxed">
              A security-first audit ecosystem for AI-generated apps.
              We never store your source code.
            </p>
          </div>
        </div>

        <div className="pt-6 border-t border-[#1F1F3D] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <p className="font-mono text-[10px] text-[#5A5A7A] tracking-[0.2em] uppercase">
            © 2026 VibeSafe 
          </p>
          <div className="flex items-center gap-3">
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
