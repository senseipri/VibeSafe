'use client';
import { useEffect, useState } from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion';
import EarthNetwork from './EarthNetwork';

const RAIN_GLYPHS = '01010101+-/*<>{}[]()=!?#$%&|~^ABCDEF0123456789';

function rainColumn(seed) {
  let s = seed;
  let out = '';
  for (let i = 0; i < 14; i++) {
    s = (s * 9301 + 49297) % 233280;
    out += RAIN_GLYPHS[s % RAIN_GLYPHS.length];
    out += '\n';
  }
  return out;
}

export default function TheMoat() {
  const [hovering, setHovering] = useState(false);
  const mx = useMotionValue(0);
  const my = useMotionValue(0);
  const sx = useSpring(mx, { stiffness: 50, damping: 22 });
  const sy = useSpring(my, { stiffness: 50, damping: 22 });
  const ox = useTransform(sx, [-1, 1], [-30, 30]);
  const oy = useTransform(sy, [-1, 1], [-22, 22]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (window.matchMedia('(pointer: coarse)').matches) return;
    const onMove = (e) => {
      const r = document.getElementById('moat')?.getBoundingClientRect();
      if (!r) return;
      const x = ((e.clientX - r.left) / r.width - 0.5) * 2;
      const y = ((e.clientY - r.top) / r.height - 0.5) * 2;
      mx.set(Math.max(-1, Math.min(1, x)));
      my.set(Math.max(-1, Math.min(1, y)));
    };
    window.addEventListener('mousemove', onMove, { passive: true });
    return () => window.removeEventListener('mousemove', onMove);
  }, [mx, my]);

  return (
    <section
      id="moat"
      onMouseEnter={() => setHovering(true)}
      onMouseLeave={() => setHovering(false)}
      className="relative py-32 lg:py-48 overflow-hidden border-t border-[#1F1F3D]"
    >
      {/* Background grid */}
      <div className="absolute inset-0 grid-lines opacity-20 pointer-events-none" />

      {/* Digital rain */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {Array.from({ length: 18 }).map((_, i) => {
          const left = (i / 18) * 100;
          const dur = 5 + ((i * 3) % 6);
          const delay = (i % 6) * 0.6;
          const opacity = hovering ? 0.55 : 0.12;
          return (
            <div
              key={i}
              className="rain-col absolute top-0 font-mono text-[11px] leading-tight whitespace-pre tracking-wider"
              style={{
                left: `${left}%`,
                color: i % 3 === 0 ? '#FF00FF' : '#B967FF',
                opacity,
                transition: 'opacity 0.5s ease',
                '--dur': `${dur}s`,
                '--delay': `${delay}s`,
                textShadow: '0 0 8px currentColor',
              }}
            >
              {rainColumn(i + 1)}
            </div>
          );
        })}
      </div>

      {/* Centered orb */}
      <motion.div
        style={{ x: ox, y: oy }}
        className="absolute inset-0 flex items-center justify-center pointer-events-none"
      >
        <div className={hovering ? 'orb-pulse' : ''}>
          <EarthNetwork size={hovering ? 500 : 480} />
        </div>
      </motion.div>

      <div className="relative max-w-7xl mx-auto px-6 lg:pl-28 lg:pr-10 z-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-5xl mx-auto"
        >
          <div className="font-mono text-[10px] tracking-[0.4em] text-[#FF00FF] uppercase mb-6">
            — The Moat / 02
          </div>
          <h2 className="font-display text-[56px] sm:text-[88px] lg:text-[120px] xl:text-[140px] uppercase leading-[0.88] tracking-[0.01em]">
            <span className="block text-white glow-text">The post-</span>
            <span className="block text-gradient">hackathon</span>
            <span className="block text-white">moat.</span>
          </h2>
          <p className="mt-10 max-w-2xl mx-auto text-[15px] text-[#A0A0A0] font-light leading-relaxed">
            10,000+ empirical scans of real vibe-coded applications.
            A proprietary pattern database of every way Claude, GPT-4o,
            Cursor, Bolt, Lovable, and v0 leave you exposed.
            <span className="block mt-3 text-white">
              This isn&rsquo;t a wrapper. It&rsquo;s an inventory of harm.
            </span>
          </p>
          <div className="mt-12 grid grid-cols-3 gap-6 max-w-2xl mx-auto">
            {[
              { n: '10,238', l: 'Scans logged' },
              { n: '312k', l: 'Vulnerabilities found' },
              { n: '$4.2M', l: 'Breaches prevented' },
            ].map((s) => (
              <div key={s.l} className="glass rounded-lg py-4 px-3">
                <div className="font-display text-2xl sm:text-3xl text-white tabular-nums">
                  {s.n}
                </div>
                <div className="font-mono text-[9px] tracking-[0.2em] text-[#5A5A7A] uppercase mt-1">
                  {s.l}
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
