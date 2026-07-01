'use client';
import { motion } from 'framer-motion';
import { Inbox, Scan, ShieldCheck, Wrench } from 'lucide-react';

const TIERS = [
  {
    n: '01',
    label: 'Ingestion',
    sub: 'Custom YAML & Pattern Detection',
    icon: Inbox,
    desc: 'Repo cloned to ephemeral container. Files indexed against the proprietary pattern DB and your team\u2019s custom YAML rules.',
    color: '#00F0FF',
  },
  {
    n: '02',
    label: 'Analysis',
    sub: 'Vibe-Code Semantic Scanning',
    icon: Scan,
    desc: 'Claude, GPT-4o, and Gemini run in parallel on suspect code paths. Consensus = real finding. Disagreement = flag for review.',
    color: '#B967FF',
  },
  {
    n: '03',
    label: 'Validation',
    sub: 'Safety & Privacy Audit',
    icon: ShieldCheck,
    desc: 'Every finding is re-checked against CVSS, OWASP, and your data-classification policy. False positives drop to ~5%.',
    color: '#8A2BE2',
  },
  {
    n: '04',
    label: 'Remediation',
    sub: 'Automated Fix Proposals',
    icon: Wrench,
    desc: 'Diff-ready fix code in your stack\u2019s language. PR comment posted automatically. CI fails if Critical findings remain.',
    color: '#FF00FF',
  },
];

export default function Architecture() {
  return (
    <section id="architecture" className="relative py-32 lg:py-40 border-t border-[#1F1F3D]">
      <div className="max-w-7xl mx-auto px-6 lg:pl-28 lg:pr-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.7 }}
          className="max-w-3xl mb-16"
        >
          <div className="font-mono text-[10px] tracking-[0.4em] text-[#FF00FF] uppercase mb-5">
            — Architecture / 03
          </div>
          <h2 className="font-display text-5xl sm:text-6xl lg:text-7xl uppercase leading-[0.95] tracking-tight">
            Modular <span className="text-gradient">enterprise stack.</span>
          </h2>
          <p className="mt-6 text-[15px] text-[#A0A0A0] font-light leading-relaxed max-w-2xl">
            Four independent engines. Each does one thing exceptionally well.
            Each is callable on its own — or chained through the orchestrator.
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-12 gap-12 items-center">
          {/* LEFT — isometric stack */}
          <div className="lg:col-span-6">
            <div
              className="relative mx-auto"
              style={{
                width: 'min(100%, 480px)',
                aspectRatio: '1/1.05',
                transform: 'rotateX(58deg) rotateZ(-42deg)',
                transformStyle: 'preserve-3d',
                transformOrigin: 'center',
              }}
            >
              {TIERS.slice().reverse().map((t, i) => {
                const z = i * 50; // Remediation at the bottom (z=0), Ingestion on top (z=150)
                return (
                <motion.div
                  key={t.n}
                  initial={{ opacity: 0, z: -100, y: 40 }}
                  whileInView={{ opacity: 1, z: 0, y: 0 }}
                  viewport={{ once: true, amount: 0.4 }}
                  transition={{ duration: 0.7, delay: 0.15 + i * 0.12, ease: [0.16, 1, 0.3, 1] }}
                  className="absolute inset-0"
                  style={{
                    transform: `translateZ(${z}px)`,
                    transformStyle: 'preserve-3d',
                  }}
                >
                  <div
                    className="w-full h-full rounded-xl"
                    style={{
                      background:
                        'linear-gradient(135deg, rgba(19,19,42,0.85) 0%, rgba(11,11,26,0.85) 100%)',
                      border: `1.5px solid ${t.color}55`,
                      boxShadow: `0 0 50px ${t.color}33, inset 0 0 60px ${t.color}10`,
                      backdropFilter: 'blur(8px)',
                    }}
                  >
                    <div className="absolute top-3 left-4 font-mono text-[10px] tracking-[0.25em] uppercase" style={{ color: t.color }}>
                      [{t.n}] {t.label}
                    </div>
                    <div className="absolute bottom-3 right-4 font-mono text-[8.5px] tracking-[0.15em] text-[#5A5A7A] uppercase">
                      {t.sub}
                    </div>
                    <t.icon
                      className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-12 h-12"
                      style={{ color: t.color, filter: `drop-shadow(0 0 12px ${t.color})` }}
                      strokeWidth={1.3}
                    />
                    {/* Grid pattern on top of tile */}
                    <div
                      className="absolute inset-0 rounded-xl opacity-30"
                      style={{
                        background:
                          'repeating-linear-gradient(90deg, transparent, transparent 28px, rgba(255,255,255,0.04) 28px, rgba(255,255,255,0.04) 29px)',
                      }}
                    />
                  </div>
                </motion.div>
                );
              })}
            </div>
          </div>

          {/* RIGHT — tier descriptions */}
          <div className="lg:col-span-6 space-y-4">
            {TIERS.map((t, i) => (
              <motion.div
                key={t.n}
                initial={{ opacity: 0, x: 30 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true, amount: 0.4 }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className="hover-aura group glass rounded-xl p-5 transition-all hover:-translate-x-1"
                style={{ borderLeft: `2px solid ${t.color}` }}
              >
                <div className="flex items-center gap-3 mb-2">
                  <span
                    className="font-mono text-[10px] tracking-[0.25em] uppercase"
                    style={{ color: t.color }}
                  >
                    [{t.n}] {t.label}
                  </span>
                  <span className="font-mono text-[10px] text-[#5A5A7A] tracking-[0.15em] uppercase">
                    · {t.sub}
                  </span>
                </div>
                <p className="text-[13.5px] text-[#A0A0A0] font-light leading-relaxed">
                  {t.desc}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
