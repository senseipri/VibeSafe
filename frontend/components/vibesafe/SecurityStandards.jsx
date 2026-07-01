'use client';
import { motion } from 'framer-motion';
import { Fingerprint, AlertOctagon, Activity } from 'lucide-react';

const COLUMNS = [
  {
    icon: Fingerprint,
    title: 'Pattern Matching',
    color: '#00F0FF',
    points: [
      'Define proprietary secret formats once.',
      'Catch every variant across .env, .ts, .py, .sql, and CI/CD configs.',
      'Ship your custom YAML rules with the repo, run them on every push.',
      'Pre-built rules for 47 LLM-coding-tool patterns.',
    ],
  },
  {
    icon: AlertOctagon,
    title: 'Risk Mitigation',
    color: '#B967FF',
    points: [
      'Hardcoded API keys, tokens, and database URLs flagged in real time.',
      'Missing auth middleware, broken access control surfaced before merge.',
      'CORS, RLS, and CSP misconfigurations caught at the schema layer.',
      'Slopsquatting check against live npm / PyPI / Cargo registries.',
    ],
  },
  {
    icon: Activity,
    title: 'Continuous Audit',
    color: '#FF00FF',
    points: [
      'Every scan adds to the proprietary 10,000+ findings dataset.',
      'Pattern engine sharpens with every false positive marked.',
      'Defensible asset: the moat compounds while competitors copy the UI.',
      'Compliance-ready exports: SOC 2, ISO 27001, GDPR Annex II.',
    ],
  },
];

export default function SecurityStandards() {
  return (
    <section className="relative py-32 lg:py-40 border-t border-[#1F1F3D]">
      <div className="max-w-7xl mx-auto px-6 lg:pl-28 lg:pr-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.7 }}
          className="max-w-3xl mb-16"
        >
          <div className="font-mono text-[10px] tracking-[0.4em] text-[#FF00FF] uppercase mb-5">
            — Standards / 05
          </div>
          <h2 className="font-display text-5xl sm:text-6xl lg:text-7xl uppercase leading-[0.95] tracking-tight">
            Nomocracy <span className="text-gradient">of code.</span>
          </h2>
          <p className="mt-6 text-[15px] text-[#A0A0A0] font-light leading-relaxed max-w-2xl">
            Rules above models. Three policy layers that govern every scan, every PR comment,
            every CI gate.
          </p>
        </motion.div>

        <div className="grid md:grid-cols-3 gap-5">
          {COLUMNS.map((c, i) => (
            <motion.div
              key={c.title}
              initial={{ opacity: 0, y: 28 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.3 }}
              transition={{ duration: 0.6, delay: i * 0.12, ease: [0.16, 1, 0.3, 1] }}
              className="hover-aura group glass rounded-2xl p-6 sm:p-7 transition-all hover:-translate-y-1"
              style={{ borderTop: `1.5px solid ${c.color}` }}
            >
              <div
                className="w-11 h-11 rounded-lg flex items-center justify-center mb-5"
                style={{
                  background: `${c.color}12`,
                  border: `1px solid ${c.color}40`,
                  boxShadow: `0 0 24px ${c.color}30`,
                }}
              >
                <c.icon className="w-5 h-5" style={{ color: c.color }} strokeWidth={1.5} />
              </div>
              <div
                className="font-mono text-[10px] tracking-[0.3em] uppercase mb-2"
                style={{ color: c.color }}
              >
                / 0{i + 1}
              </div>
              <h3 className="font-display text-2xl uppercase tracking-wide text-white mb-5">
                {c.title}
              </h3>
              <ul className="space-y-3">
                {c.points.map((p) => (
                  <li key={p} className="flex gap-3 text-[13.5px] text-[#A0A0A0] font-light leading-relaxed">
                    <span
                      className="flex-shrink-0 mt-2 w-1 h-1 rounded-full"
                      style={{ background: c.color, boxShadow: `0 0 6px ${c.color}` }}
                    />
                    {p}
                  </li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
