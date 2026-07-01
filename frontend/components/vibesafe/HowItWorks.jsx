'use client';
import { motion } from 'framer-motion';
import { Search, BrainCircuit, ShieldCheck } from 'lucide-react';

const STEPS = [
  {
    num: '01',
    title: 'Static Analysis',
    color: '#3B9EFF',
    icon: Search,
    body: 'VibeSafe goes beyond regex matching with deterministic static analysis, AST-aware code tracing, and evidence-backed path analysis to find real exploit paths in each repository. It catches hardcoded secrets, auth gaps, SQL injection, log injection, CORS misconfigurations, missing rate limits, weak JWT flows, and disabled RLS — then ranks findings by severity, confidence, and proof quality instead of noisy string matches.',
  },
  {
    num: '02',
    title: 'Multi-LLM Consensus',
    color: '#8A2BE2',
    icon: BrainCircuit,
    body: 'Multi-model verification keeps the scanner honest. Findings are cross-checked through parallel LLM analysis, validator consensus, and exploitability review so the report separates confirmed issues from needs-review candidates. The result is higher signal, lower false positives, and a clearer trust score for every vulnerability.',
  },
  {
    num: '03',
    title: 'Prioritised Report + Fix',
    color: '#22C55E',
    icon: ShieldCheck,
    body: 'Every report includes a full security narrative: risk score, verdict, OWASP mapping, exact file and line evidence, attacker path, recommendation, remediation prose, and generated fix output when available. Export the same intelligence to a printable PDF, with findings sorted by severity and exploitability so teams can act fast.',
  },
];

export default function HowItWorks() {
  return (
    <section id="how" className="relative py-24 lg:py-32">
      <div className="max-w-7xl mx-auto px-6 lg:px-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="max-w-3xl"
        >
          <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-4">
            HOW IT WORKS
          </div>
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight">
            Three layers. <span className="text-[#A0A0A0]">Zero compromises.</span>
          </h2>
          <p className="mt-5 text-lg text-[#A0A0A0] font-light max-w-2xl">
            Static analysis catches the obvious. Three LLMs argue about the rest.
          </p>
        </motion.div>

        <div className="mt-16 grid md:grid-cols-3 gap-6 relative">
          {/* Dashed connector */}
          <svg
            className="hidden md:block absolute top-12 left-[16.66%] right-[16.66%] h-px pointer-events-none"
            preserveAspectRatio="none"
            viewBox="0 0 1000 2"
          >
            <motion.line
              x1="0"
              y1="1"
              x2="1000"
              y2="1"
              stroke="#2D2D55"
              strokeWidth="1"
              strokeDasharray="6 6"
              initial={{ pathLength: 0 }}
              whileInView={{ pathLength: 1 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 1.2, ease: 'easeInOut' }}
            />
          </svg>

          {STEPS.map((s, i) => {
            const Icon = s.icon;
            return (
              <motion.div
                key={s.num}
                initial={{ opacity: 0, y: 30, rotateX: 8 }}
                whileInView={{ opacity: 1, y: 0, rotateX: 0 }}
                viewport={{ once: true, amount: 0.4 }}
                transition={{ duration: 0.6, delay: i * 0.12, ease: [0.16, 1, 0.3, 1] }}
                className="relative rounded-xl border border-[#1F1F3D] bg-[#0B0B1A] p-7 hover:border-[#2D2D55] transition-all hover:-translate-y-1 group"
                style={{ transformPerspective: 1000 }}
              >
                <div
                  className="w-12 h-12 rounded-lg flex items-center justify-center mb-5 relative"
                  style={{ background: `${s.color}12`, border: `1px solid ${s.color}30` }}
                >
                  <Icon className="w-5 h-5" style={{ color: s.color }} />
                </div>
                <div
                  className="font-mono text-[11px] tracking-[0.2em] mb-2"
                  style={{ color: s.color }}
                >
                  [{s.num}]
                </div>
                <h3 className="font-display text-2xl mb-3">{s.title}</h3>
                <p className="text-[15px] text-[#A0A0A0] leading-relaxed font-light">{s.body}</p>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
