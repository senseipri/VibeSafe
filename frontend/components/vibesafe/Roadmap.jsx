'use client';
import { motion } from 'framer-motion';

const MILESTONES = [
  {
    id: 'q4-2025',
    when: 'Q4 2025',
    title: 'Pattern Engine Alpha',
    body: 'First 1,000 AI-coding-tool patterns catalogued. CLI and GitHub Action open beta.',
    x: 12,
    y: 70,
    color: '#00F0FF',
    status: 'shipped',
  },
  {
    id: 'h1-2026',
    when: 'H1 2026',
    title: 'Multi-Agent Orchestration',
    body: 'Claude, GPT-4o, Gemini in parallel consensus. Disagreement-as-information layer goes live.',
    x: 50,
    y: 30,
    color: '#B967FF',
    status: 'now',
  },
  {
    id: 'h2-2026',
    when: 'H2 2026',
    title: 'Enterprise SaaS Launch',
    body: 'Team dashboard, compliance reports, custom rule SDK, on-prem deploy option.',
    x: 88,
    y: 65,
    color: '#FF00FF',
    status: 'upcoming',
  },
];

export default function Roadmap() {
  return (
    <section id="roadmap" className="relative py-32 lg:py-40 border-t border-[#1F1F3D]">
      <div className="max-w-7xl mx-auto px-6 lg:pl-28 lg:pr-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.7 }}
          className="max-w-3xl mb-16"
        >
          <div className="font-mono text-[10px] tracking-[0.4em] text-[#FF00FF] uppercase mb-5">
            — Roadmap / 06
          </div>
          <h2 className="font-display text-5xl sm:text-6xl lg:text-7xl uppercase leading-[0.95] tracking-tight">
            The path <span className="text-gradient">forward.</span>
          </h2>
        </motion.div>

        {/* Roadmap visual */}
        <div className="relative w-full" style={{ aspectRatio: '16/7' }}>
          <svg
            className="absolute inset-0 w-full h-full"
            viewBox="0 0 100 100"
            preserveAspectRatio="none"
            fill="none"
          >
            <defs>
              <linearGradient id="road" x1="0" x2="1" y1="0" y2="0">
                <stop offset="0%" stopColor="#00F0FF" />
                <stop offset="50%" stopColor="#B967FF" />
                <stop offset="100%" stopColor="#FF00FF" />
              </linearGradient>
            </defs>
            <motion.path
              d="M 4 70 C 28 70, 36 30, 50 30 C 64 30, 72 65, 96 65"
              stroke="url(#road)"
              strokeWidth="0.35"
              strokeLinecap="round"
              strokeDasharray="0.8 1.6"
              initial={{ pathLength: 0, opacity: 0 }}
              whileInView={{ pathLength: 1, opacity: 1 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 2.2, ease: 'easeInOut' }}
              style={{ filter: 'drop-shadow(0 0 1.6px #B967FF)' }}
            />
          </svg>

          {/* Milestones */}
          {MILESTONES.map((m, i) => (
            <motion.div
              key={m.id}
              initial={{ opacity: 0, scale: 0.8 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.5, delay: 0.6 + i * 0.25 }}
              className="absolute -translate-x-1/2 -translate-y-1/2"
              style={{ left: `${m.x}%`, top: `${m.y}%` }}
            >
              {/* Glowing ring */}
              <div className="relative w-6 h-6 mx-auto">
                <div
                  className="absolute inset-0 rounded-full orb-pulse"
                  style={{
                    background: `radial-gradient(circle, ${m.color}99 0%, ${m.color}33 50%, transparent 70%)`,
                    filter: 'blur(4px)',
                  }}
                />
                <div
                  className="absolute inset-[8px] rounded-full"
                  style={{
                    background: m.color,
                    boxShadow: `0 0 18px ${m.color}, 0 0 36px ${m.color}80`,
                  }}
                />
              </div>

              {/* Card */}
              <div
                className={`mt-3 glass rounded-lg p-4 w-[240px] -translate-x-1/2 left-1/2 relative`}
                style={{ borderTop: `1.5px solid ${m.color}` }}
              >
                <div className="flex items-center justify-between mb-1">
                  <span
                    className="font-mono text-[10px] tracking-[0.25em] uppercase"
                    style={{ color: m.color }}
                  >
                    {m.when}
                  </span>
                  <span
                    className="font-mono text-[9px] tracking-[0.2em] uppercase px-1.5 py-0.5 rounded"
                    style={{
                      color: m.color,
                      background: `${m.color}15`,
                      border: `1px solid ${m.color}40`,
                    }}
                  >
                    {m.status}
                  </span>
                </div>
                <div className="font-display text-base text-white uppercase tracking-wider mb-1.5">
                  {m.title}
                </div>
                <p className="text-[12px] text-[#A0A0A0] font-light leading-relaxed">
                  {m.body}
                </p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
