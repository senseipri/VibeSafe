'use client';
import { motion } from 'framer-motion';

const SUB = [
  { id: 'patterns', x: 65, y: 22, label: 'Proprietary Pattern DB', sub: '10k+ entries' },
  { id: 'yaml',     x: 65, y: 50, label: 'Custom YAML Schemas',   sub: 'team-defined' },
  { id: 'api',      x: 65, y: 78, label: 'Enterprise API',         sub: 'OpenAPI 3.1' },
];
const LEAF = [
  { id: 'compliance', x: 92, y: 22, label: 'Compliance Logs', from: 'patterns' },
  { id: 'alerts',     x: 92, y: 50, label: 'Real-time Alerts', from: 'yaml' },
  { id: 'dash',       x: 92, y: 78, label: 'Team Dashboard',  from: 'api' },
];

const CENTER = { x: 15, y: 50 };

function nodeStyle(color) {
  return {
    background: 'rgba(11,11,26,0.85)',
    border: `1px solid ${color}66`,
    boxShadow: `0 0 24px ${color}33`,
    backdropFilter: 'blur(8px)',
  };
}

export default function EcosystemFlowchart() {
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
            — Ecosystem / 04
          </div>
          <h2 className="font-display text-5xl sm:text-6xl lg:text-7xl uppercase leading-[0.95] tracking-tight">
            One scanner. <span className="text-gradient">Every surface.</span>
          </h2>
        </motion.div>

        <div className="relative w-full glass-strong rounded-2xl p-6 sm:p-10 lg:p-14"
             style={{ aspectRatio: '16/8.5' }}>
          {/* SVG edges */}
          <svg
            className="absolute inset-0 w-full h-full"
            viewBox="0 0 100 100"
            preserveAspectRatio="none"
            fill="none"
          >
            <defs>
              <linearGradient id="edge" x1="0" x2="1" y1="0" y2="0">
                <stop offset="0%" stopColor="#8A2BE2" stopOpacity="0.9" />
                <stop offset="50%" stopColor="#FF00FF" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#8A2BE2" stopOpacity="0.9" />
              </linearGradient>
            </defs>
            {/* center → sub */}
            {SUB.map((s, i) => (
              <motion.path
                key={s.id}
                d={`M ${CENTER.x} ${CENTER.y} C ${(CENTER.x + s.x) / 2} ${CENTER.y}, ${(CENTER.x + s.x) / 2} ${s.y}, ${s.x} ${s.y}`}
                stroke="url(#edge)"
                strokeWidth="0.35"
                strokeLinecap="round"
                initial={{ pathLength: 0, opacity: 0 }}
                whileInView={{ pathLength: 1, opacity: 1 }}
                viewport={{ once: true, amount: 0.4 }}
                transition={{ duration: 1.4, delay: 0.15 + i * 0.12, ease: 'easeInOut' }}
                style={{ filter: 'drop-shadow(0 0 1.2px #B967FF)' }}
              />
            ))}
            {/* sub → leaf */}
            {LEAF.map((l, i) => {
              const parent = SUB.find((s) => s.id === l.from);
              return (
                <motion.path
                  key={l.id}
                  d={`M ${parent.x} ${parent.y} L ${l.x} ${l.y}`}
                  stroke="url(#edge)"
                  strokeWidth="0.3"
                  strokeLinecap="round"
                  strokeDasharray="1 1.2"
                  initial={{ pathLength: 0, opacity: 0 }}
                  whileInView={{ pathLength: 1, opacity: 1 }}
                  viewport={{ once: true, amount: 0.4 }}
                  transition={{ duration: 1.0, delay: 0.9 + i * 0.12, ease: 'easeInOut' }}
                  style={{ filter: 'drop-shadow(0 0 1.2px #FF00FF)' }}
                />
              );
            })}
          </svg>

          {/* CENTER node */}
          <motion.div
            initial={{ opacity: 0, scale: 0.85 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.7 }}
            className="absolute -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${CENTER.x}%`, top: `${CENTER.y}%` }}
          >
            <div
              className="px-4 py-3 sm:px-5 sm:py-4 rounded-xl text-center min-w-[180px]"
              style={nodeStyle('#FF00FF')}
            >
              <div className="font-mono text-[9px] tracking-[0.3em] text-[#FF00FF] uppercase">
                Core
              </div>
              <div className="font-display text-base text-white uppercase tracking-wider mt-1">
                VibeSafe Scanner
              </div>
              <div className="font-mono text-[9px] text-[#5A5A7A] tracking-[0.15em] mt-1">
                v0.12 · 3-LLM consensus
              </div>
            </div>
          </motion.div>

          {/* SUB nodes */}
          {SUB.map((s, i) => (
            <motion.div
              key={s.id}
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.5, delay: 0.4 + i * 0.12 }}
              className="absolute -translate-x-1/2 -translate-y-1/2"
              style={{ left: `${s.x}%`, top: `${s.y}%` }}
            >
              <div
                className="px-3 py-2 sm:px-4 sm:py-2.5 rounded-lg min-w-[160px] text-center"
                style={nodeStyle('#8A2BE2')}
              >
                <div className="font-mono text-[11.5px] text-white tracking-[0.1em] uppercase">
                  {s.label}
                </div>
                <div className="font-mono text-[8.5px] text-[#5A5A7A] tracking-[0.15em] mt-1">
                  {s.sub}
                </div>
              </div>
            </motion.div>
          ))}

          {/* LEAF nodes */}
          {LEAF.map((l, i) => (
            <motion.div
              key={l.id}
              initial={{ opacity: 0, x: 8 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.5, delay: 1.2 + i * 0.1 }}
              className="absolute -translate-x-1/2 -translate-y-1/2"
              style={{ left: `${l.x}%`, top: `${l.y}%` }}
            >
              <div
                className="px-3 py-1.5 rounded-md min-w-[120px] text-center"
                style={nodeStyle('#FF00FF')}
              >
                <div className="font-mono text-[10px] text-[#B967FF] tracking-[0.15em] uppercase">
                  {l.label}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
