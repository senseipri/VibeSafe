'use client';
import { motion } from 'framer-motion';
import { Syringe, Brain, Database } from 'lucide-react';

const THREATS = [
  {
    id: 'injection',
    title: 'Injection Risk',
    icon: Syringe,
    body: 'SQL, NoSQL, command, and prompt injection patterns AI models routinely produce by defaulting to string interpolation.',
    metric: '38%',
    metricLabel: 'of AI-generated routes',
  },
  {
    id: 'logic',
    title: 'Insecure Logic',
    icon: Brain,
    body: 'Missing auth middleware, broken access control, CORS wildcards, and disabled RLS — invisible to dependency scanners.',
    metric: '45%',
    metricLabel: 'of vibe-coded apps',
  },
  {
    id: 'leakage',
    title: 'Data Leakage',
    icon: Database,
    body: 'Hardcoded API keys, secrets in client bundles, public Supabase tables, exposed S3 buckets. The Moltbook pattern.',
    metric: '1 in 4',
    metricLabel: 'commits leak a key',
  },
];

function ThreatIcon({ Icon }) {
  // Particle-cloud icon: stacked radial gradient with a centered glyph.
  return (
    <div className="relative w-16 h-16 mb-5">
      <div
        className="absolute inset-0 rounded-full plasma-morph-1"
        style={{
          background:
            'radial-gradient(circle at 35% 30%, rgba(0,240,255,0.55) 0%, rgba(138,43,226,0.55) 35%, rgba(255,0,255,0.85) 65%, rgba(255,0,255,0) 90%)',
          filter: 'blur(2px)',
        }}
      />
      <div
        className="absolute inset-2 rounded-full bg-[#0B0B1A] flex items-center justify-center"
        style={{ boxShadow: 'inset 0 0 20px rgba(138,43,226,0.4)' }}
      >
        <Icon className="w-5 h-5 text-[#B967FF]" strokeWidth={1.6} />
      </div>
    </div>
  );
}

export default function RealityCheck() {
  return (
    <section id="gap" className="relative py-28 lg:py-40 border-t border-[#1F1F3D]">
      <div className="max-w-7xl mx-auto px-6 lg:pl-28 lg:pr-10">
        <div className="grid lg:grid-cols-12 gap-12 items-start">
          {/* LEFT */}
          <motion.div
            initial={{ opacity: 0, y: 32 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
            className="lg:col-span-5 lg:sticky lg:top-28"
          >
            <div className="font-mono text-[10px] tracking-[0.4em] text-[#FF00FF] uppercase mb-5">
              — The Gap / 01
            </div>
            <h2 className="font-display text-5xl sm:text-6xl lg:text-7xl uppercase leading-[0.95] tracking-tight">
              The reality
              <br />
              <span className="text-gradient">of vibe-code.</span>
            </h2>
            <p className="mt-6 text-[15px] text-[#A0A0A0] font-light leading-relaxed max-w-md">
              AI now generates <span className="text-white font-medium">46% of new GitHub code</span>.
              And <span className="text-white font-medium">45% of vibe-coded apps</span> ship with
              an OWASP Top 10 vulnerability on day one. The crisis isn&rsquo;t the model.
              It&rsquo;s the lack of an audit layer between the model and production.
            </p>
            <div className="mt-8 font-mono text-[11px] text-[#5A5A7A] tracking-[0.2em] uppercase">
              Source · VibeSafe Internal Telemetry, March 2026
            </div>
          </motion.div>

          {/* RIGHT — threat cards */}
          <div className="lg:col-span-7 grid sm:grid-cols-1 gap-5">
            {THREATS.map((t, i) => (
              <motion.div
                key={t.id}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.35 }}
                transition={{ duration: 0.6, delay: i * 0.12, ease: [0.16, 1, 0.3, 1] }}
                className="hover-aura group glass rounded-2xl p-6 sm:p-7 transition-all hover:-translate-y-1"
              >
                <div className="flex items-start gap-6">
                  <ThreatIcon Icon={t.icon} />
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-display text-2xl sm:text-3xl uppercase tracking-wide text-white">
                        {t.title}
                      </h3>
                      <span className="font-mono text-[10px] tracking-[0.3em] text-[#FF00FF] uppercase">
                        / 0{i + 1}
                      </span>
                    </div>
                    <p className="text-[14px] text-[#A0A0A0] font-light leading-relaxed mb-4">
                      {t.body}
                    </p>
                    <div className="flex items-baseline gap-3 pt-3 border-t border-[#1F1F3D]">
                      <span className="font-display text-3xl text-[#B967FF] tabular-nums glow-magenta">
                        {t.metric}
                      </span>
                      <span className="font-mono text-[10px] tracking-[0.2em] text-[#5A5A7A] uppercase">
                        {t.metricLabel}
                      </span>
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
