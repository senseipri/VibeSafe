'use client';
import { useState } from 'react';
import { motion } from 'framer-motion';
import { RotateCcw, ArrowRight } from 'lucide-react';
import ScanTerminal from './ScanTerminal';
import RiskGauge from './RiskGauge';
import FindingCard from './FindingCard';

export default function LiveDemo() {
  const [replay, setReplay] = useState(0);
  return (
    <section id="features" className="relative py-24 lg:py-32 border-t border-[#1F1F3D]">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse at 50% 0%, rgba(138,43,226,0.08) 0%, transparent 50%)',
        }}
      />
      <div className="relative max-w-7xl mx-auto px-6 lg:px-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6 }}
          className="max-w-3xl mb-14"
        >
          <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-4">
            LIVE DEMO
          </div>
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight">
            See it scan in real time.
          </h2>
          <p className="mt-5 text-lg text-[#A0A0A0] font-light">
            This is exactly what you get when you point VibeSafe at a real vibe-coded repo. No
            edits. No filters.
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-12 gap-8 items-start" key={replay}>
          {/* Browser chrome */}
          <div className="lg:col-span-8 rounded-xl border border-[#1F1F3D] bg-[#0B0B1A] overflow-hidden shadow-2xl">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1F1F3D] bg-[#05050D]">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-[#8A2BE2]/70" />
                <div className="w-3 h-3 rounded-full bg-[#FF9500]/70" />
                <div className="w-3 h-3 rounded-full bg-[#22C55E]/70" />
              </div>
              <div className="flex-1 mx-3 px-3 py-1 rounded bg-[#13132A] border border-[#1F1F3D] font-mono text-[11px] text-[#A0A0A0] truncate">
                https://vibesafe.ai/scan
              </div>
              <button
                onClick={() => setReplay((r) => r + 1)}
                className="text-[#A0A0A0] hover:text-[#FFFFFF] p-1"
                aria-label="Replay scan"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="p-6">
              <div className="flex flex-col md:flex-row gap-3 mb-6">
                <input
                  defaultValue="github.com/demo/moltbook-clone"
                  className="flex-1 px-4 py-3 rounded-md bg-[#13132A] border border-[#2D2D55] font-mono text-sm text-[#FFFFFF] focus:border-[#8A2BE2] outline-none"
                  readOnly
                />
                <button 
                 
                className="px-5 py-3 bg-[#8A2BE2] hover:bg-[#B967FF] text-white rounded-md font-medium text-sm inline-flex items-center gap-2">
                  Scan now <ArrowRight className="w-4 h-4" />
                </button>
              </div>

              <ScanTerminal replayKey={replay} />

              <div className="mt-8 grid md:grid-cols-2 gap-6 items-center">
                <div className="flex justify-center">
                  <RiskGauge key={replay} score={88} size={260} />
                </div>
                <div className="space-y-2">
                  <FindingCard
                    severity="CRITICAL"
                    title="Supabase RLS disabled — public read/write on all tables"
                    file="migrations/init.sql"
                    delay={0.05}
                  />
                  <FindingCard
                    severity="CRITICAL"
                    title="Hardcoded OPENAI_API_KEY in app.config.ts"
                    file="app.config.ts"
                    line={23}
                    delay={0.15}
                  />
                  <FindingCard
                    severity="HIGH"
                    title="CORS wildcard + credentials=true — CSRF possible"
                    file="server/cors.py"
                    line={11}
                    delay={0.25}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Annotations */}
          <div className="lg:col-span-4 space-y-6">
            {[
              {
                title: 'Risk scored 0–100',
                body: 'CVSS-weighted across every finding. One number you can show your team.',
              },
              {
                title: 'Three LLMs confirm',
                body: 'Claude, GPT-4o, and Gemini must agree before we flag. ~5% false positive rate.',
              },
              {
                title: 'One-click fix code',
                body: 'Generated in your stack\u2019s language. Copy, paste, ship.',
              },
            ].map((a, i) => (
              <motion.div
                key={a.title}
                initial={{ opacity: 0, x: 24 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true, amount: 0.5 }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className="relative pl-6"
              >
                <div className="absolute left-0 top-0 bottom-0 w-px bg-[#8A2BE2]/40" />
                <div className="absolute -left-1 top-1.5 w-2.5 h-2.5 rounded-full bg-[#8A2BE2]" />
                <h4 className="font-display text-lg mb-1.5">{a.title}</h4>
                <p className="text-[14px] text-[#A0A0A0] leading-relaxed font-light">{a.body}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
