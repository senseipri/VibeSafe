'use client';
import { ArrowRight } from 'lucide-react';
import ScanTerminal from './ScanTerminal';
import RiskGauge from './RiskGauge';
import FindingCard from './FindingCard';

export default function LiveDemo() {
  return (
    <section id="features" className="relative py-24 lg:py-32 border-t border-[#1F1F3D] bg-[#070716]">
      <div className="relative max-w-7xl mx-auto px-6 lg:px-10">
        <div className="max-w-3xl mb-14">
          <div className="font-mono text-[11px] tracking-[0.2em] text-[#5A5A7A] mb-4">
            LIVE DEMO
          </div>
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight text-white">
            See it scan in real time.
          </h2>
          <p className="mt-5 text-lg text-[#A0A0A0] font-light">
            This is exactly what you get when you point VibeSafe at a real vibe-coded repo. No
            edits. No filters.
          </p>
        </div>

        <div className="grid lg:grid-cols-12 gap-8 items-start">
          {/* Browser mockup */}
          <div className="lg:col-span-8 rounded-xl border border-[#1F1F3D] bg-[#0B0B1A] overflow-hidden shadow-none">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1F1F3D] bg-[#05050D] select-none pointer-events-none">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-gray-700" />
                <div className="w-3 h-3 rounded-full bg-gray-700" />
                <div className="w-3 h-3 rounded-full bg-gray-700" />
              </div>
              <div className="flex-1 mx-3 px-3 py-1 rounded bg-[#13132A] border border-[#1F1F3D] font-mono text-[11px] text-[#A0A0A0] truncate">
                https://vibesafe.ai/scan
              </div>
            </div>
            <div className="p-6">
              <div className="flex flex-col md:flex-row gap-3 mb-6 select-none pointer-events-none">
                <input
                  defaultValue="github.com/demo/moltbook-clone"
                  className="flex-1 px-4 py-3 rounded-md bg-[#13132A] border border-[#2D2D55] font-mono text-sm text-[#FFFFFF] outline-none"
                  readOnly
                  tabIndex="-1"
                />
                <button 
                  disabled
                  className="px-5 py-3 bg-[#13132A] text-[#5A5A7A] border border-[#1F1F3D] rounded-md font-medium text-sm inline-flex items-center gap-2 cursor-not-allowed"
                >
                  Scan now <ArrowRight className="w-4 h-4" />
                </button>
              </div>

              <ScanTerminal />

              <div className="mt-8 grid md:grid-cols-2 gap-6 items-center">
                <div className="flex justify-center">
                  <RiskGauge score={88} />
                </div>
                <div className="space-y-2">
                  <FindingCard
                    severity="CRITICAL"
                    title="Supabase RLS disabled — public read/write on all tables"
                    file="migrations/init.sql"
                  />
                  <FindingCard
                    severity="CRITICAL"
                    title="Hardcoded OPENAI_API_KEY in app.config.ts"
                    file="app.config.ts"
                    line={23}
                  />
                  <FindingCard
                    severity="HIGH"
                    title="CORS wildcard + credentials=true — CSRF possible"
                    file="server/cors.py"
                    line={11}
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
                body: 'LLMs must agree before we flag. ~5% false positive rate.',
              },
              {
                title: 'One-click fix solution',
                body: 'Generated in an instance language. Use it at its best.',
              },
            ].map((a) => (
              <div
                key={a.title}
                className="relative pl-6"
              >
                <div className="absolute left-0 top-0 bottom-0 w-px bg-[#1F1F3D]" />
                <div className="absolute -left-1 top-1.5 w-2.5 h-2.5 rounded-full bg-gray-700" />
                <h4 className="font-display text-lg mb-1.5 text-white">{a.title}</h4>
                <p className="text-[14px] text-[#A0A0A0] leading-relaxed font-light">{a.body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
