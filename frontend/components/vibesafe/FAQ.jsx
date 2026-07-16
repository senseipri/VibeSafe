'use client';
import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Plus } from 'lucide-react';

const FAQS = [
  {
    q: 'Does VibeSafe store my code?',
    a: 'No. Repos are cloned to an ephemeral container, scanned, then deleted immediately. We never persist your source code. Only the findings report is stored.',
  },
  {
    q: 'How is this different from npm audit or GitHub Dependabot?',
    a: 'Those tools check your dependencies. VibeSafe checks your actual code logic — the auth patterns, the SQL queries, the CORS config, the API key handling. Dependabot finds vulnerable packages. VibeSafe finds vulnerable code you wrote (or your AI wrote for you).',
  },
  {
    q: 'Why use three LLMs instead of one?',
    a: 'Model disagreement is information. When  all three models agree a finding is real — it\u2019s real. When they disagree — that\u2019s ambiguity worth flagging. Single-model scanners give false confidence on contested findings.',
  },
  {
    q: 'What languages and frameworks does it support?',
    a: 'Python (FastAPI, Flask), JavaScript/TypeScript (Next.js, Express, Node), plus package and config scanning for npm/pip projects. It also detects patterns in PostgreSQL, Supabase, and AI/agent-style apps. More frameworks are added regularly.',
  },
  {
    q: 'What if it flags something that isn\u2019t a real vulnerability?',
    a: 'Every finding includes Qwen\u2019s confidence level. Low-confidence findings are labelled separately. You can dismiss findings with a reason — this feedback improves the model over time.',
  },
];

export default function FAQ() {
  const [open, setOpen] = useState(0);
  return (
    <section className="relative py-24 lg:py-32 border-t border-[#1F1F3D]">
      <div className="max-w-4xl mx-auto px-6 lg:px-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6 }}
          className="mb-12 text-center"
        >
          <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-4">FAQ</div>
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight">
            Questions you&rsquo;d ask{' '}
            <span className="text-[#A0A0A0]">a security engineer.</span>
          </h2>
        </motion.div>

        <div className="space-y-3">
          {FAQS.map((f, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.4, delay: i * 0.05 }}
              className="rounded-xl border border-[#1F1F3D] bg-[#0B0B1A] overflow-hidden hover:border-[#2D2D55] transition-colors"
            >
              <button
                onClick={() => setOpen(open === i ? -1 : i)}
                className="w-full flex items-center justify-between p-5 text-left"
              >
                <span className="text-[16px] text-[#FFFFFF] font-medium pr-6">{f.q}</span>
                <motion.div
                  animate={{ rotate: open === i ? 45 : 0 }}
                  transition={{ duration: 0.2 }}
                  className="flex-shrink-0"
                >
                  <Plus className="w-5 h-5 text-[#A0A0A0]" />
                </motion.div>
              </button>
              <AnimatePresence initial={false}>
                {open === i && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                    className="overflow-hidden"
                  >
                    <div className="px-5 pb-5 text-[15px] text-[#A0A0A0] font-light leading-relaxed">
                      {f.a}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
