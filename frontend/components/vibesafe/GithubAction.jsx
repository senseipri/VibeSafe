'use client';
import { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, Copy, GitPullRequest } from 'lucide-react';

const YAML = `name: VibeSafe Security Scan
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  vibesafe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vibesafe/vibesafe-action@v1
        with:
          vibesafe-api-key: \${{ secrets.VIBESAFE_API_KEY }}
          fail-on: critical
          post-comment: "true"`;

const FEATURES = [
  'Zero config — add one YAML snippet',
  'Fails CI if Critical or High findings',
  'Posts PR comment with full report',
  'Threshold customisable per team',
  'Uses your GITHUB_TOKEN — no new credentials',
];

const highlight = (line) =>
  line
    .replace(/(^|\s)(name|on|jobs|runs-on|steps|uses|with|types|pull_request):/g, (m, p1, k) => `${p1}<span class="text-[#3B9EFF]">${k}</span>:`)
    .replace(/"([^"]+)"/g, '<span class="text-[#22C55E]">"$1"</span>')
    .replace(/(\$\{\{[^}]+\}\})/g, '<span class="text-[#FF9500]">$1</span>')
    .replace(/(@v\d+|critical|vibesafe\/vibesafe-action)/g, '<span class="text-[#8A2BE2]">$1</span>');

export default function GithubAction() {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(YAML.replace(/\\\$/g, '$'));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <section id="blog" className="relative py-24 lg:py-32 border-t border-[#1F1F3D]">
      <div className="max-w-7xl mx-auto px-6 lg:px-10">
        <div className="grid lg:grid-cols-2 gap-12 items-start">
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.6 }}
          >
            <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-4">
              CI/CD INTEGRATION
            </div>
            <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight">
              Security in your CI/CD.{' '}
              <span className="text-[#A0A0A0]">One YAML snippet.</span>
            </h2>
            <p className="mt-5 text-lg text-[#A0A0A0] font-light">
              Runs on every push and PR. Fails the build if Critical vulnerabilities are
              introduced. Posts a detailed comment to every PR.
            </p>
            <ul className="mt-8 space-y-3">
              {FEATURES.map((f, i) => (
                <motion.li
                  key={f}
                  initial={{ opacity: 0, x: -12 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true, amount: 0.5 }}
                  transition={{ duration: 0.4, delay: i * 0.08 }}
                  className="flex items-start gap-3"
                >
                  <div className="w-5 h-5 rounded-full bg-[#22C55E]/15 border border-[#22C55E]/40 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Check className="w-3 h-3 text-[#22C55E]" />
                  </div>
                  <span className="text-[15px] text-[#FFFFFF]">{f}</span>
                </motion.li>
              ))}
            </ul>

            <motion.div
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="mt-10 rounded-xl border border-[#1F1F3D] bg-[#0B0B1A] p-5"
            >
              <div className="flex items-center gap-2 mb-3">
                <GitPullRequest className="w-4 h-4 text-[#3B9EFF]" />
                <span className="font-mono text-[11px] text-[#A0A0A0]">#247 · vibesafe-bot commented</span>
              </div>
              <div className="flex items-center gap-3 mb-3">
                <div className="px-2 py-1 rounded font-mono text-[11px] bg-[#8A2BE2]/15 text-[#8A2BE2] border border-[#8A2BE2]/30">
                  Risk 88 · CRITICAL
                </div>
                <span className="text-[12px] text-[#A0A0A0]">3 critical · 5 high · 4 medium</span>
              </div>
              <div className="font-mono text-[11.5px] text-[#A0A0A0] space-y-1">
                <div>• Supabase RLS disabled (migrations/init.sql)</div>
                <div>• Hardcoded OPENAI_API_KEY (app.config.ts:23)</div>
                <div>• CORS wildcard + credentials (server/cors.py:11)</div>
              </div>
              <button className="mt-3 text-[12px] text-[#3B9EFF] hover:text-[#5BB0FF] font-mono">
                View full report →
              </button>
            </motion.div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.6, delay: 0.15 }}
            className="rounded-xl border border-[#1F1F3D] bg-[#070716] overflow-hidden shadow-2xl"
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#1F1F3D] bg-[#05050D]">
              <div className="flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#8A2BE2]/70" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#FF9500]/70" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#22C55E]/70" />
                </div>
                <span className="ml-2 font-mono text-[11px] text-[#A0A0A0]">.github/workflows/vibesafe.yml</span>
              </div>
              <button
                onClick={copy}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded font-mono text-[11px] text-[#A0A0A0] hover:text-[#FFFFFF] hover:bg-[#13132A] transition-colors"
              >
                {copied ? <Check className="w-3 h-3 text-[#22C55E]" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="p-5 font-mono text-[12.5px] leading-relaxed overflow-x-auto">
              {YAML.split('\n').map((line, i) => (
                <div
                  key={i}
                  className="text-[#FFFFFF]"
                  dangerouslySetInnerHTML={{ __html: highlight(line) || '&nbsp;' }}
                />
              ))}
            </pre>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
