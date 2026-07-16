'use client';
import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, Copy, Check, Sparkles, FileCode, ShieldAlert, Brain } from 'lucide-react';
import { severityColor } from '@/lib/mockReport';

export default function FindingItem({ finding, index, modelsUsed = [], forceOpen = false }) {
  const [open, setOpen] = useState(index === 0);
  const [copied, setCopied] = useState(false);
  const color = severityColor(finding.severity);

  const copyFix = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(finding.fix_code || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const translateModelName = (name) => {
    const m = name.toLowerCase();
    if (m.includes('claude')) return 'qwen';
    if (m.includes('gpt4o') || m.includes('openai') || m.includes('gpt')) return 'kimi k2';
    if (m.includes('gemini')) return 'llm';
    return name;
  };

  // Determine LLMs involved dynamically
  const allModels = Array.from(new Set([
    ...modelsUsed,
    ...(finding.confirmed_by || []),
    ...(finding.validator ? [finding.validator] : [])
  ])).filter(Boolean);

  const displayModels = (allModels.length > 0 ? allModels : ['claude', 'gpt4o', 'gemini']).map(translateModelName);
  const confirmingCount = (finding.confirmed_by || []).length;
  const totalModelsCount = displayModels.length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.04 }}
      className="rounded-xl border border-[#1F1F3D] bg-[#0B0B1A] overflow-hidden hover:border-[#2D2D55] transition-colors"
      style={{ borderLeft: `3px solid ${color}` }}
    >
      <button
        onClick={() => !forceOpen && setOpen((o) => !o)}
        className="w-full text-left p-5 sm:p-6 flex items-start gap-4"
      >
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span
              className="font-mono text-[10.5px] font-semibold tracking-[0.12em] px-2 py-0.5 rounded"
              style={{ color, background: `${color}15`, border: `1px solid ${color}40` }}
            >
              {finding.severity}
            </span>
            <span className="font-mono text-[10.5px] text-[#5A5A7A] tracking-wider">
              {finding.owasp}
            </span>
            <span className="font-mono text-[10.5px] text-[#5A5A7A] tracking-wider">
              · {finding.category}
            </span>
            {finding.owasp_cat && (
              <span className="font-mono text-[10.5px] text-[#A0A0A0]/60 tracking-wider">
                ({finding.owasp_cat})
              </span>
            )}
          </div>
          <h3 className="font-display text-lg sm:text-xl leading-snug">{finding.title}</h3>
          <div className="mt-2 flex flex-wrap items-center gap-3 text-[12px] text-[#A0A0A0] font-mono">
            <span className="flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5" />
              {finding.file}
              {finding.line ? `:${finding.line}` : ''}
            </span>
            <span className="flex items-center gap-1.5">
              <Brain className="w-3.5 h-3.5" />
              {confirmingCount}/{totalModelsCount} LLMs confirm
            </span>
            <span
              className="flex items-center gap-1.5"
              style={{ color: finding.confidence === 'high' ? '#22C55E' : '#FF9500' }}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              {finding.confidence} confidence
            </span>
            {finding.validator && (
              <span className="text-[#A0A0A0]/70">
                · Verified by {finding.validator}
              </span>
            )}
            {finding.cvss_score && (
              <span className="text-[#FF9500]">
                · CVSS {finding.cvss_score}
              </span>
            )}
          </div>
        </div>
        <motion.div
          animate={{ rotate: forceOpen || open ? 180 : 0 }}
          transition={{ duration: 0.25 }}
          className="flex-shrink-0 mt-1 print:hidden"
        >
          <ChevronDown className="w-5 h-5 text-[#A0A0A0]" />
        </motion.div>
      </button>

      <AnimatePresence initial={false}>
        {(open || forceOpen) && (
          <motion.div
            initial={forceOpen ? false : { height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={forceOpen ? undefined : { height: 0, opacity: 0 }}
            transition={forceOpen ? { duration: 0 } : { duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <div className="px-5 sm:px-6 pb-6 space-y-5 border-t border-[#1F1F3D] pt-5">
              <div>
                <div className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] mb-1.5">
                  WHAT IT IS
                </div>
                <p className="text-[14.5px] text-[#FFFFFF] font-light leading-relaxed">
                  {finding.description}
                </p>
              </div>

              {finding.attacker_scenario && (
                <div>
                  <div className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] mb-1.5">
                    HOW AN ATTACKER USES IT / ATTACK SCENARIO
                  </div>
                  <p className="text-[14.5px] text-[#FFFFFF] font-light leading-relaxed">
                    {finding.attacker_scenario}
                  </p>
                </div>
              )}

              {finding.evidence && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-mono text-[11px] tracking-[0.15em] text-[#8A2BE2]">
                      EVIDENCE (your code)
                    </div>
                    <span className="font-mono text-[10.5px] text-[#5A5A7A]">{finding.file}:{finding.line}</span>
                  </div>
                  <pre className="font-mono text-[12.5px] bg-[#070716] border border-[#1F1F3D] rounded-lg p-4 overflow-x-auto whitespace-pre text-[#FF8C70] leading-relaxed">
                    {finding.evidence}
                  </pre>
                </div>
              )}

              {/* Conditional fix rendering */}
              {finding.fix_code ? (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2 font-mono text-[11px] tracking-[0.15em] text-[#22C55E]">
                      <Sparkles className="w-3.5 h-3.5" />
                      AI-GENERATED FIX ({finding.fix_language})
                    </div>
                    <button
                      onClick={copyFix}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded font-mono text-[11px] text-[#A0A0A0] hover:text-[#FFFFFF] hover:bg-[#13132A] transition-colors print:hidden"
                    >
                      {copied ? (
                        <Check className="w-3 h-3 text-[#22C55E]" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="font-mono text-[12.5px] bg-[#070716] border border-[#22C55E]/25 rounded-lg p-4 overflow-x-auto whitespace-pre text-[#9DECC4] leading-relaxed">
                    {finding.fix_code}
                  </pre>
                  {finding.recommendation && (
                    <div className="mt-3">
                      <div className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] mb-1">
                        RECOMMENDATION
                      </div>
                      <p className="text-[14px] text-[#A0A0A0] font-light leading-relaxed">
                        {finding.recommendation}
                      </p>
                    </div>
                  )}
                  {finding.fix && (
                    <div className="mt-2">
                      <div className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] mb-1">
                        REMEDIATION PROSE
                      </div>
                      <p className="text-[14px] text-[#A0A0A0] font-light leading-relaxed">
                        {finding.fix}
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                (finding.recommendation || finding.fix) && (
                  <div className="rounded-lg border border-[#1F1F3D] bg-[#070716] p-5">
                    <div className="flex items-center gap-2 font-mono text-[11.5px] tracking-[0.15em] text-[#FF9500] mb-3">
                      <ShieldAlert className="w-4 h-4" />
                      RECOMMENDED REMEDIATION
                    </div>
                    {finding.recommendation && (
                      <div className="mb-3">
                        <div className="font-mono text-[10.5px] tracking-[0.12em] text-[#A0A0A0] mb-1">
                          RECOMMENDATION
                        </div>
                        <p className="text-[14.5px] text-[#FFFFFF] font-medium leading-relaxed">
                          {finding.recommendation}
                        </p>
                      </div>
                    )}
                    {finding.fix && (
                      <div>
                        <div className="font-mono text-[10.5px] tracking-[0.12em] text-[#A0A0A0] mb-1">
                          FIX INSTRUCTIONS
                        </div>
                        <p className="text-[14px] text-[#D0D0D0] font-light leading-relaxed">
                          {finding.fix}
                        </p>
                      </div>
                    )}
                  </div>
                )
              )}

              {/* Dynamic Consensus display */}
              <div className="flex flex-wrap items-center gap-3 pt-1">
                <span className="font-mono text-[10.5px] text-[#A0A0A0] tracking-wider">
                  LLM CONSENSUS:
                </span>
                {displayModels.map((model) => {
                  const isConfirmed = (finding.confirmed_by || []).map(translateModelName).includes(model);
                  return (
                    <span
                      key={model}
                      className={`font-mono text-[10.5px] px-2 py-0.5 rounded border ${
                        isConfirmed
                          ? 'text-[#22C55E] border-[#22C55E]/30 bg-[#22C55E]/10'
                          : 'text-[#A0A0A0] border-[#1F1F3D]'
                      }`}
                    >
                      {model} {isConfirmed ? '✓' : '—'}
                    </span>
                  );
                })}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
