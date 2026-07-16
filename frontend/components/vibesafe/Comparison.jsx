'use client';
import { motion } from 'framer-motion';
import { Check, X } from 'lucide-react';

const ROWS = [
  { feature: 'Vibe-code specific patterns', vibesafe: true, sast: false, none: false },
  { feature: 'Multi-LLM confirmation', vibesafe: true, sast: false, none: false },
  { feature: 'Slopsquatting detection', vibesafe: true, sast: false, none: false },
  { feature: 'AI-generated fix code', vibesafe: true, sast: false, none: false },

  { feature: 'Setup time', vibesafe: '45 seconds', sast: 'Days', none: '0' },
  { feature: 'False positive rate', vibesafe: '~5%', sast: '~40%', none: 'n/a' },
];

const Cell = ({ v }) => {
  if (v === true)
    return (
      <div className="inline-flex w-7 h-7 rounded-full bg-[#22C55E]/15 border border-[#22C55E]/40 items-center justify-center">
        <Check className="w-4 h-4 text-[#22C55E]" />
      </div>
    );
  if (v === false)
    return (
      <div className="inline-flex w-7 h-7 rounded-full bg-[#8A2BE2]/10 border border-[#8A2BE2]/30 items-center justify-center hover:bg-[#8A2BE2]/25 transition-colors">
        <X className="w-4 h-4 text-[#8A2BE2]" />
      </div>
    );
  return <span className="font-mono text-[13px] text-[#FFFFFF]">{v}</span>;
};

export default function Comparison() {
  return (
    <section className="relative py-24 lg:py-32 border-t border-[#1F1F3D]">
      <div className="max-w-7xl mx-auto px-6 lg:px-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6 }}
          className="max-w-3xl mb-12"
        >
          <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-4">
            COMPARISON
          </div>
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight">
            Built for vibe-coded apps.{' '}
            <span className="text-[#A0A0A0]">Not generic code.</span>
          </h2>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.6 }}
          className="rounded-2xl border border-[#1F1F3D] bg-[#0B0B1A] overflow-hidden"
        >
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1F1F3D] bg-[#05050D]">
                  <th className="text-left p-5 font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0]">
                    FEATURE
                  </th>
                  <th className="p-5 font-display text-lg">
                    <span className="text-[#8A2BE2]">VibeSafe</span>
                  </th>
                  <th className="p-5 font-display text-lg text-[#A0A0A0]">Generic SAST</th>
                  <th className="p-5 font-display text-lg text-[#A0A0A0]">No Review</th>
                </tr>
              </thead>
              <tbody>
                {ROWS.map((r, i) => (
                  <motion.tr
                    key={r.feature}
                    initial={{ opacity: 0, x: -10 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true, amount: 0.3 }}
                    transition={{ duration: 0.4, delay: i * 0.05 }}
                    className="border-b border-[#1F1F3D] last:border-b-0 hover:bg-[#13132A]/50 transition-colors"
                  >
                    <td className="p-5 text-[14px] text-[#FFFFFF] font-light">{r.feature}</td>
                    <td className="p-5 text-center">
                      <Cell v={r.vibesafe} />
                    </td>
                    <td className="p-5 text-center">
                      <Cell v={r.sast} />
                    </td>
                    <td className="p-5 text-center">
                      <Cell v={r.none} />
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
