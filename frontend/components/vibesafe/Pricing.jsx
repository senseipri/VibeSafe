'use client';
import { motion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';

export default function Pricing() {
  return (
    <section id="pricing" className="relative py-24 lg:py-32 border-t border-[#1F1F3D]">
      <div className="max-w-7xl mx-auto px-6 lg:px-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6 }}
          className="max-w-3xl mb-10"
        >
          <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-4">PRICING</div>
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight text-white">
            Beta Access. <span className="text-[#A0A0A0]">Free for everyone.</span>
          </h2>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
          className="relative rounded-2xl p-8 md:p-12 flex flex-col md:flex-row items-center justify-between gap-8 bg-gradient-to-r from-[#0B0B1A] to-[#13132A] border border-[#8A2BE2]/30 shadow-[0_0_50px_-20px_rgba(138,43,226,0.3)]"
        >
          <div className="max-w-xl text-left">
            <span className="font-mono text-[10px] px-2.5 py-1 rounded bg-[#8A2BE2]/15 text-[#B967FF] border border-[#8A2BE2]/30 uppercase tracking-wider mb-4 inline-block">
              Beta Program
            </span>
            <h3 className="font-display text-2xl md:text-3xl text-white mb-3">Free during public beta</h3>
            <p className="text-sm md:text-base text-[#A0A0A0] font-light leading-relaxed">
              VibeSafe is currently in active public beta. We believe security should be accessible to all builders. Get full access to all features, including consensus checks, detailed package audits, and AI-generated fixes, completely free of charge for a limited time.
            </p>
          </div>
          <div className="flex-shrink-0 w-full md:w-auto">
            <a
              href="/scan"
              className="w-full md:w-auto px-8 py-4 rounded-md bg-[#8A2BE2] hover:bg-[#B967FF] text-white font-medium text-sm inline-flex items-center justify-center gap-2 hover-aura cta-glow transition-all"
            >
              Start scanning now <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
