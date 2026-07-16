'use client';
import { motion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';

export default function FinalCTA() {
  return (
    <section id="scan" className="relative py-32 lg:py-40 overflow-hidden border-t border-[#1F1F3D]">
      {/* Aurora background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div
          className="absolute top-1/4 left-1/4 w-[600px] h-[600px] rounded-full aurora-blob"
          style={{
            background:
              'radial-gradient(circle, rgba(138,43,226,0.18) 0%, transparent 70%)',
            filter: 'blur(60px)',
          }}
        />
        <div
          className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] rounded-full aurora-blob"
          style={{
            background:
              'radial-gradient(circle, rgba(59,158,255,0.14) 0%, transparent 70%)',
            filter: 'blur(60px)',
            animationDelay: '6s',
          }}
        />
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] rounded-full aurora-blob"
          style={{
            background:
              'radial-gradient(circle, rgba(255,149,0,0.10) 0%, transparent 70%)',
            filter: 'blur(60px)',
            animationDelay: '3s',
          }}
        />
      </div>
      <div className="absolute inset-0 dot-grid opacity-30 pointer-events-none" />

      <div className="relative max-w-4xl mx-auto px-6 lg:px-10 text-center">
        <motion.h2
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="font-display text-5xl sm:text-7xl lg:text-[96px] leading-[0.95] tracking-tight"
        >
          Ship fast.
          <br />
          <span className="text-[#8A2BE2]">Ship safe.</span>
        </motion.h2>

        <motion.p
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6, delay: 0.15 }}
          className="mt-8 text-lg lg:text-xl text-[#A0A0A0] font-light max-w-2xl mx-auto"
        >
          45 seconds between your codebase and a prioritised security report. Free to start. No
          account required.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="mt-10 flex flex-col sm:flex-row gap-3 justify-center"
        >
          <a
            href="#"
            className="cta-glow group inline-flex items-center justify-center gap-2 px-7 py-4 bg-[#8A2BE2] hover:bg-[#B967FF] text-white font-medium rounded-md transition-all hover:scale-[1.02]"
          >
            Scan Your Repo Free
            <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
          </a>

        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="mt-12 font-mono text-[12px] text-[#A0A0A0] tracking-wider"
        >
          500+ repos scanned · 3000+ vulnerabilities found 
        </motion.p>
      </div>
    </section>
  );
}
