'use client';
import { motion } from 'framer-motion';
import { Star } from 'lucide-react';

const T = [
  {
    name: 'Maya Chen',
    role: 'Founder, Drafthouse AI',
    avatar: '#8A2BE2',
    initials: 'MC',
    quote:
      'VibeSafe found a hardcoded Stripe live key in our repo that had been there for 3 months. We had no idea. That\u2019s a $0 fix vs. a potential regulatory disaster.',
  },
  {
    name: 'Daniel Park',
    role: 'CTO, Brieflens',
    avatar: '#3B9EFF',
    initials: 'DP',
    quote:
      'The LLM package audit caught a hallucinated npm package name that could have been a supply chain attack. I didn’t even know that was a thing.',
  },
  {
    name: 'Sofia Reyes',
    role: 'Solo founder, Notewing',
    avatar: '#22C55E',
    initials: 'SR',
    quote:
      'Running VibeSafe before every launch is now a non-negotiable part of our process. It takes 45 seconds and I sleep better.',
  },
  {
    name: 'Alex Tanaka',
    role: 'Engineer @ Vibestack',
    avatar: '#FF9500',
    initials: 'AT',
    quote:
      'I shipped a Lovable app with RLS disabled. VibeSafe caught it in seconds. Honestly should be built into every AI coding tool by default.',
  },
  {
    name: 'Priya Kapoor',
    role: 'Indie hacker',
    avatar: '#A78BFA',
    initials: 'PK',
    quote:
      'The fix code is the killer feature. I don\u2019t need to know what \u201CCORS with credentials\u201D means \u2014 just paste the diff.',
  },
  {
    name: 'Marcus Lin',
    role: 'YC W26',
    avatar: '#EC4899',
    initials: 'ML',
    quote:
      'We added the GitHub Action and our PR reviews got 4x faster. No more security back-and-forth.',
  },
];

export default function Testimonials() {
  return (
    <section className="relative py-24 lg:py-32 border-t border-[#1F1F3D]">
      <div className="max-w-7xl mx-auto px-6 lg:px-10">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6 }}
          className="max-w-3xl mb-14"
        >
          <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-4">
            TESTIMONIALS
          </div>
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight">
            Founders who checked{' '}
            <span className="text-[#A0A0A0]">before it cost them.</span>
          </h2>
        </motion.div>

        <div className="columns-1 md:columns-2 lg:columns-3 gap-5 space-y-5">
          {T.map((t, i) => (
            <motion.div
              key={t.name}
              initial={{ opacity: 0, y: 24, rotate: i % 2 === 0 ? -1 : 1 }}
              whileInView={{ opacity: 1, y: 0, rotate: 0 }}
              viewport={{ once: true, amount: 0.3 }}
              transition={{ duration: 0.5, delay: (i % 3) * 0.08 }}
              className="break-inside-avoid rounded-xl bg-[#0B0B1A] border border-[#1F1F3D] p-6 hover:border-[#2D2D55] transition-colors"
            >
              <div className="flex items-center gap-1 mb-3">
                {[0, 1, 2, 3, 4].map((s) => (
                  <Star key={s} className="w-3.5 h-3.5 fill-[#FF9500] text-[#FF9500]" />
                ))}
              </div>
              <p className="text-[15px] text-[#FFFFFF] font-light leading-relaxed mb-5">
                "{t.quote}"
              </p>
              <div className="flex items-center gap-3">
                <div
                  className="w-9 h-9 rounded-full flex items-center justify-center text-white text-[12px] font-semibold"
                  style={{ background: t.avatar }}
                >
                  {t.initials}
                </div>
                <div>
                  <div className="text-[13px] text-[#FFFFFF] font-medium">{t.name}</div>
                  <div className="text-[12px] text-[#A0A0A0]">{t.role}</div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
