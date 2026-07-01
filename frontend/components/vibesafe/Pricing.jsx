'use client';
import { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, ArrowRight } from 'lucide-react';

const PLANS = [
  {
    name: 'Free',
    monthly: 0,
    annual: 0,
    blurb: 'For weekend builders kicking the tires.',
    features: [
      '1 scan per day',
      'Full 7-category scan',
      'All 3 LLMs',
      'Shareable report link',
      'PDF download',
      'GitHub Action',
    ],
    cta: 'Start free',
    popular: false,
  },
  {
    name: 'Starter',
    monthly: 49,
    annual: 39,
    blurb: 'For solo founders who actually ship.',
    features: [
      '20 scans per month',
      'PDF report download',
      'GitHub Action (1 repo)',
      'Fix code snippets',
      'Email alerts on Critical findings',
      'Priority scan queue',
    ],
    cta: 'Start 7-day trial',
    popular: true,
  },
  {
    name: 'Pro',
    monthly: 199,
    annual: 159,
    blurb: 'For teams scaling fast.',
    features: [
      'Unlimited scans',
      'Unlimited GitHub Actions',
      'Team dashboard',
      'API access',
      'Compliance-ready reports',
      'Slack + Discord alerts',
      'Custom vulnerability rules',
    ],
    cta: 'Start trial',
    popular: false,
  },
];

export default function Pricing() {
  const [annual, setAnnual] = useState(false);
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
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl leading-[1.02] tracking-tight">
            Start for free.{' '}
            <span className="text-[#A0A0A0]">Upgrade when you ship.</span>
          </h2>
        </motion.div>

        <div className="flex items-center justify-center gap-3 mb-12">
          <span
            className={`text-sm ${!annual ? 'text-[#FFFFFF]' : 'text-[#A0A0A0]'}`}
          >
            Monthly
          </span>
          <button
            onClick={() => setAnnual((a) => !a)}
            className="relative w-12 h-6 rounded-full bg-[#1F1F3D] transition-colors"
            style={{ background: annual ? '#8A2BE2' : '#1F1F3D' }}
            aria-label="Toggle annual billing"
          >
            <motion.div
              className="absolute top-0.5 w-5 h-5 rounded-full bg-white"
              animate={{ left: annual ? 26 : 2 }}
              transition={{ type: 'spring', stiffness: 500, damping: 30 }}
            />
          </button>
          <span className={`text-sm ${annual ? 'text-[#FFFFFF]' : 'text-[#A0A0A0]'}`}>
            Annual
          </span>
          <span className="ml-1 font-mono text-[10px] px-2 py-0.5 rounded bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30">
            SAVE 20%
          </span>
        </div>

        <div className="grid md:grid-cols-3 gap-5 lg:gap-6 items-stretch">
          {PLANS.map((p, i) => {
            const price = annual ? p.annual : p.monthly;
            return (
              <motion.div
                key={p.name}
                initial={{ opacity: 0, y: 40, scale: p.popular ? 0.97 : 1 }}
                whileInView={{ opacity: 1, y: 0, scale: p.popular ? 1.02 : 1 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.55, delay: i * 0.1, ease: [0.16, 1, 0.3, 1] }}
                className={`relative rounded-2xl p-7 flex flex-col ${
                  p.popular
                    ? 'bg-gradient-to-b from-[#0B0B1A] to-[#13132A] border-2 border-[#8A2BE2]/50 shadow-2xl'
                    : 'bg-[#0B0B1A] border border-[#1F1F3D]'
                }`}
                style={
                  p.popular
                    ? { boxShadow: '0 0 60px -20px rgba(138,43,226,0.4)' }
                    : undefined
                }
              >
                {p.popular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full bg-[#8A2BE2] text-white text-[11px] font-mono tracking-wider">
                    MOST POPULAR
                  </div>
                )}
                <h3 className="font-display text-2xl mb-1">{p.name}</h3>
                <p className="text-[13px] text-[#A0A0A0] font-light mb-5">{p.blurb}</p>
                <div className="flex items-baseline gap-1.5 mb-6">
                  {annual && p.monthly > 0 && (
                    <span className="text-[#5A5A7A] line-through text-lg">${p.monthly}</span>
                  )}
                  <span className="font-display text-5xl text-[#FFFFFF]">${price}</span>
                  <span className="text-[13px] text-[#A0A0A0]">/mo</span>
                </div>
                <button
                  className={`w-full py-3 rounded-md font-medium text-sm mb-7 transition-all hover:scale-[1.02] inline-flex items-center justify-center gap-2 ${
                    p.popular
                      ? 'bg-[#8A2BE2] hover:bg-[#B967FF] text-white cta-glow'
                      : 'border border-[#2D2D55] text-[#FFFFFF] hover:border-[#3B9EFF] hover:bg-[#13132A]'
                  }`}
                >
                  {p.cta} <ArrowRight className="w-4 h-4" />
                </button>
                <ul className="space-y-2.5 mt-auto">
                  {p.features.map((f) => (
                    <li key={f} className="flex items-start gap-2.5 text-[14px]">
                      <Check className="w-4 h-4 text-[#22C55E] flex-shrink-0 mt-0.5" />
                      <span className="text-[#FFFFFF] font-light">{f}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
