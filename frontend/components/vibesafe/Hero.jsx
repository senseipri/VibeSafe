'use client';
import { useEffect } from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion';
import { ArrowRight } from 'lucide-react';
import Link from 'next/link';
import EarthNetwork from './EarthNetwork';

const SPRING = { stiffness: 55, damping: 22, mass: 1.2 };

export default function Hero() {
  const mx = useMotionValue(0);
  const my = useMotionValue(0);
  const sx = useSpring(mx, SPRING);
  const sy = useSpring(my, SPRING);

  const orbX = useTransform(sx, [-1, 1], [-70, 70]);
  const orbY = useTransform(sy, [-1, 1], [-50, 50]);
  const orbRot = useTransform(sx, [-1, 1], [-4, 4]);
  const orbScale = useTransform(sy, [-1, 1], [1.02, 0.98]);
  const titleX = useTransform(sx, [-1, 1], [10, -10]);
  const titleY = useTransform(sy, [-1, 1], [6, -6]);
  const subX = useTransform(sx, [-1, 1], [-14, 14]);
  const subY = useTransform(sy, [-1, 1], [-8, 8]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (window.matchMedia('(pointer: coarse)').matches) return;
    const onMove = (e) => {
      mx.set((e.clientX / window.innerWidth - 0.5) * 2);
      my.set((e.clientY / window.innerHeight - 0.5) * 2);
    };
    window.addEventListener('mousemove', onMove, { passive: true });
    return () => window.removeEventListener('mousemove', onMove);
  }, [mx, my]);

  return (
    <section
      id="top"
      className="relative pt-24 pb-20 lg:pt-32 lg:pb-24 min-h-screen flex items-center overflow-hidden"
      style={{ perspective: 1200 }}
    >
      <div className="absolute inset-[-5%] grid-lines opacity-40 pointer-events-none" />
      <div className="absolute inset-0 pointer-events-none"
           style={{ background: 'radial-gradient(ellipse 60% 50% at 70% 50%, rgba(138,43,226,0.15), transparent 60%)' }} />

      {/* Sentinel Orb */}
      <motion.div
        style={{ x: orbX, y: orbY, rotate: orbRot, scale: orbScale }}
        className="absolute right-[-12%] lg:right-[-6%] top-1/2 -translate-y-1/2 pointer-events-none will-change-transform"
      >
        <EarthNetwork size={620} />
      </motion.div>

      <div className="relative max-w-7xl mx-auto px-6 lg:pl-28 lg:pr-10 w-full z-10">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          style={{ x: subX, y: subY }}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full glass font-mono text-[10px] tracking-[0.3em] text-[#B967FF] mb-10 uppercase will-change-transform"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-[#8A2BE2] pulse-dot" />
          v0.12 / Security Engine Online
        </motion.div>

        <motion.h1
          style={{ x: titleX, y: titleY }}
          className="font-display text-[80px] sm:text-[140px] lg:text-[180px] xl:text-[220px] leading-[0.85] tracking-[0.02em] uppercase will-change-transform"
        >
          <motion.span
            initial={{ opacity: 0, y: 36 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.3, ease: [0.16, 1, 0.3, 1] }}
            className="block text-white"
          >
            VIBE
          </motion.span>
          <motion.span
            initial={{ opacity: 0, y: 36 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.45, ease: [0.16, 1, 0.3, 1] }}
            className="block text-gradient glow-text"
          >
            SAFE
          </motion.span>
        </motion.h1>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.7 }}
          className="mt-10 max-w-2xl"
        >
          <p className="text-[18px] sm:text-[22px] text-white font-light leading-snug max-w-xl">
            Security is not a feature.
            <br />
            <span className="text-[#A0A0A0]">It&rsquo;s the absence of an exploit.</span>
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.9 }}
          className="mt-10 flex flex-col sm:flex-row gap-5 items-start sm:items-center"
        >
          <Link
            href="/scan"
            className="hover-aura group inline-flex items-center gap-3 text-white font-mono tracking-[0.25em] uppercase text-[12px] py-3 transition-all"
          >
            <span className="text-[#B967FF] group-hover:text-[#FF00FF] transition-colors">
              Push the scaffold
            </span>
            <ArrowRight className="w-4 h-4 text-[#B967FF] group-hover:text-[#FF00FF] group-hover:translate-x-1 transition-all" />
          </Link>
          <span className="font-mono text-[10px] tracking-[0.3em] text-[#5A5A7A] uppercase">
            — 45s avg · 3 LLM consensus · 10,000+ scans
          </span>
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6, delay: 1.4 }}
        className="absolute bottom-6 left-1/2 -translate-x-1/2 font-mono text-[9px] tracking-[0.4em] text-[#5A5A7A] uppercase flex flex-col items-center gap-2"
      >
        <span>Scroll</span>
        <div className="w-px h-8 bg-gradient-to-b from-[#8A2BE2] to-transparent" />
      </motion.div>
    </section>
  );
}
