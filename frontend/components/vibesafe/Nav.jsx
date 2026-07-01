'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, ShieldCheck, Github, FileCode, Lock, BookOpen, Zap } from 'lucide-react';

const SIDE_LABELS = ['VIBESAFE', 'HOW IT WORKS', 'LIVE DEMO', 'CATALOG', 'PRICING'];
const SIDE_HREFS = ['#top', '#how', '#features', '#docs', '#pricing'];

export default function Nav() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 80);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <>
      {/* TOP HEADER */}
      <header
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled ? 'glass-strong border-b border-[#2D2D55]/40' : 'bg-transparent'
        }`}
      >
        <div className="max-w-7xl mx-auto px-6 lg:px-10 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative w-10 h-10 rounded-md border border-[#8A2BE2]/50 bg-[#05050D] flex items-center justify-center shadow-[0_0_20px_rgba(138,43,226,0.4)]">
              <span className="font-display text-[15px] tracking-wider text-[#B967FF]">VS</span>
              <div className="absolute inset-0 rounded-md bg-[#8A2BE2]/20 blur-md -z-10" />
            </div>
          </Link>

          <div className="hidden md:flex items-center gap-7">
            <NavLink href="#how" icon={Zap} label="How It Works" />
            <NavLink href="#features" icon={FileCode} label="Live Demo" />
            <NavLink href="#docs" icon={BookOpen} label="Catalog" />
            <NavLink href="#pricing" icon={Lock} label="Pricing" />
            <Link
              href="/scan"
              className="hover-aura cta-glow inline-flex items-center gap-2 px-5 py-2.5 rounded-md border border-[#8A2BE2] hover:border-[#B967FF] text-[#B967FF] hover:text-white text-[11px] font-mono tracking-[0.25em] uppercase transition-all"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              Secure Your App
            </Link>
          </div>

          <button
            className="md:hidden text-white p-2"
            onClick={() => setOpen((o) => !o)}
            aria-label="Toggle menu"
          >
            {open ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </header>

      {/* VERTICAL SIDEBAR with rotated labels */}
      <aside
        className="hidden lg:flex fixed left-0 top-0 bottom-0 z-40 w-16 flex-col items-center justify-center print:hidden"
        aria-label="Section navigation"
      >
        <div className="flex flex-col items-center gap-10">
          {SIDE_LABELS.map((label, i) => (
            <motion.a
              key={label}
              href={SIDE_HREFS[i]}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.4, delay: 0.1 + i * 0.07 }}
              className="group relative flex items-center font-mono text-[10px] tracking-[0.4em] uppercase text-[#5A5A7A] hover:text-[#B967FF] transition-colors"
              style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}
            >
              <span className="relative">{label}</span>
              <span
                className="absolute -bottom-2 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full bg-[#8A2BE2] opacity-0 group-hover:opacity-100 transition-opacity"
                style={{ boxShadow: '0 0 8px #B967FF' }}
              />
            </motion.a>
          ))}
        </div>
      </aside>

      {/* MOBILE MENU */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="md:hidden fixed inset-0 top-16 z-40 bg-[#05050D]/98 backdrop-blur-xl"
          >
            <div className="flex flex-col p-6 gap-1">
              {SIDE_LABELS.map((label, i) => (
                <a
                  key={label}
                  href={SIDE_HREFS[i]}
                  onClick={() => setOpen(false)}
                  className="px-4 py-3 text-[15px] text-white hover:bg-[#13132A] rounded-md uppercase tracking-[0.18em] font-mono"
                >
                  {label}
                </a>
              ))}
              <Link
                href="/scan"
                onClick={() => setOpen(false)}
                className="mt-4 px-4 py-3 text-center border border-[#8A2BE2] text-[#B967FF] rounded-md font-mono tracking-[0.2em] uppercase"
              >
                Secure Your App
              </Link>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

function NavLink({ href, icon: Icon, label }) {
  return (
    <a
      href={href}
      className="group flex items-center gap-1.5 text-[12px] text-[#A0A0A0] hover:text-white transition-colors font-mono tracking-[0.1em] uppercase"
    >
      <Icon className="w-3.5 h-3.5 opacity-70 group-hover:opacity-100" />
      {label}
    </a>
  );
}
