'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowRight, ShieldCheck, AlertTriangle, Loader2, Github, Lock, Timer } from 'lucide-react';
import Nav from '@/components/vibesafe/Nav';
import Footer from '@/components/vibesafe/Footer';
import ScanProgress from '@/components/vibesafe/ScanProgress';
import Turnstile from '@/components/vibesafe/Turnstile';

const TURNSTILE_SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

export default function ScanPage() {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState('https://github.com/vercel/next.js');
  const [scanId, setScanId] = useState(null);
  const [resolvedUrl, setResolvedUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [website, setWebsite] = useState(''); // honeypot
  const [turnstileToken, setTurnstileToken] = useState('');
  const [cooldown, setCooldown] = useState(0);

  // Cooldown countdown for 429
  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setInterval(() => setCooldown((s) => (s > 0 ? s - 1 : 0)), 1000);
    return () => clearInterval(t);
  }, [cooldown]);

  const submit = async (e) => {
    e?.preventDefault();
    setError('');
    if (cooldown > 0) return;
    if (TURNSTILE_SITE_KEY && !turnstileToken) {
      setError('Please complete the captcha first.');
      return;
    }
    setLoading(true);
    try {
      const res = await fetch('/api/scan/github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: repoUrl,
          website,
          turnstile_token: turnstileToken,
        }),
      });
      const data = await res.json();
      if (res.status === 429) {
        setCooldown(Number(data?.retry_after_seconds) || 60);
        setError(data?.error || 'Slow down — too many scans recently.');
        setLoading(false);
        return;
      }
      if (!res.ok || !data.ok) {
        throw new Error(data?.error || 'Unable to start scan');
      }
      setScanId(data.scan_id);
      setResolvedUrl(data.repo_url || repoUrl);
    } catch (err) {
      setError(err.message || 'Something went wrong');
      setLoading(false);
    }
  };

  const onComplete = ({ status, error_message } = {}) => {
    if (status === 'failed') {
      setScanId(null);
      setLoading(false);
      setError(error_message || 'Scan failed. The repository may be too large or inaccessible.');
      return;
    }
    if (scanId) router.push(`/report/${scanId}`);
  };

  const cooldownText =
    cooldown >= 60
      ? `${Math.floor(cooldown / 60)}m ${String(cooldown % 60).padStart(2, '0')}s`
      : `${cooldown}s`;

  const captchaReady = !TURNSTILE_SITE_KEY || !!turnstileToken;
  const disabled = loading || cooldown > 0 || !captchaReady;

  return (
    <>
      <Nav />
      <main id="main" className="relative min-h-screen pt-28 pb-24">
        <div className="absolute inset-0 dot-grid opacity-40 pointer-events-none" />
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'radial-gradient(ellipse at 50% 0%, rgba(138,43,226,0.10) 0%, transparent 55%)',
          }}
        />

        <div className="relative max-w-3xl mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="text-center mb-10"
          >
            <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-4">
              FREE SCAN
            </div>
            <h1 className="font-display text-4xl sm:text-5xl lg:text-[56px] leading-[1.02] tracking-tight">
              Paste a repo. <span className="text-[#A0A0A0]">Get a verdict.</span>
            </h1>
            <p className="mt-5 text-[15px] text-[#A0A0A0] font-light max-w-xl mx-auto">
              We never store your source code. The repository is cloned to an ephemeral container,
              scanned, then immediately destroyed.
            </p>
          </motion.div>

          <AnimatePresence mode="wait">
            {!scanId ? (
              <motion.form
                key="form"
                onSubmit={submit}
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -14 }}
                transition={{ duration: 0.35 }}
                className="rounded-2xl border border-[#1F1F3D] bg-[#0B0B1A] p-6 sm:p-8 shadow-2xl"
              >
                <label className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] block mb-2">
                  PUBLIC GITHUB REPOSITORY URL
                </label>
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="relative flex-1">
                    <Github className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[#A0A0A0]" />
                    <input
                      type="url"
                      autoFocus
                      autoComplete="off"
                      spellCheck="false"
                      required
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      placeholder="https://github.com/your/repo"
                      className="w-full pl-10 pr-4 py-3.5 rounded-md bg-[#13132A] border border-[#2D2D55] font-mono text-[14px] text-[#FFFFFF] focus:border-[#8A2BE2] focus:bg-[#05050D] outline-none transition-colors"
                    />
                  </div>
                  <input
                    type="text"
                    tabIndex={-1}
                    autoComplete="off"
                    value={website}
                    onChange={(e) => setWebsite(e.target.value)}
                    name="website"
                    aria-hidden="true"
                    className="absolute opacity-0 -z-10 w-0 h-0"
                  />
                  <button
                    type="submit"
                    disabled={disabled}
                    className="cta-glow inline-flex items-center justify-center gap-2 px-6 py-3.5 bg-[#8A2BE2] hover:bg-[#B967FF] disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-md transition-all hover:scale-[1.02]"
                  >
                    {cooldown > 0 ? (
                      <>
                        <Timer className="w-4 h-4" />
                        Wait {cooldownText}
                      </>
                    ) : loading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Starting
                      </>
                    ) : (
                      <>
                        Run Scan
                        <ArrowRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </div>

                {TURNSTILE_SITE_KEY && (
                  <div className="mt-5">
                    <Turnstile
                      siteKey={TURNSTILE_SITE_KEY}
                      onToken={setTurnstileToken}
                      onExpire={() => setTurnstileToken('')}
                    />
                  </div>
                )}

                {error && (
                  <div className="mt-4 flex items-start gap-2 text-[13px] text-[#8A2BE2]">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                    <div>
                      <div>{error}</div>
                      {cooldown > 0 && (
                        <div className="mt-1 font-mono text-[12px] text-[#FF9500]">
                          Try again in {cooldownText}.
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="mt-6 grid sm:grid-cols-3 gap-3">
                  {[
                    { icon: ShieldCheck, label: 'Never stored' },
                    { icon: Lock, label: 'Private repos OK' },
                    { icon: Github, label: '5 free scans/hr' },
                  ].map((b) => (
                    <div
                      key={b.label}
                      className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#05050D] border border-[#1F1F3D]"
                    >
                      <b.icon className="w-3.5 h-3.5 text-[#22C55E]" />
                      <span className="text-[12.5px] text-[#A0A0A0]">{b.label}</span>
                    </div>
                  ))}
                </div>

                <div className="mt-6 pt-6 border-t border-[#1F1F3D] text-[12px] text-[#5A5A7A] font-mono">
                  TRY:{' '}
                  {[
                    'https://github.com/vercel/next.js',
                    'https://github.com/supabase/supabase',
                    'https://github.com/openai/openai-cookbook',
                  ].map((u) => (
                    <button
                      key={u}
                      type="button"
                      onClick={() => setRepoUrl(u)}
                      className="mr-3 text-[#3B9EFF] hover:text-[#5BB0FF] transition-colors"
                    >
                      {u.replace('https://github.com/', '')}
                    </button>
                  ))}
                </div>
              </motion.form>
            ) : (
              <motion.div
                key="progress"
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35 }}
              >
                <ScanProgress
                  scanId={scanId}
                  repoUrl={resolvedUrl.replace(/^https?:\/\//, '')}
                  onComplete={onComplete}
                />
                <p className="mt-4 text-center text-[12px] font-mono text-[#5A5A7A] tracking-wider">
                  SCAN ID · {scanId}
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>
      <Footer />
    </>
  );
}
