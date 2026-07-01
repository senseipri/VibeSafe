'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
  Download,
  Share2,
  ArrowLeft,
  Clock,
  FileCode2,
  Package,
  Code2,
  Check,
  AlertCircle,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import Nav from '@/components/vibesafe/Nav';
import Footer from '@/components/vibesafe/Footer';
import RiskGauge from '@/components/vibesafe/RiskGauge';
import FindingItem from '@/components/vibesafe/FindingItem';

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEV_COLOR = { CRITICAL: '#8A2BE2', HIGH: '#FF9500', MEDIUM: '#FFD60A', LOW: '#3B9EFF' };

export default function ReportPage({ params }) {
  const { id } = params;
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [filter, setFilter] = useState('ALL');
  const [isPrinting, setIsPrinting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/report/${id}`)
      .then((r) => r.json())
      .then((d) => {
        if (cancelled) return;
        if (!d.ok) setError(d.error || 'Report not found');
        else setReport(d.report);
      })
      .catch(() => !cancelled && setError('Network error'));
    return () => {
      cancelled = true;
    };
  }, [id]);

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;

    const handleBeforePrint = () => setIsPrinting(true);
    const handleAfterPrint = () => setIsPrinting(false);

    window.addEventListener('beforeprint', handleBeforePrint);
    window.addEventListener('afterprint', handleAfterPrint);

    return () => {
      window.removeEventListener('beforeprint', handleBeforePrint);
      window.removeEventListener('afterprint', handleAfterPrint);
    };
  }, []);

  const shareLink = () => {
    if (typeof window === 'undefined') return;
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const downloadPdf = () => {
    if (typeof window === 'undefined') return;
    window.print();
  };

  if (error) {
    return (
      <>
        <Nav />
        <main className="min-h-screen flex items-center justify-center px-6">
          <div className="max-w-md text-center">
            <AlertCircle className="w-10 h-10 text-[#8A2BE2] mx-auto mb-4" />
            <h1 className="font-display text-3xl mb-3">Report not found</h1>
            <p className="text-[#A0A0A0] mb-6">
              This scan id doesn&rsquo;t exist or has expired. Reports are kept for 30 days.
            </p>
            <Link
              href="/scan"
              className="cta-glow inline-flex items-center gap-2 px-5 py-3 bg-[#8A2BE2] hover:bg-[#B967FF] text-white rounded-md font-medium"
            >
              Run a new scan
            </Link>
          </div>
        </main>
        <Footer />
      </>
    );
  }

  if (!report) {
    return (
      <>
        <Nav />
        <main className="min-h-screen flex items-center justify-center">
          <Loader2 className="w-6 h-6 text-[#8A2BE2] animate-spin" />
        </main>
      </>
    );
  }

  const findingsToRender = isPrinting
    ? report.findings
    : filter === 'ALL'
      ? report.findings
      : report.findings.filter((f) => f.severity === filter);

  return (
    <>
      <Nav />
      <main id="main" className="relative pt-24 pb-24 print:pt-4 print:pb-4">
        <div className="absolute inset-0 dot-grid opacity-30 pointer-events-none print:hidden" />
        <div className="relative max-w-6xl mx-auto px-6 lg:px-10">
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4 mb-8 print:hidden">
            <Link
              href="/scan"
              className="inline-flex items-center gap-1.5 text-[12px] font-mono text-[#A0A0A0] hover:text-[#FFFFFF] mb-3 sm:mb-0"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              NEW SCAN
            </Link>
            <div className="flex gap-2">
              <button
                onClick={shareLink}
                className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-md border border-[#2D2D55] hover:border-[#3B9EFF] text-[#FFFFFF] text-sm font-medium"
              >
                {copied ? <Check className="w-4 h-4 text-[#22C55E]" /> : <Share2 className="w-4 h-4" />}
                {copied ? 'Copied' : 'Share'}
              </button>
              <button
                onClick={downloadPdf}
                className="cta-glow inline-flex items-center gap-1.5 px-4 py-2.5 rounded-md bg-[#8A2BE2] hover:bg-[#B967FF] text-white text-sm font-medium"
              >
                <Download className="w-4 h-4" />
                Download PDF
              </button>
            </div>
          </div>

          <div id="printable-report" className="printable-report">
            <motion.div
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4 mb-8"
            >
              <div>
                <div className="font-mono text-[11px] tracking-[0.2em] text-[#8A2BE2] mb-2">
                  SECURITY REPORT · {report.scan_id}
                </div>
                <h1 className="font-display text-3xl sm:text-4xl lg:text-5xl leading-tight tracking-tight break-all">
                  {report.repo_url.replace('https://github.com/', '')}
                </h1>
                <p className="mt-2 text-[13px] text-[#A0A0A0] font-mono">
                  Scanned {new Date(report.created_at).toLocaleString()} · took{' '}
                  {report.stats.duration_seconds}s
                </p>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="rounded-2xl border border-[#1F1F3D] bg-[#0B0B1A] p-6 sm:p-8 mb-10"
            >
              <div className="grid lg:grid-cols-3 gap-8 items-center">
                <div className="flex justify-center lg:justify-start">
                  <RiskGauge score={report.risk_score} size={260} />
                </div>

                <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {SEV_ORDER.map((s) => (
                    <div
                      key={s}
                      className="rounded-lg border border-[#1F1F3D] bg-[#05050D] p-4"
                      style={{ borderTop: `2px solid ${SEV_COLOR[s]}` }}
                    >
                      <div className="font-display text-3xl tabular-nums" style={{ color: SEV_COLOR[s] }}>
                        {report.stats[s.toLowerCase()]}
                      </div>
                      <div className="font-mono text-[10.5px] tracking-[0.12em] text-[#A0A0A0] mt-1">
                        {s}
                      </div>
                    </div>
                  ))}
                  <Stat icon={FileCode2} label="Files scanned" value={report.stats.files_scanned} />
                  <Stat icon={Code2} label="Lines analysed" value={report.stats.lines_of_code.toLocaleString()} />
                  <Stat icon={Package} label="Packages audited" value={report.stats.packages_audited} />
                  <Stat icon={Clock} label="Scan duration" value={`${report.stats.duration_seconds}s`} />
                </div>
              </div>

              <div className="mt-8 pt-8 border-t border-[#1F1F3D]/60 grid md:grid-cols-2 gap-6">
                <div>
                  <div className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] mb-2">
                    EXECUTIVE SUMMARY
                  </div>
                  <p className="text-[14.5px] text-[#FFFFFF] font-light leading-relaxed">
                    {report.summary || 'No summary available.'}
                  </p>
                  {report.verdict && (
                    <div className="mt-3 flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-[11px] text-[#A0A0A0]">VERDICT:</span>
                      <span className="font-mono text-[12px] font-semibold text-white px-2 py-0.5 rounded bg-[#1F1F3D] border border-[#2D2D55]">
                        {report.verdict}
                      </span>
                      {report.highest_severity && (
                        <>
                          <span className="font-mono text-[11px] text-[#A0A0A0] ml-3">HIGHEST SEVERITY:</span>
                          <span
                            className="font-mono text-[12px] font-semibold px-2 py-0.5 rounded"
                            style={{
                              color: SEV_COLOR[report.highest_severity.toUpperCase()] || '#FFF',
                              background: `${SEV_COLOR[report.highest_severity.toUpperCase()]}15`,
                              border: `1px solid ${SEV_COLOR[report.highest_severity.toUpperCase()]}40`,
                            }}
                          >
                            {report.highest_severity.toUpperCase()}
                          </span>
                        </>
                      )}
                    </div>
                  )}
                </div>

                <div className="space-y-4">
                  {report.frameworks && report.frameworks.length > 0 && (
                    <div>
                      <div className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] mb-1.5">
                        DETECTED FRAMEWORKS
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {report.frameworks.map((fw) => (
                          <span key={fw} className="font-mono text-[11px] px-2.5 py-1 bg-[#13132A] border border-[#1F1F3D] rounded-md text-[#3B9EFF]">
                            {fw}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {report.models_used && report.models_used.length > 0 && (
                    <div>
                      <div className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] mb-1.5">
                        AI MODELS ENGAGED IN CONSENSUS
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {report.models_used.map((model) => (
                          <span key={model} className="font-mono text-[11px] px-2.5 py-1 bg-[#13132A] border border-[#1F1F3D] rounded-md text-[#22C55E]">
                            {model}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>

            <div className="flex items-center justify-between flex-wrap gap-4 mb-6 print:hidden">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] mr-1">
                  FILTER:
                </span>
                {['ALL', ...SEV_ORDER].map((s) => {
                  const count =
                    s === 'ALL'
                      ? report.findings.length
                      : report.findings.filter((f) => f.severity === s).length;
                  const active = filter === s;
                  const c = s === 'ALL' ? '#8A2BE2' : SEV_COLOR[s];
                  return (
                    <button
                      key={s}
                      onClick={() => setFilter(s)}
                      disabled={count === 0}
                      className={`font-mono text-[11px] tracking-wider px-2.5 py-1 rounded border transition-all disabled:opacity-30 disabled:cursor-not-allowed ${
                        active ? '' : 'hover:bg-[#13132A]'
                      }`}
                      style={{
                        color: active ? '#fff' : c,
                        background: active ? c : 'transparent',
                        borderColor: active ? c : `${c}40`,
                      }}
                    >
                      {s} · {count}
                    </button>
                  );
                })}
              </div>
              <Link
                href="/scan"
                className="inline-flex items-center gap-1.5 text-[12px] font-mono text-[#3B9EFF] hover:text-[#5BB0FF]"
              >
                <RefreshCw className="w-3 h-3" />
                SCAN AGAIN
              </Link>
            </div>

            <div className="space-y-3">
              {findingsToRender.map((f, i) => (
                <FindingItem
                  key={f.id}
                  finding={f}
                  index={i}
                  modelsUsed={report.models_used}
                  forceOpen={isPrinting}
                />
              ))}
              {findingsToRender.length === 0 && (
                <div className="text-center py-12 text-[#A0A0A0]">
                  No findings at this severity. Nice.
                </div>
              )}
            </div>
          </div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.5 }}
            className="mt-12 p-5 rounded-xl border border-[#1F1F3D] bg-[#05050D] text-center print:hidden"
          >
            <p className="text-[13px] text-[#A0A0A0] font-light">
              Scanned by VibeSafe · Claude · GPT-4o · Gemini in consensus ·{' '}
              <span className="text-[#5A5A7A]">we never store your source code</span>
            </p>
          </motion.div>
        </div>
      </main>
      <Footer />
    </>
  );
}

function Stat({ icon: Icon, label, value }) {
  return (
    <div className="rounded-lg border border-[#1F1F3D] bg-[#05050D] p-4">
      <div className="flex items-center gap-1.5 text-[#A0A0A0] mb-1">
        <Icon className="w-3.5 h-3.5" />
        <span className="font-mono text-[10.5px] tracking-[0.12em]">{label.toUpperCase()}</span>
      </div>
      <div className="font-display text-2xl text-[#FFFFFF] tabular-nums">{value}</div>
    </div>
  );
}
