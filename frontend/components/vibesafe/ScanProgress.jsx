'use client';
import { useEffect, useRef, useState } from 'react';
import { Loader2 } from 'lucide-react';

// Visual phases shown while the backend processes the scan.
// Timing is illustrative — actual completion is driven by polling /api/scan/{id}/status.
const PHASES = [
  { text: 'Authenticating with GitHub...', ms: 350 },
  { text: 'Cloning {REPO}...', ms: 700 },
  { text: 'Indexed files · building manifest', ms: 350 },
  { text: 'Running static analysis (regex + AST)...', ms: 600 },
  { text: '✓ Static pass complete', ms: 200, ok: true },
  { text: 'Qwen reviewing architectural risks...', ms: 700 },
  { text: 'Kimi K2 generating solution fix...', ms: 700 },
  { text: 'LLM auditing packages against npm/PyPI...', ms: 800 },
  { text: '✓ Multi-LLM consensus reached', ms: 250, ok: true },
  { text: 'Scoring with CVSS weights...', ms: 350 },
];

const POLL_INTERVAL_MS = 2500;

/**
 * ScanProgress — shows a terminal-style animation while polling
 * the backend scan status. Calls onComplete({ status, error_message })
 * when the backend reports 'complete' or 'failed'.
 *
 * Props:
 *   scanId   – real UUID from the backend (required for polling)
 *   repoUrl  – displayed in the terminal header
 *   onComplete – called with { status, error_message } when done
 */
export default function ScanProgress({
  scanId,
  repoUrl = 'github.com/you/repo',
  onComplete,
}) {
  const [lines, setLines] = useState([]);
  const [typing, setTyping] = useState('');
  const [phaseIdx, setPhaseIdx] = useState(0);
  const [animDone, setAnimDone] = useState(false);
  const [backendResult, setBackendResult] = useState(null); // { status, error_message }
  const [waiting, setWaiting] = useState(false); // animation done but backend still running

  const onCompleteRef = useRef(onComplete);
  useEffect(() => { onCompleteRef.current = onComplete; }, [onComplete]);

  // ── Animation ─────────────────────────────────────────────────
  useEffect(() => {
    if (phaseIdx >= PHASES.length) {
      setAnimDone(true);
      return;
    }
    const phase = PHASES[phaseIdx];
    const text = phase.text.replace('{REPO}', repoUrl);
    let i = 0;
    const speed = 22;
    const tick = setInterval(() => {
      i++;
      setTyping(text.slice(0, i));
      if (i >= text.length) {
        clearInterval(tick);
        setLines((p) => [...p, { text, ok: phase.ok }]);
        setTyping('');
        setTimeout(() => setPhaseIdx((x) => x + 1), phase.ms);
      }
    }, speed);
    return () => clearInterval(tick);
  }, [phaseIdx, repoUrl]);

  // ── Backend polling ───────────────────────────────────────────
  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;

    const poll = async () => {
      try {
        const res = await fetch(`/api/scan/${scanId}/status`);
        if (!res.ok) return; // keep polling on transient errors
        const data = await res.json();
        const backendStatus = data.status || data.ok === false ? data : null;
        const status = data.status;

        if (!cancelled && (status === 'complete' || status === 'failed')) {
          setBackendResult({ status, error_message: data.error_message || '' });
        }
      } catch {
        // network error — keep polling
      }
    };

    const id = setInterval(poll, POLL_INTERVAL_MS);
    poll(); // immediate first poll
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [scanId]);

  // ── Fire onComplete when BOTH animation is done AND backend is done ─
  useEffect(() => {
    if (!backendResult) return;

    if (animDone) {
      // Both done — redirect immediately
      onCompleteRef.current?.(backendResult);
    } else {
      // Backend done but animation still going — wait for animation
      // The animation will naturally finish, then trigger below
    }
  }, [animDone, backendResult]);

  // When animation finishes, check if backend already returned a result
  useEffect(() => {
    if (!animDone) return;
    if (backendResult) {
      onCompleteRef.current?.(backendResult);
    } else {
      // Backend still running — show waiting state
      setWaiting(true);
    }
  }, [animDone]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="font-mono text-[13px] leading-relaxed bg-[#070716] border border-[#1F1F3D] rounded-xl p-5 min-h-[360px] max-h-[480px] overflow-hidden">
      {/* Terminal chrome */}
      <div className="flex items-center gap-1.5 mb-3 pb-2 border-b border-[#1F1F3D]">
        <div className="w-2.5 h-2.5 rounded-full bg-[#8A2BE2]/70" />
        <div className="w-2.5 h-2.5 rounded-full bg-[#FF9500]/70" />
        <div className="w-2.5 h-2.5 rounded-full bg-[#22C55E]/70" />
        <span className="ml-2 text-[10px] text-[#5A5A7A] tracking-wider">vibesafe / scan</span>
      </div>

      {/* Command line */}
      <div className="text-[#FFFFFF]">
        <span className="text-[#8A2BE2]">$</span> vibesafe scan {repoUrl}
      </div>

      {/* Completed lines */}
      {lines.map((l, i) => (
        <div key={i} className={l.ok ? 'text-[#22C55E]' : 'text-[#A0A0A0]'}>
          {l.text}
        </div>
      ))}

      {/* Currently-typing line */}
      {!animDone && phaseIdx < PHASES.length && (
        <div className="text-[#A0A0A0]">
          {typing}
          <span className="cursor-blink text-[#8A2BE2]">▌</span>
        </div>
      )}

      {/* Waiting for backend after animation completes */}
      {waiting && (
        <div className="flex items-center gap-2 mt-3 text-[#8A2BE2]">
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
          <span>Finalising analysis — waiting for backend…</span>
        </div>
      )}
    </div>
  );
}
