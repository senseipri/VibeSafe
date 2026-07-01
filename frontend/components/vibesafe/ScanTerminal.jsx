'use client';
import { useEffect, useRef, useState } from 'react';
import { useInView } from 'framer-motion';

const LINES = [
  { text: 'vibesafe scan github.com/demo/moltbook-clone', kind: 'cmd' },
  { text: '[████████] Cloning repository...', kind: 'step' },
  { text: '[████████] Running static analysis (47 files)...', kind: 'step' },
  { text: '[████████] Claude reviewing findings...', kind: 'step' },
  { text: '[████████] GPT-4o generating fix code...', kind: 'step' },
  { text: '[████████] Gemini auditing 142 packages...', kind: 'step' },
  { text: '✓ Scan complete — 12 findings · Risk 88/100', kind: 'done' },
];

export default function ScanTerminal({ replayKey = 0 }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, amount: 0.3 });
  const [lines, setLines] = useState([]);
  const [typing, setTyping] = useState('');
  const [lineIdx, setLineIdx] = useState(0);
  const [done, setDone] = useState(false);

  useEffect(() => {
    setLines([]);
    setTyping('');
    setLineIdx(0);
    setDone(false);
  }, [replayKey]);

  useEffect(() => {
    if (!inView) return;
    if (lineIdx >= LINES.length) {
      setDone(true);
      return;
    }
    const current = LINES[lineIdx].text;
    let i = 0;
    const speed = LINES[lineIdx].kind === 'cmd' ? 25 : 18;
    const tick = setInterval(() => {
      i++;
      setTyping(current.slice(0, i));
      if (i >= current.length) {
        clearInterval(tick);
        setLines((prev) => [...prev, LINES[lineIdx]]);
        setTyping('');
        setTimeout(() => setLineIdx((x) => x + 1), 280);
      }
    }, speed);
    return () => clearInterval(tick);
  }, [lineIdx, inView]);

  const colorFor = (kind) =>
    kind === 'cmd'
      ? 'text-[#FFFFFF]'
      : kind === 'done'
      ? 'text-[#22C55E]'
      : 'text-[#A0A0A0]';

  return (
    <div
      ref={ref}
      className="font-mono text-[12.5px] leading-relaxed bg-[#070716] border border-[#1F1F3D] rounded-lg p-4 min-h-[200px]"
      role="img"
      aria-label="VibeSafe scan terminal showing scan progress, completing with 12 findings at risk score 88"
    >
      <div className="flex items-center gap-1.5 mb-3 pb-2 border-b border-[#1F1F3D]">
        <div className="w-2.5 h-2.5 rounded-full bg-[#8A2BE2]/70" />
        <div className="w-2.5 h-2.5 rounded-full bg-[#FF9500]/70" />
        <div className="w-2.5 h-2.5 rounded-full bg-[#22C55E]/70" />
        <span className="ml-2 text-[10px] text-[#5A5A7A] tracking-wider">~/scan</span>
      </div>
      {lines.map((l, i) => (
        <div key={i} className={`${colorFor(l.kind)} whitespace-pre-wrap`}>
          {l.kind === 'cmd' && <span className="text-[#8A2BE2]">$ </span>}
          {l.text}
        </div>
      ))}
      {lineIdx < LINES.length && (
        <div className={`${colorFor(LINES[lineIdx]?.kind)} whitespace-pre-wrap`}>
          {LINES[lineIdx]?.kind === 'cmd' && <span className="text-[#8A2BE2]">$ </span>}
          {typing}
          <span className="cursor-blink text-[#8A2BE2]">▌</span>
        </div>
      )}
      {done && <div className="text-[#5A5A7A] mt-1">$ <span className="cursor-blink">▌</span></div>}
    </div>
  );
}
