'use client';

const LINES = [
  { text: 'vibesafe scan github.com/demo/moltbook-clone', kind: 'cmd' },
  { text: '[████████] Cloning repository...', kind: 'step' },
  { text: '[████████] Running static analysis (47 files)...', kind: 'step' },
  { text: '[████████] Qwen reviewing findings...', kind: 'step' },
  { text: '[████████] Kimi K2 generating fix code...', kind: 'step' },
  { text: '[████████] LLM auditing 142 packages...', kind: 'step' },
  { text: '✓ Scan complete — 12 findings · Risk 88/100', kind: 'done' },
];

export default function ScanTerminal() {
  const colorFor = (kind) =>
    kind === 'cmd'
      ? 'text-[#FFFFFF]'
      : kind === 'done'
      ? 'text-[#22C55E]'
      : 'text-[#A0A0A0]';

  return (
    <div
      className="font-mono text-[12.5px] leading-relaxed bg-[#070716] border border-[#1F1F3D] rounded-lg p-4 min-h-[200px]"
      role="img"
      aria-label="VibeSafe scan terminal showing scan progress, completing with 12 findings at risk score 88"
    >
      <div className="flex items-center gap-1.5 mb-3 pb-2 border-b border-[#1F1F3D] select-none pointer-events-none">
        <div className="w-2.5 h-2.5 rounded-full bg-gray-700" />
        <div className="w-2.5 h-2.5 rounded-full bg-gray-700" />
        <div className="w-2.5 h-2.5 rounded-full bg-gray-700" />
        <span className="ml-2 text-[10px] text-[#5A5A7A] tracking-wider">~/scan</span>
      </div>
      {LINES.map((l, i) => (
        <div key={i} className={`${colorFor(l.kind)} whitespace-pre-wrap`}>
          {l.kind === 'cmd' && <span className="text-[#8A2BE2]">$ </span>}
          {l.text}
        </div>
      ))}
      <div className="text-[#5A5A7A] mt-1">$ <span className="text-[#8A2BE2]">▌</span></div>
    </div>
  );
}
