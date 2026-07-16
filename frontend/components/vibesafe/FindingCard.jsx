'use client';

const SEV = {
  CRITICAL: { color: '#8A2BE2', bg: 'rgba(138,43,226,0.08)' },
  HIGH: { color: '#FF9500', bg: 'rgba(255,149,0,0.08)' },
  MEDIUM: { color: '#FFD60A', bg: 'rgba(255,214,10,0.08)' },
};

export default function FindingCard({ severity, title, file, line }) {
  const sev = SEV[severity] || SEV.HIGH;
  return (
    <div
      className="rounded-lg border border-[#1F1F3D] bg-[#0B0B1A]/80 backdrop-blur p-3 hover:border-[#2D2D55] transition-colors select-none pointer-events-none"
      style={{ borderLeft: `3px solid ${sev.color}` }}
    >
      <div className="flex items-center gap-2 mb-1">
        <span
          className="font-mono text-[10px] font-semibold tracking-[0.12em] px-1.5 py-0.5 rounded"
          style={{ color: sev.color, background: sev.bg }}
        >
          {severity}
        </span>
        <span className="text-[11px] font-mono text-[#5A5A7A] truncate">
          {file}
          {line ? `:${line}` : ''}
        </span>
      </div>
      <div className="text-[13px] text-[#FFFFFF] leading-snug">{title}</div>
    </div>
  );
}
