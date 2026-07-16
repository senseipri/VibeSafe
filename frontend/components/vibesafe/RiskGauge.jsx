'use client';

export default function RiskGauge({ score = 88 }) {
  return (
    <div className="border border-[#1F1F3D] bg-[#070716] rounded-xl p-8 text-center w-full max-w-[280px] select-none pointer-events-none">
      <div className="text-sm font-mono text-[#5A5A7A] tracking-wider uppercase mb-2">Security Risk Score</div>
      <div className="text-6xl font-display font-semibold text-[#8A2BE2] mb-2">{score}</div>
      <div className="text-xs font-mono px-2.5 py-1 rounded bg-[#8A2BE2]/10 text-[#8A2BE2] border border-[#8A2BE2]/30 inline-block">
        CRITICAL RISK
      </div>
    </div>
  );
}
