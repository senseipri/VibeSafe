'use client';
import { useEffect, useRef, useState } from 'react';
import { motion, useInView } from 'framer-motion';

export default function RiskGauge({ score = 88, size = 260 }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, amount: 0.4 });
  const [display, setDisplay] = useState(0);
  const [arcOffset, setArcOffset] = useState(1);
  const [pulse, setPulse] = useState(false);

  // Arc geometry: 220deg arc, radius 110, center 130,130
  const radius = 110;
  const center = size / 2;
  const startAngle = 160; // degrees
  const endAngle = 380; // 220 deg sweep
  const totalAngle = endAngle - startAngle;
  const circumference = (Math.PI * radius * totalAngle) / 180;

  const polarToCartesian = (cx, cy, r, angle) => {
    const rad = ((angle - 90) * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  };
  const arcPath = (cx, cy, r, sA, eA) => {
    const s = polarToCartesian(cx, cy, r, eA);
    const e = polarToCartesian(cx, cy, r, sA);
    const large = eA - sA <= 180 ? '0' : '1';
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 0 ${e.x} ${e.y}`;
  };
  const fullPath = arcPath(center, center, radius, startAngle, endAngle);

  const getColor = (s) => {
    if (s <= 30) return '#22C55E';
    if (s <= 60) return '#FFD60A';
    if (s <= 80) return '#FF9500';
    return '#8A2BE2';
  };
  const color = getColor(display);

  useEffect(() => {
    if (!inView) return;
    const duration = 1800;
    const start = performance.now();
    const easeOut = (t) => 1 - Math.pow(1 - t, 3);
    let raf;
    const step = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = easeOut(t);
      setDisplay(Math.round(score * eased));
      setArcOffset(1 - eased);
      if (t < 1) raf = requestAnimationFrame(step);
      else if (score >= 81) {
        setPulse(true);
        setTimeout(() => setPulse(false), 900);
      }
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [inView, score]);

  const severity =
    display >= 81 ? 'CRITICAL' : display >= 61 ? 'HIGH' : display >= 31 ? 'MEDIUM' : 'CLEAN';

  return (
    <div ref={ref} className="relative flex flex-col items-center" style={{ width: size }}>
      <motion.svg
        width={size}
        height={size * 0.75}
        viewBox={`0 0 ${size} ${size * 0.75}`}
        animate={pulse ? { filter: ['drop-shadow(0 0 0 transparent)', 'drop-shadow(0 0 24px rgba(138,43,226,0.7))', 'drop-shadow(0 0 0 transparent)'] } : {}}
        transition={{ duration: 0.9 }}
      >
        {/* Track */}
        <path
          d={fullPath}
          stroke="#1F1F3D"
          strokeWidth="14"
          fill="none"
          strokeLinecap="round"
        />
        {/* Active arc */}
        <path
          d={fullPath}
          stroke={color}
          strokeWidth="14"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * arcOffset + (circumference * (100 - score)) / 100}
          style={{ transition: 'stroke 300ms' }}
        />
        {/* tick marks */}
        {[0, 25, 50, 75, 100].map((v) => {
          const a = startAngle + (totalAngle * v) / 100;
          const p1 = polarToCartesian(center, center, radius - 22, a);
          const p2 = polarToCartesian(center, center, radius - 30, a);
          return (
            <line
              key={v}
              x1={p1.x}
              y1={p1.y}
              x2={p2.x}
              y2={p2.y}
              stroke="#5A5A7A"
              strokeWidth="1.5"
            />
          );
        })}
      </motion.svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-4 pointer-events-none">
        <div className="font-display text-6xl tabular-nums" style={{ color }}>
          {display}
        </div>
        <div className="font-mono text-[10px] tracking-[0.2em] text-[#A0A0A0] mt-1">
          RISK SCORE / 100
        </div>
        <div
          className="mt-2 font-mono text-[11px] font-semibold tracking-[0.15em] px-2.5 py-0.5 rounded"
          style={{
            color,
            background: `${color}15`,
            border: `1px solid ${color}40`,
          }}
        >
          {severity}
        </div>
      </div>
    </div>
  );
}
