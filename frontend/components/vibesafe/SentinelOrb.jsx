'use client';
import { motion } from 'framer-motion';

/**
 * Sentinel Orb — fluid, plasma-like 3D-looking sphere.
 * Built with stacked, animated CSS gradients (no Three.js dependency).
 * • Three rotating gradient rings (UV + magenta)
 * • A morphing core that subtly changes shape (border-radius animation)
 * • Pulsing magenta vulnerability halo
 * • Specular highlight that drifts across the surface
 * • Particle ring at 0.7r
 */
export default function SentinelOrb({ size = 540, intensity = 1 }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.85 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 1.4, ease: [0.16, 1, 0.3, 1] }}
      className="relative pointer-events-none select-none"
      style={{ width: size, height: size }}
    >
      {/* Outer UV atmospheric glow */}
      <div
        className="absolute inset-[-25%] orb-pulse"
        style={{
          background:
            'radial-gradient(circle at center, rgba(138,43,226,0.40) 0%, rgba(138,43,226,0.18) 28%, transparent 65%)',
          filter: `blur(${50 * intensity}px)`,
        }}
      />

      {/* Magenta vulnerability pulse — the "scanning engine detected something" feel */}
      <div
        className="absolute inset-[-10%] magenta-pulse rounded-full"
        style={{
          background:
            'radial-gradient(circle, rgba(255,0,255,0.25) 0%, rgba(255,0,255,0.10) 30%, transparent 60%)',
          filter: 'blur(30px)',
          mixBlendMode: 'screen',
        }}
      />

      {/* Conic ring - UV */}
      <div
        className="absolute inset-[4%] orb-rotate"
        style={{
          background:
            'conic-gradient(from 0deg, rgba(138,43,226,0), rgba(185,103,255,0.55), rgba(255,0,255,0.85), rgba(91,26,168,0.55), rgba(138,43,226,0))',
          borderRadius: '50%',
          filter: 'blur(26px)',
        }}
      />

      {/* Inner conic ring - reversed */}
      <div
        className="absolute inset-[18%] orb-rotate-rev"
        style={{
          background:
            'conic-gradient(from 90deg, rgba(255,0,255,0), rgba(138,43,226,0.95), rgba(255,0,255,0.75), rgba(91,26,168,0.95), rgba(255,0,255,0))',
          borderRadius: '50%',
          filter: 'blur(16px)',
          mixBlendMode: 'screen',
        }}
      />

      {/* Morphing plasma core */}
      <div
        className="absolute inset-[32%] plasma-morph-1"
        style={{
          background:
            'radial-gradient(circle at 30% 28%, #FFFFFF 0%, #FF00FF 12%, #B967FF 28%, #8A2BE2 50%, #2A0A55 80%, #08001A 100%)',
          boxShadow:
            '0 0 100px 16px rgba(138,43,226,0.65), 0 0 200px 40px rgba(255,0,255,0.25), inset 0 0 80px 12px rgba(0,0,0,0.6)',
        }}
      />

      {/* Inner morphing swirl */}
      <div
        className="absolute inset-[38%] plasma-morph-2 opacity-70"
        style={{
          background:
            'conic-gradient(from 45deg, rgba(255,0,255,0.6), rgba(255,255,255,0.4), rgba(138,43,226,0.8), rgba(255,0,255,0.6))',
          filter: 'blur(8px)',
          mixBlendMode: 'screen',
        }}
      />

      {/* Specular highlight */}
      <div
        className="absolute inset-[32%] orb-rotate"
        style={{
          background:
            'radial-gradient(ellipse at 30% 22%, rgba(255,255,255,0.65) 0%, rgba(255,255,255,0) 22%)',
          borderRadius: '50%',
          mixBlendMode: 'screen',
        }}
      />

      {/* Particle ring */}
      <svg className="absolute inset-0 orb-rotate" viewBox="0 0 100 100">
        {Array.from({ length: 28 }).map((_, i) => {
          const a = (i / 28) * Math.PI * 2;
          const r = 45;
          const cx = 50 + r * Math.cos(a);
          const cy = 50 + r * Math.sin(a);
          const isMagenta = i % 3 === 0;
          return (
            <circle
              key={i}
              cx={cx}
              cy={cy}
              r={0.35 + (i % 3) * 0.3}
              fill={isMagenta ? '#FF00FF' : '#B967FF'}
              opacity={0.4 + (i % 5) * 0.12}
            />
          );
        })}
      </svg>
    </motion.div>
  );
}
