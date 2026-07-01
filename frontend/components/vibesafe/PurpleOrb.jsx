'use client';
import { motion } from 'framer-motion';

// The signature centerpiece: a swirling, glowing purple nebula.
// Pure CSS/SVG — no canvas, no extra dependencies.
export default function PurpleOrb({ size = 520, intensity = 1 }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.85 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 1.4, ease: [0.16, 1, 0.3, 1] }}
      className="relative pointer-events-none select-none"
      style={{ width: size, height: size }}
    >
      {/* Outer atmospheric glow */}
      <div
        className="absolute inset-[-20%] orb-pulse"
        style={{
          background:
            'radial-gradient(circle at center, rgba(138,43,226,0.35) 0%, rgba(138,43,226,0.18) 25%, transparent 60%)',
          filter: `blur(${40 * intensity}px)`,
        }}
      />

      {/* Middle ring of color */}
      <div
        className="absolute inset-[5%] orb-rotate"
        style={{
          background:
            'conic-gradient(from 0deg, rgba(138,43,226,0.0), rgba(192,132,252,0.6), rgba(232,121,249,0.8), rgba(126,34,206,0.6), rgba(138,43,226,0.0))',
          borderRadius: '50%',
          filter: 'blur(28px)',
        }}
      />

      {/* Inner swirl */}
      <div
        className="absolute inset-[18%] orb-rotate-rev"
        style={{
          background:
            'conic-gradient(from 90deg, rgba(232,121,249,0), rgba(138,43,226,0.9), rgba(232,121,249,0.7), rgba(126,34,206,0.95), rgba(232,121,249,0))',
          borderRadius: '50%',
          filter: 'blur(18px)',
          mixBlendMode: 'screen',
        }}
      />

      {/* Core sphere */}
      <div
        className="absolute inset-[34%] orb-pulse"
        style={{
          background:
            'radial-gradient(circle at 35% 30%, #FFFFFF 0%, #FF00FF 18%, #8A2BE2 45%, #4C1D95 75%, #1A052E 100%)',
          borderRadius: '50%',
          boxShadow:
            '0 0 80px 10px rgba(138,43,226,0.55), inset 0 0 60px 10px rgba(0,0,0,0.55)',
        }}
      />

      {/* Specular highlight */}
      <div
        className="absolute inset-[34%] orb-swirl"
        style={{
          background:
            'radial-gradient(ellipse at 30% 25%, rgba(255,255,255,0.55) 0%, rgba(255,255,255,0) 25%)',
          borderRadius: '50%',
          mixBlendMode: 'screen',
        }}
      />

      {/* Particle ring */}
      <svg className="absolute inset-0 orb-rotate" viewBox="0 0 100 100">
        {Array.from({ length: 24 }).map((_, i) => {
          const angle = (i / 24) * Math.PI * 2;
          const r = 44;
          const cx = 50 + r * Math.cos(angle);
          const cy = 50 + r * Math.sin(angle);
          return (
            <circle
              key={i}
              cx={cx}
              cy={cy}
              r={0.4 + (i % 3) * 0.25}
              fill="#FF00FF"
              opacity={0.4 + (i % 5) * 0.12}
            />
          );
        })}
      </svg>
    </motion.div>
  );
}
