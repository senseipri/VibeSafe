'use client';
import { useEffect, useRef } from 'react';

/**
 * Full-viewport canvas particle field.
 * • Particles drift with tiny random impulses (zero-gravity feel).
 * • Mouse repels nearby particles with a smooth falloff.
 * • Nearby particles draw faint connecting lines (constellation effect).
 * • Disabled for touch devices and prefers-reduced-motion.
 * • Sits behind all content via z-index: 0; pointer-events: none.
 */
export default function AntiGravityBackground({
  density = 0.000055,
  maxParticles = 90,
  repelRadius = 140,
  repelStrength = 0.55,
  linkRadius = 130,
}) {
  const canvasRef = useRef(null);
  const mouseRef = useRef({ x: -9999, y: -9999, vx: 0, vy: 0, active: false });
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const rafRef = useRef(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    // Bail out for users who prefer no motion or are on touch-only devices
    const noMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const coarsePointer = window.matchMedia('(pointer: coarse)').matches;
    if (noMotion || coarsePointer) return;

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: true });
    let particles = [];
    let width = 0;
    let height = 0;
    let dpr = 1;
    let running = true;

    // VibeSafe purple palette (hsl ranges for variety)
    const HUE_MIN = 268;
    const HUE_MAX = 305;

    const setup = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = width + 'px';
      canvas.style.height = height + 'px';
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);

      const count = Math.max(40, Math.min(maxParticles, Math.floor(width * height * density)));
      particles = Array.from({ length: count }, () => spawn());
    };

    const spawn = () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.18,
      vy: (Math.random() - 0.5) * 0.18,
      size: 0.7 + Math.random() * 1.7,
      baseOpacity: 0.18 + Math.random() * 0.55,
      hue: HUE_MIN + Math.random() * (HUE_MAX - HUE_MIN),
      phase: Math.random() * Math.PI * 2,
    });

    const onResize = () => setup();
    const onMouseMove = (e) => {
      const m = mouseRef.current;
      // velocity = delta since last frame — used to nudge particles when moving fast
      m.vx = e.clientX - (lastMouseRef.current.x || e.clientX);
      m.vy = e.clientY - (lastMouseRef.current.y || e.clientY);
      lastMouseRef.current.x = e.clientX;
      lastMouseRef.current.y = e.clientY;
      m.x = e.clientX;
      m.y = e.clientY;
      m.active = true;
    };
    const onMouseLeave = () => {
      mouseRef.current.active = false;
      mouseRef.current.x = -9999;
      mouseRef.current.y = -9999;
    };
    const onVisibility = () => {
      running = !document.hidden;
      if (running && !rafRef.current) {
        rafRef.current = requestAnimationFrame(tick);
      }
    };

    setup();
    window.addEventListener('resize', onResize, { passive: true });
    window.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('mouseout', onMouseLeave, { passive: true });
    document.addEventListener('visibilitychange', onVisibility);

    const DAMPING = 0.965;
    const MAX_SPEED = 1.6;
    const DRIFT = 0.012;
    const repel2 = repelRadius * repelRadius;
    const link2 = linkRadius * linkRadius;

    const tick = (now) => {
      if (!running) {
        rafRef.current = null;
        return;
      }
      ctx.clearRect(0, 0, width, height);

      const m = mouseRef.current;
      const t = (now || 0) / 1000;

      // Subtle global swirl: a low-frequency drift toward the centre of mass
      // so the field doesn't slowly migrate off-screen.
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];

        // Zero-grav drift: small randomised impulse + a sinusoidal sway tied to time
        p.vx += (Math.random() - 0.5) * DRIFT + Math.sin(t * 0.4 + p.phase) * 0.0035;
        p.vy += (Math.random() - 0.5) * DRIFT + Math.cos(t * 0.35 + p.phase) * 0.0035;

        // Mouse repulsion with smooth quadratic falloff
        if (m.active) {
          const dx = p.x - m.x;
          const dy = p.y - m.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < repel2 && d2 > 0.5) {
            const dist = Math.sqrt(d2);
            const falloff = 1 - dist / repelRadius; // 0–1
            const f = falloff * falloff * repelStrength; // quadratic ease-out
            p.vx += (dx / dist) * f;
            p.vy += (dy / dist) * f;
          }
        }

        // Clamp & damp
        const sp2 = p.vx * p.vx + p.vy * p.vy;
        if (sp2 > MAX_SPEED * MAX_SPEED) {
          const sp = Math.sqrt(sp2);
          p.vx = (p.vx / sp) * MAX_SPEED;
          p.vy = (p.vy / sp) * MAX_SPEED;
        }
        p.vx *= DAMPING;
        p.vy *= DAMPING;

        p.x += p.vx;
        p.y += p.vy;

        // Wrap with a small margin so particles re-enter naturally
        if (p.x < -20) p.x = width + 20;
        else if (p.x > width + 20) p.x = -20;
        if (p.y < -20) p.y = height + 20;
        else if (p.y > height + 20) p.y = -20;
      }

      // ---- Pass 1: connection lines (drawn under particles) ----
      ctx.lineWidth = 0.6;
      for (let i = 0; i < particles.length; i++) {
        const a = particles[i];
        for (let j = i + 1; j < particles.length; j++) {
          const b = particles[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < link2) {
            const alpha = (1 - Math.sqrt(d2) / linkRadius) * 0.18;
            ctx.strokeStyle = `hsla(285, 90%, 75%, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // ---- Pass 2: particles with soft glow ----
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        const glow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.size * 6);
        glow.addColorStop(0, `hsla(${p.hue}, 95%, 80%, ${p.baseOpacity})`);
        glow.addColorStop(0.4, `hsla(${p.hue}, 95%, 65%, ${p.baseOpacity * 0.35})`);
        glow.addColorStop(1, `hsla(${p.hue}, 95%, 50%, 0)`);
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size * 6, 0, Math.PI * 2);
        ctx.fill();

        // crisp core
        ctx.fillStyle = `hsla(${p.hue}, 100%, 92%, ${Math.min(1, p.baseOpacity + 0.2)})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
      }

      // mouse velocity decay so the impulse only fires once per gesture
      m.vx *= 0.85;
      m.vy *= 0.85;

      rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);

    return () => {
      running = false;
      window.removeEventListener('resize', onResize);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseout', onMouseLeave);
      document.removeEventListener('visibilitychange', onVisibility);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    };
  }, [density, maxParticles, repelRadius, repelStrength, linkRadius]);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none print:hidden"
      style={{ zIndex: 0, mixBlendMode: 'screen' }}
      aria-hidden="true"
    />
  );
}
