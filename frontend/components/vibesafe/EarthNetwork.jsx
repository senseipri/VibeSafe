'use client';
import { useEffect, useRef, useState } from 'react';

// 26 city nodes for the network markers + arc anchors.
const NODES = [
  { name: 'SF',        lat:  37.7749, lon: -122.4194 },
  { name: 'NYC',       lat:  40.7128, lon:  -74.0060 },
  { name: 'Toronto',   lat:  43.6532, lon:  -79.3832 },
  { name: 'Mexico',    lat:  19.4326, lon:  -99.1332 },
  { name: 'Bogota',    lat:   4.7110, lon:  -74.0721 },
  { name: 'SaoPaulo',  lat: -23.5505, lon:  -46.6333 },
  { name: 'BA',        lat: -34.6037, lon:  -58.3816 },
  { name: 'London',    lat:  51.5074, lon:   -0.1278 },
  { name: 'Paris',     lat:  48.8566, lon:    2.3522 },
  { name: 'Berlin',    lat:  52.5200, lon:   13.4050 },
  { name: 'Stockholm', lat:  59.3293, lon:   18.0686 },
  { name: 'Madrid',    lat:  40.4168, lon:   -3.7038 },
  { name: 'Lisbon',    lat:  38.7223, lon:   -9.1393 },
  { name: 'Istanbul',  lat:  41.0082, lon:   28.9784 },
  { name: 'Moscow',    lat:  55.7558, lon:   37.6173 },
  { name: 'Dubai',     lat:  25.2048, lon:   55.2708 },
  { name: 'TelAviv',   lat:  32.0853, lon:   34.7818 },
  { name: 'Nairobi',   lat:  -1.2921, lon:   36.8219 },
  { name: 'CapeTown',  lat: -33.9249, lon:   18.4241 },
  { name: 'Lagos',     lat:   6.5244, lon:    3.3792 },
  { name: 'Mumbai',    lat:  19.0760, lon:   72.8777 },
  { name: 'Bangalore', lat:  12.9716, lon:   77.5946 },
  { name: 'Singapore', lat:   1.3521, lon:  103.8198 },
  { name: 'Tokyo',     lat:  35.6762, lon:  139.6503 },
  { name: 'Seoul',     lat:  37.5665, lon:  126.9780 },
  { name: 'Sydney',    lat: -33.8688, lon:  151.2093 },
];

const ARCS = [
  [0, 23], [1, 7], [7, 14], [5, 18], [23, 24],
  [11, 17], [15, 21], [0, 1], [25, 22], [2, 9],
  [9, 14], [16, 20], [7, 8], [21, 23],
];

// Fibonacci sphere — evenly distributed points on a unit sphere.
function fibSphere(n) {
  const out = [];
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < n; i++) {
    const y = 1 - (i / (n - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const t = golden * i;
    out.push({ x: Math.cos(t) * r, y, z: Math.sin(t) * r });
  }
  return out;
}

// Convert lat/lon to a unit 3-vector.
function latLonToVec(lat, lon) {
  const la = (lat * Math.PI) / 180;
  const lo = (lon * Math.PI) / 180;
  return {
    x: Math.cos(la) * Math.sin(lo),
    y: Math.sin(la),
    z: Math.cos(la) * Math.cos(lo),
  };
}

// Rotate a 3-vector around the world Y axis by phi, then tilt around X by theta.
function rotate(p, phi, tilt = 0.32) {
  const c1 = Math.cos(phi);
  const s1 = Math.sin(phi);
  const x1 = p.x * c1 + p.z * s1;
  const z1 = -p.x * s1 + p.z * c1;
  const c2 = Math.cos(tilt);
  const s2 = Math.sin(tilt);
  const y2 = p.y * c2 - z1 * s2;
  const z2 = p.y * s2 + z1 * c2;
  return { x: x1, y: y2, z: z2 };
}

const SPHERE_DOTS = fibSphere(850);
const NODE_VECS = NODES.map((n) => latLonToVec(n.lat, n.lon));

export default function EarthNetwork({ size = 600 }) {
  const svgRef = useRef(null);
  const phiRef = useRef(0);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const noMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let raf;
    let last = performance.now();
    const loop = (now) => {
      const dt = (now - last) / 1000;
      last = now;
      if (!noMotion) phiRef.current += dt * 0.25;
      setTick((t) => (t + 1) % 1e6);
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, []);

  const phi = phiRef.current;

  // Pre-compute projected positions in the [0..100] viewBox space.
  const R = 42; // sphere radius in viewBox units, centred at 50,50
  const project = (v) => {
    const r = rotate(v, phi);
    return { x: 50 + r.x * R, y: 50 - r.y * R, z: r.z };
  };

  const dots = SPHERE_DOTS.map(project);
  const nodes = NODE_VECS.map(project);

  return (
    <div
      className="relative pointer-events-none select-none"
      style={{ width: size, height: size }}
    >
      {/* Outer UV atmospheric glow */}
      <div
        className="absolute inset-[-22%] orb-pulse"
        style={{
          background:
            'radial-gradient(circle at center, rgba(138,43,226,0.42) 0%, rgba(138,43,226,0.18) 28%, transparent 65%)',
          filter: 'blur(50px)',
        }}
      />
      {/* Magenta vulnerability pulse */}
      <div
        className="absolute inset-[-8%] magenta-pulse rounded-full"
        style={{
          background:
            'radial-gradient(circle, rgba(255,0,255,0.28) 0%, rgba(255,0,255,0.10) 32%, transparent 60%)',
          filter: 'blur(28px)',
          mixBlendMode: 'screen',
        }}
      />

      {/* The globe — single SVG canvas */}
      <svg
        ref={svgRef}
        viewBox="0 0 100 100"
        preserveAspectRatio="xMidYMid meet"
        className="absolute inset-0"
        style={{ overflow: 'visible' }}
        aria-hidden="true"
      >
        <defs>
          {/* Filled sphere gradient for the dark UV ocean */}
          <radialGradient id="sphere" cx="38%" cy="32%" r="72%">
            <stop offset="0%"  stopColor="#3A1875" stopOpacity="0.95" />
            <stop offset="60%" stopColor="#180538" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#08001A" stopOpacity="0.95" />
          </radialGradient>
          {/* Bright rim around the silhouette */}
          <radialGradient id="rim" cx="50%" cy="50%" r="50%">
            <stop offset="86%" stopColor="#B967FF" stopOpacity="0" />
            <stop offset="96%" stopColor="#B967FF" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#B967FF" stopOpacity="0" />
          </radialGradient>
          {/* Animated dash for arcs */}
          <linearGradient id="arc" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0%"  stopColor="#8A2BE2" stopOpacity="0" />
            <stop offset="50%" stopColor="#FF00FF" stopOpacity="1" />
            <stop offset="100%" stopColor="#8A2BE2" stopOpacity="0" />
          </linearGradient>
          <filter id="arcGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="0.4" />
          </filter>
        </defs>

        {/* Filled sphere body */}
        <circle cx="50" cy="50" r={R} fill="url(#sphere)" />

        {/* Latitude grid lines (rings) — subtle */}
        {[-60, -30, 0, 30, 60].map((lat) => {
          const ry = Math.abs(R * Math.cos((lat * Math.PI) / 180) * Math.cos(0.32));
          const cy = 50 - R * Math.sin((lat * Math.PI) / 180) * Math.cos(0.32);
          return (
            <ellipse
              key={`lat-${lat}`}
              cx="50"
              cy={cy}
              rx={R}
              ry={ry * 0.18}
              fill="none"
              stroke="#8A2BE2"
              strokeOpacity="0.10"
              strokeWidth="0.18"
            />
          );
        })}

        {/* Sphere dots — only front-facing ones */}
        {dots.map((d, i) => {
          if (d.z < 0.02) return null;
          // Brightness based on depth (front-most are brightest)
          const alpha = 0.25 + d.z * 0.65;
          const r = 0.18 + d.z * 0.16;
          return (
            <circle
              key={`d-${i}`}
              cx={d.x}
              cy={d.y}
              r={r}
              fill="#B967FF"
              opacity={alpha}
            />
          );
        })}

        {/* Connection arcs between visible nodes */}
        <g filter="url(#arcGlow)">
          {ARCS.map(([a, b], idx) => {
            const pa = nodes[a];
            const pb = nodes[b];
            if (!pa || !pb || pa.z < 0.05 || pb.z < 0.05) return null;
            const mx = (pa.x + pb.x) / 2;
            const my = (pa.y + pb.y) / 2;
            const dx = pb.x - pa.x;
            const dy = pb.y - pa.y;
            const len = Math.hypot(dx, dy);
            const nx = -dy / (len || 1);
            const ny = dx / (len || 1);
            const sign = (mx - 50) * nx + (my - 50) * ny >= 0 ? 1 : -1;
            const lift = Math.min(18, 4 + len * 0.45);
            const cx = mx + nx * lift * sign;
            const cy = my + ny * lift * sign;
            const depth = Math.min(pa.z, pb.z);
            return (
              <path
                key={`arc-${idx}`}
                d={`M ${pa.x} ${pa.y} Q ${cx} ${cy} ${pb.x} ${pb.y}`}
                stroke="#FF00FF"
                strokeWidth="0.5"
                fill="none"
                strokeLinecap="round"
                opacity={(0.5 + depth * 0.5).toFixed(2)}
              />
            );
          })}
        </g>
        {/* Crisp arc gradient overlay */}
        {ARCS.map(([a, b], idx) => {
          const pa = nodes[a];
          const pb = nodes[b];
          if (!pa || !pb || pa.z < 0.05 || pb.z < 0.05) return null;
          const mx = (pa.x + pb.x) / 2;
          const my = (pa.y + pb.y) / 2;
          const dx = pb.x - pa.x;
          const dy = pb.y - pa.y;
          const len = Math.hypot(dx, dy);
          const nx = -dy / (len || 1);
          const ny = dx / (len || 1);
          const sign = (mx - 50) * nx + (my - 50) * ny >= 0 ? 1 : -1;
          const lift = Math.min(18, 4 + len * 0.45);
          const cx = mx + nx * lift * sign;
          const cy = my + ny * lift * sign;
          return (
            <path
              key={`arcg-${idx}`}
              d={`M ${pa.x} ${pa.y} Q ${cx} ${cy} ${pb.x} ${pb.y}`}
              stroke="url(#arc)"
              strokeWidth="0.35"
              fill="none"
              strokeLinecap="round"
            />
          );
        })}

        {/* City markers — magenta pulse + bright core */}
        {nodes.map((n, i) => {
          if (n.z < 0.05) return null;
          const alpha = 0.5 + n.z * 0.5;
          // Pulse phase derived from time + index so they don't all pulse together
          const pulse = 0.7 + 0.3 * Math.sin(tick * 0.04 + i * 0.7);
          return (
            <g key={`n-${i}`}>
              <circle cx={n.x} cy={n.y} r={2.0 * pulse} fill="#FF00FF" opacity={alpha * 0.35} />
              <circle cx={n.x} cy={n.y} r={1.0} fill="#FF00FF" opacity={alpha} />
              <circle cx={n.x} cy={n.y} r={0.5} fill="#FFFFFF" opacity={alpha} />
            </g>
          );
        })}

        {/* Outer rim glow */}
        <circle cx="50" cy="50" r={R} fill="url(#rim)" />
      </svg>

      {/* Equatorial scan ring (decorative, rotates independently) */}
      <div
        className="absolute inset-[12%] rounded-full pointer-events-none orb-rotate"
        style={{
          border: '1px dashed rgba(185,103,255,0.35)',
          transform: 'rotateX(75deg)',
        }}
      />
    </div>
  );
}
