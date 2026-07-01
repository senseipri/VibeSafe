const ITEMS = [
  '35 CVEs from AI code in March 2026',
  '45% of vibe-coded apps have OWASP Top 10 vulnerabilities',
  'Moltbook breach: 1.5M API tokens exposed',
  '322% rise in privilege escalation flaws',
  'AI generates 46% of all new GitHub code',
  '20% of AI-suggested packages don\u2019t exist — slopsquatting risk',
];

export default function CrisisMarquee() {
  const all = [...ITEMS, ...ITEMS];
  return (
    <div className="relative border-y border-[#1F1F3D] bg-[#070716] overflow-hidden">
      <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#8A2BE2]" />
      <div className="absolute left-0 top-0 bottom-0 w-32 bg-gradient-to-r from-[#070716] to-transparent z-10 pointer-events-none" />
      <div className="absolute right-0 top-0 bottom-0 w-32 bg-gradient-to-l from-[#070716] to-transparent z-10 pointer-events-none" />
      <div className="py-3.5 flex whitespace-nowrap">
        <div className="marquee-track flex shrink-0 gap-10">
          {all.map((t, i) => (
            <span
              key={i}
              className="font-mono text-[11.5px] uppercase tracking-[0.12em] text-[#A0A0A0] flex items-center gap-10"
            >
              {t}
              <span className="text-[#8A2BE2]">·</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
