
const LETTER_S = 0.75;

/** "TRUSTPACK" in bold capitals; each letter rises in turn, then drifts up and down in a loop. Only the first letter's delay is passed in. */
export default function Wordmark({ className = '', delay = 0, step = 0.06 }: { className?: string; delay?: number; step?: number }) {
  const letters = [...'TRUST'.split('').map((ch) => ({ ch, tone: '' })), ...'PACK'.split('').map((ch) => ({ ch, tone: 'text-accent' }))];
  return (
    <h2 className={`font-display font-extrabold uppercase leading-none tracking-tight ${className}`}>
      <span className="sr-only">TrustPack</span>
      <span aria-hidden className="block whitespace-nowrap">
        {letters.map(({ ch, tone }, i) => (
          <span key={i} className={`inline-block animate-letter-float ${tone}`} style={{ animationDelay: `${delay + i * step}s, ${delay + i * step + LETTER_S + i * 0.15}s` }}>{ch}</span>
        ))}
      </span>
    </h2>
  );
}
