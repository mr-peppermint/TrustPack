import { useEffect, useState } from 'react';
import { INTRO_EXIT_MS, INTRO_MS, after, playIntro } from '../../lib/motion';

const SHIELD = 'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z';

/** Full-screen brand intro: shield draws itself, wordmark assembles, then the whole layer fades away. */
export default function IntroSplash() {
  const [phase, setPhase] = useState<'show' | 'leave' | 'gone'>(playIntro ? 'show' : 'gone');

  useEffect(() => {
    if (!playIntro) return;
    const leave = setTimeout(() => setPhase('leave'), INTRO_MS);
    const gone = setTimeout(() => setPhase('gone'), INTRO_MS + INTRO_EXIT_MS);
    return () => { clearTimeout(leave); clearTimeout(gone); };
  }, []);

  if (phase === 'gone') return null;

  return (
    <div
      aria-hidden
      className={`fixed inset-0 z-[100] flex flex-col items-center justify-center overflow-hidden bg-bg px-4 transition duration-[600ms] ease-in ${phase === 'leave' ? 'scale-105 opacity-0' : ''}`}
      style={{ transitionDuration: `${INTRO_EXIT_MS}ms` }}
    >
      <div className="page-grid animate-grid absolute inset-0" />
      <div className="absolute inset-0 m-auto h-80 w-80 animate-glow rounded-full bg-accent/10 blur-3xl" />

      <svg viewBox="0 0 24 24" className="relative h-20 w-20 text-accent sm:h-24 sm:w-24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
        <path d={SHIELD} pathLength={1} strokeDasharray={1} className="animate-draw" />
        <path d="m9 12 2 2 4-4" pathLength={1} strokeDasharray={1} className="animate-draw" style={after(0.8)} />
      </svg>

      <p className="relative mt-6 whitespace-nowrap text-center text-[2.25rem] font-display font-extrabold uppercase leading-none tracking-tight min-[400px]:text-5xl sm:text-7xl">
        {[...'TRUSTPACK'].map((ch, i) => (
          <span key={i} className={`inline-block animate-letter ${i >= 5 ? 'text-accent' : ''}`} style={after(0.5 + i * 0.07)}>{ch}</span>
        ))}
      </p>

      <p className="relative mt-4 animate-fade-in text-sm tracking-wide text-muted" style={after(1.4)}>Understand what you install.</p>
      <div className="relative mt-8 h-0.5 w-40 overflow-hidden rounded-full bg-line">
        <div className="h-full origin-left animate-bar bg-accent" style={after(0.3)} />
      </div>
    </div>
  );
}
