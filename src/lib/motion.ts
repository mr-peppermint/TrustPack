import type { CSSProperties } from 'react';

const SEEN_KEY = 'trustpack-intro-seen';

/** Milliseconds the intro splash is fully visible, then how long it takes to fade out. */
export const INTRO_MS = 2600;
export const INTRO_EXIT_MS = 600;

export const prefersReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function shouldPlayIntro() {
  try {
    if (sessionStorage.getItem(SEEN_KEY)) return false;
    sessionStorage.setItem(SEEN_KEY, '1');
  } catch { /* storage unavailable: play it every load */ }
  return !prefersReducedMotion();
}

/** Decided once per page load (not per render) so StrictMode double-mounts agree. Plays once per browser session. */
export const playIntro = shouldPlayIntro();

/** Seconds to wait before the landing hero starts animating, so it rises as the splash fades. */
export const heroDelay = playIntro ? INTRO_MS / 1000 : 0.05;

export const after = (seconds: number): CSSProperties => ({ animationDelay: `${seconds}s` });
export const stagger = (index: number) => ({ '--i': index }) as CSSProperties;
