import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { prefersReducedMotion } from '../../lib/motion';

/**
 * Landing-area backdrop, anchored at the corner formed by the sidebar and header (grid lines start on their borders): grid, cursor-lit grid and corner glow cover the first screen of the landing page
 * and scroll away with it (other routes get none). A rAF-throttled listener publishes scroll progress and pointer
 * position as CSS variables on <html>, so the cursor-lit grid and header progress bar update without re-rendering.
 */
export default function PageBackdrop() {
  const landing = useLocation().pathname === '/';
  const backdrop = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (prefersReducedMotion()) return;
    const root = document.documentElement;
    let raf = 0;
    let px = -9999, py = -9999;

    const flush = () => {
      raf = 0;
      const max = root.scrollHeight - window.innerHeight;
      root.style.setProperty('--progress', max > 0 ? String(Math.min(1, window.scrollY / max)) : '0');
      // Pointer relative to the backdrop's own box, which scrolls with the page.
      const box = backdrop.current?.getBoundingClientRect();
      root.style.setProperty('--mx', `${px - (box?.left ?? 0)}px`);
      root.style.setProperty('--my', `${py - (box?.top ?? 0)}px`);
    };
    const schedule = () => { if (!raf) raf = requestAnimationFrame(flush); };
    const onMove = (e: PointerEvent) => {
      px = e.clientX; py = e.clientY;
      schedule();
    };

    flush();
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    window.addEventListener('pointermove', onMove, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      window.removeEventListener('pointermove', onMove);
    };
  }, []);

  if (!landing) return null;

  return (
    <div ref={backdrop} aria-hidden className="landing-backdrop pointer-events-none absolute inset-x-0 top-16 -z-10 h-[max(100vh,640px)] lg:left-64">
      <div className="page-grid absolute inset-0" />
      <div className="page-grid page-grid-lit absolute inset-0" />
      <div className="absolute -left-24 -top-12 h-96 w-96">
        <div className="h-full w-full animate-glow rounded-full bg-accent/10 blur-3xl" />
      </div>
    </div>
  );
}
