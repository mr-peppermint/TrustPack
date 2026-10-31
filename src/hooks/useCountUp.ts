import { useEffect, useState } from 'react';
import { prefersReducedMotion } from '../lib/motion';

/** Eases a number from 0 up to `target`. Jumps straight to the target when reduced motion is requested. */
export function useCountUp(target: number, ms = 900) {
  const [value, setValue] = useState(() => (prefersReducedMotion() ? target : 0));
  useEffect(() => {
    if (prefersReducedMotion()) { setValue(target); return; }
    const start = performance.now();
    let raf = requestAnimationFrame(function tick(now) {
      const t = Math.min((now - start) / ms, 1);
      setValue(Math.round(target * (1 - (1 - t) ** 3)));
      if (t < 1) raf = requestAnimationFrame(tick);
    });
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return value;
}
