import { useEffect, useRef, useState, type ReactNode } from 'react';

/** Fades and lifts its children in once, the first time they scroll into view. */
export default function Reveal({ children, className = '' }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(typeof IntersectionObserver === 'undefined');

  useEffect(() => {
    const el = ref.current;
    if (shown || !el) return;
    const io = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) { setShown(true); io.disconnect(); }
    }, { threshold: 0.1 });
    io.observe(el);
    return () => io.disconnect();
  }, [shown]);

  return (
    <div ref={ref} className={`transition duration-700 ease-out ${shown ? 'translate-y-0 opacity-100' : 'translate-y-3 opacity-0'} ${className}`}>
      {children}
    </div>
  );
}
