import { useLocation } from 'react-router-dom';
import { Menu } from 'lucide-react';

function titleFor(path: string) {
  if (path === '/') return 'About TrustPack';
  if (path.startsWith('/dashboard')) return 'Overview';
  if (path.startsWith('/new')) return 'New Analysis';
  if (path.startsWith('/analysis/')) return 'Analysis Results';
  if (path.startsWith('/history')) return 'Analysis History';
  if (path.startsWith('/settings')) return 'Settings';
  return 'Not found';
}

export default function Header({ onMenu }: { onMenu: () => void }) {
  const { pathname } = useLocation();
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-line/70 bg-bg/85 px-4 backdrop-blur sm:px-6 lg:px-8">
      <button type="button" className="-ml-1 rounded p-1.5 text-muted hover:text-fg lg:hidden" onClick={onMenu} aria-label="Open menu">
        <Menu className="h-5 w-5" />
      </button>
      <h1 className="font-display text-xl font-semibold tracking-tight">{titleFor(pathname)}</h1>
      <div aria-hidden className="absolute inset-x-0 -bottom-px h-0.5 origin-left bg-accent" style={{ transform: 'scaleX(var(--progress, 0))' }} />
    </header>
  );
}
