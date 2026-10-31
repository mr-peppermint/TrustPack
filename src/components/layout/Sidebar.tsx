import { NavLink } from 'react-router-dom';
import { History as HistoryIcon, Info, LayoutDashboard, PlusCircle, Settings as SettingsIcon, ShieldCheck, X } from 'lucide-react';

const items = [
  { to: '/', label: 'About TrustPack', icon: Info, end: true },
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard, end: false },
  { to: '/new', label: 'New Analysis', icon: PlusCircle, end: false },
  { to: '/history', label: 'Analysis History', icon: HistoryIcon, end: false },
  { to: '/settings', label: 'Settings', icon: SettingsIcon, end: false },
];

export default function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={onClose} aria-hidden />}
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-line bg-panel transition-transform lg:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-16 items-center justify-between px-5">
          <div className="flex items-center gap-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent text-on-accent">
              <ShieldCheck className="h-[18px] w-[18px]" aria-hidden />
            </span>
            <span className="font-display text-lg font-semibold tracking-tight">TrustPack</span>
          </div>
          <button type="button" className="rounded p-1 text-muted hover:text-fg lg:hidden" onClick={onClose} aria-label="Close menu">
            <X className="h-5 w-5" />
          </button>
        </div>
        <nav className="flex-1 space-y-0.5 px-3 py-2" aria-label="Main">
          {items.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${isActive ? 'bg-accent/10 font-medium text-accent' : 'text-muted hover:bg-sunken hover:text-fg'}`
              }
            >
              <Icon className="h-4 w-4" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="m-3 rounded-lg bg-sunken px-4 py-3">
          <p className="text-xs font-medium">Software supply-chain integrity</p>
          <p className="mt-0.5 text-xs text-muted">Open-source package integrity analyzer</p>
        </div>
      </aside>
    </>
  );
}
