import { Monitor, Moon, Sun } from 'lucide-react';
import { useTheme, type Theme } from '../hooks/useTheme';
import { apiConfig } from '../services/analysisService';

const THEMES: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'system', label: 'System', icon: Monitor },
];

export default function Settings() {
  const [theme, setTheme] = useTheme();
  const info: [string, string][] = [
    ['Application', 'TrustPack frontend'],
    ['Version', '0.1.0'],
    ['Data source', apiConfig.useMock ? 'Mock data' : 'Backend API'],
    ['API base URL', apiConfig.baseUrl || 'Not set'],
  ];

  return (
    <div className="max-w-xl space-y-8">
      <section className="space-y-3">
        <h2 className="font-display text-xl font-semibold tracking-tight">Theme</h2>
        <div className="grid grid-cols-3 gap-3" role="group" aria-label="Theme preference">
          {THEMES.map(({ value, label, icon: Icon }) => (
            <button key={value} type="button" aria-pressed={theme === value} onClick={() => setTheme(value)}
              className={`card flex flex-col items-center gap-2 py-4 text-sm transition-colors ${theme === value ? 'border-accent bg-accent/5 text-accent' : 'text-muted hover:text-fg'}`}>
              <Icon className="h-5 w-5" aria-hidden />{label}
            </button>
          ))}
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="font-display text-xl font-semibold tracking-tight">About</h2>
        <dl className="card divide-y divide-line text-sm">
          {info.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-4 px-4 py-3">
              <dt className="text-muted">{k}</dt>
              <dd className="break-all text-right">{v}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  );
}
