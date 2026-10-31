import { useEffect, useState } from 'react';

export type Theme = 'dark' | 'light' | 'system';
const KEY = 'trustpack-theme';
const query = '(prefers-color-scheme: dark)';

export function getStoredTheme(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'dark' || v === 'light' || v === 'system') return v;
  } catch { /* storage unavailable */ }
  return 'dark';
}

export function applyTheme(theme: Theme) {
  const dark = theme === 'dark' || (theme === 'system' && window.matchMedia(query).matches);
  document.documentElement.classList.toggle('dark', dark);
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(getStoredTheme);
  useEffect(() => {
    applyTheme(theme);
    try { localStorage.setItem(KEY, theme); } catch { /* ignore */ }
    if (theme !== 'system') return;
    const mq = window.matchMedia(query);
    const onChange = () => applyTheme('system');
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [theme]);
  return [theme, setTheme] as const;
}
