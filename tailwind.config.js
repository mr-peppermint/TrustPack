const c = (name) => `rgb(var(--${name}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: { bg: c('bg'), panel: c('panel'), sunken: c('sunken'), accent: c('accent'), 'on-accent': c('on-accent'), line: c('line'), fg: c('fg'), muted: c('muted'), ok: c('ok'), warn: c('warn'), risk: c('risk') },
      fontFamily: {
        sans: ['Geist', 'system-ui', 'sans-serif'],
        display: ['"Source Serif 4"', 'Georgia', 'serif'],
        mono: ['"Geist Mono"', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
};
