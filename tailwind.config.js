const c = (name) => `rgb(var(--${name}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: { bg: c('bg'), panel: c('panel'), sunken: c('sunken'), accent: c('accent'), emphasis: c('emphasis'), secondary: c('secondary'), 'on-accent': c('on-accent'), line: c('line'), fg: c('fg'), muted: c('muted'), ok: c('ok'), warn: c('warn'), risk: c('risk') },
      keyframes: {
        rise: { from: { opacity: '0', transform: 'translateY(18px)' }, to: { opacity: '1', transform: 'none' } },
        letter: { from: { opacity: '0', transform: 'translateY(0.45em) scale(0.92)', filter: 'blur(10px)' }, to: { opacity: '1', transform: 'none', filter: 'blur(0)' } },
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        draw: { from: { strokeDashoffset: '1' }, to: { strokeDashoffset: '0' } },
        glow: { '0%, 100%': { opacity: '0.5', transform: 'scale(1)' }, '50%': { opacity: '1', transform: 'scale(1.18)' } },
        grid: { from: { backgroundPosition: '0 0' }, to: { backgroundPosition: '44px 44px' } },
        float: { '0%, 100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(-0.08em)' } },
        bar: { from: { transform: 'scaleX(0)' }, to: { transform: 'scaleX(1)' } },
      },
      animation: {
        rise: 'rise 0.7s cubic-bezier(0.2, 0.7, 0.2, 1) both',
        letter: 'letter 0.75s cubic-bezier(0.2, 0.7, 0.2, 1) both',
        'letter-float': 'letter 0.75s cubic-bezier(0.2, 0.7, 0.2, 1) both, float 4.5s ease-in-out infinite',
        'fade-in': 'fade-in 0.5s ease-out both',
        draw: 'draw 0.9s ease-in-out both',
        glow: 'glow 6s ease-in-out infinite',
        grid: 'grid 5s linear infinite',
        float: 'float 4.5s ease-in-out infinite',
        bar: 'bar 2s cubic-bezier(0.65, 0, 0.35, 1) both',
      },
      fontFamily: {
        sans: ['Geist', 'system-ui', 'sans-serif'],
        display: ['Exo', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono"', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
};
