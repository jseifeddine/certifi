/** @type {import('tailwindcss').Config} */
//
// Colors are CSS-variable backed so the same `bg-bg`, `text-text`, etc. classes
// produce the right colour in light or dark mode. Variables are defined in
// `src/index.css` under `:root` (light) and `:root.dark` (dark).
//
// The `rgb(var(--c-x) / <alpha-value>)` form lets Tailwind's `/15`-style alpha
// modifiers continue to work — Tailwind substitutes `<alpha-value>` with the
// value after the `/` (or `1` if none).
//
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        bg:       'rgb(var(--c-bg)        / <alpha-value>)',
        surface:  'rgb(var(--c-surface)   / <alpha-value>)',
        surface2: 'rgb(var(--c-surface2)  / <alpha-value>)',
        surface3: 'rgb(var(--c-surface3)  / <alpha-value>)',
        border:   'rgb(var(--c-border)    / <alpha-value>)',
        border2:  'rgb(var(--c-border2)   / <alpha-value>)',
        text:     'rgb(var(--c-text)      / <alpha-value>)',
        muted:    'rgb(var(--c-muted)     / <alpha-value>)',
        dim:      'rgb(var(--c-dim)       / <alpha-value>)',
        brand: {
          DEFAULT: 'rgb(var(--c-brand)       / <alpha-value>)',
          hover:   'rgb(var(--c-brand-hover) / <alpha-value>)',
        },
        ok:       'rgb(var(--c-ok)        / <alpha-value>)',
        warn:     'rgb(var(--c-warn)      / <alpha-value>)',
        danger:   'rgb(var(--c-danger)    / <alpha-value>)',
        info:     'rgb(var(--c-info)      / <alpha-value>)',
      },
      borderRadius: { DEFAULT: '8px' },
    },
  },
  plugins: [],
};
