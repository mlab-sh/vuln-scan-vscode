// Shared mlab design language for the webviews, aligned on vuln.mlab.sh
// (assets/css/mlab-custom.css): same surfaces, ink tones, hairlines, amber
// accent, charcoal primary buttons, Inter and JetBrains Mono. Light or dark
// follows the VS Code theme through the body class VS Code sets on webviews.
//
// Note: no em dashes anywhere in emitted UI text, by project rule.

/** Severity colors, verbatim from the site's SEVCOLOR map (/me/sbom). */
export const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
  unknown: '#9ca3af',
}

/**
 * The shared stylesheet. `fontsUri` is the webview URI of resources/fonts;
 * without it the system fallbacks are used (tests, previews).
 */
export function mlabCss(fontsUri?: string): string {
  const fonts = fontsUri
    ? `@font-face { font-family: 'Inter'; font-weight: 100 900; font-display: swap; src: url('${fontsUri}/inter-latin.woff2') format('woff2'); }
@font-face { font-family: 'JetBrains Mono'; font-weight: 100 800; font-display: swap; src: url('${fontsUri}/jetbrains-mono-latin.woff2') format('woff2'); }
`
    : ''
  return fonts + MLAB_CSS
}

const MLAB_CSS = `
:root {
  --mlab-accent: #d97706;
  --mlab-accent-rgb: 217, 119, 6;
  --mlab-tint-rgb: 62, 96, 213;

  --mlab-radius-xs: 6px;
  --mlab-radius-sm: 8px;
  --mlab-radius-md: 12px;
  --mlab-radius-lg: 16px;
  --mlab-radius-pill: 100px;

  --mlab-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
  --mlab-sans: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;

  --sev-critical: #dc2626;
  --sev-high: #ea580c;
  --sev-medium: #d97706;
  --sev-low: #2563eb;
  --sev-unknown: #9ca3af;

  --mlab-success: #22c55e;
  --mlab-danger: #ef4444;
  --mlab-info: #06b6d4;
  --mlab-warning: #f59e0b;

  /* Light, the site's :root */
  --mlab-canvas: #f4f5f7;
  --mlab-card: #ffffff;
  --mlab-muted-bg: #eef1f5;
  --mlab-ink: #0a0a0a;
  --mlab-ink-2: #111827;
  --mlab-ink-3: #6b7280;
  --mlab-line: rgba(15, 23, 42, 0.08);
  --mlab-primary: #0a0a0a;
  --mlab-primary-fg: #ffffff;
  --mlab-success-fg: #15803d;
  --mlab-danger-fg: #b91c1c;
  --mlab-shadow: 0 8px 24px rgba(var(--mlab-tint-rgb), 0.08), 0 2px 6px rgba(17, 24, 39, 0.05);
  --mlab-hairline: 1px solid var(--mlab-line);
}

/* Dark, the site's html[data-bs-theme=dark] */
body.vscode-dark, body.vscode-high-contrast {
  --mlab-canvas: #050506;
  --mlab-card: #121316;
  --mlab-muted-bg: #202329;
  --mlab-ink: #f8fafc;
  --mlab-ink-2: #f8fafc;
  --mlab-ink-3: #8b9099;
  --mlab-line: rgba(255, 255, 255, 0.08);
  --mlab-primary: #fafafa;
  --mlab-primary-fg: #0a0a0a;
  --mlab-success-fg: #4ade80;
  --mlab-danger-fg: #f87171;
  --mlab-shadow: 0 10px 30px rgba(0, 0, 0, 0.40), 0 2px 6px rgba(0, 0, 0, 0.35);
}

* { box-sizing: border-box; }

body {
  font-family: var(--mlab-sans);
  font-feature-settings: 'cv11', 'ss01';
  font-size: 14px;
  color: var(--mlab-ink-2);
  background: var(--mlab-canvas);
  line-height: 1.55;
  margin: 0;
  min-height: 100vh;
}

code, .mono { font-family: var(--mlab-mono); font-feature-settings: 'zero', 'ss01'; font-size: 0.92em; }
a { color: var(--mlab-ink); text-decoration: underline; text-decoration-color: var(--mlab-line); text-underline-offset: 3px; }
a:hover { text-decoration-color: var(--mlab-accent); }
:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(var(--mlab-accent-rgb), 0.40); border-radius: 6px; }

.muted { color: var(--mlab-ink-3); }
.small { font-size: 0.85em; }

/* Wordmark: the mlab logo tile + name, as in the site header. */
.brand { display: flex; align-items: center; gap: 8px; font-weight: 800; letter-spacing: -0.02em; color: var(--mlab-ink); }
.brand .tile {
  width: 20px; height: 20px; border-radius: 6px; flex: none;
  background: var(--mlab-ink);
  -webkit-mask: repeating-linear-gradient(-45deg, #000 0 3px, transparent 3px 6px);
  mask: repeating-linear-gradient(-45deg, #000 0 3px, transparent 3px 6px);
}
.brand img.tile { -webkit-mask: none; mask: none; background: none; }

/* Section eyebrow: uppercase micro label behind a short amber bar. */
.eyebrow {
  display: inline-flex; align-items: center; gap: 0.7rem;
  font-size: 0.68rem; font-weight: 500; letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--mlab-ink-3);
}
.eyebrow::before { content: ""; width: 24px; height: 2px; border-radius: 2px; background: var(--mlab-accent); }

/* The pulsing amber dot of .mlab-page-meta. */
.live-dot {
  display: inline-block; width: 7px; height: 7px; border-radius: 50%; flex: none;
  background: var(--mlab-accent); box-shadow: 0 0 0 3px rgba(var(--mlab-accent-rgb), 0.15);
  vertical-align: middle; margin-right: 0.5rem;
}

/* Severity pill with a leading dot, colored from SEVCOLOR. */
.sev {
  display: inline-flex; align-items: center; gap: 6px;
  font-family: var(--mlab-sans);
  font-size: 0.62rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase;
  padding: 3px 10px 3px 8px; border-radius: var(--mlab-radius-pill);
  border: 1px solid currentColor;
  white-space: nowrap;
}
.sev::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.sev-critical { color: var(--sev-critical); background: rgba(220, 38, 38, 0.08); }
.sev-high     { color: var(--sev-high);     background: rgba(234, 88, 12, 0.08); }
.sev-medium   { color: var(--sev-medium);   background: rgba(217, 119, 6, 0.08); }
.sev-low      { color: var(--sev-low);      background: rgba(37, 99, 235, 0.08); }
.sev-unknown  { color: var(--sev-unknown);  background: rgba(156, 163, 175, 0.10); }

/* Buttons: charcoal primary (inverted in dark), hairline ghost. */
.btn {
  font-family: var(--mlab-sans); font-size: 0.85rem; font-weight: 500;
  padding: 7px 16px; border: 1px solid transparent; border-radius: var(--mlab-radius-sm); cursor: pointer;
  color: var(--mlab-primary-fg); background: var(--mlab-primary);
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}
.btn:hover { opacity: 0.88; }
.btn:active { transform: translateY(1px); }
.btn:disabled { opacity: 0.5; cursor: default; }
.btn.ghost { color: var(--mlab-ink); background: transparent; border-color: var(--mlab-line); }
.btn.ghost:hover { opacity: 1; background: var(--mlab-muted-bg); }

/* Cards & banners */
.card {
  background: var(--mlab-card);
  border: var(--mlab-hairline); border-radius: var(--mlab-radius-md);
  box-shadow: var(--mlab-shadow); overflow: hidden;
}
.banner {
  display: flex; gap: 10px; align-items: flex-start;
  padding: 12px 16px; border-radius: var(--mlab-radius-md); margin: 12px 0;
  border: 1px solid transparent; font-size: 0.85rem;
}
.banner.warn   { background: rgba(245, 158, 11, 0.10); border-color: rgba(245, 158, 11, 0.30); }
.banner.info   { background: var(--mlab-card); border-color: var(--mlab-line); }
.banner.ok     { background: rgba(34, 197, 94, 0.10); border-color: rgba(34, 197, 94, 0.30); }
.banner.danger { background: rgba(239, 68, 68, 0.06); border-color: rgba(239, 68, 68, 0.50); }
`
