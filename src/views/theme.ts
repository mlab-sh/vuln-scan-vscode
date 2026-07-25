// Shared mlab design language for the webviews. Distilled from the real
// vuln.mlab.sh design system (assets/css/mlab-custom.css), not cloned: brand
// accent blue, the exact severity palette, pill badges with a leading colored
// dot, a radius/shadow scale, and mono-for-code typography. Everything is layered
// on top of VS Code theme variables so it still feels native in the editor.
//
// Note: no em dashes anywhere in emitted UI text, by project rule.

/** Severity colors, verbatim from the site's SEVCOLOR map. */
export const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
  unknown: '#9ca3af',
}

export const MLAB_CSS = `
:root {
  --mlab-accent: #3e60d5;
  --mlab-accent-rgb: 62, 96, 213;

  --mlab-radius-sm: 8px;
  --mlab-radius-md: 12px;
  --mlab-radius-lg: 16px;
  --mlab-radius-pill: 100px;

  --mlab-mono: var(--vscode-editor-font-family, 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace);
  --mlab-sans: var(--vscode-font-family, 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif);

  --sev-critical: #dc2626;
  --sev-high: #ea580c;
  --sev-medium: #d97706;
  --sev-low: #2563eb;
  --sev-unknown: #9ca3af;

  --mlab-shadow: 0 8px 24px rgba(var(--mlab-accent-rgb), 0.10), 0 2px 6px rgba(17, 24, 39, 0.06);
  --mlab-hairline: 1px solid var(--vscode-panel-border);
}

* { box-sizing: border-box; }

body {
  font-family: var(--mlab-sans);
  font-size: var(--vscode-font-size);
  color: var(--vscode-foreground);
  line-height: 1.55;
  margin: 0;
}

code, .mono { font-family: var(--mlab-mono); font-size: 0.92em; }
a { color: var(--mlab-accent); text-decoration: none; }
a:hover { text-decoration: underline; }
:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(var(--mlab-accent-rgb), 0.35); border-radius: 6px; }

.muted { color: var(--vscode-descriptionForeground); }
.small { font-size: 0.85em; }

/* Wordmark: a small brand tile + name, echoing the mlab mark. */
.brand { display: flex; align-items: center; gap: 8px; font-weight: 600; letter-spacing: -0.01em; }
.brand .tile {
  width: 18px; height: 18px; border-radius: 5px; flex: none;
  background: var(--vscode-foreground);
  -webkit-mask: repeating-linear-gradient(-45deg, #000 0 3px, transparent 3px 6px);
  mask: repeating-linear-gradient(-45deg, #000 0 3px, transparent 3px 6px);
}
.brand img.tile { -webkit-mask: none; mask: none; background: none; border-radius: 5px; }

/* Severity pill with the signature leading dot (mlab .badge::before). */
.sev {
  display: inline-flex; align-items: center; gap: 7px;
  font-family: var(--mlab-mono);
  font-size: 0.7rem; font-weight: 600; letter-spacing: 0.03em; text-transform: uppercase;
  padding: 2px 11px 2px 9px; border-radius: var(--mlab-radius-pill);
  white-space: nowrap;
}
.sev::before {
  content: ""; width: 6px; height: 6px; border-radius: 50%;
  background: currentColor; box-shadow: 0 0 0 3px rgba(127, 127, 127, 0.001);
  filter: drop-shadow(0 0 3px currentColor);
}
.sev-critical { color: var(--sev-critical); background: rgba(220, 38, 38, 0.12); }
.sev-high     { color: var(--sev-high);     background: rgba(234, 88, 12, 0.12); }
.sev-medium   { color: var(--sev-medium);   background: rgba(217, 119, 6, 0.12); }
.sev-low      { color: var(--sev-low);      background: rgba(37, 99, 235, 0.12); }
.sev-unknown  { color: var(--sev-unknown);  background: rgba(156, 163, 175, 0.16); }

/* Buttons */
.btn {
  font-family: var(--mlab-sans); font-size: 0.92em; font-weight: 500;
  padding: 7px 16px; border: none; border-radius: var(--mlab-radius-sm); cursor: pointer;
  color: var(--vscode-button-foreground); background: var(--vscode-button-background);
  transition: background 150ms ease, transform 150ms ease;
}
.btn:hover { background: var(--vscode-button-hoverBackground); }
.btn:active { transform: translateY(1px); }
.btn:disabled { opacity: 0.5; cursor: default; }
.btn.ghost {
  color: var(--vscode-foreground);
  background: transparent; border: var(--mlab-hairline);
}
.btn.ghost:hover { background: rgba(127, 127, 127, 0.08); }

/* Cards & banners */
.card {
  border: var(--mlab-hairline); border-radius: var(--mlab-radius-md);
  box-shadow: var(--mlab-shadow); overflow: hidden;
}
.banner {
  display: flex; gap: 8px; align-items: flex-start;
  padding: 10px 14px; border-radius: var(--mlab-radius-md); margin: 12px 0;
  border: 1px solid transparent;
}
.banner.warn { background: rgba(245, 158, 11, 0.12); border-color: rgba(245, 158, 11, 0.25); }
.banner.info { background: rgba(6, 182, 212, 0.12); border-color: rgba(6, 182, 212, 0.25); }
.banner.ok   { background: rgba(34, 197, 94, 0.12); border-color: rgba(34, 197, 94, 0.25); }
`
