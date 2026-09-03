// Pure HTML rendering for the report panel (no `vscode` import) so it can be
// unit-tested and previewed outside the extension host. ReportPanel supplies the
// per-render nonce, the webview CSP source, and an optional logo URI.

import { Finding, Severity, SEV_RANK, SEVERITY_ORDER } from '../api/types'
import { ScanOutcome, summarize } from '../api/client'
import { MLAB_CSS } from './theme'

export interface RenderOpts {
  nonce: string
  cspSource: string
  logoUri?: string
}

export function esc(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function brand(opts: RenderOpts): string {
  const tile = opts.logoUri
    ? `<img class="tile" src="${esc(opts.logoUri)}" alt="" width="18" height="18" />`
    : `<span class="tile"></span>`
  return `<div class="brand">${tile}<span>mlab</span></div>`
}

function shell(body: string, opts: RenderOpts, script = ''): string {
  const { nonce, cspSource } = opts
  const img = cspSource ? `img-src ${cspSource};` : 'img-src data:;'
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; ${img} style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${MLAB_CSS}${STYLE}</style>
</head>
<body><main>${body}</main>${script}</body>
</html>`
}

export function loadingHtml(filename: string, opts: RenderOpts): string {
  const body = `<div class="center">
     ${brand(opts)}
     <div class="spinner"></div>
     <h2>Scanning <code>${esc(filename)}</code></h2>
     <p id="status" class="muted">Uploading the lockfile to vuln.mlab.sh and resolving CVEs.</p>
     <p class="muted small">Only this lockfile is sent, never your source code.</p>
     <button id="cancel" class="btn ghost">Cancel</button>
   </div>`
  const script = `<script nonce="${opts.nonce}">const vscode = acquireVsCodeApi();
     document.getElementById('cancel').addEventListener('click', () => {
       document.getElementById('cancel').disabled = true;
       document.getElementById('status').textContent = 'Cancelling.';
       vscode.postMessage({ type: 'cancel' });
     });</script>`
  return shell(body, opts, script)
}

export function reportHtml(filename: string, outcome: ScanOutcome, opts: RenderOpts): string {
  const { findings, unresolved, deps, truncated } = outcome
  const summary = summarize(outcome)
  const clean = findings.length === 0

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  for (const f of findings) counts[f.severity]++
  const chips = SEVERITY_ORDER.filter((s) => counts[s] > 0)
    .map((s) => `<span class="sev sev-${s}">${counts[s]} ${s}</span>`)
    .join('')

  const banners: string[] = []
  if (truncated) {
    banners.push(
      `<div class="banner warn"><span>&#9888;</span><span>This manifest exceeds the 512 package scan ceiling; only the first 512 packages were scanned.</span></div>`,
    )
  }
  if (unresolved.length) {
    banners.push(
      `<div class="banner info"><span>&#8505;</span><span>${unresolved.length} package(s) could not be resolved by the scanner (upstream) and are <strong>not</strong> counted as clean: ${esc(
        unresolved.slice(0, 20).join(', '),
      )}${unresolved.length > 20 ? '.' : ''}</span></div>`,
    )
  }

  const hero = clean
    ? `<div class="hero ok-hero">
         <div class="hero-badge ok">&#10003;</div>
         <div>
           <div class="hero-title">No known vulnerabilities</div>
           <div class="muted">${deps} dependenc${deps === 1 ? 'y' : 'ies'} scanned against vuln.mlab.sh</div>
         </div>
       </div>`
    : `<div class="hero">
         <div class="hero-num">${findings.length}</div>
         <div>
           <div class="hero-title">${esc(summary)}</div>
           <div class="chips">${chips}</div>
         </div>
       </div>`

  let table = ''
  if (!clean) {
    const rows = [...findings]
      .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.pkg.localeCompare(b.pkg))
      .map(rowHtml)
      .join('')
    table = `<div class="card"><table>
      <thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Fixed in</th><th>Summary</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`
  }

  const body = `<header class="topbar">
     ${brand(opts)}
     <code class="file">${esc(filename)}</code>
   </header>
   ${hero}
   ${banners.join('')}
   ${table}
   <footer class="muted small">${deps} dependenc${deps === 1 ? 'y' : 'ies'} scanned. Manual scan by design.</footer>`
  return shell(body, opts)
}

function rowHtml(f: Finding): string {
  const cveCell = f.url ? `<a class="mono" href="${esc(f.url)}">${esc(f.cve)}</a>` : `<span class="mono">${esc(f.cve)}</span>`
  const fixed = f.fixedVersion ? `<span class="fixpill mono">${esc(f.fixedVersion)}</span>` : '<span class="muted">none</span>'
  const summary = f.summary ? esc(f.summary) : '<span class="muted">no summary</span>'
  return `<tr>
    <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
    <td><code>${esc(f.pkg)}</code></td>
    <td>${cveCell}</td>
    <td>${fixed}</td>
    <td class="sum">${summary}</td>
  </tr>`
}

export function errorHtml(
  filename: string,
  message: string,
  kind: string | undefined,
  opts: RenderOpts,
): string {
  const isBenign = kind === 'unparseable' || kind === 'cancelled'
  const badge = isBenign ? `<div class="hero-badge info">&#8505;</div>` : `<div class="hero-badge danger">&#9888;</div>`
  const hint =
    kind === 'rate-limit'
      ? `<p class="muted">Add an API token (command <code>mlab: Manage API token &amp; quota</code>) to raise your quota to 25 scans/hour.</p>`
      : kind === 'auth'
        ? `<p class="muted">Run <code>mlab: Manage API token &amp; quota</code> to update your token.</p>`
        : kind === 'network' || kind === 'timeout'
          ? `<p class="muted">Check your connection and try again. Previous results, if any, are kept.</p>`
          : ''
  const body = `<header class="topbar">${brand(opts)}<code class="file">${esc(filename)}</code></header>
     <div class="hero">${badge}<div><div class="hero-title">${esc(message)}</div>${hint}</div></div>`
  return shell(body, opts)
}

const STYLE = `
main { padding: 20px 24px 36px; max-width: 960px; margin: 0 auto; }
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding-bottom: 12px; margin-bottom: 18px; border-bottom: var(--mlab-hairline);
}
.file { color: var(--vscode-descriptionForeground); }

.hero { display: flex; align-items: center; gap: 16px; margin: 8px 0 18px; }
.hero-num {
  font-family: var(--mlab-mono); font-size: 2.6rem; font-weight: 700; line-height: 1;
  color: var(--sev-high); min-width: 1.4ch; text-align: center;
}
.hero-title { font-size: 1.15rem; font-weight: 600; margin-bottom: 6px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.hero-badge {
  width: 44px; height: 44px; border-radius: 50%; flex: none;
  display: flex; align-items: center; justify-content: center; font-size: 1.3rem; font-weight: 700;
}
.hero-badge.ok     { color: #22c55e; background: rgba(34, 197, 94, 0.14); }
.hero-badge.info   { color: #06b6d4; background: rgba(6, 182, 212, 0.14); }
.hero-badge.danger { color: var(--sev-critical); background: rgba(220, 38, 38, 0.14); }
.ok-hero .hero-title { color: #22c55e; }

table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 10px 14px; vertical-align: top; }
thead th {
  font-family: var(--mlab-mono); font-size: 0.68rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.05em;
  color: var(--vscode-descriptionForeground);
  background: rgba(127, 127, 127, 0.05); border-bottom: var(--mlab-hairline);
}
tbody tr { border-bottom: var(--mlab-hairline); }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: rgba(var(--mlab-accent-rgb), 0.05); }
td.sum { max-width: 42ch; color: var(--vscode-descriptionForeground); }
.fixpill {
  display: inline-block; padding: 1px 8px; border-radius: var(--mlab-radius-pill);
  background: rgba(34, 197, 94, 0.14); color: #22c55e; font-size: 0.82em; font-weight: 600;
}

footer { margin-top: 22px; padding-top: 14px; border-top: var(--mlab-hairline); }

.center { text-align: center; margin-top: 12vh; display: flex; flex-direction: column; align-items: center; gap: 10px; }
.center h2 { font-weight: 600; margin: 6px 0 0; }
.center .brand { margin-bottom: 10px; opacity: 0.85; }
.err { color: var(--vscode-errorForeground); }
.spinner {
  width: 42px; height: 42px; margin: 6px auto;
  border: 3px solid rgba(var(--mlab-accent-rgb), 0.18);
  border-top-color: var(--mlab-accent);
  border-radius: 50%;
  animation: spin 0.85s cubic-bezier(0.16, 1, 0.3, 1) infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
`
