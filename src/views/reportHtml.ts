// Pure HTML rendering for the report panel (no `vscode` import) so it can be
// unit-tested and previewed outside the extension host. ReportPanel supplies the
// per-render nonce, the webview CSP source, the logo and fonts URIs.
//
// The layout mirrors the result of vuln.mlab.sh/scan: eyebrow, page title and
// meta line, a verdict card, a row of stats, then the findings table.

import { Finding, Severity, SEV_RANK, SEVERITY_ORDER } from '../api/types'
import { ScanOutcome } from '../api/client'
import { mlabCss } from './theme'
import { epssLabel, urgencyOf } from '../api/intel'

export interface RenderOpts {
  nonce: string
  cspSource: string
  logoUri?: string
  /** Webview URI of resources/fonts, for Inter and JetBrains Mono. */
  fontsUri?: string
}

export function esc(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// Lucide icons (ISC), inlined: the webview CSP allows no remote script.
const ICON = {
  octagon:
    '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
  shield:
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
  info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  triangle:
    '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
}

function icon(name: keyof typeof ICON, size = 18): string {
  return `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[name]}</svg>`
}

function brand(opts: RenderOpts): string {
  const tile = opts.logoUri
    ? `<img class="tile" src="${esc(opts.logoUri)}" alt="" width="20" height="20" />`
    : `<span class="tile"></span>`
  return `<div class="brand">${tile}<span>vuln.mlab.sh</span></div>`
}

function shell(body: string, opts: RenderOpts, script = ''): string {
  const { nonce, cspSource } = opts
  const src = cspSource ? `img-src ${cspSource}; font-src ${cspSource};` : 'img-src data:;'
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; ${src} style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${mlabCss(opts.fontsUri)}${STYLE}</style>
</head>
<body><main>${body}</main>${script}</body>
</html>`
}

function header(opts: RenderOpts, eyebrow: string, title: string, meta: string): string {
  return `<header class="top">
     <div>
       <div class="eyebrow">${esc(eyebrow)}</div>
       <h1 class="title">${title}</h1>
       <p class="meta"><span class="live-dot"></span>${meta}</p>
     </div>
     ${brand(opts)}
   </header>`
}

export function loadingHtml(filename: string, opts: RenderOpts): string {
  const body = `${header(opts, 'Lockfile scan', esc(filename), 'Resolving known vulnerabilities')}
     <div class="card loading">
       <div class="progress"><div class="bar"></div></div>
       <p id="status" class="mono muted small">Uploading the lockfile to vuln.mlab.sh and resolving CVEs.</p>
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

/** Coarse "how old is this" label, good enough for a staleness hint. */
function agoLabel(ms: number): string {
  const mins = Math.floor((Date.now() - ms) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'} ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`
  const days = Math.floor(hours / 24)
  return `${days} day${days === 1 ? '' : 's'} ago`
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`
}

function stat(n: number, label: string, tone = ''): string {
  return `<div class="stat"><span class="n${tone ? ' ' + tone : ''}">${n}</span><span class="l">${label}</span></div>`
}

export function reportHtml(
  filename: string,
  outcome: ScanOutcome,
  opts: RenderOpts,
  scannedAt?: number,
): string {
  const { findings, unresolved, deps, truncated } = outcome
  const clean = findings.length === 0

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  for (const f of findings) counts[f.severity]++
  const bySeverity = SEVERITY_ORDER.filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`)
    .join(', ')
  const vulnerable = new Set(findings.map((f) => f.pkg)).size
  const exploited = findings.filter((f) => urgencyOf(f.intel) === 'exploited')

  const when = scannedAt === undefined ? 'scanned just now' : `cached, scanned ${esc(agoLabel(scannedAt))}`
  const meta = `${plural(deps, 'dependency', 'dependencies')} · ${when}`

  const verdict = clean
    ? `<div class="verdict ok">${icon('shield', 30)}<div>
         <div class="verdict-num">No known vulnerabilities</div>
         <div class="verdict-sub">${plural(deps, 'package', 'packages')} checked, all clear</div>
       </div></div>`
    : `<div class="verdict bad">${icon('octagon', 30)}<div>
         <div class="verdict-num">${plural(vulnerable, 'vulnerable package', 'vulnerable packages')}</div>
         <div class="verdict-sub">${plural(findings.length, 'advisory', 'advisories')} across your dependencies: ${bySeverity}</div>
       </div></div>`

  const stats = `<div class="stats">
     ${stat(deps, 'Packages')}
     ${stat(vulnerable, 'Vulnerable', vulnerable ? 'bad' : '')}
     ${stat(findings.length, 'Advisories')}
     ${exploited.length ? stat(exploited.length, 'Exploited', 'bad') : ''}
     ${unresolved.length ? stat(unresolved.length, 'Not scanned', 'warn') : ''}
   </div>`

  const banners: string[] = []
  if (exploited.length) {
    const list = exploited.map((f) => esc(f.cve)).slice(0, 8).join(', ')
    banners.push(
      `<div class="banner danger">${icon('triangle')}<span><strong>${exploited.length} ` +
        `${exploited.length === 1 ? 'advisory is' : 'advisories are'} actively exploited</strong> ` +
        `according to a known exploited vulnerabilities catalogue: <span class="mono">${list}</span>` +
        `${exploited.length > 8 ? ' and more' : ''}. Treat these first, whatever their CVSS band says.</span></div>`,
    )
  }
  if (scannedAt !== undefined) {
    banners.push(
      `<div class="banner info">${icon('info')}<span>Cached result. The lockfile has not changed since it was scanned, so nothing was re-uploaded.</span></div>`,
    )
  }
  if (truncated) {
    banners.push(
      `<div class="banner warn">${icon('triangle')}<span>This manifest exceeds the 512 package scan ceiling; only the first 512 packages were scanned.</span></div>`,
    )
  }
  if (unresolved.length) {
    banners.push(
      `<div class="banner warn">${icon('info')}<span>${plural(unresolved.length, 'package', 'packages')} could not be resolved by the scanner (upstream) and ${unresolved.length === 1 ? 'is' : 'are'} <strong>not</strong> counted as clean: <span class="mono">${esc(
        unresolved.slice(0, 20).join(', '),
      )}${unresolved.length > 20 ? ', ...' : ''}</span></span></div>`,
    )
  }

  let table = ''
  if (!clean) {
    // Known exploited first: that is the only signal that says attacks are
    // actually happening, so it outranks the severity band.
    const rank = (f: Finding): number => (urgencyOf(f.intel) === 'exploited' ? 1 : 0)
    const rows = [...findings]
      .sort(
        (a, b) =>
          rank(b) - rank(a) ||
          SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
          (b.intel?.epssScore ?? 0) - (a.intel?.epssScore ?? 0) ||
          a.pkg.localeCompare(b.pkg),
      )
      .map(rowHtml)
      .join('')
    table = `<div class="card table-card"><table>
      <thead><tr><th>Package</th><th>Advisory</th><th>Severity</th><th>Exploitation</th><th>Fixed in</th><th>Summary</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`
  }

  const body = `${header(opts, 'Lockfile scan', esc(filename), meta)}
   ${verdict}
   ${stats}
   ${banners.join('')}
   ${table}
   <footer class="muted small">Only this lockfile was sent to vuln.mlab.sh, never your source code. Nothing is uploaded without your agreement.</footer>`
  return shell(body, opts)
}

/** The exploitation cell: catalogue membership first, then EPSS. */
function exploitCell(f: Finding): string {
  const intel = f.intel
  if (!intel) return '<span class="muted">n/a</span>'
  const epss = epssLabel(intel)
  const bits: string[] = []
  if (intel.inKev || intel.inEuKev) {
    const which = intel.inKev ? 'CISA KEV' : 'EU KEV'
    const since = intel.kevDateAdded ? ` since ${esc(intel.kevDateAdded)}` : ''
    bits.push(`<span class="kev" title="Actively exploited${since}">${which}</span>`)
  }
  if (epss) {
    const hot = (intel.epssScore ?? 0) >= 0.1 ? ' hot' : ''
    bits.push(`<span class="epss${hot}" title="Probability of exploitation in the next 30 days">EPSS ${epss}</span>`)
  }
  return bits.length ? bits.join(' ') : '<span class="muted">n/a</span>'
}

function rowHtml(f: Finding): string {
  const cveCell = f.url
    ? `<a class="adv" href="${esc(f.url)}">${esc(f.cve)}</a>`
    : `<span class="adv">${esc(f.cve)}</span>`
  const fixed = f.fixedVersion
    ? `<span class="fixed">&rarr; ${esc(f.fixedVersion)}</span>`
    : '<span class="muted">no fix yet</span>'
  const summary = f.summary ? esc(f.summary) : '<span class="muted">no summary</span>'
  const score =
    f.intel?.cvssScore !== undefined ? `<span class="score">${f.intel.cvssScore.toFixed(1)}</span>` : ''
  return `<tr>
    <td><span class="pkg">${esc(f.name || f.pkg)}</span>${f.version ? `<span class="ver">${esc(f.version)}</span>` : ''}</td>
    <td>${cveCell}</td>
    <td class="nowrap">${score}<span class="sev sev-${f.severity}">${f.severity}</span></td>
    <td class="nowrap">${exploitCell(f)}</td>
    <td class="nowrap">${fixed}</td>
    <td class="sum">${summary}</td>
  </tr>`
}

export function errorHtml(
  filename: string,
  message: string,
  kind: string | undefined,
  opts: RenderOpts,
): string {
  const benign = kind === 'unparseable' || kind === 'cancelled'
  const hint =
    kind === 'rate-limit'
      ? `Add an API token (command <code>mlab: Manage API token &amp; quota</code>) to raise your quota to 25 scans/hour.`
      : kind === 'auth'
        ? `Run <code>mlab: Manage API token &amp; quota</code> to update your token.`
        : kind === 'network' || kind === 'timeout'
          ? `Check your connection and try again. Previous results, if any, are kept.`
          : ''
  const body = `${header(opts, 'Lockfile scan', esc(filename), benign ? 'Scan stopped' : 'Scan failed')}
     <div class="verdict ${benign ? 'neutral' : 'bad'}">${icon(benign ? 'info' : 'octagon', 30)}<div>
       <div class="verdict-num small-num">${esc(message)}</div>
       ${hint ? `<div class="verdict-sub">${hint}</div>` : ''}
     </div></div>`
  return shell(body, opts)
}

const STYLE = `
main { padding: 28px 28px 40px; max-width: 1080px; margin: 0 auto; }

.top { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 22px; }
.title {
  font-family: var(--mlab-sans); font-weight: 800; letter-spacing: -0.035em; line-height: 1;
  font-size: clamp(1.6rem, 4vw, 2.4rem); color: var(--mlab-ink); margin: 0.45rem 0 0.7rem;
  word-break: break-all;
}
.meta {
  font-size: 0.68rem; font-weight: 500; letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--mlab-ink-3); margin: 0; line-height: 1.6;
}
.top .brand { font-size: 0.95rem; padding-top: 2px; white-space: nowrap; }

.verdict {
  display: flex; align-items: center; gap: 1rem;
  border-radius: 14px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; border: 1px solid;
}
.verdict .ico { flex: none; }
.verdict.bad     { border-color: rgba(239, 68, 68, 0.5); background: rgba(239, 68, 68, 0.06); color: var(--mlab-danger); }
.verdict.ok      { border-color: rgba(34, 197, 94, 0.5); background: rgba(34, 197, 94, 0.07); color: var(--mlab-success-fg); }
.verdict.neutral { border-color: var(--mlab-line); background: var(--mlab-card); color: var(--mlab-ink-2); }
.verdict-num { font-weight: 800; font-size: 1.75rem; line-height: 1.1; letter-spacing: -0.02em; }
.verdict-num.small-num { font-size: 1.1rem; letter-spacing: -0.01em; }
.verdict-sub { font-size: 0.85rem; opacity: 0.85; margin-top: 4px; }

.stats { display: flex; flex-wrap: wrap; gap: 1.5rem 2rem; margin: 0 0 1.25rem; }
.stat { display: flex; flex-direction: column; gap: 3px; }
.stat .n { font-weight: 800; font-size: 1.6rem; line-height: 1; color: var(--mlab-ink); letter-spacing: -0.02em; }
.stat .n.bad { color: var(--mlab-danger); }
.stat .n.warn { color: #b45309; }
body.vscode-dark .stat .n.warn, body.vscode-high-contrast .stat .n.warn { color: var(--mlab-warning); }
.stat .l { font-family: var(--mlab-mono); font-size: 0.6rem; letter-spacing: 0.16em; text-transform: uppercase; color: var(--mlab-ink-3); }

.banner .ico { flex: none; margin-top: 1px; }
.banner.danger .ico { color: var(--mlab-danger); }
.banner.warn .ico { color: var(--mlab-warning); }
.banner.info .ico { color: var(--mlab-ink-3); }

.table-card { margin-top: 1.25rem; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.825rem; }
th, td { text-align: left; padding: 0.7rem 0.85rem; vertical-align: middle; }
thead th {
  font-size: 0.8125rem; font-weight: 500; color: var(--mlab-ink-3);
  border-bottom: var(--mlab-hairline); white-space: nowrap;
}
tbody tr { border-bottom: var(--mlab-hairline); transition: background 150ms ease; }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: var(--mlab-muted-bg); }
td.nowrap { white-space: nowrap; }
td.sum { min-width: 220px; max-width: 46ch; color: var(--mlab-ink-3); }

.pkg { font-family: var(--mlab-mono); font-weight: 700; color: var(--mlab-ink); display: block; white-space: nowrap; }
.ver { font-family: var(--mlab-mono); font-size: 0.75rem; color: var(--mlab-ink-3); }
.adv { font-family: var(--mlab-mono); font-weight: 700; white-space: nowrap; }
.score { font-weight: 800; margin-right: 8px; color: var(--mlab-ink); }
.fixed { font-family: var(--mlab-mono); font-size: 0.78rem; color: var(--mlab-success-fg); }

.kev {
  display: inline-block; padding: 3px 9px; border-radius: var(--mlab-radius-pill);
  background: var(--sev-critical); color: #fff;
  font-size: 0.6rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase;
}
.epss {
  display: inline-block; padding: 2px 8px; border-radius: var(--mlab-radius-pill);
  border: 1px solid var(--mlab-line); color: var(--mlab-ink-3);
  font-family: var(--mlab-mono); font-size: 0.7rem; font-weight: 600;
}
.epss.hot { border-color: var(--sev-high); color: var(--sev-high); }

footer { margin-top: 24px; padding-top: 14px; border-top: var(--mlab-hairline); }

.loading { padding: 22px 24px; display: flex; flex-direction: column; gap: 10px; align-items: flex-start; }
.loading p { margin: 0; }
.progress { width: 100%; height: 6px; border-radius: 100px; background: var(--mlab-muted-bg); overflow: hidden; margin-bottom: 6px; }
.progress .bar {
  width: 100%; height: 100%; border-radius: 100px; background-color: var(--mlab-ink);
  background-image: linear-gradient(45deg, rgba(255,255,255,.18) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.18) 50%, rgba(255,255,255,.18) 75%, transparent 75%, transparent);
  background-size: 1rem 1rem; animation: stripes 1s linear infinite;
}
@keyframes stripes { from { background-position: 1rem 0; } to { background-position: 0 0; } }
@media (prefers-reduced-motion: reduce) { .progress .bar { animation: none; } }

@media (max-width: 560px) {
  main { padding: 20px 16px 32px; }
  .top { flex-direction: column-reverse; }
}
`
