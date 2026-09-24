import * as vscode from 'vscode'
import { mlabCss } from './theme'
import { esc } from './reportHtml'
import { IndicatorReport, worstSeverity } from '../api/indicator'
import { IndicatorKind, kindLabel } from '../ioc'

// Result panel for a single analysed indicator.
//
// Separate from the scan report: that one is about a lockfile and its findings
// over time, this one is a one shot lookup the user asked for by selecting
// something. Reusing the report panel would mean an indicator lookup wiping a
// scan report the user was still reading.

function nonce(): string {
  let s = ''
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  for (let i = 0; i < 32; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

export class IndicatorPanel {
  private static current: IndicatorPanel | undefined
  private readonly panel: vscode.WebviewPanel
  private disposed = false
  private readonly fontsUri: string

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this.panel = panel
    this.fontsUri = panel.webview
      .asWebviewUri(vscode.Uri.joinPath(extensionUri, 'resources', 'fonts'))
      .toString()
    panel.onDidDispose(() => {
      this.disposed = true
      if (IndicatorPanel.current === this) IndicatorPanel.current = undefined
    })
  }

  static show(extensionUri: vscode.Uri): IndicatorPanel {
    if (IndicatorPanel.current && !IndicatorPanel.current.disposed) {
      IndicatorPanel.current.panel.reveal(vscode.ViewColumn.Beside, true)
      return IndicatorPanel.current
    }
    const panel = vscode.window.createWebviewPanel(
      'mlab.indicator',
      'mlab indicator',
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      { enableScripts: false, localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'resources')] },
    )
    panel.iconPath = vscode.Uri.joinPath(extensionUri, 'resources', 'icon.png')
    IndicatorPanel.current = new IndicatorPanel(panel, extensionUri)
    return IndicatorPanel.current
  }

  loading(kind: IndicatorKind, value: string): void {
    if (this.disposed) return
    this.panel.title = `mlab · ${truncate(value, 30)}`
    this.render(`<div class="center">
       <div class="spinner"></div>
       <h2>Looking up this ${esc(kindLabel(kind))}</h2>
       <code class="val">${esc(truncate(value, 120))}</code>
     </div>`)
  }

  report(r: IndicatorReport): void {
    if (this.disposed) return
    this.panel.title = `mlab · ${truncate(r.value, 30)}`
    this.render(bodyHtml(r))
  }

  error(kind: IndicatorKind, value: string, message: string): void {
    if (this.disposed) return
    this.render(`<header class="top">
       <span class="kind">${esc(kindLabel(kind))}</span>
       <code class="val">${esc(truncate(value, 120))}</code>
     </header>
     <div class="verdict bad"><strong>${esc(message)}</strong></div>`)
  }

  private render(body: string): void {
    const n = nonce()
    this.panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; font-src ${this.panel.webview.cspSource}; style-src 'unsafe-inline'; script-src 'nonce-${n}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${mlabCss(this.fontsUri)}${STYLE}</style>
</head>
<body><main>${body}</main></body>
</html>`
  }
}

function truncate(v: string, n: number): string {
  return v.length <= n ? v : v.slice(0, n - 1) + '…'
}

function bodyHtml(r: IndicatorReport): string {
  const worst = worstSeverity(r.findings)

  const verdict = r.verdict
    ? `<div class="verdict ${r.verdict.tone}"><strong>${esc(r.verdict.label)}</strong></div>`
    : ''

  const findings = r.findings.length
    ? `<section><h3>Findings</h3>${r.findings
        .map(
          (f) => `<div class="finding sev-border-${esc(f.severity)}">
            <div class="fh"><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
              <span class="ft">${esc(f.title)}</span></div>
            ${f.detail ? `<p class="muted">${esc(f.detail)}</p>` : ''}
          </div>`,
        )
        .join('')}</section>`
    : `<div class="banner ok"><span>&#10003;</span><span>Nothing flagged on this ${esc(
        kindLabel(r.kind),
      )}.</span></div>`

  const facts = r.facts.length
    ? `<section><h3>Details</h3><table>${r.facts
        .map(
          (f) =>
            `<tr><th>${esc(f.label)}</th><td${f.mono ? ' class="mono"' : ''}>${esc(f.value)}</td></tr>`,
        )
        .join('')}</table></section>`
    : ''

  const headline = worst
    ? `<span class="sev sev-${esc(worst)}">${r.findings.length} finding${
        r.findings.length === 1 ? '' : 's'
      }</span>`
    : ''

  return `<header class="top">
      <span class="kind">${esc(kindLabel(r.kind))}</span>
      ${headline}
    </header>
    <code class="val big">${esc(truncate(r.value, 200))}</code>
    ${verdict}
    ${findings}
    ${facts}
    ${
      r.webUrl
        ? `<div class="actions"><a class="btn" href="${esc(r.webUrl)}">See the full scan on mlab</a></div>`
        : ''
    }
    <footer class="muted small">Looked up on the mlab platform. Only the value above was sent.</footer>`
}

const STYLE = `
main { padding: 22px 26px 34px; max-width: 760px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.top { display: flex; align-items: center; gap: 10px; }
.kind {
  font-family: var(--mlab-mono); font-size: 0.68rem; font-weight: 700;
  letter-spacing: 0.08em; text-transform: uppercase; color: var(--vscode-descriptionForeground);
}
.val { font-family: var(--mlab-mono); word-break: break-all; color: var(--vscode-foreground); }
.val.big { font-size: 1.02rem; }
h3 {
  font-family: var(--mlab-mono); font-size: 0.68rem; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.06em; color: var(--vscode-descriptionForeground);
  margin: 0 0 9px; padding-bottom: 7px; border-bottom: var(--mlab-hairline);
}
section { margin: 0; }
.verdict { padding: 11px 15px; border-radius: var(--mlab-radius-md); border: 1px solid transparent; }
.verdict.good { background: rgba(34, 197, 94, 0.12); border-color: rgba(34, 197, 94, 0.25); color: #22c55e; }
.verdict.bad { background: rgba(220, 38, 38, 0.12); border-color: rgba(220, 38, 38, 0.28); color: var(--sev-critical); }
.verdict.warn { background: rgba(217, 119, 6, 0.12); border-color: rgba(217, 119, 6, 0.28); color: var(--sev-medium); }
.verdict.neutral { background: rgba(127, 127, 127, 0.10); border-color: var(--vscode-panel-border); }
.finding { padding: 11px 0; border-bottom: var(--mlab-hairline); }
.finding:last-child { border-bottom: none; }
.fh { display: flex; align-items: center; gap: 9px; margin-bottom: 5px; flex-wrap: wrap; }
.ft { font-weight: 600; }
.finding p { margin: 0; font-size: 0.94em; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 6px 10px 6px 0; vertical-align: top; font-weight: 400; }
th { color: var(--vscode-descriptionForeground); white-space: nowrap; width: 1%; padding-right: 20px; }
td { word-break: break-all; }
tr + tr th, tr + tr td { border-top: var(--mlab-hairline); }
.actions { display: flex; gap: 8px; }
a.btn {
  display: inline-block; text-decoration: none;
  color: var(--vscode-button-foreground); background: var(--vscode-button-background);
  padding: 8px 16px; border-radius: var(--mlab-radius-sm); font-size: 0.92em; font-weight: 500;
}
a.btn:hover { background: var(--vscode-button-hoverBackground); text-decoration: none; }
footer { margin-top: 6px; padding-top: 12px; border-top: var(--mlab-hairline); }
.center { text-align: center; margin-top: 14vh; display: flex; flex-direction: column; align-items: center; gap: 10px; }
.center h2 { font-weight: 600; margin: 4px 0 0; font-size: 1.05rem; }
.spinner {
  width: 38px; height: 38px;
  border: 3px solid rgba(var(--mlab-accent-rgb), 0.18);
  border-top-color: var(--mlab-accent);
  border-radius: 50%;
  animation: spin 0.85s cubic-bezier(0.16, 1, 0.3, 1) infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
`
