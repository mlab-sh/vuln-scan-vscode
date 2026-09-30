import * as vscode from 'vscode'
import { mlabCss } from './theme'
import { DATA_NOTICE, esc } from './reportHtml'
import { Finding } from '../api/types'
import { epssLabel } from '../api/intel'

// Detail page for one finding, opened by clicking it in the sidebar.
//
// No scripts: http links are opened externally by VS Code itself, and the one
// action back into the editor is a command URI restricted to mlab.revealFinding.

export class FindingPanel {
  private static current: vscode.WebviewPanel | undefined

  static show(extensionUri: vscode.Uri, f: Finding, lockfile?: vscode.Uri): void {
    let panel = FindingPanel.current
    if (panel) {
      panel.reveal(vscode.ViewColumn.Active)
    } else {
      panel = vscode.window.createWebviewPanel(
        'mlab.finding',
        f.cve,
        vscode.ViewColumn.Active,
        {
          enableScripts: false,
          enableCommandUris: ['mlab.revealFinding'],
          localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'resources')],
        },
      )
      panel.iconPath = vscode.Uri.joinPath(extensionUri, 'resources', 'icon.png')
      panel.onDidDispose(() => (FindingPanel.current = undefined))
      FindingPanel.current = panel
    }
    const fontsUri = panel.webview
      .asWebviewUri(vscode.Uri.joinPath(extensionUri, 'resources', 'fonts'))
      .toString()
    panel.title = f.cve
    panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; font-src ${panel.webview.cspSource}; style-src 'unsafe-inline';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${mlabCss(fontsUri)}${STYLE}</style>
</head>
<body><main>${bodyHtml(f, lockfile)}</main></body>
</html>`
  }
}

/** Where to read about this finding, best first, without duplicates. */
export function sourcesOf(f: Finding): Array<{ label: string; url: string }> {
  const out: Array<{ label: string; url: string }> = []
  const add = (label: string, url: string) => {
    if (!out.some((s) => s.url === url)) out.push({ label, url })
  }
  if (f.cve.startsWith('CVE-')) {
    add('vuln.mlab.sh', `https://vuln.mlab.sh/cve/${f.cve}`)
    add('NVD', `https://nvd.nist.gov/vuln/detail/${f.cve}`)
  }
  add('OSV', `https://osv.dev/vulnerability/${encodeURIComponent(f.cve)}`)
  for (const id of f.aliases ?? []) {
    if (id.startsWith('GHSA-')) add(id, `https://github.com/advisories/${id}`)
  }
  for (const url of f.references ?? []) add(hostOf(url), url)
  return out
}

function hostOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}

function bodyHtml(f: Finding, lockfile?: vscode.Uri): string {
  const i = f.intel
  const rows: Array<[string, string]> = [['Package', f.pkg]]
  rows.push(['Fixed in', f.fixedVersion ?? 'No fixed version published'])
  if (i?.cvssScore !== undefined) rows.push(['CVSS', `${i.cvssScore}${i.cvssSeverity ? ` (${i.cvssSeverity})` : ''}`])
  if (i?.cvssVector) rows.push(['Vector', i.cvssVector])
  const epss = i && epssLabel(i)
  if (epss) rows.push(['EPSS', `${epss} in the next 30 days`])
  if (i?.riskScore !== undefined) rows.push(['mlab risk', `${i.riskScore.toFixed(1)} / 100`])
  if (i?.weaknesses.length) rows.push(['Weaknesses', i.weaknesses.join(', ')])
  if (f.aliases?.length) rows.push(['Aliases', f.aliases.join(', ')])

  const kev =
    i && (i.inKev || i.inEuKev)
      ? `<div class="kev"><strong>Actively exploited</strong> (${i.inKev ? 'CISA' : 'EU'} known exploited catalogue${
          i.kevDateAdded ? `, added ${esc(i.kevDateAdded)}` : ''
        }${i.kevDueDate ? `, remediation due ${esc(i.kevDueDate)}` : ''})</div>`
      : ''

  const reveal = lockfile
    ? `<a class="btn" href="command:mlab.revealFinding?${encodeURIComponent(
        JSON.stringify([lockfile.toString(), f.name, f.version]),
      )}">Show in lockfile</a>`
    : ''

  return `<header class="top">
      <span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
      <h1>${esc(f.cve)}</h1>
    </header>
    ${f.summary ? `<p class="summary">${esc(f.summary)}</p>` : ''}
    ${kev}
    <div class="actions">${reveal}</div>
    <section><h3>Details</h3><table>${rows
      .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`)
      .join('')}</table></section>
    ${f.details ? `<section><h3>Description</h3><div class="details">${esc(f.details)}</div></section>` : ''}
    <section><h3>Sources</h3><ul class="sources">${sourcesOf(f)
      .map((s) => `<li><a href="${esc(s.url)}">${esc(s.label)}</a> <span class="muted">${esc(s.url)}</span></li>`)
      .join('')}</ul></section>
    <footer class="small">${DATA_NOTICE}</footer>`
}

const STYLE = `
main { padding: 22px 26px 34px; max-width: 820px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.top { display: flex; align-items: center; gap: 12px; }
h1 { font-family: var(--mlab-mono); font-size: 1.3rem; margin: 0; }
.summary { font-size: 1.02rem; margin: 0; }
.kev { padding: 11px 15px; border-radius: var(--mlab-radius-md); background: rgba(220, 38, 38, 0.12); border: 1px solid rgba(220, 38, 38, 0.28); color: var(--sev-critical); }
h3 {
  font-family: var(--mlab-mono); font-size: 0.68rem; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.06em; color: var(--vscode-descriptionForeground);
  margin: 0 0 9px; padding-bottom: 7px; border-bottom: var(--mlab-hairline);
}
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 6px 10px 6px 0; vertical-align: top; font-weight: 400; }
th { color: var(--vscode-descriptionForeground); white-space: nowrap; width: 1%; padding-right: 20px; }
td { word-break: break-word; }
tr + tr th, tr + tr td { border-top: var(--mlab-hairline); }
.details { white-space: pre-wrap; line-height: 1.5; }
.sources { list-style: none; padding: 0; margin: 0; }
.sources li { padding: 5px 0; word-break: break-all; }
.sources .muted { font-size: 0.85em; margin-left: 6px; }
.actions:empty { display: none; }
a.btn {
  display: inline-block; text-decoration: none;
  color: var(--vscode-button-foreground); background: var(--vscode-button-background);
  padding: 8px 16px; border-radius: var(--mlab-radius-sm); font-size: 0.92em; font-weight: 500;
}
a.btn:hover { background: var(--vscode-button-hoverBackground); text-decoration: none; }
footer { margin-top: 6px; padding-top: 12px; border-top: var(--mlab-hairline); }
`
