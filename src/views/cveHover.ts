import * as vscode from 'vscode'
import { CveIntel, epssLabel, fetchCve } from '../api/intel'
import { IntelCache } from '../intelCache'
import * as config from '../config'

// Hovering a CVE identifier anywhere shows what it actually means: CVSS, how
// likely it is to be exploited, whether it is being exploited right now, and the
// weaknesses behind it.
//
// This works on any file, not just lockfiles: CVE ids turn up in comments,
// changelogs, tickets pasted into code and dependency notes.
//
// Only the identifier is sent, and only for an id the user hovered. Nothing
// about the surrounding code leaves the machine, which is why this needs no
// privacy consent of its own. Lookups are cached for a day.

/** A CVE id, as it appears in text. */
export const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/i

export class CveHover implements vscode.HoverProvider {
  constructor(private readonly intelCache: IntelCache) {}

  async provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    token: vscode.CancellationToken,
  ): Promise<vscode.Hover | undefined> {
    if (config.get('cveHover') !== true) return undefined
    // Hovering triggers a request, so Restricted Mode stays quiet.
    if (!vscode.workspace.isTrusted) return undefined

    const range = document.getWordRangeAtPosition(position, new RegExp(CVE_PATTERN, 'i'))
    if (!range) return undefined
    const id = document.getText(range).toUpperCase()

    const intel = await this.lookup(id, token)
    if (!intel || token.isCancellationRequested) return undefined
    return new vscode.Hover(markdown(intel), range)
  }

  private async lookup(
    id: string,
    token: vscode.CancellationToken,
  ): Promise<CveIntel | undefined> {
    const cached = this.intelCache.get(id)
    if (cached) return cached

    const ctrl = new AbortController()
    token.onCancellationRequested(() => ctrl.abort())
    const intel = await fetchCve(id, {
      origin: new URL(config.get('apiUrl')).origin,
      // Short: a hover that takes five seconds is worse than no hover.
      timeoutMs: 4000,
      signal: ctrl.signal,
    })
    if (intel) await this.intelCache.putAll(new Map([[id, intel]]))
    return intel
  }
}

/** Render the hover card. Exported so its shape can be unit tested. */
export function markdown(intel: CveIntel): vscode.MarkdownString {
  const md = new vscode.MarkdownString()
  md.supportHtml = false

  const sev = intel.cvssSeverity ? intel.cvssSeverity.toUpperCase() : 'unrated'
  const score = intel.cvssScore !== undefined ? ` ${intel.cvssScore}` : ''
  md.appendMarkdown(`**${intel.id}** ${sev}${score}\n\n`)

  if (intel.inKev || intel.inEuKev) {
    const which = intel.inKev ? 'CISA' : 'EU'
    const since = intel.kevDateAdded ? `, added ${intel.kevDateAdded}` : ''
    const due = intel.kevDueDate ? `, remediation due ${intel.kevDueDate}` : ''
    md.appendMarkdown(`⚠ **Actively exploited** (${which} known exploited catalogue${since}${due})\n\n`)
  }

  const rows: string[] = []
  const epss = epssLabel(intel)
  if (epss) {
    const pct =
      intel.epssPercentile !== undefined
        ? ` (higher than ${Math.round(intel.epssPercentile * 100)}% of all CVEs)`
        : ''
    rows.push(`Exploitation likelihood: **${epss}** in the next 30 days${pct}`)
  }
  if (intel.riskScore !== undefined) rows.push(`mlab risk score: **${intel.riskScore.toFixed(1)}** / 100`)
  if (intel.weaknesses.length) rows.push(`Weaknesses: ${intel.weaknesses.join(', ')}`)
  if (intel.cvssVector) rows.push(`\`${intel.cvssVector}\``)
  if (rows.length) md.appendMarkdown(rows.join('\n\n') + '\n\n')

  md.appendMarkdown(`[Open on vuln.mlab.sh](https://vuln.mlab.sh/cve/${intel.id})`)
  return md
}
