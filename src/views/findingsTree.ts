import * as vscode from 'vscode'
import { Finding, Severity, SEVERITY_ORDER } from '../api/types'
import { ScanOutcome, summarize } from '../api/client'

// The results surface in the sidebar. Holds the outcome of every lockfile
// scanned this session and renders it as lockfile -> severity group -> finding.
//
// This provider is pure state plus rendering: it never scans anything itself, so
// the "no automatic scanning" rule still holds. extension.ts pushes results in
// via `record()`, and the tree is the only thing that reads them back.

/** One scanned lockfile and what came back for it. */
export interface ScanRecord {
  uri: vscode.Uri
  filename: string
  outcome: ScanOutcome
  at: number
}

type Node =
  | { kind: 'file'; key: string }
  | { kind: 'severity'; key: string; severity: Severity }
  | { kind: 'finding'; key: string; finding: Finding }
  | { kind: 'clean'; key: string }

/** Severity to theme color, matching the webview's severity palette. */
const SEV_COLOR: Record<Severity, string> = {
  critical: 'charts.red',
  high: 'charts.orange',
  medium: 'charts.yellow',
  low: 'charts.blue',
  unknown: 'charts.foreground',
}

export class FindingsTree implements vscode.TreeDataProvider<Node> {
  private readonly changed = new vscode.EventEmitter<Node | undefined>()
  readonly onDidChangeTreeData = this.changed.event

  /** Keyed by `uri.toString()`, so rescanning a file replaces its entry. */
  private readonly records = new Map<string, ScanRecord>()

  // ── State written by the command layer ─────────────────────────────────────
  record(uri: vscode.Uri, filename: string, outcome: ScanOutcome): void {
    this.records.set(uri.toString(), { uri, filename, outcome, at: Date.now() })
    this.changed.fire(undefined)
  }

  clear(): void {
    this.records.clear()
    this.changed.fire(undefined)
  }

  get isEmpty(): boolean {
    return this.records.size === 0
  }

  /** Every lockfile currently in the tree, oldest scan first. */
  scannedUris(): vscode.Uri[] {
    return [...this.records.values()].sort((a, b) => a.at - b.at).map((r) => r.uri)
  }

  /** Total findings across every scanned lockfile, for the view badge. */
  get totalFindings(): number {
    let n = 0
    for (const r of this.records.values()) n += r.outcome.findings.length
    return n
  }

  // ── Rendering ──────────────────────────────────────────────────────────────
  getChildren(element?: Node): Node[] {
    if (!element) {
      return [...this.records.values()]
        .sort((a, b) => b.at - a.at)
        .map((r) => ({ kind: 'file', key: r.uri.toString() }) as Node)
    }

    if (element.kind === 'file') {
      const rec = this.records.get(element.key)
      if (!rec) return []
      if (rec.outcome.findings.length === 0) return [{ kind: 'clean', key: element.key }]
      const present = new Set(rec.outcome.findings.map((f) => f.severity))
      return SEVERITY_ORDER.filter((s) => present.has(s)).map(
        (severity) => ({ kind: 'severity', key: element.key, severity }) as Node,
      )
    }

    if (element.kind === 'severity') {
      const rec = this.records.get(element.key)
      if (!rec) return []
      return rec.outcome.findings
        .filter((f) => f.severity === element.severity)
        .sort((a, b) => a.pkg.localeCompare(b.pkg) || a.cve.localeCompare(b.cve))
        .map((finding) => ({ kind: 'finding', key: element.key, finding }) as Node)
    }

    return []
  }

  getTreeItem(node: Node): vscode.TreeItem {
    const { Collapsed, Expanded, None } = vscode.TreeItemCollapsibleState

    if (node.kind === 'file') {
      const rec = this.records.get(node.key)
      const item = new vscode.TreeItem(rec?.filename ?? '(gone)', Expanded)
      if (rec) {
        item.description = summarize(rec.outcome)
        item.resourceUri = rec.uri
        item.tooltip = new vscode.MarkdownString(
          `**${rec.filename}**\n\n${summarize(rec.outcome)}\n\n${rec.outcome.deps} ` +
            `dependenc${rec.outcome.deps === 1 ? 'y' : 'ies'} scanned`,
        )
        item.iconPath = vscode.ThemeIcon.File
        item.contextValue = 'mlab.file'
        item.command = {
          command: 'vscode.open',
          title: 'Open lockfile',
          arguments: [rec.uri],
        }
      }
      return item
    }

    if (node.kind === 'clean') {
      const item = new vscode.TreeItem('No known vulnerabilities', None)
      item.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('charts.green'))
      return item
    }

    if (node.kind === 'severity') {
      const rec = this.records.get(node.key)
      const n = rec?.outcome.findings.filter((f) => f.severity === node.severity).length ?? 0
      const item = new vscode.TreeItem(node.severity, Collapsed)
      item.description = String(n)
      item.iconPath = new vscode.ThemeIcon(
        'circle-filled',
        new vscode.ThemeColor(SEV_COLOR[node.severity]),
      )
      item.contextValue = 'mlab.severity'
      return item
    }

    const f = node.finding
    const item = new vscode.TreeItem(f.cve, None)
    item.description = f.fixedVersion ? `${f.pkg} (fix: ${f.fixedVersion})` : f.pkg
    item.iconPath = new vscode.ThemeIcon(
      'shield',
      new vscode.ThemeColor(SEV_COLOR[f.severity]),
    )
    const md = new vscode.MarkdownString(
      `**${f.cve}** · ${f.severity}\n\n\`${f.pkg}\`\n\n` +
        (f.summary ? `${f.summary}\n\n` : '') +
        (f.fixedVersion ? `Fixed in \`${f.fixedVersion}\`` : 'No fixed version published'),
    )
    item.tooltip = md
    item.contextValue = f.url ? 'mlab.finding.linked' : 'mlab.finding'
    if (f.url) {
      item.command = {
        command: 'vscode.open',
        title: 'Open advisory',
        arguments: [vscode.Uri.parse(f.url)],
      }
    }
    return item
  }
}
