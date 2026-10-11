import * as vscode from 'vscode'
import { worstOf } from '../cache'
import { FindingsTree } from './findingsTree'

// Colors a lockfile in the Explorer by the worst severity its last scan found:
// red for high/critical, orange for medium, blue for low/unknown.
//
// The decoration mirrors the sidebar tree, which is rebuilt from the content
// keyed cache, so the file stays red for exactly as long as the vulnerable
// content is still on disk. Reading the tree rather than the cache means
// whatever the tree hides (ignored advisories, gitignored files, a disabled
// workspace) is not painted red either.

const BADGE: Record<string, string> = {
  critical: 'C',
  high: 'H',
  medium: 'M',
  low: 'L',
  unknown: '?',
}

export class LockfileDecorations implements vscode.FileDecorationProvider {
  private readonly changed = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>()
  readonly onDidChangeFileDecorations = this.changed.event

  constructor(private readonly tree: FindingsTree) {}

  /** Repaint one file, or everything when no uri is given. */
  refresh(uri?: vscode.Uri): void {
    this.changed.fire(uri)
  }

  provideFileDecoration(uri: vscode.Uri): vscode.FileDecoration | undefined {
    const outcome = this.tree.get(uri)?.outcome
    if (!outcome || outcome.findings.length === 0) return undefined

    const n = outcome.findings.length
    const sev = worstOf(outcome)
    return {
      badge: BADGE[sev] ?? '!',
      tooltip: `mlab: ${n} known vulnerabilit${n === 1 ? 'y' : 'ies'}, worst is ${sev}`,
      color: new vscode.ThemeColor(
        sev === 'critical' || sev === 'high'
          ? 'list.errorForeground'
          : sev === 'medium'
            ? 'list.warningForeground'
            : 'editorInfo.foreground',
      ),
      propagate: false,
    }
  }
}
