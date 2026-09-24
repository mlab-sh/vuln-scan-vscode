import * as vscode from 'vscode'
import { ScanCache, keyOf } from '../cache'

// Colors a lockfile in the Explorer by the worst severity its last scan found:
// red for high/critical, orange for medium, blue for low/unknown.
//
// The decoration is driven purely by the cache, and the cache is keyed by file
// content, so the file stays red for exactly as long as the vulnerable content
// is still on disk. Editing the lockfile invalidates the entry, the next scan
// repopulates it, and a clean result drops the decoration. That is the
// "stays red until it is patched" behaviour, without any polling.

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

  constructor(private readonly cache: ScanCache) {}

  /** Repaint one file, or everything when no uri is given. */
  refresh(uri?: vscode.Uri): void {
    this.changed.fire(uri)
  }

  provideFileDecoration(uri: vscode.Uri): vscode.FileDecoration | undefined {
    const entry = this.cache.peek(keyOf(uri))
    if (!entry || entry.findingCount === 0) return undefined

    const n = entry.findingCount
    const sev = entry.worstSeverity
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
