import * as vscode from 'vscode'
import { isSupportedLockfile } from './detect'
import * as config from './config'

// Watches lockfiles and asks for a rescan when their content changes.
//
// The extension's promise is that nothing is uploaded without the user's
// agreement. Auto scanning does NOT weaken that: the watcher only ever calls
// back into the normal scan path, which is gated on the one time privacy
// consent. Until that consent is given, watching produces no network traffic at
// all. `activate()` still makes zero network calls.
//
// Writes are debounced because a single `npm install` rewrites the lockfile
// several times in a row, and each real scan costs one unit of an hourly quota.

const GLOB = '**/{Cargo.lock,package-lock.json,npm-shrinkwrap.json,composer.lock,Gemfile.lock,go.sum,requirements.txt,mise.lock}'

export const DEBOUNCE_MS = 4000

export class AutoScanner {
  private watcher: vscode.FileSystemWatcher | undefined
  private readonly timers = new Map<string, NodeJS.Timeout>()
  private disposed = false

  constructor(private readonly onChanged: (uri: vscode.Uri) => void) {}

  /** Start or stop watching to match the current `autoScan` setting. */
  sync(): void {
    if (this.disposed) return
    const wanted = config.get('autoScan') === true
    if (wanted && !this.watcher) this.start()
    else if (!wanted && this.watcher) this.stop()
  }

  private start(): void {
    const w = vscode.workspace.createFileSystemWatcher(GLOB, false, false, true)
    w.onDidChange((uri) => this.schedule(uri))
    w.onDidCreate((uri) => this.schedule(uri))
    this.watcher = w
  }

  private stop(): void {
    this.watcher?.dispose()
    this.watcher = undefined
    for (const t of this.timers.values()) clearTimeout(t)
    this.timers.clear()
  }

  /** Coalesce a burst of writes to the same file into one callback. */
  private schedule(uri: vscode.Uri): void {
    if (!isSupportedLockfile(uri.fsPath)) return
    const key = uri.toString()
    const existing = this.timers.get(key)
    if (existing) clearTimeout(existing)
    this.timers.set(
      key,
      setTimeout(() => {
        this.timers.delete(key)
        if (!this.disposed) this.onChanged(uri)
      }, DEBOUNCE_MS),
    )
  }

  dispose(): void {
    this.disposed = true
    this.stop()
  }
}
