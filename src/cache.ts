import * as vscode from 'vscode'
import * as crypto from 'crypto'
import { ScanOutcome } from './api/client'

// Persistent scan cache, keyed by the SHA-256 of the lockfile's bytes.
//
// The point is that a lockfile's scan result is a pure function of its content:
// the same bytes always resolve to the same advisories. So we can skip the
// network entirely until the file actually changes, which is what makes auto
// scanning affordable against an 8 scans/hour anonymous quota.
//
// Two consequences worth stating:
//   - A cached "clean" result stays clean until the lockfile changes, even if a
//     new CVE is published upstream in the meantime. `maxAgeMs` bounds that.
//   - A cached "vulnerable" result keeps the file red until the lockfile is
//     actually edited, which is exactly the "stays red until patched" behaviour.

const STORE_KEY = 'mlab.scanCache.v1'

/** Entries older than this are re-scanned, so new advisories are eventually seen. */
export const DEFAULT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

export interface CacheEntry {
  /** SHA-256 of the lockfile bytes at scan time. */
  hash: string
  /** Absolute path, for the Explorer decoration and for reporting. */
  fsPath: string
  filename: string
  findingCount: number
  worstSeverity: string
  outcome: ScanOutcome
  at: number
}

export function hashOf(body: Uint8Array): string {
  return crypto.createHash('sha256').update(body).digest('hex')
}

export class ScanCache {
  private entries: Record<string, CacheEntry>

  constructor(private readonly memento: vscode.Memento) {
    this.entries = memento.get<Record<string, CacheEntry>>(STORE_KEY, {})
  }

  /** Cached result for this exact content, if fresh enough. */
  lookup(fsPath: string, hash: string, maxAgeMs = DEFAULT_MAX_AGE_MS): CacheEntry | undefined {
    const e = this.entries[fsPath]
    if (!e || e.hash !== hash) return undefined
    if (Date.now() - e.at > maxAgeMs) return undefined
    return e
  }

  /** Whatever we last knew about this path, regardless of the current content. */
  peek(fsPath: string): CacheEntry | undefined {
    return this.entries[fsPath]
  }

  async put(
    fsPath: string,
    filename: string,
    hash: string,
    outcome: ScanOutcome,
  ): Promise<CacheEntry> {
    const worst = worstOf(outcome)
    const entry: CacheEntry = {
      hash,
      fsPath,
      filename,
      findingCount: outcome.findings.length,
      worstSeverity: worst,
      outcome,
      at: Date.now(),
    }
    this.entries[fsPath] = entry
    await this.memento.update(STORE_KEY, this.entries)
    return entry
  }

  async forget(fsPath: string): Promise<void> {
    if (!(fsPath in this.entries)) return
    delete this.entries[fsPath]
    await this.memento.update(STORE_KEY, this.entries)
  }

  async clearAll(): Promise<void> {
    this.entries = {}
    await this.memento.update(STORE_KEY, this.entries)
  }

  /** Every path we hold a result for. */
  paths(): string[] {
    return Object.keys(this.entries)
  }
}

const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }

/** Highest severity present in an outcome, or 'none' when it is clean. */
export function worstOf(outcome: ScanOutcome): string {
  let worst = 'none'
  let best = -1
  for (const f of outcome.findings) {
    const r = RANK[f.severity] ?? 0
    if (r > best) {
      best = r
      worst = f.severity
    }
  }
  return worst
}
