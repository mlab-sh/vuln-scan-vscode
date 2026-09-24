import { sha256Hex } from './platform'
import { ScanOutcome } from './api/client'

// Persistent scan cache, keyed by the SHA-256 of the lockfile's bytes.
//
// The point is that a lockfile's scan result is a pure function of its content:
// the same bytes always resolve to the same advisories. So we can skip the
// network entirely until the file actually changes, which is what makes auto
// scanning affordable against an 8 scans/hour anonymous quota.
//
// Two time bounds, doing different jobs. Do not confuse them:
//   - FRESHNESS (`DEFAULT_MAX_AGE_MS`) is how long a hit is trusted for. Past it
//     the lockfile is rescanned even though its bytes did not change, so a CVE
//     published in the meantime is eventually seen.
//   - RETENTION (`RETENTION_MS`) is how long an entry is kept at all. Past it the
//     entry is dropped from storage, which is what stops the cache growing
//     forever across every project ever opened.
//
// Two consequences worth stating:
//   - A cached "clean" result stays clean until the lockfile changes or its
//     freshness runs out.
//   - A cached "vulnerable" result keeps the file red until the lockfile is
//     actually edited, which is the "stays red until patched" behaviour. That
//     mark does not outlive retention: a vulnerable lockfile left untouched for
//     longer than RETENTION_MS loses its entry, and with it its mark, until it
//     is scanned again.

const STORE_KEY = 'mlab.scanCache.v1'

const DAY_MS = 24 * 60 * 60 * 1000

/** Entries older than this are re-scanned, so new advisories are eventually seen. */
export const DEFAULT_MAX_AGE_MS = 7 * DAY_MS

/** Entries older than this are dropped from storage entirely. */
export const RETENTION_MS = 30 * DAY_MS

/**
 * The slice of `vscode.Memento` this needs. Declared structurally so the module
 * has no `vscode` import and can be unit tested, the same way detect.ts and
 * api/client.ts are.
 */
export interface Store {
  get<T>(key: string, defaultValue: T): T
  update(key: string, value: unknown): Thenable<void>
}

/**
 * Keys of every entry past its retention. Pure, so the eviction rule is testable
 * without a fake editor around it.
 */
export function expiredKeys(
  entries: Record<string, CacheEntry>,
  now: number,
  retentionMs: number = RETENTION_MS,
): string[] {
  return Object.keys(entries).filter((k) => now - entries[k].at > retentionMs)
}

export interface CacheEntry {
  /** SHA-256 of the lockfile bytes at scan time. */
  hash: string
  /** The cache key (see keyOf), for the Explorer decoration and for reporting. */
  fsPath: string
  filename: string
  findingCount: number
  worstSeverity: string
  outcome: ScanOutcome
  at: number
}

export function hashOf(body: Uint8Array): Promise<string> {
  return sha256Hex(body)
}

/**
 * Cache key for a file. Local files keep their plain path, which is what every
 * existing cache already holds. Anything else (github.dev's `vscode-vfs`, ...)
 * uses the full URI, since its path alone does not say where it lives.
 */
export function keyOf(uri: { scheme: string; fsPath: string; toString(): string }): string {
  return uri.scheme === 'file' ? uri.fsPath : uri.toString()
}

export class ScanCache {
  private entries: Record<string, CacheEntry>

  constructor(private readonly memento: Store) {
    this.entries = memento.get<Record<string, CacheEntry>>(STORE_KEY, {})
  }

  /**
   * Drop everything past retention. Called when the cache is first opened and
   * after each write, so storage cannot grow without bound across projects.
   * Returns how many entries went, for the log.
   */
  async prune(now: number = Date.now()): Promise<number> {
    const gone = expiredKeys(this.entries, now)
    if (gone.length === 0) return 0
    for (const k of gone) delete this.entries[k]
    await this.memento.update(STORE_KEY, this.entries)
    return gone.length
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
    // Prune on write rather than on a timer: it keeps the bound honest without
    // any background work, and the cost is one pass over a small object.
    for (const k of expiredKeys(this.entries, Date.now())) delete this.entries[k]
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
