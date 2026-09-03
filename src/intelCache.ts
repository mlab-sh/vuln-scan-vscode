import { CveIntel } from './api/intel'
import { Store } from './cache'

// Cache for CVE intelligence.
//
// CVE records move slowly: a CVSS score is stable, EPSS is recomputed daily, and
// KEV membership changes rarely. So a day of freshness is generous, and caching
// keeps a rescan of an unchanged report from re-fetching forty CVEs.
//
// Kept separate from the scan cache because it is keyed by CVE id rather than by
// file content, and it outlives any particular lockfile.

const STORE_KEY = 'mlab.cveIntel.v1'

const DAY_MS = 24 * 60 * 60 * 1000

/** How long a record is trusted. EPSS is recomputed daily upstream. */
export const INTEL_MAX_AGE_MS = DAY_MS

/** How long a record is kept at all, matching the scan cache's retention. */
export const INTEL_RETENTION_MS = 30 * DAY_MS

interface Entry {
  intel: CveIntel
  at: number
}

export class IntelCache {
  private entries: Record<string, Entry>

  constructor(private readonly memento: Store) {
    this.entries = memento.get<Record<string, Entry>>(STORE_KEY, {})
  }

  /** Fresh records only; a stale one is refetched. */
  get(id: string, now: number = Date.now()): CveIntel | undefined {
    const e = this.entries[id]
    if (!e) return undefined
    if (now - e.at > INTEL_MAX_AGE_MS) return undefined
    return e.intel
  }

  /** Split ids into what is already known and what has to be fetched. */
  partition(ids: string[], now: number = Date.now()): { known: Map<string, CveIntel>; missing: string[] } {
    const known = new Map<string, CveIntel>()
    const missing: string[] = []
    for (const id of new Set(ids)) {
      const hit = this.get(id, now)
      if (hit) known.set(id, hit)
      else missing.push(id)
    }
    return { known, missing }
  }

  async putAll(intel: Map<string, CveIntel>, now: number = Date.now()): Promise<void> {
    if (intel.size === 0) return
    for (const [id, v] of intel) this.entries[id] = { intel: v, at: now }
    this.prune(now)
    await this.memento.update(STORE_KEY, this.entries)
  }

  /** Drop records past retention, so this cache is bounded like the other one. */
  prune(now: number = Date.now()): number {
    const gone = Object.keys(this.entries).filter((k) => now - this.entries[k].at > INTEL_RETENTION_MS)
    for (const k of gone) delete this.entries[k]
    return gone.length
  }

  get size(): number {
    return Object.keys(this.entries).length
  }
}
