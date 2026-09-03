// Client for the public CVE intelligence API on vuln.mlab.sh.
//
// This is what turns a severity band into something you can actually triage.
// A critical with an EPSS of 0.0002 and no exploitation in the wild is not the
// same emergency as a high that CISA has listed as actively exploited.
//
// Three properties make this safe to call on every finding:
//   - No authentication. The endpoint is public.
//   - No scan quota.
//   - Only a CVE identifier is sent. Nothing about the user's code leaves the
//     machine, so this needs no new privacy consent.
//
// No `vscode` import, so it stays unit testable like ./client and ../detect.

/** The subset of the API record this extension uses. */
export interface CveIntel {
  id: string
  cvssScore?: number
  cvssSeverity?: string
  cvssVector?: string
  /** Probability of exploitation in the next 30 days, 0 to 1. */
  epssScore?: number
  /** Where that probability sits against every other CVE, 0 to 1. */
  epssPercentile?: number
  /** Listed in the CISA known exploited vulnerabilities catalogue. */
  inKev: boolean
  /** Listed in the EU equivalent. */
  inEuKev: boolean
  kevDateAdded?: string
  kevDueDate?: string
  /** The API's own composite score, 0 to 100. */
  riskScore?: number
  weaknesses: string[]
}

export interface IntelRequest {
  /** Origin of the mlab instance, e.g. `https://vuln.mlab.sh`. */
  origin: string
  timeoutMs: number
  signal?: AbortSignal
}

const num = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isFinite(v) ? v : undefined

const str = (v: unknown): string | undefined =>
  typeof v === 'string' && v !== '' ? v : undefined

/** Normalize one raw API record. Every field is treated as optional. */
export function parseRecord(raw: Record<string, unknown>): CveIntel | undefined {
  const id = str(raw.id)
  if (!id) return undefined
  return {
    id,
    cvssScore: num(raw.cvss_score),
    cvssSeverity: str(raw.cvss_severity)?.toLowerCase(),
    cvssVector: str(raw.cvss_vector),
    epssScore: num(raw.epss_score),
    epssPercentile: num(raw.epss_percentile),
    inKev: raw.in_kev === true,
    inEuKev: raw.in_eu_kev === true,
    kevDateAdded: str(raw.kev_date_added),
    kevDueDate: str(raw.kev_due_date),
    riskScore: num(raw.risk_score),
    weaknesses: Array.isArray(raw.weaknesses) ? raw.weaknesses.filter((w): w is string => typeof w === 'string') : [],
  }
}

/**
 * Pick the record that actually matches the id we asked for.
 *
 * The endpoint is a search, not a lookup: querying a CVE id can return related
 * records too, so position is not trustworthy.
 */
export function pickExact(id: string, records: unknown): CveIntel | undefined {
  if (!Array.isArray(records)) return undefined
  const wanted = id.toUpperCase()
  for (const r of records) {
    if (r && typeof r === 'object') {
      const parsed = parseRecord(r as Record<string, unknown>)
      if (parsed && parsed.id.toUpperCase() === wanted) return parsed
    }
  }
  return undefined
}

/** The CVE endpoint for a given mlab origin. */
export function intelUrl(origin: string, id: string): string {
  const u = new URL('/api/v1/cve', origin)
  u.searchParams.set('q', id)
  u.searchParams.set('limit', '5')
  return u.toString()
}

/**
 * Fetch intelligence for one CVE. Returns undefined rather than throwing when
 * anything goes wrong: enrichment is a bonus on top of the report, and a
 * network hiccup must never turn a successful scan into an error.
 */
export async function fetchCve(id: string, req: IntelRequest): Promise<CveIntel | undefined> {
  const ctrl = new AbortController()
  const onAbort = () => ctrl.abort()
  if (req.signal) {
    if (req.signal.aborted) return undefined
    req.signal.addEventListener('abort', onAbort, { once: true })
  }
  const timer = setTimeout(() => ctrl.abort(), req.timeoutMs)
  try {
    const resp = await fetch(intelUrl(req.origin, id), { signal: ctrl.signal })
    if (!resp.ok) return undefined
    const body = (await resp.json()) as { cves?: unknown }
    return pickExact(id, body?.cves)
  } catch {
    return undefined
  } finally {
    clearTimeout(timer)
    req.signal?.removeEventListener('abort', onAbort)
  }
}

/** How many CVE lookups run at once. Keeps a big report from opening 40 sockets. */
export const CONCURRENCY = 6

/**
 * Fetch several CVEs with a bounded number of requests in flight.
 * Ids that fail are simply absent from the result.
 */
export async function fetchMany(
  ids: string[],
  req: IntelRequest,
): Promise<Map<string, CveIntel>> {
  const out = new Map<string, CveIntel>()
  const queue = [...new Set(ids)]

  const worker = async (): Promise<void> => {
    for (;;) {
      const id = queue.shift()
      if (id === undefined) return
      if (req.signal?.aborted) return
      const intel = await fetchCve(id, req)
      if (intel) out.set(id, intel)
    }
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker))
  return out
}

// ── Presentation helpers, kept here so the report and the hover agree ────────

/** EPSS as a percentage string, e.g. `1.6%`. */
export function epssLabel(intel: CveIntel): string | undefined {
  if (intel.epssScore === undefined) return undefined
  const pct = intel.epssScore * 100
  if (pct >= 10) return `${Math.round(pct)}%`
  if (pct >= 1) return `${pct.toFixed(1)}%`
  if (pct >= 0.01) return `${pct.toFixed(2)}%`
  return '<0.01%'
}

/**
 * How loudly a finding should be flagged, beyond its severity band.
 *
 * Being in a known-exploited catalogue is the strongest signal there is: it
 * means attacks are happening, not that they are theoretically possible.
 */
export type Urgency = 'exploited' | 'likely' | 'normal'

export function urgencyOf(intel: CveIntel | undefined): Urgency {
  if (!intel) return 'normal'
  if (intel.inKev || intel.inEuKev) return 'exploited'
  if ((intel.epssScore ?? 0) >= 0.1) return 'likely'
  return 'normal'
}
