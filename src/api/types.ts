// Shapes of the POST /api/v2/scan response, and the normalized Finding the rest
// of the extension works with. Field names are verbatim from the live API
// (verified against https://vuln.mlab.sh/api/v2/scan) and mirror the OSV schema
// that mlab-sh/vuln-scan-action decodes.

/** One OSV vulnerability object, as returned inside `results[i].vulns[]`. */
export interface OsvVuln {
  id?: string
  aliases?: string[]
  summary?: string
  details?: string
  database_specific?: { severity?: string }
  severity?: Array<{ type?: string; score?: string }>
  affected?: Array<{
    ranges?: Array<{
      type?: string
      events?: Array<{ introduced?: string; fixed?: string }>
    }>
  }>
}

/** One entry of `results[]`, index-aligned with `packages[]`. */
export interface ScanResult {
  ok: boolean
  unqueryable?: boolean
  vulns?: OsvVuln[]
}

export interface ScanPackage {
  ecosystem?: string
  name?: string
  version?: string
}

/** Full JSON body returned by POST /api/v2/scan. */
export interface ScanResponse {
  hash: string
  count: number
  truncated: boolean
  cached?: boolean
  logged_in?: boolean
  outage?: boolean
  ttl?: number
  packages?: ScanPackage[]
  results: ScanResult[]
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

/** Severity ranking, copied from vuln-scan-action (src/index.ts `SEV_RANK`). */
export const SEV_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown']

/** A single vulnerability against a single package, ready to render. */
export interface Finding {
  /** Filled in after the scan by the CVE intelligence lookup, when available. */
  intel?: import('./intel').CveIntel
  /** `name@version`. */
  pkg: string
  name: string
  version: string
  /** CVE id when available, else the OSV advisory id. */
  cve: string
  severity: Severity
  summary?: string
  fixedVersion?: string
  /** Link to the CVE page, when `cve` is a real CVE id. */
  url?: string
}
