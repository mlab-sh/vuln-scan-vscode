// Shapes of the POST /api/v2/scan response, and the normalized Finding the rest
// of the extension works with. Field names are verbatim from the live API
// (verified against https://vuln.mlab.sh/api/v2/scan) and mirror the OSV schema
// that mlab-sh/vuln-scan-action decodes.

/** One OSV vulnerability object, as returned inside `results[i].vulns[]`. */
export interface OsvVuln {
  id?: string
  aliases?: string[]
  /** CVEs a distro record (Debian, Ubuntu) is about, when `aliases` is empty. */
  upstream?: string[]
  summary?: string
  details?: string
  database_specific?: { severity?: string }
  severity?: Array<{ type?: string; score?: string }>
  references?: Array<{ type?: string; url?: string }>
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
  /** Set for an SBOM component known only by its CPE (`ecosystem` is "CPE"). */
  cpe?: string
}

/** The caller's tier: anonymous, a free account, or a paid plan. */
export type ScanTier = 'anonymous' | 'free' | 'paid'

/** Limits of a tier, as the server states them in every response. */
export interface ScanLimits {
  max_packages: number
  /** 0 means no cooldown. */
  cooldown_secs: number
  max_body_bytes: number
}

/** The next tier up and what it unlocks, sent with any limit that was hit. */
export interface ScanUpgrade extends ScanLimits {
  tier: ScanTier
  message: string
  url: string
}

/** Present when the manifest had more packages than the tier scans. */
export interface ScanTruncation {
  total_packages: number
  scanned: number
  not_scanned: number
  message: string
  upgrade?: ScanUpgrade
}

/** Full JSON body returned by POST /api/v2/scan. */
export interface ScanResponse {
  hash: string
  /** Packages scanned (after any truncation). */
  count: number
  truncated: boolean
  truncation?: ScanTruncation
  tier?: ScanTier
  limits?: ScanLimits
  /** Entries the server parsed but could not turn into a coordinate (git or path deps, unpinned requirements, SBOM components without purl or cpe). */
  unscanned?: string[]
  cached?: boolean
  logged_in?: boolean
  outage?: boolean
  ttl?: number
  packages?: ScanPackage[]
  results: ScanResult[]
}

/** Body of a refused scan: 429 (cooldown), 413 (too large), 422, 400. */
export interface ScanRefusal {
  error?: string
  message?: string
  hint?: string
  retry_after_secs?: number
  tier?: ScanTier
  limits?: ScanLimits
  upgrade?: ScanUpgrade
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
  /** Long description from the advisory. */
  details?: string
  /** Every advisory id merged into this finding (GHSA, RUSTSEC ...). */
  aliases?: string[]
  /** Source links from the advisories, deduplicated. */
  references?: string[]
}
