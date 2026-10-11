// HTTP client for POST /api/v2/scan.
//
// Deliberately free of any `vscode` import so it stays unit-testable and its only
// runtime dependency is Node 18+'s global fetch. The severity/CVE/fixed-version
// normalization is ported verbatim from mlab-sh/vuln-scan-action (src/index.ts).

import { scoreOf } from './cvss'
import {
  Finding,
  OsvVuln,
  ScanRefusal,
  ScanResponse,
  ScanTier,
  ScanTruncation,
  ScanUpgrade,
  Severity,
  SEV_RANK,
} from './types'

// ── Severity model (mirrors the server's normalization) ──────────────────────
function bandFromCvss(score: number): Severity {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'unknown'
}

/**
 * Normalize an OSV vuln to one of our severity bands.
 *
 * `database_specific.severity` wins when present, which is what GitHub
 * advisories carry. Otherwise the CVSS vector is scored: OSV entries very often
 * have only that, and reading it is the difference between a real band and
 * `unknown`. See ./cvss for why the vector cannot just be parseFloat'd.
 */
export function severityOf(v: OsvVuln): Severity {
  const ds = v.database_specific?.severity?.toLowerCase()
  if (ds) return ds === 'moderate' ? 'medium' : (ds in SEV_RANK ? (ds as Severity) : 'unknown')
  for (const s of v.severity ?? []) {
    const num = scoreOf(s.score ?? '')
    if (num !== undefined) return bandFromCvss(num)
  }
  return 'unknown'
}

/**
 * The CVE an advisory is about, the way the server picks it: an alias first,
 * then `upstream` (Debian and Ubuntu records list their CVEs there, not in
 * aliases), then a CVE embedded in the id (`DEBIAN-CVE-2024-1234`). Falls back
 * to the advisory id when there is no CVE at all.
 */
export function cveOf(v: OsvVuln): string {
  for (const s of [...(v.aliases ?? []), ...(v.upstream ?? []), v.id ?? '']) {
    const m = /CVE-\d{4}-\d{4,}/i.exec(s)
    if (m) return m[0].toUpperCase()
  }
  return v.id ?? 'UNKNOWN'
}

/** Last non-empty `fixed` event across all affected ranges, if any. */
export function fixedVersionOf(v: OsvVuln): string | undefined {
  let fixed: string | undefined
  for (const a of v.affected ?? []) {
    for (const r of a.ranges ?? []) {
      for (const e of r.events ?? []) {
        if (e.fixed) fixed = e.fixed
      }
    }
  }
  return fixed
}

// ── Request / outcome contracts ──────────────────────────────────────────────
export interface ScanRequest {
  apiUrl: string
  filename: string
  format?: string
  body: Uint8Array
  token?: string
  timeoutMs: number
  /** Aborts the in-flight request when triggered (wires the Cancel button). */
  signal?: AbortSignal
}

export interface ScanOutcome {
  findings: Finding[]
  /** `name@version` of packages the scanner could not resolve (upstream). */
  unresolved: string[]
  /** Dependencies scanned by the server (after any truncation). */
  deps: number
  /** True when the manifest had more packages than the caller's tier scans. */
  truncated: boolean
  /** The server's account of the cut: counts, message, the way up. */
  truncation?: ScanTruncation
  /** Entries the server parsed but could not scan (git/path deps, …). */
  unscanned?: string[]
  tier?: ScanTier
  hash: string
}

export type ScanErrorKind =
  | 'auth'
  | 'rate-limit'
  | 'too-large'
  | 'unparseable'
  | 'timeout'
  | 'cancelled'
  | 'network'
  | 'http'
  | 'bad-response'

export class ScanError extends Error {
  constructor(
    message: string,
    readonly kind: ScanErrorKind,
    /** Seconds, for a cooldown (429). */
    readonly retryAfter?: string,
    /** What the next tier unlocks, when a limit was hit. */
    readonly upgrade?: ScanUpgrade,
  ) {
    super(message)
    this.name = 'ScanError'
  }
}

/**
 * The error for a refused scan. The server states the reason itself (cooldown,
 * size limit, unparseable manifest), so its `message` is shown as is, followed
 * by what the next tier unlocks when a limit was hit.
 */
export function errorFor(status: number, body: ScanRefusal | undefined, retryHeader: string | null, filename: string): ScanError {
  const b = body ?? {}
  const withUpgrade = (msg: string) => (b.upgrade ? `${msg} ${b.upgrade.message}` : msg)
  if (status === 401) {
    return new ScanError('Invalid or revoked API token (401). Set a new token.', 'auth')
  }
  if (status === 429) {
    const retry = b.retry_after_secs !== undefined ? String(b.retry_after_secs) : retryHeader ?? undefined
    return new ScanError(
      withUpgrade(b.message ?? `Too many scans (429).${retry ? ` Retry in ${retry} s.` : ''}`),
      'rate-limit',
      retry,
      b.upgrade,
    )
  }
  if (status === 413) {
    return new ScanError(withUpgrade(b.message ?? `${filename} is too large to scan (413).`), 'too-large', undefined, b.upgrade)
  }
  if (status === 422) {
    return new ScanError(
      `No dependencies could be parsed from ${filename} (422). Try forcing a format.`,
      'unparseable',
    )
  }
  return new ScanError(`Scan failed: HTTP ${status}${b.message ? `: ${b.message}` : '.'}`, 'http')
}

// ── Scan ─────────────────────────────────────────────────────────────────────
export async function scanLockfile(req: ScanRequest): Promise<ScanOutcome> {
  const url = new URL(req.apiUrl)
  if (req.format) url.searchParams.set('format', req.format)
  url.searchParams.set('filename', req.filename)

  const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' }
  if (req.token) headers['Authorization'] = `Bearer ${req.token}`

  const ctrl = new AbortController()
  let timedOut = false
  const onExternalAbort = () => ctrl.abort()
  if (req.signal) {
    if (req.signal.aborted) ctrl.abort()
    else req.signal.addEventListener('abort', onExternalAbort)
  }
  const timer = setTimeout(() => {
    timedOut = true
    ctrl.abort()
  }, req.timeoutMs)

  let resp: Response
  try {
    resp = await fetch(url.toString(), {
      method: 'POST',
      headers,
      // Node 18+ fetch accepts a Uint8Array body directly.
      body: req.body,
      signal: ctrl.signal,
    })
  } catch (err) {
    if (timedOut) throw new ScanError(`Scan timed out after ${req.timeoutMs} ms.`, 'timeout')
    if (ctrl.signal.aborted) throw new ScanError('Scan cancelled.', 'cancelled')
    const detail = err instanceof Error ? err.message : String(err)
    throw new ScanError(`Could not reach ${url.host}: ${detail}`, 'network')
  } finally {
    clearTimeout(timer)
    req.signal?.removeEventListener('abort', onExternalAbort)
  }

  if (!resp.ok) {
    const body = (await resp.json().catch(() => undefined)) as ScanRefusal | undefined
    throw errorFor(resp.status, body, resp.headers.get('retry-after'), req.filename)
  }

  let data: ScanResponse
  try {
    data = (await resp.json()) as ScanResponse
  } catch {
    throw new ScanError('The server returned a response that was not valid JSON.', 'bad-response')
  }

  return buildOutcome(data)
}

/** Turn the raw API response into deduplicated findings + unresolved packages. */
export function buildOutcome(data: ScanResponse): ScanOutcome {
  const findings: Finding[] = []
  const unresolved: string[] = []

  data.results.forEach((r, i) => {
    const p = data.packages?.[i]
    const name = p?.name ?? `#${i}`
    const version = p?.version ?? ''
    const pkg = p?.name ? `${p.name}@${p.version ?? ''}` : `#${i}`

    if (!r.ok) {
      unresolved.push(pkg)
      return
    }

    // The same CVE can arrive as several advisory objects (GHSA + RUSTSEC …).
    // Collapse them per CVE, keeping the highest severity and first summary/fix.
    const byCve = new Map<string, Finding>()
    for (const v of r.vulns ?? []) {
      const cve = cveOf(v)
      const severity = severityOf(v)
      const existing = byCve.get(cve)
      if (existing) {
        if (SEV_RANK[severity] > SEV_RANK[existing.severity]) existing.severity = severity
        if (!existing.summary && v.summary) existing.summary = v.summary
        if (!existing.fixedVersion) existing.fixedVersion = fixedVersionOf(v)
        if (!existing.details && v.details) existing.details = v.details
        mergeSources(existing, v)
      } else {
        byCve.set(cve, {
          pkg,
          name,
          version,
          cve,
          severity,
          summary: v.summary,
          fixedVersion: fixedVersionOf(v),
          url: cve.startsWith('CVE-') ? `https://vuln.mlab.sh/cve/${cve}` : undefined,
          details: v.details,
        })
        mergeSources(byCve.get(cve)!, v)
      }
    }
    findings.push(...byCve.values())
  })

  return {
    findings,
    unresolved,
    deps: data.count,
    truncated: data.truncated || data.truncation !== undefined,
    truncation: data.truncation,
    unscanned: data.unscanned?.length ? data.unscanned : undefined,
    tier: data.tier,
    hash: data.hash,
  }
}

/** Fold an advisory's ids and reference links into a finding, without duplicates. */
function mergeSources(f: Finding, v: OsvVuln): void {
  const ids = new Set(f.aliases)
  for (const id of [v.id, ...(v.aliases ?? [])]) if (id && id !== f.cve) ids.add(id)
  f.aliases = [...ids]
  const refs = new Set(f.references)
  for (const r of v.references ?? []) if (r.url?.startsWith('https://') || r.url?.startsWith('http://')) refs.add(r.url)
  f.references = [...refs]
}

/** Human summary line, e.g. `3 critical, 12 high across 6 packages`. */
export function summarize(outcome: ScanOutcome): string {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  for (const f of outcome.findings) counts[f.severity]++
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown']
  const parts = order.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`)
  if (parts.length === 0) return 'No known vulnerabilities found'
  const pkgs = new Set(outcome.findings.map((f) => f.pkg)).size
  return `${parts.join(', ')} across ${pkgs} package${pkgs === 1 ? '' : 's'}`
}
