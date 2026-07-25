// HTTP client for POST /api/v2/scan.
//
// Deliberately free of any `vscode` import so it stays unit-testable and its only
// runtime dependency is Node 18+'s global fetch. The severity/CVE/fixed-version
// normalization is ported verbatim from mlab-sh/vuln-scan-action (src/index.ts).

import {
  Finding,
  OsvVuln,
  ScanResponse,
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

/** Normalize an OSV vuln to one of our severity bands (vuln-scan-action logic). */
export function severityOf(v: OsvVuln): Severity {
  const ds = v.database_specific?.severity?.toLowerCase()
  if (ds) return ds === 'moderate' ? 'medium' : (ds in SEV_RANK ? (ds as Severity) : 'unknown')
  for (const s of v.severity ?? []) {
    const raw = s.score ?? ''
    const num = parseFloat(raw.includes('/') ? raw.split('/').pop()! : raw)
    if (!Number.isNaN(num)) return bandFromCvss(num)
  }
  return 'unknown'
}

/** Prefer a CVE alias; fall back to the advisory id (vuln-scan-action logic). */
export function cveOf(v: OsvVuln): string {
  return v.aliases?.find((a) => a.startsWith('CVE-')) ?? v.id ?? 'UNKNOWN'
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
  /** Total dependencies parsed by the server. */
  deps: number
  /** True when the manifest exceeded the 512-package scan ceiling. */
  truncated: boolean
  hash: string
}

export type ScanErrorKind =
  | 'auth'
  | 'rate-limit'
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
    readonly retryAfter?: string,
  ) {
    super(message)
    this.name = 'ScanError'
  }
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

  if (resp.status === 401) {
    throw new ScanError('Invalid or revoked API token (401). Set a new token.', 'auth')
  }
  if (resp.status === 429) {
    const retry = resp.headers.get('retry-after') ?? undefined
    throw new ScanError(
      'Rate limit reached (429). Anonymous scans are capped at 8/hour per IP; an API token raises this to 25/hour.',
      'rate-limit',
      retry ?? undefined,
    )
  }
  if (resp.status === 422) {
    throw new ScanError(
      `No dependencies could be parsed from ${req.filename} (422). Try forcing a format.`,
      'unparseable',
    )
  }
  if (!resp.ok) {
    throw new ScanError(`Scan failed: HTTP ${resp.status} ${resp.statusText}.`, 'http')
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
        })
      }
    }
    findings.push(...byCve.values())
  })

  return {
    findings,
    unresolved,
    deps: data.count,
    truncated: data.truncated,
    hash: data.hash,
  }
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
