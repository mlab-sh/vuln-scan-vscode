// Client for the indicator endpoints on the mlab platform API.
//
// One endpoint per indicator type, chosen locally from ../ioc so the value only
// ever reaches the endpoint that handles it. Everything works without a key at a
// reduced quota; a platform key raises it and unlocks premium enrichment. That
// key is NOT the vuln.mlab.sh scan token: they are separate credentials.
//
// No `vscode` import, so the routing and the normalisation are unit tested.

import { IndicatorKind } from '../ioc'

export const DEFAULT_PLATFORM_URL = 'https://mlab.sh/api/v1'

/** Path and query parameter for each supported kind. */
const ROUTES: Partial<Record<IndicatorKind, { path: string; param: string }>> = {
  ip: { path: '/scan/ip', param: 'ip' },
  url: { path: '/scan/url', param: 'url' },
  email: { path: '/scan/email', param: 'email' },
  hash: { path: '/scan/hash', param: 'hash' },
  mac: { path: '/scan/mac', param: 'mac' },
}

/** The request URL for one indicator, or undefined when the kind has no route. */
export function endpointFor(base: string, kind: IndicatorKind, value: string): string | undefined {
  const route = ROUTES[kind]
  if (!route) return undefined
  const u = new URL(base.replace(/\/+$/, '') + route.path)
  u.searchParams.set(route.param, value)
  return u.toString()
}

/**
 * The human facing page for an indicator on mlab.sh, so a result can always be
 * opened in full in a browser.
 *
 * Verified against the live site: every kind has a path form except URL, whose
 * page takes the value as a `q` parameter instead.
 */
export function webUrlFor(site: string, kind: IndicatorKind, value: string): string | undefined {
  const origin = site.replace(/\/+$/, '')
  if (kind === 'url') return `${origin}/url?q=${encodeURIComponent(value)}`
  const paths: Partial<Record<IndicatorKind, string>> = {
    ip: 'ip',
    hash: 'hash',
    email: 'email',
    mac: 'mac',
    domain: 'domain',
  }
  const seg = paths[kind]
  return seg ? `${origin}/${seg}/${encodeURIComponent(value)}` : undefined
}

export type Tone = 'good' | 'bad' | 'warn' | 'neutral'

export interface IndicatorFinding {
  severity: string
  title: string
  detail: string
}

export interface Fact {
  label: string
  value: string
  mono?: boolean
}

/** A response normalised into something the panel can render for any kind. */
export interface IndicatorReport {
  kind: IndicatorKind
  value: string
  /** Where to see the full result on mlab.sh, when the kind has a page. */
  webUrl?: string
  verdict?: { label: string; tone: Tone }
  findings: IndicatorFinding[]
  facts: Fact[]
  /** What is left of the key's quota, from the X-RateLimit-* headers. */
  quota?: Quota
}

/** The platform quota as reported on a key call that spends it. */
export interface Quota {
  limit: number
  remaining: number
  /** What the quota counts, e.g. `ip`. */
  resource?: string
  /** Length of the rolling window, in seconds. */
  windowSecs?: number
}

/** Read the X-RateLimit-* headers, or undefined when the call spent no quota. */
export function readQuota(headers: { get(name: string): string | null }): Quota | undefined {
  const limit = Number(headers.get('x-ratelimit-limit'))
  const remaining = Number(headers.get('x-ratelimit-remaining'))
  if (!headers.get('x-ratelimit-limit') || !Number.isFinite(limit) || !Number.isFinite(remaining)) return undefined
  const window = Number(headers.get('x-ratelimit-window'))
  return {
    limit,
    remaining,
    resource: headers.get('x-ratelimit-resource') ?? undefined,
    windowSecs: Number.isFinite(window) && window > 0 ? window : undefined,
  }
}

/** One line for the panel and the output channel. */
export function quotaLine(q: Quota): string {
  const per = q.windowSecs === 86400 ? ' per rolling 24 h' : ''
  return `${q.remaining} of ${q.limit}${q.resource ? ` ${q.resource}` : ''} lookups left${per}`
}

export class IndicatorError extends Error {
  constructor(
    message: string,
    readonly kind: 'rate-limit' | 'auth' | 'http' | 'network' | 'timeout' | 'bad-response',
    readonly retryAfter?: string,
  ) {
    super(message)
    this.name = 'IndicatorError'
  }
}

export interface LookupRequest {
  base: string
  kind: IndicatorKind
  value: string
  /** Platform API key. Absent means anonymous, which works at a lower quota. */
  key?: string
  timeoutMs: number
  signal?: AbortSignal
}

export async function lookup(req: LookupRequest): Promise<IndicatorReport> {
  const url = endpointFor(req.base, req.kind, req.value)
  if (!url) throw new IndicatorError(`No endpoint for a ${req.kind}.`, 'http')

  const ctrl = new AbortController()
  const onAbort = () => ctrl.abort()
  if (req.signal) {
    if (req.signal.aborted) ctrl.abort()
    else req.signal.addEventListener('abort', onAbort, { once: true })
  }
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    ctrl.abort()
  }, req.timeoutMs)

  let resp: Response
  try {
    resp = await fetch(url, {
      headers: req.key ? { Authorization: `Bearer ${req.key}` } : {},
      signal: ctrl.signal,
    })
  } catch (err) {
    if (timedOut) throw new IndicatorError(`Lookup timed out after ${req.timeoutMs} ms.`, 'timeout')
    const detail = err instanceof Error ? err.message : String(err)
    throw new IndicatorError(`Could not reach the mlab platform: ${detail}`, 'network')
  } finally {
    clearTimeout(timer)
    req.signal?.removeEventListener('abort', onAbort)
  }

  if (resp.status === 401 || resp.status === 403 || resp.status === 429) {
    let body: unknown
    try {
      body = await resp.json()
    } catch {
      body = undefined
    }
    throw errorFor(resp.status, body, Boolean(req.key), resp.headers.get('retry-after') ?? undefined)
  }
  if (!resp.ok) throw new IndicatorError(`Lookup failed: HTTP ${resp.status}.`, 'http')

  let raw: Record<string, unknown>
  try {
    raw = (await resp.json()) as Record<string, unknown>
  } catch {
    throw new IndicatorError('The platform returned a response that was not valid JSON.', 'bad-response')
  }
  const report = summarize(req.kind, req.value, raw)
  report.quota = req.key ? readQuota(resp.headers) : undefined
  return report
}

/**
 * The error for a refused lookup, worded for someone who has to act on it.
 *
 * The platform answers 401 to a key it does not know: mistyped, revoked, or
 * expired (keys expire after 90 days unless set otherwise). 403 means the key is
 * valid but lacks the permission, and the server's own message names it. 429 is
 * the quota, which refills over a rolling 24 hours.
 */
export function errorFor(status: number, body: unknown, withKey: boolean, retryAfter?: string): IndicatorError {
  const said =
    body && typeof body === 'object' && typeof (body as Record<string, unknown>).error === 'string'
      ? ((body as Record<string, unknown>).error as string)
      : undefined
  if (status === 401) {
    return new IndicatorError(
      withKey
        ? 'The mlab platform key was not accepted: it is mistyped, revoked or expired (keys expire after 90 days by default). Create a new one in your organization settings on mlab.sh.'
        : 'The mlab platform refused the anonymous lookup (401).',
      'auth',
    )
  }
  if (status === 403) {
    return new IndicatorError(said ?? 'The mlab platform key is not allowed to make this lookup.', 'auth')
  }
  const base = said && said !== 'limit' ? said.replace(/\.?$/, '.') : 'Lookup quota reached.'
  return new IndicatorError(
    `${base} The quota refills over a rolling 24 hours${withKey ? '' : '; an mlab platform key raises it'}.`,
    'rate-limit',
    retryAfter,
  )
}

// ── Normalisation ────────────────────────────────────────────────────────────

const s = (v: unknown): string | undefined =>
  typeof v === 'string' && v.trim() !== '' ? v : undefined
const b = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined)

function readFindings(raw: Record<string, unknown>): IndicatorFinding[] {
  const arr = raw.findings
  if (!Array.isArray(arr)) return []
  return arr.flatMap((f) => {
    if (!f || typeof f !== 'object') return []
    const o = f as Record<string, unknown>
    const title = s(o.title)
    if (!title) return []
    return [{ severity: (s(o.severity) ?? 'info').toLowerCase(), title, detail: s(o.detail) ?? '' }]
  })
}

const yesNo = (v: boolean | undefined): string | undefined =>
  v === undefined ? undefined : v ? 'yes' : 'no'

/** Turn a raw response into the shape the panel renders, per indicator kind. */
export function summarize(
  kind: IndicatorKind,
  value: string,
  raw: Record<string, unknown>,
): IndicatorReport {
  const facts: Fact[] = []
  const push = (label: string, v: string | undefined, mono = false) => {
    if (v !== undefined && v !== '') facts.push({ label, value: v, mono })
  }
  let verdict: IndicatorReport['verdict']

  if (kind === 'url') {
    push('Scheme', s(raw.scheme), true)
    push('Host', s(raw.host), true)
    push('Port', raw.port === null || raw.port === undefined ? undefined : String(raw.port), true)
    push('Path', s(raw.path), true)
    push('Unicode host', s(raw.host_unicode), true)
    push('Embedded URL', s(raw.embedded_url), true)
    push('Decoded', s(raw.decoded), true)
    push('Credentials in URL', yesNo(b(raw.has_userinfo)))
    push('Host is a raw IP', yesNo(b(raw.host_is_ip)))
  } else if (kind === 'hash') {
    const v = s(raw.verdict)
    if (v === 'known_good') verdict = { label: 'Known good', tone: 'good' }
    else if (v === 'known_malicious') verdict = { label: 'Known malicious', tone: 'bad' }
    else if (b(raw.found) === false) verdict = { label: 'Unknown to every source', tone: 'neutral' }
    push('Algorithm', s(raw.algorithm))
    push('Product', s(raw.product))
    push('File name', s(raw.file_name), true)
    push('Source', s(raw.enrichment_source))
    push('Sources hit', `${raw.sources_hit ?? 0} of ${raw.sources_queried ?? 0}`)
    push('Trust', raw.trust === undefined ? undefined : String(raw.trust))
  } else if (kind === 'email') {
    const score = raw.score as Record<string, unknown> | undefined
    const band = s(score?.band)
    if (band) {
      const tone: Tone = band === 'clean' ? 'good' : band === 'suspect' ? 'warn' : 'bad'
      verdict = { label: band, tone }
    }
    push('Mailbox type', s(raw.mailbox_type))
    push('Domain', s(raw.domain), true)
    push('Disposable', yesNo(b(raw.is_disposable)))
    push('Role address', yesNo(b(raw.is_role)))
    push('Free provider', yesNo(b(raw.is_free_provider)))
    push('Canonical', s(raw.canonical), true)
  } else if (kind === 'mac') {
    const v = s(raw.verdict)
    if (v) verdict = { label: v, tone: b(raw.randomized) ? 'warn' : 'neutral' }
    push('Vendor', s(raw.vendor))
    push('OUI', s(raw.oui), true)
    push('Cast', s(raw.cast))
    push('Administration', s(raw.administration))
    push('Randomized', yesNo(b(raw.randomized)))
    push('Virtualization', s(raw.virtualization))
    push('EUI-64 IPv6', s(raw.eui64_ipv6), true)
  } else if (kind === 'ip') {
    const flags: string[] = []
    if (b(raw.proxy)) flags.push('proxy or VPN')
    if (b(raw.hosting)) flags.push('hosting provider')
    if (b(raw.mobile)) flags.push('mobile network')
    if (b(raw.reserved)) flags.push('reserved range')
    if (flags.length) verdict = { label: flags.join(', '), tone: b(raw.proxy) ? 'warn' : 'neutral' }
    push('Organisation', s(raw.org))
    push('ISP', s(raw.isp))
    push('AS', s(raw.as), true)
    const where = [s(raw.city), s(raw.region), s(raw.country)].filter(Boolean).join(', ')
    push('Location', where || undefined)
    const rdns = raw.rdns as Record<string, unknown> | undefined
    push('Reverse DNS', s(rdns?.name) ?? s(rdns?.ptr), true)
    const rdap = raw.rdap as Record<string, unknown> | undefined
    push('Abuse contact', s(rdap?.abuse_email), true)
  }

  return { kind, value, verdict, findings: readFindings(raw), facts }
}

/** Highest severity among findings, for the panel's headline. */
export function worstSeverity(findings: IndicatorFinding[]): string | undefined {
  const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
  let best = -1
  let out: string | undefined
  for (const f of findings) {
    const r = rank[f.severity] ?? 0
    if (r > best) {
      best = r
      out = f.severity
    }
  }
  return out
}
