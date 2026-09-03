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

  if (resp.status === 401 || resp.status === 403) {
    throw new IndicatorError(
      'The mlab platform key was rejected (or this lookup needs a plan that allows it).',
      'auth',
    )
  }
  if (resp.status === 429) {
    throw new IndicatorError(
      'Daily lookup quota reached. Adding an mlab platform key raises it.',
      'rate-limit',
      resp.headers.get('retry-after') ?? undefined,
    )
  }
  if (!resp.ok) throw new IndicatorError(`Lookup failed: HTTP ${resp.status}.`, 'http')

  let raw: Record<string, unknown>
  try {
    raw = (await resp.json()) as Record<string, unknown>
  } catch {
    throw new IndicatorError('The platform returned a response that was not valid JSON.', 'bad-response')
  }
  return summarize(req.kind, req.value, raw)
}

// ── Domain, which is a scan rather than a lookup ─────────────────────────────
// Unlike the five direct lookups, a domain is launched, polled, then read. It
// also contacts the target and spends a daily, organisation wide quota.

export type DomainState = 'pending' | 'scanning' | 'done' | 'reused'

async function getJson(
  url: string,
  key: string | undefined,
  timeoutMs: number,
  signal?: AbortSignal,
  method: 'GET' | 'POST' = 'GET',
  body?: unknown,
): Promise<Record<string, unknown>> {
  const ctrl = new AbortController()
  const onAbort = () => ctrl.abort()
  if (signal) {
    if (signal.aborted) ctrl.abort()
    else signal.addEventListener('abort', onAbort, { once: true })
  }
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const headers: Record<string, string> = {}
    if (key) headers.Authorization = `Bearer ${key}`
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const resp = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: ctrl.signal,
    })
    if (resp.status === 429) {
      throw new IndicatorError(
        'Daily domain scan quota reached. Adding an mlab platform key raises it.',
        'rate-limit',
        resp.headers.get('retry-after') ?? undefined,
      )
    }
    if (resp.status === 401 || resp.status === 403) {
      throw new IndicatorError('The mlab platform key was rejected.', 'auth')
    }
    if (!resp.ok) throw new IndicatorError(`Domain scan failed: HTTP ${resp.status}.`, 'http')
    return (await resp.json()) as Record<string, unknown>
  } catch (err) {
    if (err instanceof IndicatorError) throw err
    throw new IndicatorError(
      `Could not reach the mlab platform: ${err instanceof Error ? err.message : String(err)}`,
      'network',
    )
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }
}

export interface DomainRequest {
  base: string
  domain: string
  key?: string
  timeoutMs: number
  signal?: AbortSignal
  /** Called between polls so the caller can show progress. */
  onState?: (state: DomainState) => void
}

/** Read the state out of a status response. */
export function readState(raw: Record<string, unknown>): DomainState {
  const st = typeof raw.status === 'string' ? raw.status : ''
  if (st === 'pending') return 'pending'
  if (st === 'scanning') return 'scanning'
  return 'done'
}

/** Gap before the next poll, growing so a long scan does not hammer the API. */
export function pollDelay(attempt: number): number {
  return Math.min(2000 + attempt * 1000, 8000)
}

export const MAX_POLLS = 40

/** True when a results payload holds a finished scan we can reuse as is. */
export function isCompleted(raw: Record<string, unknown>): boolean {
  return raw.status === 'completed' && raw.results !== undefined && raw.results !== null
}

/**
 * Existing results for a domain, or undefined when there are none to reuse.
 *
 * This is a plain GET and costs nothing, which is the whole point: `POST
 * /scan/domain` checks the quota and then purges and relaunches, so it spends
 * one of the daily scans even when a perfectly good recent scan already exists.
 * Reading first is free and usually enough.
 */
export async function existingDomainScan(req: DomainRequest): Promise<IndicatorReport | undefined> {
  const origin = req.base.replace(/\/+$/, '')
  try {
    const raw = await getJson(
      `${origin}/scan/domain/results?domain=${encodeURIComponent(req.domain)}`,
      req.key,
      req.timeoutMs,
      req.signal,
    )
    return isCompleted(raw) ? summarize('domain', req.domain, raw) : undefined
  } catch {
    // No scan yet, or the read failed. Either way, fall through and launch one.
    return undefined
  }
}

/**
 * Launch a domain scan, wait for it, and return the report.
 *
 * If a recent completed scan exists the platform answers immediately, so the
 * common case costs one request.
 */
export async function scanDomain(req: DomainRequest): Promise<IndicatorReport> {
  const origin = req.base.replace(/\/+$/, '')

  // Reuse before spending. A launch always costs a daily scan; a read costs
  // nothing, so ask whether the answer already exists.
  const existing = await existingDomainScan(req)
  if (existing) {
    req.onState?.('reused')
    return existing
  }

  await getJson(`${origin}/scan/domain`, req.key, req.timeoutMs, req.signal, 'POST', {
    domain: req.domain,
  })

  const statusUrl = `${origin}/scan/domain/status?domain=${encodeURIComponent(req.domain)}`
  for (let i = 0; i < MAX_POLLS; i++) {
    if (req.signal?.aborted) throw new IndicatorError('Domain scan cancelled.', 'network')
    const status = await getJson(statusUrl, req.key, req.timeoutMs, req.signal)
    const state = readState(status)
    req.onState?.(state)
    if (state === 'done') break
    await new Promise((r) => setTimeout(r, pollDelay(i)))
    if (i === MAX_POLLS - 1) {
      throw new IndicatorError(
        'The domain scan is still running. Open it on mlab to follow it there.',
        'timeout',
      )
    }
  }

  const results = await getJson(
    `${origin}/scan/domain/results?domain=${encodeURIComponent(req.domain)}`,
    req.key,
    req.timeoutMs,
    req.signal,
  )
  return summarize('domain', req.domain, results)
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

  if (kind === 'domain') {
    // The payload is an envelope: { domain, scan_date, status, results: {...} }.
    const res = (raw.results ?? {}) as Record<string, unknown>
    const dns = (res.dns ?? {}) as Record<string, unknown>
    const txt = (dns.txt ?? {}) as Record<string, unknown>
    const files = (res.files ?? {}) as Record<string, unknown>

    const suspicious = Array.isArray(res.subdomains_suspicious) ? res.subdomains_suspicious : []
    const subdomains = Array.isArray(res.subdomains) ? res.subdomains : []
    const ssl = Array.isArray(res.ssl) ? res.ssl : []

    if (suspicious.length) {
      verdict = {
        label: `${suspicious.length} suspicious subdomain${suspicious.length === 1 ? '' : 's'}`,
        tone: 'warn',
      }
    }

    push('Scanned', s(raw.scan_date))
    const resolve = Array.isArray(dns.resolve) ? (dns.resolve[0] as Record<string, unknown>) : undefined
    const a = Array.isArray(resolve?.a) ? (resolve!.a as string[]) : []
    const aaaa = Array.isArray(resolve?.aaaa) ? (resolve!.aaaa as string[]) : []
    push('A records', a.join(', ') || undefined, true)
    push('AAAA records', aaaa.join(', ') || undefined, true)
    push('SPF', s(txt.spf) ? 'present' : 'absent')
    push('DMARC', s(txt.dmarc) ? 'present' : 'absent')
    push('DKIM', Array.isArray(txt.dkim) && txt.dkim.length ? 'present' : 'absent')
    push('Subdomains', subdomains.length ? String(subdomains.length) : undefined)
    if (suspicious.length) push('Suspicious', (suspicious as string[]).join(', '), true)
    push('security.txt', s(files.security_txt) === 'not found' ? 'not found' : 'present')
    push('SSL issues', ssl.length ? String(ssl.length) : 'none')
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
