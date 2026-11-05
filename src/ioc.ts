// Local recognition of what a selected string is.
//
// The type is worked out here, on the machine, and only then is the value sent
// to the endpoint that handles that type. Nothing is uploaded to find out what
// something is: `/scan/ioc` would do that server side, but it is not stable, and
// doing it locally is both faster and one less thing leaving the editor.
//
// No `vscode` import, so it is unit tested like ../detect.

export type IndicatorKind = 'ip' | 'url' | 'email' | 'hash' | 'mac' | 'domain' | 'unknown'

/** Characters people select by accident: quotes, brackets, trailing punctuation. */
const TRIM = /^[\s'"`<([{,;]+|[\s'"`>)\]},;.]+$/g

/** Strip the noise around a selection without touching the value itself. */
export function clean(raw: string): string {
  return raw.trim().replace(TRIM, '').trim()
}

const RE = {
  url: /^[a-z][a-z0-9+.-]*:\/\/\S+$/i,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,
  // 6 groups of two hex digits. Checked before IPv6, which it can resemble.
  mac: /^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$/i,
  macBare: /^[0-9a-f]{12}$/i,
  macCisco: /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/i,
  hash: /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$/i,
  ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/,
  ipv6: /^(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i,
  domain: /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i,
}

/**
 * Classify a selection.
 *
 * Order matters. A 12 hex digit string is a bare MAC, not a short hash. A MAC
 * with colons resembles an IPv6 address. A hash is checked before anything that
 * accepts hex, and `unknown` is returned rather than a wrong guess: sending a
 * value to the wrong endpoint is worse than saying so.
 */
export function detectKind(value: string): IndicatorKind {
  const v = clean(value)
  if (v === '') return 'unknown'

  if (RE.url.test(v)) return 'url'
  if (RE.email.test(v)) return 'email'
  if (RE.mac.test(v) || RE.macCisco.test(v)) return 'mac'
  if (RE.hash.test(v)) return 'hash'
  if (RE.macBare.test(v)) return 'mac'
  if (RE.ipv4.test(v)) return 'ip'
  if (v.includes(':') && RE.ipv6.test(v) && v.split(':').length >= 3) return 'ip'
  // A domain needs a non-numeric last label. Without this, a malformed address
  // like 256.0.0.1 is a syntactically valid domain name and would open a domain
  // page, when what the user actually selected was a broken IP.
  if (RE.domain.test(v) && /[^0-9]/.test(v.split('.').pop() ?? '')) return 'domain'
  return 'unknown'
}

/** Human label for a kind, used in messages and the result panel. */
export function kindLabel(kind: IndicatorKind): string {
  switch (kind) {
    case 'ip':
      return 'IP address'
    case 'url':
      return 'URL'
    case 'email':
      return 'email address'
    case 'hash':
      return 'file hash'
    case 'mac':
      return 'MAC address'
    case 'domain':
      return 'domain'
    case 'unknown':
      return 'indicator'
  }
}

/** Kinds this extension looks up in place. All five are passive: they read a database. */
export const SUPPORTED_KINDS: IndicatorKind[] = ['ip', 'url', 'email', 'hash', 'mac']

export function isSupported(kind: IndicatorKind): boolean {
  return SUPPORTED_KINDS.includes(kind)
}

/**
 * Kinds that are never scanned from the editor: the action opens their page on
 * mlab.sh instead, where the user starts the scan themselves. A domain scan
 * contacts the target and spends the organisation's scan quota, which is not
 * something a right-click on a string in a file should do.
 */
export const BROWSER_KINDS: IndicatorKind[] = ['domain']

export function opensInBrowser(kind: IndicatorKind): boolean {
  return BROWSER_KINDS.includes(kind)
}

/** Kinds whose lookup spends the platform quota (rolling 24 h). */
export const QUOTA_KINDS: IndicatorKind[] = ['ip']

export function costsQuota(kind: IndicatorKind): boolean {
  return QUOTA_KINDS.includes(kind)
}

/** A selection longer than this is not an indicator; refuse rather than upload it. */
export const MAX_LENGTH = 2048
