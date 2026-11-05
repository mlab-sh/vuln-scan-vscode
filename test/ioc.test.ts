import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  clean,
  detectKind,
  isSupported,
  costsQuota,
  opensInBrowser,
  SUPPORTED_KINDS,
  IndicatorKind,
} from '../src/ioc'
import {
  endpointFor,
  errorFor,
  lookup,
  quotaLine,
  readQuota,
  summarize,
  worstSeverity,
  webUrlFor,
} from '../src/api/indicator'

// ── Cleaning a selection ─────────────────────────────────────────────────────

test('strips what people select by accident', () => {
  assert.equal(clean('  8.8.8.8  '), '8.8.8.8')
  assert.equal(clean('"example.com"'), 'example.com')
  assert.equal(clean("'8.8.8.8',"), '8.8.8.8')
  assert.equal(clean('<security@example.com>'), 'security@example.com')
  assert.equal(clean('(1.1.1.1);'), '1.1.1.1')
})

test('does not eat characters that belong to the value', () => {
  // A trailing slash is part of a URL, a dot inside a domain is not punctuation.
  assert.equal(clean('https://example.com/a/'), 'https://example.com/a/')
  assert.equal(clean('sub.example.com'), 'sub.example.com')
})

// ── Detection ────────────────────────────────────────────────────────────────

const cases: Array<[string, IndicatorKind]> = [
  ['https://example.com/a?b=c', 'url'],
  ['http://admin:x@192.168.9.7:8080/a.exe', 'url'],
  ['ftp://files.example.com/x', 'url'],
  ['security@example.com', 'email'],
  ['throwaway@mailinator.com', 'email'],
  ['00:1A:2B:3C:4D:5E', 'mac'],
  ['00-1A-2B-3C-4D-5E', 'mac'],
  ['001a.2b3c.4d5e', 'mac'],
  ['001A2B3C4D5E', 'mac'],
  ['d41d8cd98f00b204e9800998ecf8427e', 'hash'],
  ['da39a3ee5e6b4b0d3255bfef95601890afd80709', 'hash'],
  ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hash'],
  ['8.8.8.8', 'ip'],
  ['192.168.1.1', 'ip'],
  ['2606:4700:4700::1111', 'ip'],
  ['example.com', 'domain'],
  ['vuln.mlab.sh', 'domain'],
]

for (const [value, expected] of cases) {
  test(`detects ${JSON.stringify(value)} as ${expected}`, () => {
    assert.equal(detectKind(value), expected)
  })
}

test('a colon separated MAC is not mistaken for an IPv6 address', () => {
  // Both are colon separated hex. The MAC pattern has to win.
  assert.equal(detectKind('00:1A:2B:3C:4D:5E'), 'mac')
  assert.equal(detectKind('2606:4700:4700::1111'), 'ip')
})

test('a bare MAC is not mistaken for a short hash', () => {
  // 12 hex digits. Neither MD5 (32) nor SHA1 (40), so it must land on MAC.
  assert.equal(detectKind('001A2B3C4D5E'), 'mac')
  assert.equal(detectKind('d41d8cd98f00b204e9800998ecf8427e'), 'hash')
})

test('a malformed address is unknown, not silently treated as a domain', () => {
  // These parse as syntactically valid domain names, but nobody selecting them
  // means a domain, and opening a page for a broken IP helps no one. Refuse instead.
  for (const v of ['999.1.1.1', '1.2.3', '256.0.0.1', '8.8.8.256']) {
    assert.equal(detectKind(v), 'unknown', `${v} should not be classified`)
  }
  assert.equal(detectKind('8.8.8.8'), 'ip')
  assert.equal(detectKind('example.com'), 'domain', 'a real domain still works')
})

test('nonsense is unknown rather than guessed at', () => {
  for (const v of ['', '   ', 'hello world', 'const x = 1', 'CVE-2021-44228', '/usr/bin/env']) {
    assert.equal(detectKind(v), 'unknown', `${JSON.stringify(v)} should be unknown`)
  }
})

test('the five lookups each have a GET route; a domain has none, by design', () => {
  for (const k of ['ip', 'url', 'email', 'hash', 'mac'] as IndicatorKind[]) {
    assert.ok(endpointFor('https://mlab.sh/api/v1', k, 'x'), `${k} should have a route`)
    assert.ok(isSupported(k))
    assert.equal(opensInBrowser(k), false, `${k} is looked up in place`)
  }
  // A domain is never scanned from the editor: its page on mlab.sh is opened.
  assert.equal(isSupported('domain'), false)
  assert.equal(opensInBrowser('domain'), true)
  assert.equal(endpointFor('https://mlab.sh/api/v1', 'domain', 'x'), undefined)
  assert.equal(isSupported('unknown'), false)
  assert.equal(opensInBrowser('unknown'), false)
})

// ── Seeing the full result on mlab ───────────────────────────────────────────

test('every supported kind has a page on the site', () => {
  for (const k of SUPPORTED_KINDS) {
    assert.ok(webUrlFor('https://mlab.sh', k, 'value'), `${k} should have a web page`)
  }
  assert.equal(webUrlFor('https://mlab.sh', 'unknown', 'x'), undefined)
})

test('the URL page takes its value as a query, the others as a path', () => {
  // Verified against the live site: /url/<value> is a 404, /url?q=<value> is not.
  assert.equal(
    webUrlFor('https://mlab.sh', 'url', 'https://example.com/a b'),
    'https://mlab.sh/url?q=https%3A%2F%2Fexample.com%2Fa%20b',
  )
  assert.equal(webUrlFor('https://mlab.sh', 'ip', '8.8.8.8'), 'https://mlab.sh/ip/8.8.8.8')
})

test('a domain opens its page, which shows the report or offers to start a scan', () => {
  // /domain/<name> on mlab.sh: the latest report when there is one, otherwise a
  // page with a button the user presses to launch the scan. Nothing starts on open.
  assert.equal(webUrlFor('https://mlab.sh', 'domain', 'example.com'), 'https://mlab.sh/domain/example.com')
  assert.equal(webUrlFor('https://mlab.internal:8443/', 'domain', 'a.test'), 'https://mlab.internal:8443/domain/a.test')
})

test('values that need escaping are escaped', () => {
  assert.equal(
    webUrlFor('https://mlab.sh', 'email', 'a+b@example.com'),
    'https://mlab.sh/email/a%2Bb%40example.com',
  )
  assert.equal(webUrlFor('https://mlab.sh/', 'ip', '::1'), 'https://mlab.sh/ip/%3A%3A1')
})

test('only an IP lookup spends the quota', () => {
  assert.equal(costsQuota('ip'), true)
  for (const k of ['url', 'email', 'hash', 'mac', 'domain'] as IndicatorKind[]) {
    assert.equal(costsQuota(k), false, `${k} spends nothing from the editor`)
  }
})

// ── Routing ──────────────────────────────────────────────────────────────────

test('each kind goes to its own endpoint with its own parameter name', () => {
  const at = (k: IndicatorKind, v: string) => new URL(endpointFor('https://mlab.sh/api/v1', k, v)!)
  assert.equal(at('ip', '8.8.8.8').pathname, '/api/v1/scan/ip')
  assert.equal(at('ip', '8.8.8.8').searchParams.get('ip'), '8.8.8.8')
  assert.equal(at('url', 'https://x/y').searchParams.get('url'), 'https://x/y')
  assert.equal(at('hash', 'abc').searchParams.get('hash'), 'abc')
  assert.equal(at('email', 'a@b.co').searchParams.get('email'), 'a@b.co')
  assert.equal(at('mac', '00:1A:2B:3C:4D:5E').searchParams.get('mac'), '00:1A:2B:3C:4D:5E')
})

test('a trailing slash on the base does not produce a doubled path', () => {
  assert.equal(
    new URL(endpointFor('https://mlab.sh/api/v1/', 'ip', '1.1.1.1')!).pathname,
    '/api/v1/scan/ip',
  )
})

test('a self-hosted base is honoured', () => {
  const u = new URL(endpointFor('https://mlab.internal.example/api/v1', 'url', 'https://x')!)
  assert.equal(u.origin, 'https://mlab.internal.example')
})

// ── Normalising responses ────────────────────────────────────────────────────

test('a URL response keeps its findings and surfaces the parts that matter', () => {
  const r = summarize('url', 'http://admin:x@192.168.9.7/a.exe', {
    scheme: 'http',
    host: '192.168.9.7',
    path: '/a.exe',
    has_userinfo: true,
    host_is_ip: true,
    port: null,
    findings: [
      { severity: 'high', title: 'Credentials in the URL (userinfo)', detail: 'Everything before the @…' },
      { severity: 'medium', title: 'Plaintext HTTP', detail: 'Traffic is not encrypted.' },
    ],
  })
  assert.equal(r.findings.length, 2)
  assert.equal(worstSeverity(r.findings), 'high')
  const labels = r.facts.map((f) => f.label)
  assert.ok(labels.includes('Host'))
  assert.ok(labels.includes('Credentials in URL'))
  assert.ok(!labels.includes('Port'), 'a null port is omitted rather than shown as null')
})

test('a hash verdict becomes a tone the panel can colour', () => {
  assert.deepEqual(summarize('hash', 'x', { verdict: 'known_good', found: true }).verdict, {
    label: 'Known good',
    tone: 'good',
  })
  assert.deepEqual(summarize('hash', 'x', { verdict: 'known_malicious' }).verdict, {
    label: 'Known malicious',
    tone: 'bad',
  })
  assert.equal(summarize('hash', 'x', { found: false }).verdict?.tone, 'neutral')
})

test('an email score band maps onto a tone', () => {
  assert.equal(summarize('email', 'a@b.co', { score: { band: 'clean' } }).verdict?.tone, 'good')
  assert.equal(summarize('email', 'a@b.co', { score: { band: 'suspect' } }).verdict?.tone, 'warn')
  assert.equal(summarize('email', 'a@b.co', { score: { band: 'malicious' } }).verdict?.tone, 'bad')
})

test('IP flags are summarised rather than dumped', () => {
  const r = summarize('ip', '8.8.8.8', {
    org: 'Google Public DNS',
    as: 'AS15169 Google LLC',
    city: 'Ashburn',
    region: 'Virginia',
    country: 'United States',
    hosting: true,
    proxy: false,
  })
  assert.ok(r.verdict?.label.includes('hosting provider'))
  assert.equal(r.verdict?.tone, 'neutral', 'hosting alone is not suspicious')
  assert.ok(r.facts.some((f) => f.label === 'Location' && f.value === 'Ashburn, Virginia, United States'))
})

test('a proxy flag is worth a warning tone', () => {
  assert.equal(summarize('ip', '1.2.3.4', { proxy: true }).verdict?.tone, 'warn')
})

test('a malformed findings array does not crash the normaliser', () => {
  const r = summarize('url', 'x', { findings: [null, 'nope', { detail: 'no title' }, { title: 'ok' }] })
  assert.equal(r.findings.length, 1)
  assert.equal(r.findings[0].title, 'ok')
  assert.equal(r.findings[0].severity, 'info', 'a missing severity defaults rather than throwing')
})

// ── Errors and quota ─────────────────────────────────────────────────────────

test('a 401 with a key says why a key stops working and where to get a new one', () => {
  const e = errorFor(401, { error: 'Unauthorized' }, true)
  assert.equal(e.kind, 'auth')
  assert.match(e.message, /revoked or expired/)
  assert.match(e.message, /90 days/)
  assert.doesNotMatch(errorFor(401, undefined, false).message, /90 days/, 'no key, nothing expired')
})

test('a 403 shows the server message, which names the missing permission', () => {
  const said = "This API key does not have the 'scan.lookup' permission (Lookups)."
  assert.equal(errorFor(403, { error: said }, true).message, said)
  assert.equal(errorFor(403, 'not json', true).kind, 'auth')
})

test('a 429 keeps the server message and explains the rolling window', () => {
  const e = errorFor(429, { error: 'IP lookup limit reached. Please try again later.' }, true, '3600')
  assert.equal(e.kind, 'rate-limit')
  assert.equal(e.retryAfter, '3600')
  assert.match(e.message, /^IP lookup limit reached/)
  assert.match(e.message, /rolling 24 hours/)
  assert.doesNotMatch(e.message, /raises it/, 'a key holder is not told to add a key')
  assert.match(errorFor(429, undefined, false).message, /platform key raises it/)
})

function headers(h: Record<string, string>) {
  return { get: (n: string) => h[n.toLowerCase()] ?? null }
}

test('the quota is read from the X-RateLimit headers', () => {
  const q = readQuota(
    headers({
      'x-ratelimit-limit': '500',
      'x-ratelimit-remaining': '497',
      'x-ratelimit-resource': 'ip',
      'x-ratelimit-window': '86400',
    }),
  )
  assert.deepEqual(q, { limit: 500, remaining: 497, resource: 'ip', windowSecs: 86400 })
  assert.equal(quotaLine(q!), '497 of 500 ip lookups left per rolling 24 h')
  assert.equal(readQuota(headers({})), undefined, 'a call that spends nothing has no quota')
  assert.equal(readQuota(headers({ 'x-ratelimit-limit': 'x', 'x-ratelimit-remaining': '1' })), undefined)
})

function stubResponse(status: number, body: unknown, h: Record<string, string> = {}) {
  const original = globalThis.fetch
  const calls: string[] = []
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
    calls.push(String(input))
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: headers(h),
      json: async () => body,
    } as unknown as Response
  }) as typeof fetch
  return { calls, restore: () => { globalThis.fetch = original } }
}

test('a keyed IP lookup carries its quota into the report', async () => {
  const f = stubResponse(200, { org: 'Google' }, { 'x-ratelimit-limit': '10', 'x-ratelimit-remaining': '9' })
  try {
    const r = await lookup({ base: 'https://mlab.sh/api/v1', kind: 'ip', value: '8.8.8.8', key: 'k', timeoutMs: 1000 })
    assert.equal(r.quota?.remaining, 9)
    assert.equal(f.calls.length, 1)
    assert.ok(f.calls[0].endsWith('/scan/ip?ip=8.8.8.8'))
  } finally {
    f.restore()
  }
})

test('a refused lookup reaches the caller as the mapped error', async () => {
  const f = stubResponse(401, { error: 'Unauthorized' })
  try {
    await assert.rejects(
      lookup({ base: 'https://mlab.sh/api/v1', kind: 'hash', value: 'a'.repeat(64), key: 'old', timeoutMs: 1000 }),
      (e: Error & { kind?: string }) => e.kind === 'auth' && /expired/.test(e.message),
    )
  } finally {
    f.restore()
  }
})
