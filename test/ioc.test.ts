import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  clean,
  detectKind,
  isSupported,
  costsQuota,
  SUPPORTED_KINDS,
  IndicatorKind,
} from '../src/ioc'
import {
  endpointFor,
  isCompleted,
  scanDomain,
  summarize,
  worstSeverity,
  webUrlFor,
  readState,
  pollDelay,
  MAX_POLLS,
} from '../src/api/indicator'
import { isActive } from '../src/ioc'

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
  // means a domain, and a domain scan spends quota. Refuse instead.
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

test('the direct lookups each have a GET route; the domain does not, by design', () => {
  for (const k of ['ip', 'url', 'email', 'hash', 'mac'] as IndicatorKind[]) {
    assert.ok(endpointFor('https://mlab.sh/api/v1', k, 'x'), `${k} should have a route`)
    assert.ok(isSupported(k))
    assert.equal(isActive(k), false, `${k} reads a database, it does not touch anyone`)
  }
  // A domain is supported but goes through launch, poll and read instead.
  assert.ok(isSupported('domain'))
  assert.equal(endpointFor('https://mlab.sh/api/v1', 'domain', 'x'), undefined)
  assert.equal(isActive('domain'), true, 'a domain scan contacts the target')
  assert.equal(isSupported('unknown'), false)
})

test('every supported kind is either a direct lookup or an active scan', () => {
  for (const k of SUPPORTED_KINDS) {
    const direct = endpointFor('https://mlab.sh/api/v1', k, 'x') !== undefined
    assert.notEqual(direct, isActive(k), `${k} must be exactly one of the two`)
  }
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
  assert.equal(webUrlFor('https://mlab.sh', 'domain', 'example.com'), 'https://mlab.sh/domain/example.com')
})

test('values that need escaping are escaped', () => {
  assert.equal(
    webUrlFor('https://mlab.sh', 'email', 'a+b@example.com'),
    'https://mlab.sh/email/a%2Bb%40example.com',
  )
  assert.equal(webUrlFor('https://mlab.sh/', 'ip', '::1'), 'https://mlab.sh/ip/%3A%3A1')
})

// ── Domain polling ───────────────────────────────────────────────────────────

test('the scan states are read from the status payload', () => {
  assert.equal(readState({ status: 'pending' }), 'pending')
  assert.equal(readState({ status: 'scanning' }), 'scanning')
  assert.equal(readState({ status: 'completed' }), 'done')
  assert.equal(readState({}), 'done', 'anything unrecognised means stop polling')
})

test('polling backs off but stays bounded', () => {
  assert.ok(pollDelay(1) > pollDelay(0), 'the gap grows')
  assert.ok(pollDelay(100) <= 8000, 'and is capped')
  // The worst case wait has to stay sane rather than run for an hour.
  let total = 0
  for (let i = 0; i < MAX_POLLS; i++) total += pollDelay(i)
  assert.ok(total <= 5 * 60 * 1000, `worst case ${total} ms should stay under five minutes`)
})

test('only IP and domain spend a daily quota', () => {
  assert.equal(costsQuota('ip'), true)
  assert.equal(costsQuota('domain'), true)
  for (const k of ['url', 'email', 'hash', 'mac'] as IndicatorKind[]) {
    assert.equal(costsQuota(k), false, `${k} is documented as free`)
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

// ── Reusing a domain scan instead of spending a daily one ────────────────────

test('a completed payload is reusable, anything else is not', () => {
  assert.equal(isCompleted({ status: 'completed', results: { dns: {} } }), true)
  // Both halves matter: a scan in progress can already carry partial results,
  // and a completed record can carry none.
  assert.equal(isCompleted({ status: 'pending', results: { dns: {} } }), false, 'still running')
  assert.equal(isCompleted({ status: 'scanning', results: { dns: {} } }), false)
  assert.equal(isCompleted({ status: 'completed', results: null }), false, 'no results to reuse')
  assert.equal(isCompleted({ status: 'failed' }), false)
  assert.equal(isCompleted({}), false)
})

/** Record every request so a test can assert what was and was not called. */
function stubFetch(handler: (url: string, init?: { method?: string }) => unknown) {
  const calls: Array<{ url: string; method: string }> = []
  const original = globalThis.fetch
  // Types derived from `fetch` itself: this project compiles without the DOM
  // lib, so RequestInfo and friends are not in scope.
  type Args = Parameters<typeof fetch>
  globalThis.fetch = (async (input: Args[0], init?: Args[1]) => {
    const url = String(input)
    calls.push({ url, method: init?.method ?? 'GET' })
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => handler(url, init),
    } as unknown as Response
  }) as typeof fetch
  return { calls, restore: () => { globalThis.fetch = original } }
}

const COMPLETED = {
  domain: 'example.com',
  status: 'completed',
  scan_date: '2026-08-30 16:43:11 UTC',
  results: { subdomains: [], subdomains_suspicious: [] },
}

test('an existing completed scan is reused, and no scan is launched', async () => {
  // This is the whole point: POST spends one of 25 daily organisation scans,
  // the results read costs nothing.
  const f = stubFetch(() => COMPLETED)
  try {
    const states: string[] = []
    const r = await scanDomain({
      base: 'https://mlab.sh/api/v1',
      domain: 'example.com',
      timeoutMs: 5000,
      onState: (st) => states.push(st),
    })
    assert.equal(r.kind, 'domain')
    assert.deepEqual(states, ['reused'])
    assert.deepEqual(
      f.calls.map((c) => c.method),
      ['GET'],
      'exactly one request, and it must not be the POST that spends quota',
    )
    assert.ok(f.calls[0].url.includes('/scan/domain/results'))
  } finally {
    f.restore()
  }
})

test('with no usable scan, one is launched and then polled', async () => {
  let readCount = 0
  const f = stubFetch((url) => {
    if (url.includes('/scan/domain/results')) {
      readCount++
      // First read: nothing usable yet. Second read: the finished report.
      return readCount === 1 ? { status: 'pending', results: null } : COMPLETED
    }
    if (url.includes('/scan/domain/status')) return { status: 'completed' }
    return { status: 'started' }
  })
  try {
    const r = await scanDomain({
      base: 'https://mlab.sh/api/v1',
      domain: 'example.com',
      timeoutMs: 5000,
    })
    assert.equal(r.kind, 'domain')
    assert.ok(
      f.calls.some((c) => c.method === 'POST' && c.url.endsWith('/scan/domain')),
      'a scan must actually be launched when there is nothing to reuse',
    )
  } finally {
    f.restore()
  }
})

test('the domain summary reads the real envelope, not a flat payload', () => {
  // Captured from the live endpoint: the data sits under `results`, not at the top.
  const r = summarize('domain', 'badssl.com', {
    domain: 'badssl.com',
    status: 'completed',
    scan_date: '2026-08-30 16:43:11.682 UTC',
    results: {
      dns: {
        resolve: [{ a: ['104.154.89.105'], aaaa: [], cname: null, domain: 'badssl.com' }],
        txt: { dkim: [], dmarc: null, raw: ['x'], spf: null },
      },
      files: { robots_txt: 'User-agent: *', security_txt: 'not found' },
      ssl: [],
      subdomains: ['revoked.badssl.com'],
      subdomains_suspicious: [],
    },
  })
  const fact = (l: string) => r.facts.find((f) => f.label === l)?.value
  assert.equal(fact('Scanned'), '2026-08-30 16:43:11.682 UTC')
  assert.equal(fact('A records'), '104.154.89.105')
  assert.equal(fact('SPF'), 'absent')
  assert.equal(fact('DMARC'), 'absent')
  assert.equal(fact('Subdomains'), '1')
  assert.equal(fact('security.txt'), 'not found')
  assert.equal(r.verdict, undefined, 'no suspicious subdomains means no warning')
})

test('suspicious subdomains raise a warning verdict', () => {
  const r = summarize('domain', 'x.test', {
    status: 'completed',
    results: { subdomains: ['a', 'b'], subdomains_suspicious: ['login-x.test'] },
  })
  assert.equal(r.verdict?.tone, 'warn')
  assert.ok(r.verdict?.label.includes('1 suspicious subdomain'))
  assert.equal(r.facts.find((f) => f.label === 'Suspicious')?.value, 'login-x.test')
})

test('a domain payload missing every section does not throw', () => {
  assert.doesNotThrow(() => summarize('domain', 'x.test', {}))
  assert.doesNotThrow(() => summarize('domain', 'x.test', { results: {} }))
})
