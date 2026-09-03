import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  parseRecord,
  pickExact,
  intelUrl,
  epssLabel,
  urgencyOf,
  CveIntel,
} from '../src/api/intel'
import { IntelCache, INTEL_MAX_AGE_MS, INTEL_RETENTION_MS } from '../src/intelCache'
import { Store } from '../src/cache'

const DAY = 24 * 60 * 60 * 1000

/** A record shaped exactly like the live API returns, captured from it. */
const LOG4SHELL = {
  id: 'CVE-2021-44228',
  cvss_score: 10.0,
  cvss_severity: 'CRITICAL',
  cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  epss_score: 0.99999,
  epss_percentile: 1.0,
  in_kev: true,
  in_eu_kev: false,
  kev_date_added: '2021-12-10',
  kev_due_date: '2021-12-24',
  risk_score: 100.0,
  weaknesses: ['CWE-20', 'CWE-400', 'CWE-502', 'CWE-917'],
}

// ── Parsing ──────────────────────────────────────────────────────────────────

test('parses the live API record shape', () => {
  const i = parseRecord(LOG4SHELL)!
  assert.equal(i.id, 'CVE-2021-44228')
  assert.equal(i.cvssScore, 10)
  assert.equal(i.cvssSeverity, 'critical', 'severity is lowercased to match our bands')
  assert.equal(i.epssScore, 0.99999)
  assert.equal(i.inKev, true)
  assert.equal(i.kevDueDate, '2021-12-24')
  assert.deepEqual(i.weaknesses, ['CWE-20', 'CWE-400', 'CWE-502', 'CWE-917'])
})

test('nulls and missing fields do not become garbage', () => {
  const i = parseRecord({
    id: 'CVE-2020-26235',
    cvss_score: null,
    epss_score: null,
    kev_date_added: null,
    in_kev: false,
    weaknesses: null,
  })!
  assert.equal(i.cvssScore, undefined)
  assert.equal(i.epssScore, undefined)
  assert.equal(i.kevDateAdded, undefined)
  assert.equal(i.inKev, false)
  assert.deepEqual(i.weaknesses, [], 'a null weakness list is an empty list, not a crash')
})

test('a record with no id is rejected', () => {
  assert.equal(parseRecord({ cvss_score: 9 }), undefined)
  assert.equal(parseRecord({ id: '' }), undefined)
})

test('in_kev only counts when it is really true', () => {
  assert.equal(parseRecord({ id: 'CVE-1', in_kev: 'yes' })!.inKev, false)
  assert.equal(parseRecord({ id: 'CVE-1' })!.inKev, false)
})

// ── Exact matching ───────────────────────────────────────────────────────────

test('picks the requested id, not whatever came back first', () => {
  // The endpoint is a search, so a query can return neighbours too.
  const records = [
    { id: 'CVE-2021-45046', cvss_score: 9 },
    { id: 'CVE-2021-44228', cvss_score: 10 },
  ]
  assert.equal(pickExact('CVE-2021-44228', records)!.cvssScore, 10)
})

test('matching is case insensitive but never approximate', () => {
  const records = [{ id: 'CVE-2021-44228' }]
  assert.ok(pickExact('cve-2021-44228', records))
  assert.equal(pickExact('CVE-2021-4422', records), undefined, 'a prefix is not a match')
  assert.equal(pickExact('CVE-2021-44228', []), undefined)
  assert.equal(pickExact('CVE-2021-44228', null), undefined)
})

test('the query url targets the documented endpoint on the given origin', () => {
  const u = new URL(intelUrl('https://vuln.mlab.sh', 'CVE-2021-44228'))
  assert.equal(u.origin, 'https://vuln.mlab.sh')
  assert.equal(u.pathname, '/api/v1/cve')
  assert.equal(u.searchParams.get('q'), 'CVE-2021-44228')
})

test('a self-hosted origin is honoured', () => {
  const u = new URL(intelUrl('https://vuln.internal.example', 'CVE-2020-26235'))
  assert.equal(u.origin, 'https://vuln.internal.example')
  assert.equal(u.pathname, '/api/v1/cve')
})

// ── Presentation ─────────────────────────────────────────────────────────────

const withEpss = (score?: number, kev = false): CveIntel =>
  ({ id: 'CVE-x', epssScore: score, inKev: kev, inEuKev: false, weaknesses: [] })

test('EPSS reads as a percentage at a useful precision', () => {
  assert.equal(epssLabel(withEpss(0.99999)), '100%')
  assert.equal(epssLabel(withEpss(0.14)), '14%')
  assert.equal(epssLabel(withEpss(0.01641)), '1.6%')
  assert.equal(epssLabel(withEpss(0.0002)), '0.02%')
  assert.equal(epssLabel(withEpss(0.00001)), '<0.01%')
  assert.equal(epssLabel(withEpss(undefined)), undefined)
})

test('being in a catalogue outranks any likelihood score', () => {
  // Actively exploited beats a high probability, which beats everything else.
  assert.equal(urgencyOf(withEpss(0.00001, true)), 'exploited')
  assert.equal(urgencyOf(withEpss(0.5)), 'likely')
  assert.equal(urgencyOf(withEpss(0.1)), 'likely', 'the threshold is inclusive')
  assert.equal(urgencyOf(withEpss(0.099)), 'normal')
  assert.equal(urgencyOf(undefined), 'normal')
})

// ── Cache ────────────────────────────────────────────────────────────────────

function store(initial: Record<string, unknown> = {}): Store {
  let disk = structuredClone(initial)
  return {
    get<T>(key: string, dflt: T): T {
      return (key in disk ? structuredClone(disk[key]) : dflt) as T
    },
    async update(key: string, value: unknown) {
      disk = { ...disk, [key]: structuredClone(value) }
    },
  }
}

const intelOf = (id: string): CveIntel => ({ id, inKev: false, inEuKev: false, weaknesses: [] })

test('freshness is a day, retention a month', () => {
  assert.equal(INTEL_MAX_AGE_MS, DAY)
  assert.equal(INTEL_RETENTION_MS, 30 * DAY)
})

test('partition separates what is cached from what must be fetched', async () => {
  const c = new IntelCache(store())
  await c.putAll(new Map([['CVE-A', intelOf('CVE-A')]]))

  const { known, missing } = c.partition(['CVE-A', 'CVE-B', 'CVE-B'])
  assert.deepEqual([...known.keys()], ['CVE-A'])
  assert.deepEqual(missing, ['CVE-B'], 'duplicates are asked for once')
})

test('a record past its freshness is refetched, not served stale', async () => {
  const c = new IntelCache(store())
  const now = Date.now()
  await c.putAll(new Map([['CVE-A', intelOf('CVE-A')]]), now - 2 * DAY)

  assert.equal(c.get('CVE-A', now), undefined, 'too old to trust')
  assert.deepEqual(c.partition(['CVE-A'], now).missing, ['CVE-A'])
})

test('records past retention are dropped on write', async () => {
  const c = new IntelCache(store())
  const now = Date.now()
  await c.putAll(new Map([['CVE-OLD', intelOf('CVE-OLD')]]), now - 40 * DAY)
  await c.putAll(new Map([['CVE-NEW', intelOf('CVE-NEW')]]), now)
  assert.equal(c.size, 1, 'the 40 day old record went')
  assert.ok(c.get('CVE-NEW', now))
})

test('writes survive a new cache over the same store', async () => {
  const s = store()
  await new IntelCache(s).putAll(new Map([['CVE-A', intelOf('CVE-A')]]))
  assert.ok(new IntelCache(s).get('CVE-A'), 'must have been persisted')
})
