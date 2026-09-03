import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  severityOf,
  cveOf,
  fixedVersionOf,
  buildOutcome,
  summarize,
} from '../src/api/client'
import { baseScoreV3, roundUp, scoreOf } from '../src/api/cvss'
import { OsvVuln, ScanResponse } from '../src/api/types'

// ── CVSS scoring ─────────────────────────────────────────────────────────────

test('roundUp follows the v3.1 spec, not Math.ceil on one decimal', () => {
  // An exact tenth stays put rather than being pushed to the next one.
  assert.equal(roundUp(4.0), 4.0)
  assert.equal(roundUp(6.2), 6.2)
  assert.equal(roundUp(0), 0)
  // Anything above a tenth rounds up to it.
  assert.equal(roundUp(6.11), 6.2)
  assert.equal(roundUp(4.00001), 4.1)
  // The spec rounds to hundred-thousandths first, which is the point: float
  // noise below that threshold must not push a score to the next tenth.
  assert.equal(roundUp(4.0000001), 4)
})

test('scores the exact vector the live API returns for CVE-2020-26235', () => {
  // Captured from vuln.mlab.sh. NVD publishes 6.2 for this vector.
  const v = 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
  assert.equal(baseScoreV3(v), 6.2)
})

test('scores known reference vectors', () => {
  // Log4Shell, the canonical 10.0.
  assert.equal(baseScoreV3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10)
  // A plain network critical with unchanged scope.
  assert.equal(baseScoreV3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8)
  // No impact at all scores zero.
  assert.equal(baseScoreV3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0)
})

test('accepts 3.0 as well as 3.1', () => {
  assert.equal(
    baseScoreV3('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    baseScoreV3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
  )
})

test('refuses vectors it cannot score rather than guessing', () => {
  assert.equal(baseScoreV3('AV:N/AC:L/Au:N/C:P/I:P/A:P'), undefined, 'v2 vector')
  assert.equal(baseScoreV3('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N'), undefined, 'v4 vector')
  assert.equal(baseScoreV3('CVSS:3.1/AV:N/AC:L'), undefined, 'missing base metrics')
  assert.equal(baseScoreV3('not a vector'), undefined)
})

test('scoreOf handles a bare number, a vector, and junk', () => {
  assert.equal(scoreOf('7.5'), 7.5)
  assert.equal(scoreOf('  9.8  '), 9.8)
  assert.equal(scoreOf('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), 6.2)
  assert.equal(scoreOf(''), undefined)
  assert.equal(scoreOf('AV:N/AC:L/Au:N/C:P/I:P/A:P'), undefined)
})

// ── severityOf ───────────────────────────────────────────────────────────────

test('database_specific.severity wins over the CVSS vector', () => {
  const v: OsvVuln = {
    database_specific: { severity: 'LOW' },
    severity: [{ score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  }
  assert.equal(severityOf(v), 'low')
})

test('GitHub\'s "moderate" maps onto our "medium"', () => {
  assert.equal(severityOf({ database_specific: { severity: 'MODERATE' } }), 'medium')
  assert.equal(severityOf({ database_specific: { severity: 'moderate' } }), 'medium')
})

test('an unrecognised database_specific value is unknown, not a crash', () => {
  assert.equal(severityOf({ database_specific: { severity: 'SPICY' } }), 'unknown')
})

test('a CVSS vector alone yields a real band', () => {
  // This is the regression that mattered: the live API returns advisories with
  // no database_specific severity and only a vector. They used to read unknown.
  const v: OsvVuln = {
    id: 'RUSTSEC-2020-0071',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }],
  }
  assert.equal(severityOf(v), 'medium')
})

test('CVSS bands sit on the documented boundaries', () => {
  const at = (score: number) => severityOf({ severity: [{ score: String(score) }] })
  assert.equal(at(10), 'critical')
  assert.equal(at(9), 'critical')
  assert.equal(at(8.9), 'high')
  assert.equal(at(7), 'high')
  assert.equal(at(6.9), 'medium')
  assert.equal(at(4), 'medium')
  assert.equal(at(3.9), 'low')
  assert.equal(at(0.1), 'low')
  assert.equal(at(0), 'unknown')
})

test('an unscoreable entry falls through to the next one', () => {
  const v: OsvVuln = {
    severity: [
      { type: 'CVSS_V2', score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' },
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    ],
  }
  assert.equal(severityOf(v), 'critical')
})

test('no severity information at all is unknown', () => {
  assert.equal(severityOf({}), 'unknown')
  assert.equal(severityOf({ severity: [] }), 'unknown')
})

// ── cveOf ────────────────────────────────────────────────────────────────────

test('a CVE alias is preferred over the advisory id', () => {
  assert.equal(
    cveOf({ id: 'GHSA-wcg3-cvx6-7396', aliases: ['RUSTSEC-2020-0071', 'CVE-2020-26235'] }),
    'CVE-2020-26235',
  )
})

test('without a CVE alias the advisory id is used', () => {
  assert.equal(cveOf({ id: 'GHSA-xxxx', aliases: ['RUSTSEC-2020-0071'] }), 'GHSA-xxxx')
  assert.equal(cveOf({ id: 'RUSTSEC-2020-0071' }), 'RUSTSEC-2020-0071')
})

test('a vuln with neither is labelled rather than dropped', () => {
  assert.equal(cveOf({}), 'UNKNOWN')
})

// ── fixedVersionOf ───────────────────────────────────────────────────────────

test('takes the last fixed event across every affected range', () => {
  const v: OsvVuln = {
    affected: [
      { ranges: [{ events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] },
      { ranges: [{ events: [{ introduced: '2.0.0' }, { fixed: '2.3.1' }] }] },
    ],
  }
  assert.equal(fixedVersionOf(v), '2.3.1')
})

test('an introduced-only range has no fixed version', () => {
  assert.equal(fixedVersionOf({ affected: [{ ranges: [{ events: [{ introduced: '0' }] }] }] }), undefined)
  assert.equal(fixedVersionOf({}), undefined)
})

// ── buildOutcome ─────────────────────────────────────────────────────────────

/** The two-advisory, one-CVE shape the live API returns for the fixture. */
const duplicated: ScanResponse = {
  hash: 'abc123',
  count: 2,
  truncated: false,
  packages: [
    { ecosystem: 'crates.io', name: 'time', version: '0.1.43' },
    { ecosystem: 'crates.io', name: 'serde', version: '1.0.100' },
  ],
  results: [
    {
      ok: true,
      vulns: [
        {
          id: 'GHSA-wcg3-cvx6-7396',
          aliases: ['CVE-2020-26235', 'RUSTSEC-2020-0071'],
          summary: 'Segmentation fault in time',
          severity: [{ score: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }],
        },
        {
          id: 'RUSTSEC-2020-0071',
          aliases: ['CVE-2020-26235', 'GHSA-wcg3-cvx6-7396'],
          summary: 'Potential segfault in the time crate',
          database_specific: { severity: 'HIGH' },
          affected: [{ ranges: [{ events: [{ fixed: '0.2.23' }] }] }],
        },
      ],
    },
    { ok: true, vulns: [] },
  ],
}

test('the same CVE arriving as two advisories collapses into one finding', () => {
  const out = buildOutcome(duplicated)
  assert.equal(out.findings.length, 1)
  assert.equal(out.findings[0].cve, 'CVE-2020-26235')
})

test('collapsing keeps the highest severity of the group', () => {
  const out = buildOutcome(duplicated)
  // medium from the vector, high from database_specific: high must win.
  assert.equal(out.findings[0].severity, 'high')
})

test('collapsing backfills the fixed version from whichever advisory has it', () => {
  const out = buildOutcome(duplicated)
  assert.equal(out.findings[0].fixedVersion, '0.2.23')
})

test('findings link to their CVE page only for real CVE ids', () => {
  const out = buildOutcome(duplicated)
  assert.equal(out.findings[0].url, 'https://vuln.mlab.sh/cve/CVE-2020-26235')

  const ghsaOnly = buildOutcome({
    hash: 'h', count: 1, truncated: false,
    packages: [{ name: 'x', version: '1.0' }],
    results: [{ ok: true, vulns: [{ id: 'GHSA-zzzz' }] }],
  })
  assert.equal(ghsaOnly.findings[0].url, undefined)
})

test('unresolvable packages are collected, never counted as clean', () => {
  const out = buildOutcome({
    hash: 'h', count: 2, truncated: false,
    packages: [{ name: 'ok-pkg', version: '1.0' }, { name: 'mystery', version: '2.0' }],
    results: [{ ok: true, vulns: [] }, { ok: false }],
  })
  assert.deepEqual(out.unresolved, ['mystery@2.0'])
  assert.equal(out.findings.length, 0)
})

test('a result with no matching package entry is still reported by index', () => {
  const out = buildOutcome({
    hash: 'h', count: 1, truncated: false,
    results: [{ ok: true, vulns: [{ id: 'GHSA-a' }] }],
  })
  assert.equal(out.findings[0].pkg, '#0')
})

test('metadata is carried through untouched', () => {
  const out = buildOutcome({ ...duplicated, truncated: true, count: 512 })
  assert.equal(out.hash, 'abc123')
  assert.equal(out.deps, 512)
  assert.equal(out.truncated, true)
})

// ── summarize ────────────────────────────────────────────────────────────────

const finding = (severity: string, pkg: string) =>
  ({ pkg, name: pkg, version: '1', cve: `CVE-${pkg}`, severity }) as never

test('a clean outcome says so plainly', () => {
  assert.equal(
    summarize({ findings: [], unresolved: [], deps: 10, truncated: false, hash: 'h' }),
    'No known vulnerabilities found',
  )
})

test('counts are listed worst first and packages are deduplicated', () => {
  const out = {
    findings: [
      finding('low', 'a'),
      finding('critical', 'b'),
      finding('critical', 'b'),
      finding('medium', 'a'),
    ],
    unresolved: [], deps: 9, truncated: false, hash: 'h',
  }
  // Two distinct packages despite four findings.
  assert.equal(summarize(out), '2 critical, 1 medium, 1 low across 2 packages')
})

test('a single package is not pluralised', () => {
  const out = {
    findings: [finding('high', 'solo')],
    unresolved: [], deps: 1, truncated: false, hash: 'h',
  }
  assert.equal(summarize(out), '1 high across 1 package')
})
