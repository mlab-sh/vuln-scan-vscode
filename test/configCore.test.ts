import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseFlatYaml, validateConfig, dropIgnored } from '../src/configCore'
import type { ScanOutcome } from '../src/api/client'

test('parses the scalars and lists a vuln.yml uses', () => {
  const text = [
    '# mlab settings for this repo',
    'disable: true',
    'autoScan: no   # quiet please',
    'timeoutMs: 15000',
    'apiUrl: "https://scan.internal/api#v2"',
    "severityFloor: 'high'",
    'empty:',
    'nested:',
    '  child: 1',
    'ignoreVulns:',
    '  - CVE-2024-0001   # accepted, not reachable',
    '',
    '  - "GHSA-xxxx-yyyy-zzzz"',
    'inline: [a, "b", c]',
  ].join('\n')
  assert.deepEqual(parseFlatYaml(text), {
    disable: true,
    autoScan: false,
    timeoutMs: 15000,
    apiUrl: 'https://scan.internal/api#v2',
    severityFloor: 'high',
    ignoreVulns: ['CVE-2024-0001', 'GHSA-xxxx-yyyy-zzzz'],
    inline: ['a', 'b', 'c'],
  })
})

test('validation keeps good values and names every bad one', () => {
  const { values, problems } = validateConfig(
    {
      autoScan: false,
      autoscan: true,
      severityFloor: 'hgih',
      timeoutMs: 10,
      apiUrl: 'ftp://x',
      ignoreVulns: 'CVE-1',
      disable: true,
    },
    false,
  )
  assert.deepEqual(values, { autoScan: false, ignoreVulns: ['CVE-1'] })
  assert.equal(problems.length, 5)
  assert.ok(problems.some((p) => p.includes('did you mean autoScan')))
  assert.ok(problems.some((p) => p.startsWith('disable:')))
  assert.deepEqual(validateConfig({ disable: true }, true).values, { disable: true })
})

test('dropIgnored matches ids and aliases, case insensitive', () => {
  const f = (cve: string, aliases?: string[]) =>
    ({ pkg: 'a@1', name: 'a', version: '1', cve, severity: 'high', aliases }) as const
  const outcome: ScanOutcome = {
    findings: [f('CVE-1'), f('CVE-2', ['GHSA-abcd']), f('CVE-3')],
    unresolved: [],
    deps: 1,
    truncated: false,
    hash: 'h',
  }
  assert.deepEqual(
    dropIgnored(outcome, ['cve-1', 'ghsa-ABCD']).findings.map((x) => x.cve),
    ['CVE-3'],
  )
  assert.equal(dropIgnored(outcome, []), outcome)
})
