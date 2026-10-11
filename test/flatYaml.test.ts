import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseFlatYaml } from '../src/flatYaml'

test('parses the scalars a vuln.yml uses', () => {
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
    '- item',
  ].join('\n')
  assert.deepEqual(parseFlatYaml(text), {
    disable: true,
    autoScan: false,
    timeoutMs: 15000,
    apiUrl: 'https://scan.internal/api#v2',
    severityFloor: 'high',
  })
})
