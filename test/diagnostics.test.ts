import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { levelFor, locateLine, FLOOR_RANK } from '../src/diagnosticsCore'
import { Severity } from '../src/api/types'

// `npm test` runs from the package root, and tsconfig targets CommonJS, so
// import.meta is not available here.
const fixture = (name: string) =>
  readFileSync(join(process.cwd(), 'test', 'fixtures', name), 'utf8')

// ── severityFloor mapping ────────────────────────────────────────────────────

test('critical and high are errors, medium warnings, low and unknown information', () => {
  assert.equal(levelFor('critical', 'any'), 'error')
  assert.equal(levelFor('high', 'any'), 'error')
  assert.equal(levelFor('medium', 'any'), 'warning')
  assert.equal(levelFor('low', 'any'), 'information')
  assert.equal(levelFor('unknown', 'any'), 'information')
})

test('findings below the floor are demoted to information', () => {
  assert.equal(levelFor('medium', 'high'), 'information')
  assert.equal(levelFor('low', 'high'), 'information')
  assert.equal(levelFor('unknown', 'low'), 'information')
  // At the floor exactly is not below it.
  assert.equal(levelFor('high', 'high'), 'error')
  assert.equal(levelFor('medium', 'medium'), 'warning')
})

test('a floor of critical leaves only critical undemoted', () => {
  assert.equal(levelFor('critical', 'critical'), 'error')
  for (const sev of ['high', 'medium', 'low', 'unknown'] as Severity[]) {
    assert.equal(levelFor(sev, 'critical'), 'information', `${sev} should be demoted`)
  }
})

test('an unknown floor value behaves like "any" rather than hiding findings', () => {
  assert.equal(levelFor('medium', 'nonsense'), 'warning')
})

test('every floor declared in the manifest enum is ranked', () => {
  for (const floor of ['any', 'low', 'medium', 'high', 'critical']) {
    assert.ok(floor in FLOOR_RANK, `${floor} should have a rank`)
  }
})

// ── Locating a package in a lockfile ─────────────────────────────────────────

test('anchors on the declaration in Cargo.lock, not on a comment mentioning it', () => {
  const text = fixture('Cargo.lock')
  const hit = locateLine(text, 'time', '0.1.43')
  const line = text.split('\n')[hit.line]
  // The fixture's first line is a comment naming the crate and a different
  // version; the declaration is what the squiggle must land on.
  assert.equal(line.trim(), 'name = "time"', `landed on: ${line}`)
  assert.equal(line.slice(hit.col, hit.endCol), 'time')
})

test('comment lines never win over a real declaration', () => {
  const text = ['# see left-pad 1.0.0 advisory', 'x = 1', 'name = "left-pad"'].join('\n')
  const hit = locateLine(text, 'left-pad', '9.9.9')
  assert.equal(hit.line, 2, 'should skip the comment on line 0')
})

test('the version wins over an earlier bare mention, across nearby lines', () => {
  // First mention has no version anywhere near it; the second block does. This
  // is the Cargo.lock shape, where name and version sit on separate lines.
  const text = [
    'dependencies = ["time"]',
    '',
    '[[package]]',
    'name = "time"',
    'version = "0.1.43"',
  ].join('\n')
  const hit = locateLine(text, 'time', '0.1.43')
  assert.equal(hit.line, 3, 'should prefer the block that carries the version')
})

test('locates a package in package-lock.json on the line carrying its version', () => {
  const text = fixture('package-lock.json')
  const hit = locateLine(text, 'lodash', '4.17.11')
  const line = text.split('\n')[hit.line]
  assert.ok(line.includes('lodash'), `expected a lodash line, got: ${line}`)
  assert.ok(line.includes('4.17.11'), `expected the version on the same line, got: ${line}`)
  assert.equal(line.slice(hit.col, hit.endCol), 'lodash')
})

test('matches the name as a whole token, not as a substring', () => {
  const text = ['name = "serde_json"', 'name = "serde"'].join('\n')
  const hit = locateLine(text, 'serde', '')
  assert.equal(hit.line, 1, 'should skip serde_json and match serde')
})

test('falls back to the start of the file when the name is absent', () => {
  const hit = locateLine('nothing relevant here\nsecond line', 'ghost', '9.9.9')
  assert.equal(hit.line, 0)
  assert.equal(hit.col, 0)
})

test('a name containing regex metacharacters does not throw', () => {
  assert.doesNotThrow(() => locateLine('a\nb', 'foo.bar+baz(', '1.0'))
  const hit = locateLine('dep = "foo.bar" 1.0', 'foo.bar', '1.0')
  assert.equal(hit.line, 0)
})

test('handles CRLF line endings', () => {
  const hit = locateLine('first\r\nname = "left-pad"\r\n', 'left-pad', '')
  assert.equal(hit.line, 1)
  assert.equal(hit.endCol - hit.col, 'left-pad'.length)
})

test('an empty file does not produce an out of range position', () => {
  const hit = locateLine('', 'anything', '1.0')
  assert.equal(hit.line, 0)
  assert.equal(hit.col, 0)
  assert.equal(hit.endCol, 0)
})
