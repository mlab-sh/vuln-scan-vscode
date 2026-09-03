import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  LOCKFILES,
  KNOWN,
  SUPPORTED_BASENAMES,
  lockfileGlob,
  excludeGlob,
  whenClause,
  supportedSentence,
  SKIP_DIRS,
} from '../src/detect'

// package.json cannot import src/detect.ts, so these tests are what keeps the
// manifest honest. If one fails, run `npm run sync:manifest`.

const manifest = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'))

// ── Everything derives from one array ────────────────────────────────────────

test('KNOWN and SUPPORTED_BASENAMES are both derived, not hand maintained', () => {
  assert.equal(Object.keys(KNOWN).length, LOCKFILES.length)
  assert.equal(SUPPORTED_BASENAMES.length, LOCKFILES.length)
  for (const { name, format } of LOCKFILES) {
    assert.equal(KNOWN[name.toLowerCase()], format, `${name} should map to ${format}`)
    assert.ok(SUPPORTED_BASENAMES.includes(name))
  }
})

test('no lockfile is listed twice', () => {
  const lowered = LOCKFILES.map((l) => l.name.toLowerCase())
  assert.equal(new Set(lowered).size, lowered.length)
})

test('the globs cover every lockfile and every skipped directory', () => {
  const glob = lockfileGlob()
  for (const name of SUPPORTED_BASENAMES) {
    assert.ok(glob.includes(name), `${name} missing from the glob`)
  }
  for (const dir of SKIP_DIRS) {
    assert.ok(excludeGlob().includes(dir), `${dir} missing from the exclude glob`)
  }
})

// ── The manifest agrees with the source ──────────────────────────────────────

/** Every menu entry that is gated on "this file is a lockfile". */
function gatedEntries(): Array<{ menu: string; command: string; when: string }> {
  const out: Array<{ menu: string; command: string; when: string }> = []
  for (const menu of ['explorer/context', 'editor/context']) {
    for (const e of manifest.contributes.menus[menu] ?? []) {
      if (typeof e.when === 'string' && e.when.startsWith('resourceFilename =~')) {
        out.push({ menu, command: e.command, when: e.when })
      }
    }
  }
  return out
}

test('every lockfile-gated menu entry uses the generated when clause', () => {
  const entries = gatedEntries()
  assert.ok(entries.length > 0, 'expected some gated entries')
  for (const e of entries) {
    assert.equal(
      e.when,
      whenClause(),
      `${e.menu} / ${e.command} has drifted. Run: npm run sync:manifest`,
    )
  }
})

test('the when clause actually matches the lockfiles and rejects other files', () => {
  const source = whenClause().replace('resourceFilename =~ /', '').replace(/\/i$/, '')
  const re = new RegExp(source, 'i')
  for (const name of SUPPORTED_BASENAMES) {
    assert.ok(re.test(name), `${name} should match the menu clause`)
  }
  for (const name of ['README.md', 'Cargo.toml', 'yarn.lock', 'main.rs', 'package.json']) {
    assert.equal(re.test(name), false, `${name} should not match`)
  }
})

test('the welcome text lists exactly the supported lockfiles', () => {
  const contents: string = manifest.contributes.viewsWelcome[0].contents
  assert.ok(
    contents.includes(supportedSentence()),
    'welcome text has drifted. Run: npm run sync:manifest',
  )
})

test('the manifest declares an activation event covering every lockfile', () => {
  const events: string[] = manifest.activationEvents ?? []
  const workspaceContains = events.find((e) => e.startsWith('workspaceContains:'))
  assert.ok(workspaceContains, 'expected a workspaceContains activation event')
  for (const name of SUPPORTED_BASENAMES) {
    assert.ok(workspaceContains.includes(name), `${name} missing from the activation glob`)
  }
})

// ── The test workspace keeps up with the source ──────────────────────────────

test('every supported lockfile has a fixture to exercise it', () => {
  const dir = join(process.cwd(), 'test', 'fixtures')
  const present = readdirSync(dir)
  for (const name of SUPPORTED_BASENAMES) {
    assert.ok(
      present.includes(name),
      `${name} is supported but has no fixture in test/fixtures. Add one so F5 can exercise it.`,
    )
  }
})

test('the fixtures include the cases the exclude glob must reject', () => {
  const dir = join(process.cwd(), 'test', 'fixtures')
  assert.ok(
    existsSync(join(dir, 'node_modules', 'leftpad', 'package-lock.json')),
    'a lockfile inside node_modules is what proves the exclude glob works',
  )
  assert.ok(
    existsSync(join(dir, 'nested', 'deep', 'Cargo.lock')),
    'a nested lockfile is what proves the sweep recurses',
  )
})
