import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  basenameOf,
  detectFormat,
  isSupportedLockfile,
  KNOWN,
  SUPPORTED_BASENAMES,
} from '../src/detect'

test('every supported basename maps to a format hint', () => {
  for (const name of SUPPORTED_BASENAMES) {
    assert.ok(isSupportedLockfile(name), `${name} should be supported`)
    assert.ok(detectFormat(name), `${name} should have a format`)
  }
})

test('detectFormat returns the expected parser hints', () => {
  assert.equal(detectFormat('Cargo.lock'), 'cargo')
  assert.equal(detectFormat('package-lock.json'), 'npm')
  assert.equal(detectFormat('npm-shrinkwrap.json'), 'npm')
  assert.equal(detectFormat('composer.lock'), 'composer')
  assert.equal(detectFormat('Gemfile.lock'), 'gem')
  assert.equal(detectFormat('go.sum'), 'go')
  assert.equal(detectFormat('requirements.txt'), 'pip')
  assert.equal(detectFormat('mise.lock'), 'mise')
})

test('detection works on full paths and is case-insensitive', () => {
  assert.equal(detectFormat('/home/me/project/Cargo.lock'), 'cargo')
  assert.equal(detectFormat('C:\\proj\\package-lock.json'), 'npm')
  assert.equal(detectFormat('cargo.lock'), 'cargo')
  assert.ok(isSupportedLockfile('/a/b/GEMFILE.LOCK'))
})

test('unsupported files are rejected', () => {
  for (const name of ['README.md', 'main.rs', 'yarn.lock', 'Cargo.toml', 'notes.txt']) {
    assert.equal(isSupportedLockfile(name), false, `${name} should not be supported`)
    assert.equal(detectFormat(name), undefined)
  }
})

test('basenameOf handles both separators', () => {
  assert.equal(basenameOf('/a/b/c/go.sum'), 'go.sum')
  assert.equal(basenameOf('a\\b\\go.sum'), 'go.sum')
  assert.equal(basenameOf('go.sum'), 'go.sum')
})

test('KNOWN keys are all lowercase', () => {
  for (const key of Object.keys(KNOWN)) {
    assert.equal(key, key.toLowerCase(), `${key} should be lowercase`)
  }
})
