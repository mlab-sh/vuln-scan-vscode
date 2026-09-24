import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ScanCache,
  CacheEntry,
  Store,
  expiredKeys,
  hashOf,
  keyOf,
  worstOf,
  RETENTION_MS,
  DEFAULT_MAX_AGE_MS,
} from '../src/cache'
import { ScanOutcome } from '../src/api/client'
import { sha256Hex as webSha256 } from '../src/platform.web'

const DAY = 24 * 60 * 60 * 1000

/**
 * A Memento standing in for globalState.
 *
 * It clones on both read and write on purpose: the real one serializes to disk,
 * so it never hands back a live reference. Sharing the reference would make a
 * missing `update` call invisible, since mutating the cache in memory would also
 * appear to mutate storage.
 */
function store(initial: Record<string, unknown> = {}): Store & {
  readonly raw: Record<string, unknown>
} {
  let disk = structuredClone(initial)
  return {
    get raw() {
      return structuredClone(disk)
    },
    get<T>(key: string, defaultValue: T): T {
      return (key in disk ? structuredClone(disk[key]) : defaultValue) as T
    },
    async update(key: string, value: unknown) {
      disk = { ...disk, [key]: structuredClone(value) }
    },
  }
}

const outcome = (findings: Array<{ severity: string }> = []): ScanOutcome =>
  ({ findings, unresolved: [], deps: 1, truncated: false, hash: 'h' }) as never

const entry = (fsPath: string, agedDays: number, hash = 'aa'): CacheEntry => ({
  hash,
  fsPath,
  filename: fsPath.split('/').pop() ?? fsPath,
  findingCount: 0,
  worstSeverity: 'none',
  outcome: outcome(),
  at: Date.now() - agedDays * DAY,
})

const seeded = (entries: CacheEntry[]) =>
  store({ 'mlab.scanCache.v1': Object.fromEntries(entries.map((e) => [e.fsPath, e])) })

// ── The two bounds are different ─────────────────────────────────────────────

test('freshness and retention are distinct bounds', () => {
  assert.equal(DEFAULT_MAX_AGE_MS, 7 * DAY, 'freshness is 7 days')
  assert.equal(RETENTION_MS, 30 * DAY, 'retention is 30 days')
  assert.ok(RETENTION_MS > DEFAULT_MAX_AGE_MS, 'an entry must outlive its freshness')
})

test('an entry past freshness but within retention is kept, just not trusted', async () => {
  const s = seeded([entry('/p/Cargo.lock', 10)])
  const cache = new ScanCache(s)

  assert.equal(cache.lookup('/p/Cargo.lock', 'aa'), undefined, 'too old to trust')
  assert.ok(cache.peek('/p/Cargo.lock'), 'but still on disk')

  await cache.prune()
  assert.ok(cache.peek('/p/Cargo.lock'), 'and survives a prune')
})

// ── Retention ────────────────────────────────────────────────────────────────

test('expiredKeys picks out only what is past retention', () => {
  const now = Date.now()
  const entries = {
    fresh: entry('fresh', 1),
    borderline: entry('borderline', 29),
    stale: entry('stale', 31),
    ancient: entry('ancient', 400),
  }
  assert.deepEqual(expiredKeys(entries, now).sort(), ['ancient', 'stale'])
})

test('exactly at the retention boundary is kept, past it is dropped', () => {
  const now = 1_000_000_000_000
  const at = (age: number) => ({ x: { ...entry('x', 0), at: now - age } })
  assert.deepEqual(expiredKeys(at(RETENTION_MS), now), [], 'exactly 30 days survives')
  assert.deepEqual(expiredKeys(at(RETENTION_MS + 1), now), ['x'], 'a millisecond past goes')
})

test('prune removes stale entries and persists the result', async () => {
  const s = seeded([entry('/a', 1), entry('/b', 45), entry('/c', 90)])
  const cache = new ScanCache(s)

  const removed = await cache.prune()
  assert.equal(removed, 2)
  assert.deepEqual(cache.paths(), ['/a'])

  // The store, not just the in-memory copy, must reflect it.
  const persisted = s.raw['mlab.scanCache.v1'] as Record<string, CacheEntry>
  assert.deepEqual(Object.keys(persisted), ['/a'])
})

test('prune on a clean cache reports nothing removed', async () => {
  const s = seeded([entry('/a', 1)])
  const removed = await new ScanCache(s).prune()
  assert.equal(removed, 0)
  assert.deepEqual(Object.keys(s.raw['mlab.scanCache.v1'] as object), ['/a'])
})

test('writing an entry also evicts what is past retention', async () => {
  const s = seeded([entry('/old', 60)])
  const cache = new ScanCache(s)
  await cache.put('/new/Cargo.lock', 'Cargo.lock', 'bb', outcome())

  assert.deepEqual(cache.paths(), ['/new/Cargo.lock'], 'the stale entry went with the write')
})

// ── Lookup semantics ─────────────────────────────────────────────────────────

test('a lookup only hits when the content hash matches', () => {
  const cache = new ScanCache(seeded([entry('/p/go.sum', 0, 'hash-one')]))
  assert.ok(cache.lookup('/p/go.sum', 'hash-one'))
  assert.equal(cache.lookup('/p/go.sum', 'hash-two'), undefined, 'edited file must miss')
  assert.equal(cache.lookup('/other', 'hash-one'), undefined)
})

test('peek ignores age, which is what keeps a file marked red', () => {
  const cache = new ScanCache(seeded([entry('/p/Cargo.lock', 20)]))
  assert.equal(cache.lookup('/p/Cargo.lock', 'aa'), undefined)
  assert.ok(cache.peek('/p/Cargo.lock'), 'the decoration still has something to read')
})

test('forget and clearAll persist', async () => {
  const s = seeded([entry('/a', 0), entry('/b', 0)])
  const cache = new ScanCache(s)

  await cache.forget('/a')
  assert.deepEqual(cache.paths(), ['/b'])

  await cache.clearAll()
  assert.deepEqual(cache.paths(), [])
  assert.deepEqual(s.raw['mlab.scanCache.v1'], {})
})

// ── Supporting helpers ───────────────────────────────────────────────────────

test('hashOf is stable and content sensitive', async () => {
  const a = await hashOf(new TextEncoder().encode('name = "time"'))
  const b = await hashOf(new TextEncoder().encode('name = "time"'))
  const c = await hashOf(new TextEncoder().encode('name = "time" '))
  assert.equal(a, b)
  assert.notEqual(a, c)
  assert.match(a, /^[0-9a-f]{64}$/)
})

test('the web build hashes exactly like the Node build', async () => {
  // Otherwise a cache filled on desktop would miss in the browser, and back.
  const body = new TextEncoder().encode('name = "time"\nversion = "0.3.36"\n')
  assert.equal(await webSha256(body), await hashOf(body))
})

test('keyOf keeps plain paths for local files and full URIs otherwise', () => {
  const local = { scheme: 'file', fsPath: '/repo/Cargo.lock', toString: () => 'file:///repo/Cargo.lock' }
  assert.equal(keyOf(local), '/repo/Cargo.lock')
  const vfs = {
    scheme: 'vscode-vfs',
    fsPath: '/o/r/Cargo.lock',
    toString: () => 'vscode-vfs://github/o/r/Cargo.lock',
  }
  assert.equal(keyOf(vfs), 'vscode-vfs://github/o/r/Cargo.lock')
})

test('worstOf reports the highest severity present', () => {
  assert.equal(worstOf(outcome()), 'none')
  assert.equal(worstOf(outcome([{ severity: 'low' }, { severity: 'critical' }])), 'critical')
  assert.equal(worstOf(outcome([{ severity: 'medium' }, { severity: 'high' }])), 'high')
  assert.equal(worstOf(outcome([{ severity: 'unknown' }])), 'unknown')
})
