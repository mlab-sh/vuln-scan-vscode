// Pure configuration logic: the settings shape and defaults, the `.mlab/vuln.yml`
// parser, validation of every config file, and the ignore list filter. No
// `vscode` import, so all of it is unit tested.

import type { ScanOutcome } from './api/client'

export interface MlabConfig {
  apiUrl: string
  /** Base of the mlab platform API, used for indicator lookups. */
  platformUrl: string
  severityFloor: 'any' | 'low' | 'medium' | 'high' | 'critical'
  timeoutMs: number
  autoScan: boolean
  /** Skip lockfiles that git ignores, in the workspace sweep and auto scans. */
  ignoreGitIgnored: boolean
  cveHover: boolean
  analyzeSelection: boolean
  /** Advisory ids (CVE, GHSA, RUSTSEC ...) accepted as known risk and hidden. */
  ignoreVulns: string[]
}

export const DEFAULTS: MlabConfig = {
  apiUrl: 'https://vuln.mlab.sh/api/v2/scan',
  platformUrl: 'https://mlab.sh/api/v1',
  severityFloor: 'any',
  timeoutMs: 30000,
  autoScan: true,
  ignoreGitIgnored: true,
  cveHover: true,
  analyzeSelection: true,
  ignoreVulns: [],
}

export const SEVERITY_FLOORS = ['any', 'low', 'medium', 'high', 'critical'] as const

// ── vuln.yml ─────────────────────────────────────────────────────────────────
// ponytail: flat `key: scalar` plus lists of scalars (block `- item` or inline
// `[a, b]`), with comments and quotes. Nested maps are ignored. Swap for a real
// YAML parser if the file ever needs deeper structure.

export type YamlValue = string | number | boolean | string[]

export function parseFlatYaml(text: string): Record<string, YamlValue> {
  const out: Record<string, YamlValue> = {}
  let listKey: string | undefined
  for (const raw of text.split(/\r?\n/)) {
    if (/^\s*(#.*)?$/.test(raw)) continue
    const item = /^\s*-\s+(.*)$/.exec(raw)
    if (item && listKey) {
      const v = scalar(item[1])
      if (v !== undefined) (out[listKey] as string[]).push(String(v))
      continue
    }
    if (/^\s/.test(raw)) continue // indented, not a list item: nested map
    listKey = undefined
    const m = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(raw)
    if (!m) continue
    const [, key, rest] = m
    const inline = /^\[(.*)\]\s*(#.*)?$/.exec(rest)
    if (inline) {
      out[key] = inline[1]
        .split(',')
        .map((s) => scalar(s.trim()))
        .filter((v) => v !== undefined)
        .map(String)
      continue
    }
    const value = scalar(rest)
    if (value !== undefined) out[key] = value
    else {
      out[key] = [] // empty value: a block list may follow
      listKey = key
    }
  }
  // An empty key with nothing under it was not a list after all.
  for (const [k, v] of Object.entries(out)) if (Array.isArray(v) && v.length === 0) delete out[k]
  return out
}

function scalar(v: string): string | number | boolean | undefined {
  const quoted = /^(["'])(.*)\1\s*(#.*)?$/.exec(v)
  if (quoted) return quoted[2]
  const bare = v.replace(/\s+#.*$/, '').replace(/^#.*$/, '').trim()
  if (bare === '' || bare === '~' || bare === 'null') return undefined
  if (/^(true|yes|on)$/i.test(bare)) return true
  if (/^(false|no|off)$/i.test(bare)) return false
  if (/^-?\d+(\.\d+)?$/.test(bare)) return Number(bare)
  return bare
}

// ── Validation ───────────────────────────────────────────────────────────────

export interface Validated {
  values: Partial<MlabConfig> & { disable?: boolean }
  /** Human readable, one per rejected key. */
  problems: string[]
}

function isHttpUrl(v: string): boolean {
  try {
    const u = new URL(v)
    return u.protocol === 'https:' || u.protocol === 'http:'
  } catch {
    return false
  }
}

/**
 * Keep only known keys with values of the right shape. A typo or a bad value
 * is reported rather than silently applied or silently dropped. `disable` is
 * only meaningful in vuln.yml, so other files do not accept it.
 */
export function validateConfig(raw: Record<string, unknown>, allowDisable: boolean): Validated {
  const values: Validated['values'] = {}
  const problems: string[] = []
  const known = Object.keys(DEFAULTS)
  for (const [key, v] of Object.entries(raw)) {
    if (key === 'disable' && allowDisable) {
      if (typeof v === 'boolean') values.disable = v
      else problems.push(`disable: expected true or false, got ${JSON.stringify(v)}`)
      continue
    }
    if (!known.includes(key)) {
      const near = known.find((k) => k.toLowerCase() === key.toLowerCase())
      problems.push(
        key === 'disable'
          ? 'disable: only read from .mlab/vuln.yml'
          : `${key}: unknown setting${near ? `, did you mean ${near}?` : ''}`,
      )
      continue
    }
    const k = key as keyof MlabConfig
    const bad = (expected: string) =>
      problems.push(`${key}: expected ${expected}, got ${JSON.stringify(v)}`)
    if (k === 'ignoreVulns') {
      const list = typeof v === 'string' ? [v] : v
      if (Array.isArray(list) && list.every((x) => typeof x === 'string')) {
        values.ignoreVulns = list.map((x) => x.trim()).filter(Boolean)
      } else bad('a list of advisory ids')
    } else if (k === 'severityFloor') {
      if ((SEVERITY_FLOORS as readonly unknown[]).includes(v)) values.severityFloor = v as MlabConfig['severityFloor']
      else bad(SEVERITY_FLOORS.join(' | '))
    } else if (k === 'timeoutMs') {
      if (typeof v === 'number' && Number.isFinite(v) && v >= 1000) values.timeoutMs = Math.round(v)
      else bad('a number of milliseconds, at least 1000')
    } else if (k === 'apiUrl' || k === 'platformUrl') {
      if (typeof v === 'string' && isHttpUrl(v)) values[k] = v
      else bad('an http(s) URL')
    } else if (typeof DEFAULTS[k] === 'boolean') {
      if (typeof v === 'boolean') (values as Record<string, unknown>)[k] = v
      else bad('true or false')
    }
  }
  return { values, problems }
}

// ── Ignore list ──────────────────────────────────────────────────────────────

/**
 * `outcome` without the findings whose id or any alias is in `ignore`
 * (case insensitive). Applied when results are shown, never when they are
 * cached, so editing the list takes effect without a rescan.
 */
export function dropIgnored(outcome: ScanOutcome, ignore: readonly string[]): ScanOutcome {
  if (ignore.length === 0) return outcome
  const set = new Set(ignore.map((s) => s.toUpperCase()))
  const findings = outcome.findings.filter(
    (f) => !set.has(f.cve.toUpperCase()) && !(f.aliases ?? []).some((a) => set.has(a.toUpperCase())),
  )
  return findings.length === outcome.findings.length ? outcome : { ...outcome, findings }
}
