// CVSS v3.x base score computation.
//
// Why this exists: OSV advisories very often carry their severity only as a
// vector string, with no `database_specific.severity` alongside. Verified
// against the live API: RUSTSEC and GHSA entries for CVE-2020-26235 return
// `severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:L/.../A:H" }]` and nothing
// else. Without this module those findings fall through to `unknown`, which
// ranks below `low` and gets demoted in the Problems panel.
//
// The formula is the one from the CVSS v3.1 specification, section 8.

/** Metric weights, v3.1 specification table. */
const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC: Record<string, number> = { L: 0.77, H: 0.44 }
const UI: Record<string, number> = { N: 0.85, R: 0.62 }
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }
/** Privileges Required is scope dependent. */
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 }
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 }

/**
 * Round up to one decimal, per the v3.1 spec's Roundup. Plain `Math.ceil` on
 * one decimal is not equivalent: the spec works in integer hundred-thousandths
 * to avoid the floating point edge cases that would otherwise push a score up.
 */
export function roundUp(input: number): number {
  const i = Math.round(input * 100000)
  if (i % 10000 === 0) return i / 100000
  return (Math.floor(i / 10000) + 1) / 10
}

/**
 * Compute the CVSS v3.x base score from a vector string.
 *
 * Returns undefined when the string is not a v3 vector or is missing a base
 * metric, so callers can fall back rather than trust a partial parse.
 */
export function baseScoreV3(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//i.test(vector)) return undefined

  const m: Record<string, string> = {}
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':')
    if (k && v) m[k.toUpperCase()] = v.toUpperCase()
  }

  const scopeChanged = m.S === 'C'
  const av = AV[m.AV]
  const ac = AC[m.AC]
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.PR]
  const ui = UI[m.UI]
  const c = CIA[m.C]
  const i = CIA[m.I]
  const a = CIA[m.A]

  // Every base metric is mandatory; a vector missing one is not scoreable.
  if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined) || m.S === undefined) {
    return undefined
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss
  if (impact <= 0) return 0

  const exploitability = 8.22 * av * ac * pr * ui
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10)
  return roundUp(raw)
}

/**
 * Read a numeric score out of an OSV `severity[].score`, whatever shape it is.
 *
 * Handles a bare number ("7.5"), a v3 vector, and a "vector/score" tail. Returns
 * undefined when nothing numeric can be established, which includes CVSS v2 and
 * v4 vectors: guessing a band from an unparsed vector would be worse than
 * falling through to the next severity entry.
 */
export function scoreOf(raw: string): number | undefined {
  const text = raw.trim()
  if (text === '') return undefined

  const direct = Number(text)
  if (Number.isFinite(direct)) return direct

  const vector = baseScoreV3(text)
  if (vector !== undefined) return vector

  // Some feeds append the numeric score to the vector.
  const tail = Number(text.split('/').pop())
  return Number.isFinite(tail) ? tail : undefined
}
