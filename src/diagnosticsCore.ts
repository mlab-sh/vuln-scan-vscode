// Pure logic behind the lockfile diagnostics: no `vscode` import, so it can be
// unit tested the same way detect.ts and api/client.ts are. The vscode facing
// wrapper lives in ./diagnostics and only translates these results into
// DiagnosticSeverity and Range.

import { Severity, SEV_RANK } from './api/types'

export type DiagLevel = 'error' | 'warning' | 'information'

/** Ranks for the floor itself. `any` lets everything through. */
export const FLOOR_RANK: Record<string, number> = {
  any: 0,
  low: SEV_RANK.low,
  medium: SEV_RANK.medium,
  high: SEV_RANK.high,
  critical: SEV_RANK.critical,
}

/**
 * Map a finding's severity to a diagnostic level, given the configured floor.
 *
 * At or above the floor, critical and high read as errors and the rest as
 * warnings. Below the floor everything is demoted to information, which is
 * exactly what `mlab.severityFloor` promises. Nothing here ever fails a build.
 */
export function levelFor(finding: Severity, floor: string): DiagLevel {
  const rank = SEV_RANK[finding] ?? 0
  const min = FLOOR_RANK[floor] ?? 0
  if (rank < min) return 'information'
  return rank >= SEV_RANK.high ? 'error' : 'warning'
}

/** Zero-based position of a package declaration inside a lockfile. */
export interface Hit {
  line: number
  col: number
  endCol: number
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Find where `name` is declared in a lockfile.
 *
 * Lockfile formats differ too much to justify a parser per format just to place
 * a squiggle, so this works on the shape they all share: the package name
 * appears verbatim on a line, usually near its version. A line carrying both
 * name and version wins; failing that, the first line mentioning the name as a
 * whole token; failing that, the start of the file, so a finding is never lost.
 */
export function locateLine(text: string, name: string, version: string): Hit {
  const lines = text.split(/\r?\n/)
  const token = new RegExp(`(?:^|[^A-Za-z0-9_.\\-/@])${escapeRe(name)}(?:[^A-Za-z0-9_.\\-]|$)`)

  let fallback = -1
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (isComment(line)) continue
    if (!token.test(line)) continue

    // Cargo.lock and friends put `name` and `version` on separate lines of the
    // same block, so the version is looked for in a small window rather than on
    // the matching line alone.
    if (version && nearby(lines, i).includes(version)) return at(lines, i, name)
    if (fallback === -1) fallback = i
  }
  if (fallback !== -1) return at(lines, fallback, name)
  return { line: 0, col: 0, endCol: Math.min(lines[0]?.length ?? 0, 200) }
}

/** How far past the matching line to look for the version. */
const WINDOW = 2

function nearby(lines: string[], i: number): string {
  return lines.slice(i, i + WINDOW + 1).join('\n')
}

/**
 * Comment lines are skipped: a changelog note or a header mentioning a package
 * should never win over the line that actually declares it.
 */
function isComment(line: string): boolean {
  const t = line.trimStart()
  return t.startsWith('#') || t.startsWith('//')
}

function at(lines: string[], i: number, name: string): Hit {
  const col = lines[i].indexOf(name)
  if (col === -1) return { line: i, col: 0, endCol: lines[i].length }
  return { line: i, col, endCol: col + name.length }
}
