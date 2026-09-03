// Lockfile detection, and the single source of truth for which lockfiles this
// extension knows about. Pure module (no `vscode` import) so it can be unit
// tested and reused everywhere.
//
// Everything downstream is DERIVED from `LOCKFILES` below: the format hints, the
// display names, the watcher glob, the workspace sweep glob, and the `when`
// clauses in package.json. Adding a format means editing one array.
//
// package.json cannot import this file, so its menu clauses are generated from
// here by `npm run sync:manifest` and guarded by a test that fails if the two
// ever drift apart.
//
// The basename to format mapping mirrors the server's supported parsers, from
// mlab-sh/vuln-scan-action (src/index.ts `KNOWN`).

export interface LockfileKind {
  /** Canonical display name, with its real casing. */
  name: string
  /** The `format` query hint the API expects for this file. */
  format: string
}

/** THE list. Add a supported lockfile here and nowhere else. */
export const LOCKFILES: readonly LockfileKind[] = [
  { name: 'Cargo.lock', format: 'cargo' },
  { name: 'package-lock.json', format: 'npm' },
  { name: 'npm-shrinkwrap.json', format: 'npm' },
  { name: 'composer.lock', format: 'composer' },
  { name: 'Gemfile.lock', format: 'gem' },
  { name: 'go.sum', format: 'go' },
  { name: 'requirements.txt', format: 'pip' },
  { name: 'mise.lock', format: 'mise' },
]

/** Directories excluded when walking a workspace for lockfiles. */
export const SKIP_DIRS = ['node_modules', 'vendor', 'target', 'dist', '.git']

/** Canonical display names, for menus and docs. */
export const SUPPORTED_BASENAMES: string[] = LOCKFILES.map((l) => l.name)

/** Lowercased basename to format hint, for lookups. */
export const KNOWN: Record<string, string> = Object.fromEntries(
  LOCKFILES.map((l) => [l.name.toLowerCase(), l.format]),
)

// ── Derived globs and clauses ────────────────────────────────────────────────

/** Glob matching every supported lockfile, at any depth. */
export function lockfileGlob(): string {
  return `**/{${SUPPORTED_BASENAMES.join(',')}}`
}

/** Glob of the directories a workspace sweep skips. */
export function excludeGlob(): string {
  return `**/{${SKIP_DIRS.join(',')}}/**`
}

/**
 * The `when` clause package.json uses to show the context menu entries only on
 * recognized lockfiles. Generated into the manifest, never written by hand.
 */
export function whenClause(): string {
  const alternatives = SUPPORTED_BASENAMES.map((n) => n.replace(/\./g, '\\.')).join('|')
  return `resourceFilename =~ /^(${alternatives})$/i`
}

/** The sentence listing supported lockfiles in the view's welcome content. */
export function supportedSentence(): string {
  return `Supported lockfiles: ${SUPPORTED_BASENAMES.join(', ')}.`
}

// ── Detection ────────────────────────────────────────────────────────────────

/** Extract the basename from a path, handling both `/` and `\` separators. */
export function basenameOf(filePath: string): string {
  const parts = filePath.split(/[\\/]/)
  return parts[parts.length - 1] ?? filePath
}

/** True when `filePath`'s basename is a lockfile the API can parse. */
export function isSupportedLockfile(filePath: string): boolean {
  return basenameOf(filePath).toLowerCase() in KNOWN
}

/**
 * Parser hint for a lockfile path, or `undefined` if unrecognised.
 * `undefined` means "let the server auto-detect", so the `format` query param is
 * then omitted, exactly as the Action does.
 */
export function detectFormat(filePath: string): string | undefined {
  return KNOWN[basenameOf(filePath).toLowerCase()]
}
