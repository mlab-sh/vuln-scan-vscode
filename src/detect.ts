// Lockfile detection. Pure module (no `vscode` import) so it can be unit-tested
// and reused by both the command layer and the `Scan all lockfiles` walker.
//
// The basename → format-hint mapping mirrors the server's supported parsers,
// copied from mlab-sh/vuln-scan-action (src/index.ts `KNOWN`).

/** Lockfile basenames the API can parse, mapped to their `format` query hint. */
export const KNOWN: Record<string, string> = {
  'cargo.lock': 'cargo',
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'composer.lock': 'composer',
  'gemfile.lock': 'gem',
  'go.sum': 'go',
  'requirements.txt': 'pip',
  'mise.lock': 'mise',
}

/** Directories excluded when walking a workspace for lockfiles. */
export const SKIP_DIRS = ['node_modules', 'vendor', 'target', 'dist', '.git']

/** Canonical display names of the supported lockfiles (for menus / docs). */
export const SUPPORTED_BASENAMES = [
  'Cargo.lock',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'composer.lock',
  'Gemfile.lock',
  'go.sum',
  'requirements.txt',
  'mise.lock',
]

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
