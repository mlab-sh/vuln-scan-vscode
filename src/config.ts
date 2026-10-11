import * as vscode from 'vscode'
import { homeDir } from './platform'
import { DEFAULTS, MlabConfig, dropIgnored, parseFlatYaml, validateConfig } from './configCore'
import type { ScanOutcome } from './api/client'

// Layered configuration for mlab.
//
// Settings live in mlab-owned JSON files so they are portable (the CLI and the
// GitHub Action can read the same file) and so a workspace `.mlab/config.json`
// can be committed to share one configuration across a team.
//
// Precedence, highest first:
//   0. <workspace>/.mlab/vuln.yml      hand written override, never written by
//                                      the extension; `disable: true` turns the
//                                      extension off for this workspace
//   1. <workspace>/.mlab/config.json   committed with the repo, team wide
//   2. ~/.mlab/config.json             personal, all workspaces (desktop only)
//   3. VS Code settings `mlab.*`       what existing installs already use
//   4. built in defaults
//
// Layer 3 is kept deliberately: dropping it would silently change behaviour for
// anyone who had already configured the extension the native way, and it keeps
// the native settings editor meaningful rather than decorative.

export const CONFIG_DIRNAME = '.mlab'
export const CONFIG_FILENAME = 'config.json'
export const OVERRIDE_FILENAME = 'vuln.yml'

export type { MlabConfig } from './configCore'
export { DEFAULTS } from './configCore'

/** Which layer a value came from, so the UI can say so out loud. */
export type Layer = 'override-file' | 'workspace-file' | 'user-file' | 'vscode' | 'default'

export type Scope = 'workspace' | 'user'

export interface Resolved<K extends keyof MlabConfig> {
  value: MlabConfig[K]
  layer: Layer
}

// ── File locations ───────────────────────────────────────────────────────────
// `<first workspace folder>/.mlab/config.json` and `~/.mlab/config.json`. Either
// can be missing: no folder open, or no home directory at all in the browser.
function uriFor(scope: Scope): vscode.Uri | undefined {
  if (scope === 'workspace') {
    const folder = vscode.workspace.workspaceFolders?.[0]
    return folder && vscode.Uri.joinPath(folder.uri, CONFIG_DIRNAME, CONFIG_FILENAME)
  }
  const home = homeDir()
  return home === undefined
    ? undefined
    : vscode.Uri.joinPath(vscode.Uri.file(home), CONFIG_DIRNAME, CONFIG_FILENAME)
}

// ── Reading ──────────────────────────────────────────────────────────────────
// The files are read through `workspace.fs`, which is async, while `get()` is
// called synchronously all over the extension. So both files are held in a
// snapshot, filled by `load()` at activation and refreshed by `watch()` and by
// every write.
let files: Record<Scope, Partial<MlabConfig>> = { workspace: {}, user: {} }
let override: Partial<MlabConfig> & { disable?: boolean } = {}

/** Show a file's validation problems once per load, not on every read. */
function report(uri: vscode.Uri, problems: string[]): void {
  if (problems.length === 0) return
  vscode.window.showWarningMessage(
    `mlab: ignored in ${vscode.workspace.asRelativePath(uri)}: ${problems.join('; ')}`,
  )
}

function overrideUri(): vscode.Uri | undefined {
  const folder = vscode.workspace.workspaceFolders?.[0]
  return folder && vscode.Uri.joinPath(folder.uri, CONFIG_DIRNAME, OVERRIDE_FILENAME)
}

async function readOverride(): Promise<typeof override> {
  const uri = overrideUri()
  if (!uri) return {}
  let text: string
  try {
    text = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri))
  } catch {
    return {} // absent
  }
  const { values, problems } = validateConfig(parseFlatYaml(text), true)
  report(uri, problems)
  return values
}

const OVERRIDE_TEMPLATE = `# mlab settings for this workspace. Overrides every other layer.
# Uncomment what you need. Read by the VS Code extension and the GitHub Action.

# Turn mlab off entirely in this workspace (no scans, no hovers, no lookups).
# disable: true

# Advisories accepted as known risk, hidden everywhere. Say why next to each.
# ignoreVulns:
#   - CVE-2024-0000   # not reachable: only used in tests

# autoScan: true            # rescan a lockfile when it changes
# ignoreGitIgnored: true    # skip lockfiles git ignores
# severityFloor: any        # any | low | medium | high | critical
# cveHover: true
# analyzeSelection: true
# timeoutMs: 30000
# apiUrl: https://vuln.mlab.sh/api/v2/scan
# platformUrl: https://mlab.sh/api/v1
`

/** Open `.mlab/vuln.yml`, creating it from a commented template if missing. */
export async function openOverrideFile(): Promise<void> {
  const uri = overrideUri()
  if (!uri) {
    vscode.window.showWarningMessage('mlab: open a folder first, .mlab/vuln.yml lives in the workspace.')
    return
  }
  try {
    await vscode.workspace.fs.stat(uri)
  } catch {
    await vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(uri, '..'))
    await vscode.workspace.fs.writeFile(uri, new TextEncoder().encode(OVERRIDE_TEMPLATE))
  }
  await vscode.window.showTextDocument(uri)
}

/** True when `.mlab/vuln.yml` says `disable: true`. */
export function isDisabled(): boolean {
  return override.disable === true
}

/**
 * Parse a config file, tolerating absence. Malformed JSON is surfaced once.
 * `raw` skips validation, for writes that must keep keys they do not own.
 */
async function readFile(uri: vscode.Uri | undefined, raw = false): Promise<Record<string, unknown>> {
  if (!uri) return {}
  let text: string
  try {
    text = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri))
  } catch {
    return {} // absent is the normal case, not an error
  }
  try {
    const parsed = JSON.parse(text)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    if (raw) return parsed
    const { values, problems } = validateConfig(parsed, false)
    report(uri, problems)
    return values
  } catch (err) {
    vscode.window.showWarningMessage(
      `mlab: ${uri.fsPath} is not valid JSON and was ignored. ${err instanceof Error ? err.message : ''}`,
    )
    return {}
  }
}

/** (Re)read both config files into the snapshot. */
export async function load(): Promise<void> {
  const [workspace, user, yml] = await Promise.all([
    readFile(uriFor('workspace')),
    readFile(uriFor('user')),
    readOverride(),
  ])
  files = { workspace, user }
  override = yml
}

/** Resolve one key through every layer, reporting which one won. */
export function resolve<K extends keyof MlabConfig>(key: K): Resolved<K> {
  if (override[key] !== undefined) return { value: override[key] as MlabConfig[K], layer: 'override-file' }

  const ws = files.workspace
  if (ws[key] !== undefined) return { value: ws[key] as MlabConfig[K], layer: 'workspace-file' }

  const user = files.user
  if (user[key] !== undefined) return { value: user[key] as MlabConfig[K], layer: 'user-file' }

  const native = vscode.workspace.getConfiguration('mlab').inspect(key)
  const fromVscode = native?.workspaceValue ?? native?.globalValue
  if (fromVscode !== undefined) return { value: fromVscode as MlabConfig[K], layer: 'vscode' }

  return { value: DEFAULTS[key], layer: 'default' }
}

/** `outcome` as it should be shown: minus the advisories in `ignoreVulns`. */
export function visible(outcome: ScanOutcome): ScanOutcome {
  return dropIgnored(outcome, get('ignoreVulns'))
}

/** Convenience for call sites that only need the value. */
export function get<K extends keyof MlabConfig>(key: K): MlabConfig[K] {
  return resolve(key).value
}

// ── Writing ──────────────────────────────────────────────────────────────────
async function writeJson(uri: vscode.Uri, data: object): Promise<void> {
  await vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(uri, '..'))
  await vscode.workspace.fs.writeFile(
    uri,
    new TextEncoder().encode(JSON.stringify(data, null, 2) + '\n'),
  )
}

/**
 * Write one key into the `.mlab/config.json` of the given scope, creating the
 * directory and file as needed. Existing unrelated keys are preserved.
 *
 * In the browser there is no home directory, so the user scope falls back to
 * the VS Code user settings, which the browser does persist.
 */
export async function write<K extends keyof MlabConfig>(
  key: K,
  value: MlabConfig[K],
  scope: Scope,
): Promise<void> {
  const uri = uriFor(scope)
  if (!uri) {
    if (scope === 'workspace') {
      throw new Error('No workspace folder is open, so there is nowhere to write.')
    }
    await vscode.workspace
      .getConfiguration('mlab')
      .update(key, value, vscode.ConfigurationTarget.Global)
    return
  }
  const next = { ...(await readFile(uri, true)), [key]: value }
  await writeJson(uri, next)
  files[scope] = validateConfig(next, false).values
}

/**
 * Remove one key from both `.mlab` files, and from the native settings, so the
 * value genuinely falls back to the built in default rather than to a lower
 * layer the user cannot see from the page.
 */
export async function reset<K extends keyof MlabConfig>(key: K): Promise<void> {
  for (const scope of ['workspace', 'user'] as Scope[]) {
    const uri = uriFor(scope)
    if (!uri) continue
    const current = await readFile(uri, true)
    if (current[key] === undefined) continue
    delete current[key]
    try {
      if (Object.keys(current).length === 0) await vscode.workspace.fs.delete(uri)
      else await writeJson(uri, current)
      files[scope] = validateConfig(current, false).values
    } catch {
      // Nothing to do: the file is already gone or not writable.
    }
  }
  const cfg = vscode.workspace.getConfiguration('mlab')
  await cfg.update(key, undefined, vscode.ConfigurationTarget.Global)
  if (vscode.workspace.workspaceFolders?.length) {
    await cfg.update(key, undefined, vscode.ConfigurationTarget.Workspace)
  }
}

/**
 * Watch both `.mlab/config.json` files and call back when either changes.
 *
 * These live outside the VS Code configuration system, so
 * `onDidChangeConfiguration` never fires for them. Without this, editing a
 * config file by hand leaves the settings page showing a stale value and the
 * auto scanner running on an outdated setting.
 */
export function watch(onChanged: () => void): vscode.Disposable {
  const subs: vscode.Disposable[] = []
  const changed = () => void load().then(onChanged)

  const folder = vscode.workspace.workspaceFolders?.[0]
  if (folder) {
    const w = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(folder, `${CONFIG_DIRNAME}/${CONFIG_FILENAME}`),
    )
    subs.push(w, w.onDidChange(changed), w.onDidCreate(changed), w.onDidDelete(changed))
    const o = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(folder, `${CONFIG_DIRNAME}/${OVERRIDE_FILENAME}`),
    )
    subs.push(o, o.onDidChange(changed), o.onDidCreate(changed), o.onDidDelete(changed))
  }

  // The user file is outside every workspace folder, so it needs its own
  // pattern rooted at the home directory. No home, nothing to watch.
  const home = homeDir()
  if (home !== undefined) {
    const uw = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(vscode.Uri.file(home), `${CONFIG_DIRNAME}/${CONFIG_FILENAME}`),
    )
    subs.push(uw, uw.onDidChange(changed), uw.onDidCreate(changed), uw.onDidDelete(changed))
  }

  return vscode.Disposable.from(...subs)
}

/** Human label for a layer, used by the settings page badges. */
export function layerLabel(layer: Layer): string {
  switch (layer) {
    case 'override-file':
      return 'vuln.yml'
    case 'workspace-file':
      return 'workspace'
    case 'user-file':
      return 'user'
    case 'vscode':
      return 'vs code'
    case 'default':
      return 'default'
  }
}
