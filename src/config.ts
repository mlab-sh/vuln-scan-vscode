import * as vscode from 'vscode'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'

// Layered configuration for mlab.
//
// Settings live in mlab-owned JSON files so they are portable (the CLI and the
// GitHub Action can read the same file) and so a workspace `.mlab/config.json`
// can be committed to share one configuration across a team.
//
// Precedence, highest first:
//   1. <workspace>/.mlab/config.json   committed with the repo, team wide
//   2. ~/.mlab/config.json             personal, all workspaces
//   3. VS Code settings `mlab.*`       what existing installs already use
//   4. built in defaults
//
// Layer 3 is kept deliberately: dropping it would silently change behaviour for
// anyone who had already configured the extension the native way, and it keeps
// the native settings editor meaningful rather than decorative.

export const CONFIG_DIRNAME = '.mlab'
export const CONFIG_FILENAME = 'config.json'

export interface MlabConfig {
  apiUrl: string
  /** Base of the mlab platform API, used for indicator lookups. */
  platformUrl: string
  severityFloor: 'any' | 'low' | 'medium' | 'high' | 'critical'
  timeoutMs: number
  autoScan: boolean
  cveHover: boolean
  analyzeSelection: boolean
}

export const DEFAULTS: MlabConfig = {
  apiUrl: 'https://vuln.mlab.sh/api/v2/scan',
  platformUrl: 'https://mlab.sh/api/v1',
  severityFloor: 'any',
  timeoutMs: 30000,
  autoScan: true,
  cveHover: true,
  analyzeSelection: true,
}

/** Which layer a value came from, so the UI can say so out loud. */
export type Layer = 'workspace-file' | 'user-file' | 'vscode' | 'default'

export type Scope = 'workspace' | 'user'

export interface Resolved<K extends keyof MlabConfig> {
  value: MlabConfig[K]
  layer: Layer
}

// ── File locations ───────────────────────────────────────────────────────────
/** `<first workspace folder>/.mlab/config.json`, or undefined with no folder. */
export function workspaceConfigPath(): string | undefined {
  const folder = vscode.workspace.workspaceFolders?.[0]
  if (!folder || folder.uri.scheme !== 'file') return undefined
  return path.join(folder.uri.fsPath, CONFIG_DIRNAME, CONFIG_FILENAME)
}

/** `~/.mlab/config.json`. */
export function userConfigPath(): string {
  return path.join(os.homedir(), CONFIG_DIRNAME, CONFIG_FILENAME)
}

function pathFor(scope: Scope): string | undefined {
  return scope === 'workspace' ? workspaceConfigPath() : userConfigPath()
}

// ── Reading ──────────────────────────────────────────────────────────────────
/** Parse a config file, tolerating absence. Malformed JSON is surfaced once. */
function readFile(file: string | undefined): Partial<MlabConfig> {
  if (!file) return {}
  let text: string
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch {
    return {} // absent is the normal case, not an error
  }
  try {
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' ? (parsed as Partial<MlabConfig>) : {}
  } catch (err) {
    vscode.window.showWarningMessage(
      `mlab: ${file} is not valid JSON and was ignored. ${err instanceof Error ? err.message : ''}`,
    )
    return {}
  }
}

/** Resolve one key through every layer, reporting which one won. */
export function resolve<K extends keyof MlabConfig>(key: K): Resolved<K> {
  const ws = readFile(workspaceConfigPath())
  if (ws[key] !== undefined) return { value: ws[key] as MlabConfig[K], layer: 'workspace-file' }

  const user = readFile(userConfigPath())
  if (user[key] !== undefined) return { value: user[key] as MlabConfig[K], layer: 'user-file' }

  const native = vscode.workspace.getConfiguration('mlab').inspect(key)
  const fromVscode = native?.workspaceValue ?? native?.globalValue
  if (fromVscode !== undefined) return { value: fromVscode as MlabConfig[K], layer: 'vscode' }

  return { value: DEFAULTS[key], layer: 'default' }
}

/** Convenience for call sites that only need the value. */
export function get<K extends keyof MlabConfig>(key: K): MlabConfig[K] {
  return resolve(key).value
}

// ── Writing ──────────────────────────────────────────────────────────────────
/**
 * Write one key into the `.mlab/config.json` of the given scope, creating the
 * directory and file as needed. Existing unrelated keys are preserved.
 */
export function write<K extends keyof MlabConfig>(
  key: K,
  value: MlabConfig[K],
  scope: Scope,
): void {
  const file = pathFor(scope)
  if (!file) throw new Error('No workspace folder is open, so there is nowhere to write.')
  const current = readFile(file)
  const next = { ...current, [key]: value }
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + '\n', 'utf8')
}

/**
 * Remove one key from both `.mlab` files, and from the native settings, so the
 * value genuinely falls back to the built in default rather than to a lower
 * layer the user cannot see from the page.
 */
export async function reset<K extends keyof MlabConfig>(key: K): Promise<void> {
  for (const scope of ['workspace', 'user'] as Scope[]) {
    const file = pathFor(scope)
    if (!file) continue
    const current = readFile(file)
    if (current[key] === undefined) continue
    delete current[key]
    try {
      if (Object.keys(current).length === 0) fs.rmSync(file)
      else fs.writeFileSync(file, JSON.stringify(current, null, 2) + '\n', 'utf8')
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

  const folder = vscode.workspace.workspaceFolders?.[0]
  if (folder) {
    const w = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(folder, `${CONFIG_DIRNAME}/${CONFIG_FILENAME}`),
    )
    subs.push(w, w.onDidChange(onChanged), w.onDidCreate(onChanged), w.onDidDelete(onChanged))
  }

  // The user file is outside every workspace folder, so it needs its own
  // pattern rooted at the home directory.
  const home = vscode.Uri.file(os.homedir())
  const uw = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(home, `${CONFIG_DIRNAME}/${CONFIG_FILENAME}`),
  )
  subs.push(uw, uw.onDidChange(onChanged), uw.onDidCreate(onChanged), uw.onDidDelete(onChanged))

  return vscode.Disposable.from(...subs)
}

/** Human label for a layer, used by the settings page badges. */
export function layerLabel(layer: Layer): string {
  switch (layer) {
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
