import * as vscode from 'vscode'
import * as fs from 'fs'
import * as path from 'path'
import { basenameOf, detectFormat, isSupportedLockfile, SKIP_DIRS, SUPPORTED_BASENAMES } from './detect'
import { ReportPanel } from './views/reportPanel'
import { HomePanel, onSettingsWritten } from './views/homePanel'
import { FindingsTree } from './views/findingsTree'
import { LockfileDecorations } from './views/decorations'
import { ScanCache, hashOf } from './cache'
import { AutoScanner } from './autoscan'
import { LockfileDiagnostics } from './diagnostics'
import * as config from './config'
import { scanLockfile, ScanError, summarize, ScanOutcome } from './api/client'

// ─────────────────────────────────────────────────────────────────────────────
// Non-negotiable rule: NOTHING is uploaded without the user's agreement.
// Auto scanning is allowed and is on by default, but every path to the network
// goes through ensurePrivacyConsent(), so until the user has agreed once the
// watcher produces no traffic at all. activate() still makes zero network calls,
// and a cached result never re-uploads anything. Automatic scans are also
// silent: they never open the report panel and never raise a notification.
// ─────────────────────────────────────────────────────────────────────────────

const TOKEN_KEY = 'mlab.apiToken'
const PRIVACY_KEY = 'mlab.privacyConsent'

let output: vscode.OutputChannel
let ctx: vscode.ExtensionContext
let tree: FindingsTree
let view: vscode.TreeView<unknown>
let cache: ScanCache
let decorations: LockfileDecorations
let autoScanner: AutoScanner
let diagnostics: LockfileDiagnostics

export function activate(context: vscode.ExtensionContext): void {
  ctx = context
  output = vscode.window.createOutputChannel('mlab')
  context.subscriptions.push(output)

  tree = new FindingsTree()
  view = vscode.window.createTreeView('mlab.findings', { treeDataProvider: tree })
  context.subscriptions.push(view)

  diagnostics = new LockfileDiagnostics()
  context.subscriptions.push(diagnostics)

  cache = new ScanCache(context.globalState)
  decorations = new LockfileDecorations(cache)
  context.subscriptions.push(vscode.window.registerFileDecorationProvider(decorations))

  // Restore the previous results from the cache straight away, with no network
  // call, so a lockfile that was vulnerable when the window closed comes back
  // red and listed rather than looking clean until the next scan.
  void rehydrate()

  autoScanner = new AutoScanner((uri) => void checkLockfile(uri, { auto: true }))
  context.subscriptions.push(autoScanner)
  autoScanner.sync()
  // `.mlab` files live outside the VS Code config system, so the page tells us
  // directly when one is written.
  onSettingsWritten(() => {
    autoScanner.sync()
    void refreshDiagnostics()
  })
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration('mlab')) return
      autoScanner.sync()
      void refreshDiagnostics()
    }),
  )

  const register = (id: string, fn: (...args: any[]) => any) =>
    context.subscriptions.push(vscode.commands.registerCommand(id, fn))

  register('mlab.checkLockfile', (resource?: vscode.Uri) => checkLockfile(resource))
  register('mlab.scanWorkspace', () => scanWorkspace())
  register('mlab.rescan', () => rescan())
  register('mlab.clearResults', () => void clearResults())
  register('mlab.setToken', () => setToken())
  register('mlab.clearToken', () => clearToken())
  register('mlab.showReport', (arg?: vscode.Uri | { resourceUri?: vscode.Uri }) =>
    showReport(arg instanceof vscode.Uri ? arg : arg?.resourceUri),
  )
  register('mlab.openLockfile', (arg?: vscode.Uri | { resourceUri?: vscode.Uri }) => {
    const uri = arg instanceof vscode.Uri ? arg : arg?.resourceUri
    if (uri) vscode.commands.executeCommand('vscode.open', uri)
  })
  register('mlab.openHome', () => HomePanel.show(ctx))
  register('mlab.manageToken', () => HomePanel.show(ctx))

  // Make the empty state explicit rather than relying on an unset context key,
  // so the Rescan and Clear buttons are hidden until there is something to act on.
  syncView()
}

/**
 * Repopulate the tree and the Explorer marks from the cache.
 *
 * The cache is global (it survives across windows and projects), so entries are
 * filtered to the folders actually open here. Without that, opening project B
 * would list project A's findings. Entries whose lockfile is gone from an open
 * folder are pruned, so a deleted lockfile does not linger forever.
 */
async function rehydrate(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders ?? []
  const roots = folders.filter((f) => f.uri.scheme === 'file').map((f) => f.uri.fsPath)

  let restored = 0
  for (const fsPath of cache.paths()) {
    const inWorkspace = roots.some(
      (root) => fsPath === root || fsPath.startsWith(root + path.sep),
    )
    if (!inWorkspace) continue

    if (!fs.existsSync(fsPath)) {
      await cache.forget(fsPath)
      continue
    }
    const entry = cache.peek(fsPath)
    if (!entry) continue
    tree.record(vscode.Uri.file(fsPath), entry.filename, entry.outcome)
    await setDiagnosticsFor(vscode.Uri.file(fsPath), entry.outcome)
    restored++
  }

  syncView()
  decorations.refresh()
  if (restored > 0) {
    output.appendLine(`[cache] restored ${restored} previous result(s) without scanning`)
  }
}

/**
 * Publish diagnostics for a lockfile we are not currently scanning, so it needs
 * to read the file back. Failures are silent: a missing lockfile just means no
 * squiggles, never an error popup.
 */
async function setDiagnosticsFor(uri: vscode.Uri, outcome: ScanOutcome): Promise<void> {
  try {
    const body = await vscode.workspace.fs.readFile(uri)
    diagnostics.set(uri, Buffer.from(body).toString('utf8'), outcome)
  } catch {
    // The file is gone or unreadable; nothing to anchor a diagnostic on.
  }
}

/** Re-publish every diagnostic, e.g. after `severityFloor` changed. */
async function refreshDiagnostics(): Promise<void> {
  for (const fsPath of cache.paths()) {
    const entry = cache.peek(fsPath)
    if (entry) await setDiagnosticsFor(vscode.Uri.file(fsPath), entry.outcome)
  }
}

/** Keep the view badge and title in step with what the tree holds. */
function syncView(): void {
  const n = tree.totalFindings
  view.badge = n > 0 ? { value: n, tooltip: `${n} finding${n === 1 ? '' : 's'}` } : undefined
  vscode.commands.executeCommand('setContext', 'mlab.hasResults', !tree.isEmpty)
}

export function deactivate(): void {
  // Disposables are handled via context.subscriptions.
}

// ── The one scan primitive ───────────────────────────────────────────────────
// Every caller goes through this: the command, the file watcher and the
// workspace sweep. Keeping one implementation is what guarantees that the cache
// is always consulted first and that consent is always checked before anything
// leaves the machine.

interface ScanOpts {
  /** True when the file watcher triggered this, not the user. */
  auto?: boolean
  /** Suppresses the report panel and per file notifications (workspace sweep). */
  batch?: boolean
  /** Lets a batch caller cancel the whole run. */
  signal?: AbortSignal
}

type ScanResult =
  | { kind: 'cached'; outcome: ScanOutcome }
  | { kind: 'scanned'; outcome: ScanOutcome }
  | { kind: 'skipped'; reason: 'unsupported' | 'untrusted' | 'no-consent' | 'unreadable' }
  | { kind: 'failed'; error: unknown }

async function performScan(uri: vscode.Uri, opts: ScanOpts): Promise<ScanResult> {
  const auto = opts.auto === true
  const quiet = auto || opts.batch === true
  const filename = basenameOf(uri.fsPath)

  if (!isSupportedLockfile(uri.fsPath)) return { kind: 'skipped', reason: 'unsupported' }
  if (!vscode.workspace.isTrusted) return { kind: 'skipped', reason: 'untrusted' }

  // Read first: the cache is keyed on content, so an unchanged lockfile costs
  // nothing at all, no consent prompt and no request.
  let body: Uint8Array
  try {
    body = await vscode.workspace.fs.readFile(uri)
  } catch (err) {
    output.appendLine(`[error] ${filename}: unreadable: ${err instanceof Error ? err.message : err}`)
    return { kind: 'skipped', reason: 'unreadable' }
  }
  const hash = hashOf(body)
  const text = Buffer.from(body).toString('utf8')

  const hit = cache.lookup(uri.fsPath, hash)
  if (hit) {
    publish(uri, filename, text, hit.outcome)
    output.appendLine(`[cache] ${filename}: ${summarize(hit.outcome)} (unchanged since last scan)`)
    return { kind: 'cached', outcome: hit.outcome }
  }

  // Only now does anything leave the machine, so this is where consent belongs.
  // An automatic scan never shows the modal: without prior consent it does
  // nothing at all.
  if (auto) {
    if (!ctx.globalState.get<boolean>(PRIVACY_KEY)) {
      output.appendLine(`[auto] ${filename}: skipped, privacy consent not given yet`)
      return { kind: 'skipped', reason: 'no-consent' }
    }
  } else if (!(await ensurePrivacyConsent())) {
    return { kind: 'skipped', reason: 'no-consent' }
  }

  const panel = quiet ? undefined : ReportPanel.show(ctx.extensionUri)
  panel?.loading(filename)

  const controller = new AbortController()
  panel?.onCancel(() => controller.abort())
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort()
    else opts.signal.addEventListener('abort', () => controller.abort(), { once: true })
  }

  const label = auto ? 'auto' : opts.batch ? 'sweep' : 'scan'
  try {
    const token = await ctx.secrets.get(TOKEN_KEY)
    const apiUrl = config.get('apiUrl')
    output.appendLine(`[${label}] ${filename} → ${apiUrl}${token ? ' (token)' : ' (anonymous)'}`)

    const outcome = await scanLockfile({
      apiUrl,
      filename,
      format: detectFormat(uri.fsPath),
      body,
      token: token || undefined,
      timeoutMs: config.get('timeoutMs'),
      signal: controller.signal,
    })

    await cache.put(uri.fsPath, filename, hash, outcome)
    publish(uri, filename, text, outcome)
    panel?.report(filename, outcome)
    output.appendLine(`[${label}] ${filename}: ${summarize(outcome)}`)
    return { kind: 'scanned', outcome }
  } catch (err) {
    handleScanError(err, filename, panel, quiet)
    return { kind: 'failed', error: err }
  }
}

/** Push one outcome to every surface that shows results. */
function publish(uri: vscode.Uri, filename: string, text: string, outcome: ScanOutcome): void {
  tree.record(uri, filename, outcome)
  syncView()
  decorations.refresh(uri)
  diagnostics.set(uri, text, outcome)
}

// ── Scan a single lockfile ───────────────────────────────────────────────────
async function checkLockfile(resource?: vscode.Uri, opts: ScanOpts = {}): Promise<void> {
  const auto = opts.auto === true
  const uri = resource ?? vscode.window.activeTextEditor?.document.uri
  if (!uri) {
    vscode.window.showWarningMessage('mlab: open or right-click a lockfile to scan it.')
    return
  }

  const filename = basenameOf(uri.fsPath)
  const go = async (): Promise<ScanResult> => performScan(uri, opts)

  // ProgressLocation.Window is the discreet status bar spinner, so an automatic
  // scan is visible if you look for it but never steals focus.
  const result = auto
    ? await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Window, title: `mlab: checking ${filename}` },
        go,
      )
    : await go()

  if (auto) return

  if (result.kind === 'skipped') {
    if (result.reason === 'unsupported') {
      vscode.window.showWarningMessage(`mlab: "${filename}" is not a supported lockfile.`)
    } else if (result.reason === 'untrusted') {
      vscode.window.showWarningMessage(
        'mlab: scanning is disabled in Restricted Mode because it uploads the lockfile. Trust this workspace to scan.',
      )
    } else if (result.reason === 'unreadable') {
      vscode.window.showErrorMessage(`mlab: could not read ${filename}.`)
    }
    return
  }
  if (result.kind === 'failed') return

  if (result.kind === 'cached') {
    ReportPanel.show(ctx.extensionUri).report(
      filename,
      result.outcome,
      cache.peek(uri.fsPath)?.at,
    )
  }

  const line = summarize(result.outcome)
  if (result.outcome.findings.length === 0) {
    vscode.window.showInformationMessage(`mlab: no known vulnerabilities in ${filename}.`)
  } else {
    vscode.window.showWarningMessage(`mlab: ${line} in ${filename}.`)
  }
}

// Opens the report for a lockfile we already have results for. Reads the cache
// only: this never touches the network and never spends a scan from the quota,
// which is the whole point after a silent automatic scan.
async function showReport(resource?: vscode.Uri): Promise<void> {
  const uri = resource ?? vscode.window.activeTextEditor?.document.uri
  if (!uri) {
    vscode.window.showInformationMessage('mlab: select a lockfile to see its report.')
    return
  }

  const entry = cache.peek(uri.fsPath)
  if (!entry) {
    const scan = 'Scan now'
    const choice = await vscode.window.showInformationMessage(
      `mlab: no results for ${basenameOf(uri.fsPath)} yet.`,
      scan,
    )
    if (choice === scan) await checkLockfile(uri)
    return
  }

  ReportPanel.show(ctx.extensionUri).report(entry.filename, entry.outcome, entry.at)
  output.appendLine(`[report] ${entry.filename}: shown from cache, scanned ${new Date(entry.at).toISOString()}`)
}

// Rescans every lockfile currently in the tree, one at a time. Each one spends a
// scan from the hourly quota, which is why this is only ever reachable from an
// explicit click on the Rescan button.
async function rescan(): Promise<void> {
  const uris = tree.scannedUris()
  if (uris.length === 0) {
    vscode.window.showInformationMessage('mlab: nothing to rescan yet. Run a scan first.')
    return
  }
  for (const uri of uris) await checkLockfile(uri)
}

// Clearing results also drops the cache, which is what removes the red badges in
// the Explorer. Without that the files would stay red with nothing behind them.
async function clearResults(): Promise<void> {
  const paths = cache.paths()
  tree.clear()
  await cache.clearAll()
  syncView()
  decorations.refresh()
  diagnostics.clear()
  output.appendLine(`[tree] results cleared (${paths.length} cached entr${paths.length === 1 ? 'y' : 'ies'} dropped)`)
}

// ── Error handling ───────────────────────────────────────────────────────────
function handleScanError(
  err: unknown,
  filename: string,
  panel: ReportPanel | undefined,
  auto = false,
): void {
  if (err instanceof ScanError) {
    output.appendLine(`[error] ${filename}: ${err.kind}: ${err.message}`)
    panel?.error(filename, err.message, err.kind)

    // A background scan never interrupts. A rate limit in particular would
    // otherwise pop on every debounced write for the rest of the hour.
    if (auto) return

    if (err.kind === 'rate-limit') {
      const retry = err.retryAfter ? ` Retry after ${err.retryAfter}s.` : ''
      vscode.window
        .showWarningMessage(
          `mlab: rate limit reached.${retry} Use an API token for 25 scans/hour.`,
          'Get a token',
          'Add token…',
        )
        .then((choice) => {
          if (choice === 'Get a token') {
            vscode.env.openExternal(vscode.Uri.parse('https://vuln.mlab.sh/me/tokens'))
          } else if (choice === 'Add token…') {
            vscode.commands.executeCommand('mlab.manageToken')
          }
        })
    } else if (err.kind !== 'cancelled') {
      vscode.window.showErrorMessage(`mlab: ${err.message}`)
    }
    return
  }

  const message = err instanceof Error ? err.message : String(err)
  output.appendLine(`[error] ${filename}: ${message}`)
  panel?.error(filename, `Unexpected error: ${message}`)
  if (auto) return
  vscode.window.showErrorMessage(`mlab: unexpected error scanning ${filename}. See the "mlab" output channel.`)
}

// ── First-scan privacy consent ───────────────────────────────────────────────
// Shown once, before the very first network scan. The choice is remembered in
// globalState so we never nag on later scans. Cancel aborts the scan.
async function ensurePrivacyConsent(): Promise<boolean> {
  if (ctx.globalState.get<boolean>(PRIVACY_KEY)) return true

  const scanOnce = 'Scan now'
  const always = "Scan and don't ask again"
  const choice = await vscode.window.showInformationMessage(
    'Scan this lockfile with vuln.mlab.sh?',
    {
      modal: true,
      detail:
        'The contents of the selected lockfile are uploaded to vuln.mlab.sh to resolve known CVEs. Only the lockfile is sent, never your source code. Nothing is uploaded until you trigger a scan.',
    },
    scanOnce,
    always,
  )

  if (choice === always) {
    await ctx.globalState.update(PRIVACY_KEY, true)
    return true
  }
  return choice === scanOnce
}

// ── Token management (SecretStorage) ─────────────────────────────────────────
async function setToken(): Promise<void> {
  const token = await vscode.window.showInputBox({
    title: 'mlab API token',
    prompt: 'Stored securely in SecretStorage. Never written to settings or the workspace.',
    password: true,
    ignoreFocusOut: true,
    placeHolder: 'Paste your token from vuln.mlab.sh/me/tokens',
  })
  if (token === undefined) return
  if (token.trim() === '') {
    await ctx.secrets.delete(TOKEN_KEY)
    vscode.window.showInformationMessage('mlab: API token cleared.')
    return
  }
  await ctx.secrets.store(TOKEN_KEY, token.trim())
  vscode.window.showInformationMessage('mlab: API token saved.')
}

async function clearToken(): Promise<void> {
  await ctx.secrets.delete(TOKEN_KEY)
  vscode.window.showInformationMessage('mlab: API token cleared.')
}

// ── Scan every lockfile in the workspace ─────────────────────────────────────
// Quota aware by construction. Cached lockfiles cost nothing, so the sweep first
// works out how many files would actually hit the network and asks before
// spending them: the anonymous budget is 8 scans an hour, 25 with a token.
async function scanWorkspace(): Promise<void> {
  if (!vscode.workspace.isTrusted) {
    vscode.window.showWarningMessage(
      'mlab: scanning is disabled in Restricted Mode because it uploads the lockfile. Trust this workspace to scan.',
    )
    return
  }

  const includes = lockfileGlob()
  const excludes = `**/{${SKIP_DIRS.join(',')}}/**`
  const found = await vscode.workspace.findFiles(includes, excludes)
  if (found.length === 0) {
    vscode.window.showInformationMessage('mlab: no supported lockfile found in this workspace.')
    return
  }

  // Split cached from not, so the confirmation names the real cost.
  const fresh: vscode.Uri[] = []
  const cached: vscode.Uri[] = []
  for (const uri of found) {
    let hit = false
    try {
      const body = await vscode.workspace.fs.readFile(uri)
      hit = cache.lookup(uri.fsPath, hashOf(body)) !== undefined
    } catch {
      hit = false
    }
    if (hit) cached.push(uri)
    else fresh.push(uri)
  }

  if (fresh.length > 1) {
    const go = `Scan ${fresh.length}`
    const cachedNote = cached.length ? ` ${cached.length} already cached and free.` : ''
    const choice = await vscode.window.showWarningMessage(
      `mlab: ${fresh.length} lockfiles need a fresh scan.${cachedNote} That spends ${fresh.length} of your hourly quota (8 anonymous, 25 with a token).`,
      { modal: true },
      go,
    )
    if (choice !== go) return
  }

  const order = [...cached, ...fresh]
  let scanned = 0
  let reused = 0
  let vulnerable = 0
  let stopped: string | undefined

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'mlab: scanning workspace',
      cancellable: true,
    },
    async (progress, token) => {
      const controller = new AbortController()
      token.onCancellationRequested(() => controller.abort())

      for (let i = 0; i < order.length; i++) {
        if (token.isCancellationRequested) {
          stopped = 'cancelled'
          break
        }
        const uri = order[i]
        const name = basenameOf(uri.fsPath)
        progress.report({
          message: `${name} (${i + 1}/${order.length})`,
          increment: 100 / order.length,
        })

        const result = await performScan(uri, { batch: true, signal: controller.signal })
        if (result.kind === 'cached') reused++
        else if (result.kind === 'scanned') scanned++
        else if (result.kind === 'skipped' && result.reason === 'no-consent') {
          stopped = 'no-consent'
          break
        } else if (result.kind === 'failed') {
          // A rate limit will hit every remaining file too, so stop rather than
          // burn the rest of the run on the same error.
          if (result.error instanceof ScanError && result.error.kind === 'rate-limit') {
            stopped = 'rate-limit'
            break
          }
        }
        if (result.kind !== 'skipped' && result.kind !== 'failed') {
          if (result.outcome.findings.length > 0) vulnerable++
        }
      }
    },
  )

  const parts = [`${scanned} scanned`, `${reused} from cache`]
  const line = `mlab: ${parts.join(', ')}. ${vulnerable} lockfile${vulnerable === 1 ? '' : 's'} with known vulnerabilities.`
  output.appendLine(`[sweep] ${line}`)

  if (stopped === 'rate-limit') {
    vscode.window.showWarningMessage(`${line} Stopped early: hourly quota reached.`)
  } else if (stopped === 'cancelled') {
    vscode.window.showInformationMessage(`${line} Stopped: cancelled.`)
  } else if (stopped === 'no-consent') {
    output.appendLine('[sweep] stopped: privacy consent declined')
  } else if (vulnerable > 0) {
    vscode.window.showWarningMessage(line)
  } else {
    vscode.window.showInformationMessage(line)
  }
}

/** Single source for the lockfile glob, derived from `KNOWN` in detect.ts. */
function lockfileGlob(): string {
  return `**/{${SUPPORTED_BASENAMES.join(',')}}`
}

