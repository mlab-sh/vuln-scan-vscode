import * as vscode from 'vscode'
import * as fs from 'fs'
import * as path from 'path'
import { basenameOf, detectFormat, isSupportedLockfile } from './detect'
import { ReportPanel } from './views/reportPanel'
import { HomePanel, onSettingsWritten } from './views/homePanel'
import { FindingsTree } from './views/findingsTree'
import { LockfileDecorations } from './views/decorations'
import { ScanCache, hashOf } from './cache'
import { AutoScanner } from './autoscan'
import * as config from './config'
import { scanLockfile, ScanError, summarize } from './api/client'

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

export function activate(context: vscode.ExtensionContext): void {
  ctx = context
  output = vscode.window.createOutputChannel('mlab')
  context.subscriptions.push(output)

  tree = new FindingsTree()
  view = vscode.window.createTreeView('mlab.findings', { treeDataProvider: tree })
  context.subscriptions.push(view)

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
  onSettingsWritten(() => autoScanner.sync())
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('mlab')) autoScanner.sync()
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
    restored++
  }

  syncView()
  decorations.refresh()
  if (restored > 0) {
    output.appendLine(`[cache] restored ${restored} previous result(s) without scanning`)
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

// ── Scan a single lockfile ───────────────────────────────────────────────────
interface ScanOpts {
  /** True when the file watcher triggered this, not the user. */
  auto?: boolean
}

async function checkLockfile(resource?: vscode.Uri, opts: ScanOpts = {}): Promise<void> {
  const auto = opts.auto === true
  const uri = resource ?? vscode.window.activeTextEditor?.document.uri
  if (!uri) {
    vscode.window.showWarningMessage('mlab: open or right-click a lockfile to scan it.')
    return
  }
  if (!isSupportedLockfile(uri.fsPath)) {
    if (!auto) {
      vscode.window.showWarningMessage(`mlab: "${basenameOf(uri.fsPath)}" is not a supported lockfile.`)
    }
    return
  }
  if (!vscode.workspace.isTrusted) {
    if (!auto) {
      vscode.window.showWarningMessage(
        'mlab: scanning is disabled in Restricted Mode because it uploads the lockfile. Trust this workspace to scan.',
      )
    }
    return
  }

  const filename = basenameOf(uri.fsPath)

  // Read first: the cache is keyed on content, so an unchanged lockfile costs
  // nothing at all, no consent prompt and no request.
  let body: Uint8Array
  try {
    body = await vscode.workspace.fs.readFile(uri)
  } catch (err) {
    if (!auto) vscode.window.showErrorMessage(`mlab: could not read ${filename}.`)
    output.appendLine(`[error] ${filename}: unreadable: ${err instanceof Error ? err.message : err}`)
    return
  }
  const hash = hashOf(body)

  const hit = cache.lookup(uri.fsPath, hash)
  if (hit) {
    tree.record(uri, filename, hit.outcome)
    syncView()
    decorations.refresh(uri)
    output.appendLine(`[cache] ${filename}: ${summarize(hit.outcome)} (unchanged since last scan)`)
    if (!auto) ReportPanel.show(ctx.extensionUri).report(filename, hit.outcome)
    return
  }

  // Only now does anything leave the machine, so this is where consent belongs.
  // An automatic scan never shows the modal: if consent was not given already,
  // it simply does nothing.
  if (auto) {
    if (!ctx.globalState.get<boolean>(PRIVACY_KEY)) {
      output.appendLine(`[auto] ${filename}: skipped, privacy consent not given yet`)
      return
    }
  } else if (!(await ensurePrivacyConsent())) {
    return
  }

  const format = detectFormat(uri.fsPath)
  const apiUrl = config.get('apiUrl')
  const timeoutMs = config.get('timeoutMs')

  // An automatic scan is silent: no report panel, no popups. Its results surface
  // through the red mark in the Explorer, the findings tree and the output
  // channel. Only a user triggered scan gets the panel.
  const panel = auto ? undefined : ReportPanel.show(ctx.extensionUri)
  panel?.loading(filename)

  const controller = new AbortController()
  panel?.onCancel(() => controller.abort())

  const run = async (): Promise<void> => {
    try {
      const token = await ctx.secrets.get(TOKEN_KEY)
      output.appendLine(
        `[${auto ? 'auto' : 'scan'}] ${filename} → ${apiUrl}${token ? ' (token)' : ' (anonymous)'}`,
      )

      const outcome = await scanLockfile({
        apiUrl,
        filename,
        format,
        body,
        token: token || undefined,
        timeoutMs,
        signal: controller.signal,
      })

      await cache.put(uri.fsPath, filename, hash, outcome)
      tree.record(uri, filename, outcome)
      syncView()
      decorations.refresh(uri)
      panel?.report(filename, outcome)

      const line = summarize(outcome)
      output.appendLine(`[${auto ? 'auto' : 'scan'}] ${filename}: ${line}`)
      if (auto) return
      if (outcome.findings.length === 0) {
        vscode.window.showInformationMessage(`mlab: no known vulnerabilities in ${filename}.`)
      } else {
        vscode.window.showWarningMessage(`mlab: ${line} in ${filename}.`)
      }
    } catch (err) {
      handleScanError(err, filename, panel, auto)
    }
  }

  // ProgressLocation.Window is the discreet status bar spinner, so an automatic
  // scan is visible if you look for it but never steals focus.
  if (auto) {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: `mlab: checking ${filename}` },
      run,
    )
  } else {
    await run()
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

// ── Placeholder (arrives with the tree view + diagnostics) ───────────────────
async function scanWorkspace(): Promise<void> {
  const excludes = `**/{node_modules,vendor,target,dist,.git}/**`
  const includes = `**/{Cargo.lock,package-lock.json,npm-shrinkwrap.json,composer.lock,Gemfile.lock,go.sum,requirements.txt,mise.lock}`
  const found = await vscode.workspace.findFiles(includes, excludes)
  const list = found.map((u) => basenameOf(u.fsPath)).join(', ') || '(none)'
  const msg = `mlab (stub): found ${found.length} lockfile(s): ${list}`
  output.appendLine(msg)
  vscode.window.showInformationMessage(msg)
}
