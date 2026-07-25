import * as vscode from 'vscode'
import { basenameOf, detectFormat, isSupportedLockfile } from './detect'
import { ReportPanel } from './views/reportPanel'
import { TokenPanel } from './views/tokenPanel'
import { scanLockfile, ScanError, summarize } from './api/client'

// ─────────────────────────────────────────────────────────────────────────────
// Non-negotiable rule: NO automatic scanning. No FileSystemWatcher, no document
// listeners, no scan on activation, no background polling. Every scan below is
// triggered by an explicit user action, and activate() makes zero network calls.
// ─────────────────────────────────────────────────────────────────────────────

const TOKEN_KEY = 'mlab.apiToken'
const PRIVACY_KEY = 'mlab.privacyConsent'

let output: vscode.OutputChannel
let ctx: vscode.ExtensionContext
let lastScanned: vscode.Uri | undefined

export function activate(context: vscode.ExtensionContext): void {
  ctx = context
  output = vscode.window.createOutputChannel('mlab')
  context.subscriptions.push(output)

  const register = (id: string, fn: (...args: any[]) => any) =>
    context.subscriptions.push(vscode.commands.registerCommand(id, fn))

  register('mlab.checkLockfile', (resource?: vscode.Uri) => checkLockfile(resource))
  register('mlab.scanWorkspace', () => scanWorkspace())
  register('mlab.rescan', () => rescan())
  register('mlab.clearResults', () => stub('Clear results'))
  register('mlab.setToken', () => setToken())
  register('mlab.clearToken', () => clearToken())
  register('mlab.manageToken', () => TokenPanel.show(ctx))
}

export function deactivate(): void {
  // Disposables are handled via context.subscriptions.
}

// ── Scan a single lockfile ───────────────────────────────────────────────────
async function checkLockfile(resource?: vscode.Uri): Promise<void> {
  const uri = resource ?? vscode.window.activeTextEditor?.document.uri
  if (!uri) {
    vscode.window.showWarningMessage('mlab: open or right-click a lockfile to scan it.')
    return
  }
  if (!isSupportedLockfile(uri.fsPath)) {
    vscode.window.showWarningMessage(`mlab: "${basenameOf(uri.fsPath)}" is not a supported lockfile.`)
    return
  }
  if (!vscode.workspace.isTrusted) {
    vscode.window.showWarningMessage(
      'mlab: scanning is disabled in Restricted Mode because it uploads the lockfile. Trust this workspace to scan.',
    )
    return
  }
  if (!(await ensurePrivacyConsent())) return

  const filename = basenameOf(uri.fsPath)
  const format = detectFormat(uri.fsPath)
  const cfg = vscode.workspace.getConfiguration('mlab')
  const apiUrl = cfg.get<string>('apiUrl', 'https://vuln.mlab.sh/api/v2/scan')
  const timeoutMs = cfg.get<number>('timeoutMs', 30000)

  const panel = ReportPanel.show(ctx.extensionUri)
  panel.loading(filename)

  const controller = new AbortController()
  panel.onCancel(() => controller.abort())

  try {
    const body = await vscode.workspace.fs.readFile(uri)
    const token = await ctx.secrets.get(TOKEN_KEY)
    output.appendLine(`[scan] ${filename} → ${apiUrl}${token ? ' (token)' : ' (anonymous)'}`)

    const outcome = await scanLockfile({
      apiUrl,
      filename,
      format,
      body,
      token: token || undefined,
      timeoutMs,
      signal: controller.signal,
    })

    lastScanned = uri
    panel.report(filename, outcome)

    const line = summarize(outcome)
    output.appendLine(`[scan] ${filename}: ${line}`)
    if (outcome.findings.length === 0) {
      vscode.window.showInformationMessage(`mlab: no known vulnerabilities in ${filename}.`)
    } else {
      vscode.window.showWarningMessage(`mlab: ${line} in ${filename}.`)
    }
  } catch (err) {
    handleScanError(err, filename, panel)
  }
}

async function rescan(): Promise<void> {
  if (!lastScanned) {
    vscode.window.showInformationMessage('mlab: nothing to rescan yet. Run a scan first.')
    return
  }
  await checkLockfile(lastScanned)
}

// ── Error handling ───────────────────────────────────────────────────────────
function handleScanError(err: unknown, filename: string, panel: ReportPanel): void {
  if (err instanceof ScanError) {
    output.appendLine(`[error] ${filename}: ${err.kind}: ${err.message}`)
    panel.error(filename, err.message, err.kind)

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
  panel.error(filename, `Unexpected error: ${message}`)
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
    title: 'vuln.mlab.sh API token',
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

function stub(label: string): void {
  const msg = `mlab (stub): "${label}" is not implemented yet.`
  output.appendLine(msg)
  vscode.window.showInformationMessage(msg)
}
