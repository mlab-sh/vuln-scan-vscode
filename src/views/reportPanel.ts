import * as vscode from 'vscode'
import { ScanOutcome, ScanErrorKind } from '../api/client'
import { loadingHtml, reportHtml, errorHtml, RenderOpts } from './reportHtml'

// A single reusable webview panel: shows a loading state while a scan runs, then
// the final report (or a friendly error). Opens beside the lockfile, keeping
// focus on the editor. The Cancel button posts a message wired to an
// AbortController so cancellation truly aborts the in-flight HTTP request.
//
// Because the panel is shared, scans are generation stamped. Starting a second
// scan aborts the first (its panel is gone, so its result would be discarded
// anyway) and any late result from a superseded scan is ignored rather than
// overwriting what is on screen.
//
// All HTML lives in the vscode-free ./reportHtml module; this class only owns the
// panel lifecycle and message plumbing.

function nonce(): string {
  let s = ''
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  for (let i = 0; i < 32; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

export class ReportPanel {
  private static current: ReportPanel | undefined
  private readonly panel: vscode.WebviewPanel
  private readonly logoUri: string
  private disposed = false
  private cancelHandler: (() => void) | undefined
  /** Incremented per scan; a stale generation may no longer write to the panel. */
  private generation = 0

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this.panel = panel
    this.logoUri = panel.webview
      .asWebviewUri(vscode.Uri.joinPath(extensionUri, 'resources', 'icon.png'))
      .toString()
    this.panel.onDidDispose(() => {
      this.disposed = true
      if (ReportPanel.current === this) ReportPanel.current = undefined
    })
    this.panel.webview.onDidReceiveMessage((msg) => {
      if (msg?.type === 'cancel') this.cancelHandler?.()
    })
  }

  static show(extensionUri: vscode.Uri): ReportPanel {
    if (ReportPanel.current && !ReportPanel.current.disposed) {
      ReportPanel.current.panel.reveal(vscode.ViewColumn.Beside, true)
      return ReportPanel.current
    }
    const panel = vscode.window.createWebviewPanel(
      'mlab.report',
      'mlab scan report',
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'resources')],
      },
    )
    panel.iconPath = vscode.Uri.joinPath(extensionUri, 'resources', 'icon.png')
    ReportPanel.current = new ReportPanel(panel, extensionUri)
    return ReportPanel.current
  }

  private opts(): RenderOpts {
    return { nonce: nonce(), cspSource: this.panel.webview.cspSource, logoUri: this.logoUri }
  }

  /**
   * Claim the panel for a new scan. Any scan already showing is cancelled, since
   * it has just lost the only surface it could report on. The returned token is
   * how later calls prove they are still the scan the panel belongs to.
   */
  begin(filename: string, onCancel: () => void): number {
    const superseded = this.cancelHandler
    this.cancelHandler = onCancel
    this.generation++
    if (superseded) superseded()

    if (!this.disposed) {
      this.panel.title = `Scanning ${filename}…`
      this.panel.webview.html = loadingHtml(filename, this.opts())
    }
    return this.generation
  }

  /**
   * `scannedAt` is set when the report comes from the cache, not a live scan.
   * `token` identifies the scan; a superseded one is ignored rather than allowed
   * to overwrite whatever replaced it.
   */
  report(filename: string, outcome: ScanOutcome, scannedAt?: number, token?: number): void {
    if (this.disposed) return
    if (token !== undefined && token !== this.generation) return
    this.cancelHandler = undefined
    this.panel.title = `Report · ${filename}`
    this.panel.webview.html = reportHtml(filename, outcome, this.opts(), scannedAt)
  }

  error(filename: string, message: string, kind?: ScanErrorKind, token?: number): void {
    if (this.disposed) return
    if (token !== undefined && token !== this.generation) return
    this.cancelHandler = undefined
    this.panel.title = `Report · ${filename}`
    this.panel.webview.html = errorHtml(filename, message, kind, this.opts())
  }
}
