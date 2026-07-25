import * as vscode from 'vscode'
import { ScanOutcome, ScanErrorKind } from '../api/client'
import { loadingHtml, reportHtml, errorHtml, RenderOpts } from './reportHtml'

// A single reusable webview panel: shows a loading state while a scan runs, then
// the final report (or a friendly error). Opens beside the lockfile, keeping
// focus on the editor. The Cancel button posts a message wired to an
// AbortController so cancellation truly aborts the in-flight HTTP request.
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
      'vuln.mlab.sh Scan report',
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

  onCancel(handler: () => void): void {
    this.cancelHandler = handler
  }

  loading(filename: string): void {
    if (this.disposed) return
    this.panel.title = `Scanning ${filename}…`
    this.panel.webview.html = loadingHtml(filename, this.opts())
  }

  report(filename: string, outcome: ScanOutcome): void {
    if (this.disposed) return
    this.cancelHandler = undefined
    this.panel.title = `Report · ${filename}`
    this.panel.webview.html = reportHtml(filename, outcome, this.opts())
  }

  error(filename: string, message: string, kind?: ScanErrorKind): void {
    if (this.disposed) return
    this.cancelHandler = undefined
    this.panel.title = `Report · ${filename}`
    this.panel.webview.html = errorHtml(filename, message, kind, this.opts())
  }
}
