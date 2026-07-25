import * as vscode from 'vscode'
import { MLAB_CSS } from './theme'

// A small settings / token page. The user pastes their vuln.mlab.sh API token
// here to raise the quota from 8 to 25 scans/hour. The token is stored ONLY in
// SecretStorage: never in settings.json, never on disk in plaintext, never in
// the workspace. The webview field is transient; on Save it is handed to the
// extension via postMessage and immediately persisted to SecretStorage.

const TOKEN_KEY = 'mlab.apiToken'

function nonce(): string {
  let s = ''
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  for (let i = 0; i < 32; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

export class TokenPanel {
  private static current: TokenPanel | undefined
  private readonly panel: vscode.WebviewPanel
  private disposed = false

  private constructor(
    panel: vscode.WebviewPanel,
    private readonly context: vscode.ExtensionContext,
  ) {
    this.panel = panel
    panel.onDidDispose(() => {
      this.disposed = true
      if (TokenPanel.current === this) TokenPanel.current = undefined
    })
    panel.webview.onDidReceiveMessage((msg) => this.onMessage(msg))
  }

  static async show(context: vscode.ExtensionContext): Promise<void> {
    if (TokenPanel.current && !TokenPanel.current.disposed) {
      TokenPanel.current.panel.reveal(vscode.ViewColumn.Active)
      await TokenPanel.current.render()
      return
    }
    const panel = vscode.window.createWebviewPanel(
      'mlab.token',
      'vuln.mlab.sh API token',
      vscode.ViewColumn.Active,
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'resources')],
      },
    )
    panel.iconPath = vscode.Uri.joinPath(context.extensionUri, 'resources', 'icon.png')
    TokenPanel.current = new TokenPanel(panel, context)
    await TokenPanel.current.render()
  }

  private async onMessage(msg: any): Promise<void> {
    switch (msg?.type) {
      case 'save': {
        const token = String(msg.token ?? '').trim()
        if (!token) {
          await this.context.secrets.delete(TOKEN_KEY)
          vscode.window.showInformationMessage('mlab: API token cleared.')
        } else {
          await this.context.secrets.store(TOKEN_KEY, token)
          vscode.window.showInformationMessage('mlab: API token saved. Quota raised to 25 scans/hour.')
        }
        await this.render()
        break
      }
      case 'clear':
        await this.context.secrets.delete(TOKEN_KEY)
        vscode.window.showInformationMessage('mlab: API token cleared.')
        await this.render()
        break
      case 'openTokens':
        vscode.env.openExternal(vscode.Uri.parse('https://vuln.mlab.sh/me/tokens'))
        break
      case 'openSettings':
        vscode.commands.executeCommand('workbench.action.openSettings', 'mlab.')
        break
    }
  }

  private async render(): Promise<void> {
    if (this.disposed) return
    const hasToken = !!(await this.context.secrets.get(TOKEN_KEY))
    this.panel.webview.html = this.html(hasToken)
  }

  private html(hasToken: boolean): string {
    const n = nonce()
    const logo = this.panel.webview.asWebviewUri(
      vscode.Uri.joinPath(this.context.extensionUri, 'resources', 'icon.png'),
    )

    const status = hasToken
      ? `<div class="status ok"><span class="dot"></span><div><strong>Token set.</strong> You have <strong>25 scans/hour</strong>.</div></div>`
      : `<div class="status anon"><span class="dot"></span><div><strong>Anonymous.</strong> Limited to <strong>8 scans/hour</strong> per IP. Add a token for 25/hour.</div></div>`

    const clearBtn = hasToken
      ? `<button id="clear" class="btn ghost" type="button">Remove token</button>`
      : ''

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${this.panel.webview.cspSource}; style-src 'unsafe-inline'; script-src 'nonce-${n}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${MLAB_CSS}${STYLE}</style>
</head>
<body>
  <main>
  <header>
    <img class="logo" src="${logo}" alt="mlab" />
    <div>
      <h1>vuln.mlab.sh API token</h1>
      <p class="muted">Raise your scan quota. Stored securely in VS Code SecretStorage, never in your settings or workspace.</p>
    </div>
  </header>

  ${status}

  <ol class="steps">
    <li>Open <a id="tokens-link" href="#">vuln.mlab.sh/me/tokens</a> and generate a personal token.</li>
    <li>Paste it below and click <em>Save token</em>.</li>
  </ol>

  <label for="token" class="lbl">API token</label>
  <div class="row">
    <input id="token" type="password" placeholder="${hasToken ? 'A token is already set' : 'Paste your token'}" autocomplete="off" spellcheck="false" />
    <button id="reveal" class="btn ghost" type="button" title="Show or hide">&#128065;</button>
  </div>

  <div class="actions">
    <button id="save" class="btn" type="button">Save token</button>
    ${clearBtn}
    <button id="settings" class="btn ghost" type="button">Open extension settings</button>
  </div>

  <div class="card quota-card">
    <table class="quota">
      <thead><tr><th>Tier</th><th>Scans per hour</th></tr></thead>
      <tbody>
        <tr><td><span class="sev sev-unknown">Anonymous</span></td><td class="mono">8 <span class="muted">/ IP</span></td></tr>
        <tr><td><span class="sev sev-low">With token</span></td><td class="mono"><strong>25</strong></td></tr>
      </tbody>
    </table>
  </div>

  <p class="muted small">Only the lockfile you choose to scan is uploaded, never your source code.</p>
  </main>

<script nonce="${n}">
  const vscode = acquireVsCodeApi();
  const input = document.getElementById('token');
  document.getElementById('save').addEventListener('click', () => {
    vscode.postMessage({ type: 'save', token: input.value });
    input.value = '';
  });
  document.getElementById('clear')?.addEventListener('click', () => vscode.postMessage({ type: 'clear' }));
  document.getElementById('settings').addEventListener('click', () => vscode.postMessage({ type: 'openSettings' }));
  document.getElementById('tokens-link').addEventListener('click', (e) => { e.preventDefault(); vscode.postMessage({ type: 'openTokens' }); });
  document.getElementById('reveal').addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
  });
</script>
</body>
</html>`
  }
}

const STYLE = `
main { padding: 26px 30px 36px; max-width: 680px; margin: 0 auto; }
header { display: flex; gap: 16px; align-items: center; }
.logo { width: 52px; height: 52px; border-radius: var(--mlab-radius-md); box-shadow: var(--mlab-shadow); }
h1 { font-size: 1.3rem; margin: 0 0 3px; letter-spacing: -0.01em; }
.status {
  display: flex; align-items: center; gap: 10px;
  margin: 20px 0; padding: 12px 16px; border-radius: var(--mlab-radius-md); border: 1px solid transparent;
}
.status .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; }
.status.ok { background: rgba(34, 197, 94, 0.12); border-color: rgba(34, 197, 94, 0.25); }
.status.ok .dot { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
.status.anon { background: rgba(245, 158, 11, 0.12); border-color: rgba(245, 158, 11, 0.25); }
.status.anon .dot { background: #f59e0b; box-shadow: 0 0 8px #f59e0b; }
.steps { padding-left: 20px; color: var(--vscode-descriptionForeground); }
.steps li { margin: 3px 0; }
.lbl { display: block; margin: 18px 0 6px; font-family: var(--mlab-mono); font-size: 0.72em; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; color: var(--vscode-descriptionForeground); }
.row { display: flex; gap: 8px; }
input {
  flex: 1; padding: 9px 12px; border-radius: var(--mlab-radius-sm); font-family: var(--mlab-mono);
  color: var(--vscode-input-foreground);
  background: var(--vscode-input-background);
  border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
}
.actions { display: flex; gap: 8px; flex-wrap: wrap; margin: 16px 0 8px; }
.quota-card { margin: 22px 0; }
.quota { border-collapse: collapse; width: 100%; }
.quota th, .quota td { padding: 10px 16px; text-align: left; }
.quota thead th {
  font-family: var(--mlab-mono); font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
  color: var(--vscode-descriptionForeground); background: rgba(127,127,127,0.05); border-bottom: var(--mlab-hairline);
}
.quota tbody tr:first-child td { border-bottom: var(--mlab-hairline); }
`
