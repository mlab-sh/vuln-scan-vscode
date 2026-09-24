import * as vscode from 'vscode'
import { mlabCss } from './theme'
import { esc } from './reportHtml'
import { SUPPORTED_BASENAMES } from '../detect'
import * as config from '../config'

// The full width mlab home, opened in the editor area rather than the sidebar.
// The Activity Bar icon can only ever open a sidebar, so the sidebar holds the
// findings tree and pushes here for everything else: quota status, the API
// token, the scan entry points, and a jump to the native settings UI.
//
// The `mlab.*` settings are editable inline here. To avoid the usual trap of a
// custom settings page, writes go through the real configuration API with an
// explicit User/Workspace target, each row says where its current value comes
// from, and the native settings editor stays one click away.
//
// The token is stored ONLY in SecretStorage: never in settings, never in the
// workspace, never on disk in plaintext. The webview field is transient; on Save
// it is handed to the extension via postMessage and immediately persisted.

const TOKEN_KEY = 'mlab.apiToken'
/** The mlab platform key: a different credential, for indicator lookups. */
const PLATFORM_KEY = 'mlab.platformKey'

/**
 * Called after any settings write. `.mlab` files are outside the VS Code
 * configuration system, so `onDidChangeConfiguration` does not fire for them and
 * the watcher has to be told explicitly.
 */
let autoScanChanged: () => void = () => {}
export function onSettingsWritten(fn: () => void): void {
  autoScanChanged = fn
}

/** The `mlab.*` settings rendered inline on the page, in display order. */
interface SettingDesc {
  key: string
  label: string
  kind: 'string' | 'enum' | 'number' | 'boolean'
  hint: string
  options?: string[]
  min?: number
}

const SETTINGS: SettingDesc[] = [
  {
    key: 'autoScan',
    label: 'Scan automatically on change',
    kind: 'boolean',
    hint: 'Rescan a lockfile when its contents change. Results are cached per content, so an unchanged file is never re-uploaded, and nothing is uploaded at all before you accept the privacy prompt.',
  },
  {
    key: 'analyzeSelection',
    label: 'Analyze selection in the context menu',
    kind: 'boolean',
    hint: 'Right-click a selected URL, IP, email, file hash or MAC address to look it up. Only the selected value is sent, never the file around it.',
  },
  {
    key: 'cveHover',
    label: 'CVE details on hover',
    kind: 'boolean',
    hint: 'Hover a CVE identifier in any file to see its CVSS, its exploitation likelihood and whether it is actively exploited. Only the identifier is looked up, never your code.',
  },
  {
    key: 'apiUrl',
    label: 'Scan endpoint',
    kind: 'string',
    hint: 'Point this at a self-hosted vuln.mlab.sh instance to keep lockfiles inside your network.',
  },
  {
    key: 'severityFloor',
    label: 'Severity floor',
    kind: 'enum',
    options: ['any', 'low', 'medium', 'high', 'critical'],
    hint: 'Lowest severity reported as a Warning or Error. Below it, findings are Information. Never fails anything.',
  },
  {
    key: 'timeoutMs',
    label: 'Request timeout',
    kind: 'number',
    min: 1000,
    hint: 'Per request timeout in milliseconds. Raise it for very large manifests on a slow link.',
  },
]

/** Where a value currently comes from, so the page can say so out loud. */
type Origin = config.Layer

interface SettingState {
  desc: SettingDesc
  value: unknown
  origin: Origin
}

function nonce(): string {
  let s = ''
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  for (let i = 0; i < 32; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

export class HomePanel {
  private static current: HomePanel | undefined
  private readonly panel: vscode.WebviewPanel
  private disposed = false
  /** Which configuration target inline edits are written to. */
  private scope: 'user' | 'workspace' = 'user'

  private constructor(
    panel: vscode.WebviewPanel,
    private readonly context: vscode.ExtensionContext,
  ) {
    this.panel = panel
    panel.onDidDispose(() => {
      this.disposed = true
      if (HomePanel.current === this) HomePanel.current = undefined
    })
    panel.webview.onDidReceiveMessage((msg) => this.onMessage(msg))

    // Settings can also change from the native editor or another window; keep
    // the page honest rather than showing a stale value.
    const sub = vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('mlab')) void this.render()
    })
    panel.onDidDispose(() => sub.dispose())
  }

  /** True when a folder is open, so the Workspace target is actually writable. */
  private get hasWorkspace(): boolean {
    return (vscode.workspace.workspaceFolders?.length ?? 0) > 0
  }

  /** Current value of each setting plus which layer it came from. */
  private readSettings(): SettingState[] {
    return SETTINGS.map((desc) => {
      const r = config.resolve(desc.key as keyof config.MlabConfig)
      return { desc, value: r.value, origin: r.layer }
    })
  }

  static async show(context: vscode.ExtensionContext): Promise<void> {
    if (HomePanel.current && !HomePanel.current.disposed) {
      HomePanel.current.panel.reveal(vscode.ViewColumn.Active)
      await HomePanel.current.render()
      return
    }
    const panel = vscode.window.createWebviewPanel(
      'mlab.home',
      'mlab',
      vscode.ViewColumn.Active,
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'resources')],
      },
    )
    panel.iconPath = vscode.Uri.joinPath(context.extensionUri, 'resources', 'icon.png')
    HomePanel.current = new HomePanel(panel, context)
    await HomePanel.current.render()
  }

  /** Re-render the open page, e.g. after a token changed elsewhere. */
  static async refresh(): Promise<void> {
    if (HomePanel.current && !HomePanel.current.disposed) await HomePanel.current.render()
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
      case 'savePlatform': {
        const key = String(msg.token ?? '').trim()
        if (!key) {
          await this.context.secrets.delete(PLATFORM_KEY)
          vscode.window.showInformationMessage('mlab: platform key cleared.')
        } else {
          await this.context.secrets.store(PLATFORM_KEY, key)
          vscode.window.showInformationMessage('mlab: platform key saved.')
        }
        await this.render()
        break
      }
      case 'clearPlatform':
        await this.context.secrets.delete(PLATFORM_KEY)
        vscode.window.showInformationMessage('mlab: platform key cleared.')
        await this.render()
        break
      case 'openPlatformKeys':
        vscode.env.openExternal(vscode.Uri.parse('https://mlab.sh/account/subscription'))
        break
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
      case 'checkLockfile':
        vscode.commands.executeCommand('mlab.checkLockfile')
        break
      case 'scanWorkspace':
        vscode.commands.executeCommand('mlab.scanWorkspace')
        break
      case 'setScope':
        this.scope = msg.scope === 'workspace' ? 'workspace' : 'user'
        await this.render()
        break
      case 'setConfig': {
        const desc = SETTINGS.find((d) => d.key === msg.key)
        if (!desc) break
        const parsed = this.coerce(desc, msg.value)
        if (parsed === undefined) {
          vscode.window.showWarningMessage(`mlab: "${String(msg.value)}" is not a valid ${desc.label}.`)
          await this.render()
          break
        }
        try {
          await config.write(desc.key as keyof config.MlabConfig, parsed as never, this.scope)
        } catch (err) {
          vscode.window.showWarningMessage(
            `mlab: ${err instanceof Error ? err.message : 'could not write the config file.'}`,
          )
        }
        autoScanChanged()
        await this.render()
        break
      }
      case 'resetConfig': {
        const desc = SETTINGS.find((d) => d.key === msg.key)
        if (!desc) break
        await config.reset(desc.key as keyof config.MlabConfig)
        autoScanChanged()
        await this.render()
        break
      }
    }
  }

  /** Validate and convert a raw webview value, or undefined when it is invalid. */
  private coerce(desc: SettingDesc, raw: unknown): unknown {
    if (desc.kind === 'boolean') return raw === true || raw === 'true'
    if (desc.kind === 'number') {
      const n = Number(raw)
      if (!Number.isFinite(n)) return undefined
      if (desc.min !== undefined && n < desc.min) return undefined
      return Math.round(n)
    }
    const text = String(raw ?? '').trim()
    if (desc.kind === 'enum') return desc.options?.includes(text) ? text : undefined
    if (desc.key === 'apiUrl') {
      if (text === '') return undefined
      try {
        const u = new URL(text)
        if (u.protocol !== 'https:' && u.protocol !== 'http:') return undefined
      } catch {
        return undefined
      }
    }
    return text
  }

  private async render(): Promise<void> {
    if (this.disposed) return
    const hasToken = !!(await this.context.secrets.get(TOKEN_KEY))
    const hasPlatform = !!(await this.context.secrets.get(PLATFORM_KEY))
    this.panel.webview.html = this.html(hasToken, hasPlatform, this.readSettings())
  }

  /** One editable settings row: control, provenance badge, reset. */
  private settingRow(st: SettingState): string {
    const { desc, value, origin } = st
    const id = `set-${desc.key}`
    let control: string
    if (desc.kind === 'boolean') {
      control = `<label class="switch"><input id="${id}" data-key="${desc.key}" data-kind="boolean" class="ctl" type="checkbox"${value ? ' checked' : ''} /><span>${value ? 'Enabled' : 'Disabled'}</span></label>`
    } else if (desc.kind === 'enum') {
      const opts = (desc.options ?? [])
        .map((o) => `<option value="${esc(o)}"${o === value ? ' selected' : ''}>${esc(o)}</option>`)
        .join('')
      control = `<select id="${id}" data-key="${desc.key}" class="ctl">${opts}</select>`
    } else if (desc.kind === 'number') {
      control = `<input id="${id}" data-key="${desc.key}" class="ctl" type="number" min="${desc.min ?? 0}" step="1000" value="${esc(String(value ?? ''))}" />`
    } else {
      control = `<input id="${id}" data-key="${desc.key}" class="ctl mono" type="text" spellcheck="false" value="${esc(String(value ?? ''))}" />`
    }
    const badge =
      origin === 'default'
        ? `<span class="origin def">default</span>`
        : `<span class="origin set">${esc(config.layerLabel(origin))}</span>`
    const reset =
      origin === 'default'
        ? ''
        : `<button class="btn ghost tiny reset" data-key="${desc.key}" type="button" title="Reset to default">Reset</button>`
    return `<div class="setting">
      <div class="setting-head"><label for="${id}">${esc(desc.label)}</label>${badge}</div>
      <div class="setting-ctl">${control}${reset}</div>
      <p class="muted small">${esc(desc.hint)} <code>mlab.${esc(desc.key)}</code></p>
    </div>`
  }

  private html(hasToken: boolean, hasPlatform: boolean, settings: SettingState[]): string {
    const n = nonce()
    const logo = this.panel.webview.asWebviewUri(
      vscode.Uri.joinPath(this.context.extensionUri, 'resources', 'icon.png'),
    )
    const fonts = this.panel.webview.asWebviewUri(
      vscode.Uri.joinPath(this.context.extensionUri, 'resources', 'fonts'),
    )

    const status = hasToken
      ? `<div class="status ok"><span class="dot"></span><div><strong>Token set.</strong> You have <strong>25 scans/hour</strong>.</div></div>`
      : `<div class="status anon"><span class="dot"></span><div><strong>Anonymous.</strong> Limited to <strong>8 scans/hour</strong> per IP. Add a token below for 25/hour.</div></div>`

    const clearBtn = hasToken
      ? `<button id="clear" class="btn ghost" type="button">Remove token</button>`
      : ''

    const lockfiles = SUPPORTED_BASENAMES.map((b) => `<code class="chip">${b}</code>`).join('')

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${this.panel.webview.cspSource}; font-src ${this.panel.webview.cspSource}; style-src 'unsafe-inline'; script-src 'nonce-${n}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${mlabCss(fonts.toString())}${STYLE}</style>
</head>
<body>
  <main>
  <header>
    <img class="logo" src="${logo}" alt="mlab" />
    <div>
      <h1>mlab</h1>
      <p class="muted">On demand CVE scanning for your lockfiles. Nothing leaves your machine until you ask.</p>
    </div>
  </header>

  ${status}

  <section>
    <h2>Scan</h2>
    <div class="actions">
      <button id="check" class="btn" type="button">Check a lockfile</button>
      <button id="workspace" class="btn ghost" type="button">Scan all lockfiles in workspace</button>
    </div>
    <p class="muted small">You can also right-click any lockfile in the Explorer. Results land in the
      <strong>mlab</strong> view in the Activity Bar.</p>
    <div class="chips">${lockfiles}</div>
  </section>

  <section>
    <h2>API token</h2>
    <p class="muted">Anonymous scans are capped at 8/hour per IP. A personal token raises this to 25/hour.
      Stored in VS Code SecretStorage, never in your settings or workspace.</p>
    <ol class="steps">
      <li>Open <a id="tokens-link" href="#">vuln.mlab.sh/me/tokens</a> and generate a personal token.</li>
      <li>Paste it below and click <em>Save token</em>.</li>
    </ol>
    <div class="row">
      <input id="token" type="password" aria-label="API token" placeholder="${hasToken ? 'A token is already set' : 'Paste your token'}" autocomplete="off" spellcheck="false" />
      <button id="reveal" class="btn ghost" type="button" title="Show or hide">&#128065;</button>
    </div>
    <div class="actions">
      <button id="save" class="btn" type="button">Save token</button>
      ${clearBtn}
    </div>
  </section>

  <section>
    <h2>Platform key</h2>
    <p class="muted">A <strong>separate credential</strong> from the scan token above: that one is for
      lockfile scans on vuln.mlab.sh, this one is for indicator lookups on the mlab platform
      (<em>Analyze selection</em>). Indicator lookups work without it at a reduced daily quota; a key
      raises the quota and unlocks the richer enrichment.</p>
    <div class="status ${hasPlatform ? 'ok' : 'anon'}">
      <span class="dot"></span>
      <div>${
        hasPlatform
          ? '<strong>Platform key set.</strong> Lookups run against your plan quota.'
          : '<strong>No platform key.</strong> Lookups still work, at the anonymous quota.'
      }</div>
    </div>
    <ol class="steps">
      <li>Open <a id="platform-link" href="#">mlab.sh account settings</a> and create an API key.</li>
      <li>Paste it below and click <em>Save key</em>.</li>
    </ol>
    <div class="row">
      <input id="platform" type="password" aria-label="mlab platform key" placeholder="${hasPlatform ? 'A key is already set' : 'Paste your platform key'}" autocomplete="off" spellcheck="false" />
      <button id="reveal-platform" class="btn ghost" type="button" title="Show or hide">&#128065;</button>
    </div>
    <div class="actions">
      <button id="save-platform" class="btn" type="button">Save key</button>
      ${hasPlatform ? '<button id="clear-platform" class="btn ghost" type="button">Remove key</button>' : ''}
    </div>
  </section>

  <section>
    <h2>Settings</h2>
    <div class="scope-row">
      <span class="muted small">Write changes to</span>
      <div class="scope" role="group">
        <button class="seg${this.scope === 'user' ? ' on' : ''}" data-scope="user" type="button">User</button>
        <button class="seg${this.scope === 'workspace' ? ' on' : ''}" data-scope="workspace" type="button"${this.hasWorkspace ? '' : ' disabled title="No folder is open"'}>Workspace</button>
      </div>
    </div>
    ${settings.map((st) => this.settingRow(st)).join('')}
    <div class="actions">
      <button id="settings" class="btn ghost" type="button">Open in native settings editor</button>
    </div>
  </section>

  <footer class="muted small">
    Only the lockfile you choose to scan is uploaded to vuln.mlab.sh, never your source code.
    No file watcher, no scan on save or startup, no background polling.
  </footer>
  </main>

<script nonce="${n}">
  const vscode = acquireVsCodeApi();
  const input = document.getElementById('token');
  const post = (type) => vscode.postMessage({ type });
  document.getElementById('save').addEventListener('click', () => {
    vscode.postMessage({ type: 'save', token: input.value });
    input.value = '';
  });
  document.getElementById('clear')?.addEventListener('click', () => post('clear'));
  document.getElementById('settings').addEventListener('click', () => post('openSettings'));
  document.getElementById('check').addEventListener('click', () => post('checkLockfile'));
  document.getElementById('workspace').addEventListener('click', () => post('scanWorkspace'));
  document.getElementById('tokens-link').addEventListener('click', (e) => { e.preventDefault(); post('openTokens'); });
  const platform = document.getElementById('platform');
  document.getElementById('save-platform').addEventListener('click', () => {
    vscode.postMessage({ type: 'savePlatform', token: platform.value });
    platform.value = '';
  });
  document.getElementById('clear-platform')?.addEventListener('click', () => post('clearPlatform'));
  document.getElementById('platform-link').addEventListener('click', (e) => { e.preventDefault(); post('openPlatformKeys'); });
  document.getElementById('reveal-platform').addEventListener('click', () => {
    platform.type = platform.type === 'password' ? 'text' : 'password';
  });
  document.querySelectorAll('.seg').forEach((b) => b.addEventListener('click', () => {
    vscode.postMessage({ type: 'setScope', scope: b.dataset.scope });
  }));
  document.querySelectorAll('.reset').forEach((b) => b.addEventListener('click', () => {
    vscode.postMessage({ type: 'resetConfig', key: b.dataset.key });
  }));
  document.querySelectorAll('.ctl').forEach((el) => {
    const isBool = el.dataset.kind === 'boolean';
    const send = () => vscode.postMessage({
      type: 'setConfig', key: el.dataset.key, value: isBool ? el.checked : el.value,
    });
    // Checkboxes and selects commit immediately; text and number on blur or Enter.
    if (isBool || el.tagName === 'SELECT') el.addEventListener('change', send);
    else {
      el.addEventListener('blur', send);
      el.addEventListener('keydown', (e) => { if (e.key === 'Enter') el.blur(); });
    }
  });
  document.getElementById('reveal').addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
  });
</script>
</body>
</html>`
  }
}

const STYLE = `
main { padding: 32px 40px 44px; max-width: 820px; margin: 0 auto; }
header { display: flex; gap: 18px; align-items: center; }
.logo { width: 56px; height: 56px; border-radius: var(--mlab-radius-md); box-shadow: var(--mlab-shadow); }
h1 { font-size: 1.6rem; margin: 0 0 4px; letter-spacing: -0.02em; }
h2 {
  font-family: var(--mlab-mono); font-size: 0.72rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--vscode-descriptionForeground);
  margin: 0 0 10px; padding-bottom: 8px; border-bottom: var(--mlab-hairline);
}
section { margin: 30px 0; }
section p { margin: 0 0 10px; }
.status {
  display: flex; align-items: center; gap: 10px;
  margin: 24px 0; padding: 12px 16px; border-radius: var(--mlab-radius-md); border: 1px solid transparent;
}
.status .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; }
.status.ok { background: rgba(34, 197, 94, 0.12); border-color: rgba(34, 197, 94, 0.25); }
.status.ok .dot { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
.status.anon { background: rgba(245, 158, 11, 0.12); border-color: rgba(245, 158, 11, 0.25); }
.status.anon .dot { background: #f59e0b; box-shadow: 0 0 8px #f59e0b; }
.steps { padding-left: 20px; color: var(--vscode-descriptionForeground); margin: 8px 0; }
.steps li { margin: 3px 0; }
.row { display: flex; gap: 8px; margin-top: 14px; }
input {
  flex: 1; padding: 9px 12px; border-radius: var(--mlab-radius-sm); font-family: var(--mlab-mono);
  color: var(--vscode-input-foreground);
  background: var(--vscode-input-background);
  border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
}
.actions { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0 8px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
.chip {
  padding: 2px 10px; border-radius: var(--mlab-radius-pill);
  background: rgba(127, 127, 127, 0.10); color: var(--vscode-descriptionForeground);
  font-size: 0.82em;
}
footer { margin-top: 34px; padding-top: 16px; border-top: var(--mlab-hairline); }

/* Settings */
.scope-row { display: flex; align-items: center; gap: 10px; margin: 4px 0 18px; }
.scope { display: inline-flex; border: var(--mlab-hairline); border-radius: var(--mlab-radius-sm); overflow: hidden; }
.seg {
  font-family: var(--mlab-sans); font-size: 0.86em; padding: 5px 14px;
  border: none; background: transparent; color: var(--vscode-foreground); cursor: pointer;
}
.seg + .seg { border-left: var(--mlab-hairline); }
.seg:hover:not(:disabled) { background: rgba(127, 127, 127, 0.08); }
.seg.on { background: var(--mlab-accent); color: #fff; }
.seg:disabled { opacity: 0.4; cursor: default; }

.setting { padding: 14px 0; border-bottom: var(--mlab-hairline); }
.setting:last-of-type { border-bottom: none; }
.setting-head { display: flex; align-items: center; gap: 9px; margin-bottom: 7px; }
.setting-head label { font-weight: 600; font-size: 0.95em; }
.setting-ctl { display: flex; gap: 8px; align-items: center; }
.ctl {
  flex: 1; max-width: 460px; padding: 7px 11px; border-radius: var(--mlab-radius-sm);
  color: var(--vscode-input-foreground);
  background: var(--vscode-input-background);
  border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
}
select.ctl { max-width: 220px; }
.switch { display: inline-flex; align-items: center; gap: 9px; cursor: pointer; }
.switch input { width: 16px; height: 16px; flex: none; accent-color: var(--mlab-accent); margin: 0; }
.switch span { font-size: 0.92em; color: var(--vscode-descriptionForeground); }
.btn.tiny { padding: 5px 12px; font-size: 0.84em; }
.origin {
  font-family: var(--mlab-mono); font-size: 0.64rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.05em;
  padding: 2px 8px; border-radius: var(--mlab-radius-pill);
}
.origin.def { color: var(--vscode-descriptionForeground); background: rgba(127, 127, 127, 0.12); }
.origin.set { color: var(--mlab-accent); background: rgba(var(--mlab-accent-rgb), 0.14); }
.setting p { margin: 7px 0 0; }
`
