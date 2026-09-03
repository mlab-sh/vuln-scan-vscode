# mlab security

Scan your lockfiles for known CVEs from inside VS Code, on demand, powered by
[mlab](https://vuln.mlab.sh). Parsing and vulnerability resolution happen
entirely server side: the extension only uploads the lockfile you pick and shows
the result. No local database, no heavy dependencies.

## Manual by design

This extension **never scans on its own**. There is no file watcher, no scan on
save, open, startup, or on a timer, and no network call happens when the
extension activates. A lockfile leaves your machine only when **you** trigger a
scan. The first time you scan, a dialog explains what is sent and asks for
confirmation.

## How to scan

Any of these, and nothing else, starts a scan:

1. **Right-click a lockfile** in the Explorer and choose **Check for lock
   vulnerabilities**. This is the primary path.
2. **Right-click inside the editor** when the active file is a recognized
   lockfile, same menu entry.
3. **Command Palette**: `mlab: Check for lock vulnerabilities`,
   `mlab: Scan all lockfiles in workspace`, `mlab: Clear results`,
   `mlab: Set API token`, `mlab: Manage API token & quota`.
4. The **Rescan** button in the results view.

The context-menu entry only appears on recognized lockfiles, never on other
files.

### The context menu (described)

Right-clicking a file named, for example, `Cargo.lock` or `package-lock.json`
adds a single **Check for lock vulnerabilities** item to the Explorer context
menu, grouped with the other workspace actions. Right-clicking any other file
(for instance `README.md` or `main.rs`) shows no mlab entry at all. Selecting the
item opens a report panel beside the file: first an animated "Scanning ..." state
with a **Cancel** button, then the final report.

## What you get

- A report panel beside the lockfile with a per-severity summary
  (for example `3 critical, 12 high, 4 low across 6 packages`) and a table of
  findings: package, advisory (CVE id linking to its
  [vuln.mlab.sh](https://vuln.mlab.sh) page), the version it was fixed in, and a
  short summary.
- A progress state that is genuinely cancellable: cancelling aborts the in-flight
  HTTP request.
- An **mlab** entry in the Activity Bar holding the findings tree, grouped
  lockfile -> severity -> advisory, with a badge showing the total finding count.
  Clicking a lockfile opens it; clicking an advisory opens its CVE page.
- A full width **mlab** page (`mlab: Open mlab`, or the home button in the view
  title bar) with your quota status, the API token, the scan entry points and a
  jump to the native settings editor. The Activity Bar icon can only ever open a
  sidebar, so results live there and everything else lives on this page.

## Supported lockfiles

`Cargo.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `composer.lock`,
`Gemfile.lock`, `go.sum`, `requirements.txt`, `mise.lock`.

`Scan all lockfiles in workspace` walks the workspace with `workspace.findFiles`
and skips `node_modules`, `vendor`, `target`, `dist`, and `.git`.

## API token and quotas

Anonymous scans are limited to **8 per hour per IP**. A personal API token raises
this to **25 per hour**.

1. Generate a token at [vuln.mlab.sh/me/tokens](https://vuln.mlab.sh/me/tokens).
2. Run `mlab: Manage API token & quota` (or `mlab: Set API token`) and paste it.

The token is stored **only** in VS Code
[SecretStorage](https://code.visualstudio.com/api/references/vscode-api#SecretStorage).
It is never written to your settings, to the workspace, or to disk in plaintext.
When an anonymous scan is rate limited (HTTP 429), the extension keeps your
previous results and offers to open the token page or add a token.

## Privacy

- Only the lockfile you choose to scan is uploaded to `vuln.mlab.sh`. Your source
  code is never sent.
- Nothing is uploaded until you explicitly trigger a scan, and the first scan
  asks for confirmation.
- The extension declares support for
  [Workspace Trust](https://code.visualstudio.com/docs/editor/workspace-trust):
  in Restricted Mode, scanning is disabled with a clear message.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `mlab.apiUrl` | `https://vuln.mlab.sh/api/v2/scan` | Scan endpoint. Override for a self-hosted instance. |
| `mlab.severityFloor` | `any` | Lowest severity reported as a Warning/Error diagnostic; below it, findings are shown as Information. Tunes severity mapping only, never fails anything. |
| `mlab.timeoutMs` | `30000` | Per-request timeout in milliseconds. |

## Notes and limits

- Manifests over **512 packages** are scanned up to that ceiling; the report
  shows a visible warning.
- Coordinates the scanner could not resolve (an upstream outage) are surfaced and
  are **not** counted as clean.
- Timeouts, unreachable DNS, and non-JSON responses produce a readable
  notification; full detail goes to the `mlab` output channel.

## Development

```bash
npm install
npm run build      # bundle src -> dist/extension.js (esbuild)
npm run watch      # rebuild on change
npm run typecheck
npm run lint
npm run test       # unit tests
npm run package    # produce a .vsix
```

Press `F5` to launch an Extension Development Host on `test/fixtures`. It runs
`npm: watch`, so sources rebuild on change with sourcemaps; press `Cmd+R` in that
window to reload the extension. Useful commands from its Command Palette:
`Developer: Reload Window`, `Developer: Show Running Extensions`, and
`Developer: Open Webview Developer Tools` to inspect the report and home panels
(webview code runs in its own context, so the Node debugger cannot see it).

## License

[MIT](LICENSE)
