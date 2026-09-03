# Changelog

All notable changes to this extension are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Automatic rescanning when a lockfile's contents change (`mlab.autoScan`, on by
  default), debounced so a burst of writes costs one scan. Automatic scans are
  silent: they show a discreet status bar progress, never open the report panel
  and never raise a notification, since the Explorer mark and the findings tree
  already carry the result.
- `mlab: See vuln report`, which opens the stored result for a lockfile from the
  cache with no network call and no quota cost. Available on the Explorer and
  editor context menus and by clicking a lockfile in the findings tree. The
  report shows how old a cached result is.
- The findings tree is rehydrated from the cache on startup, so it agrees with
  the Explorer marks after a window reload instead of coming back empty.
- Persistent scan cache keyed by the SHA-256 of the lockfile's bytes. An
  unchanged lockfile is served from cache and never re-uploaded, which is what
  makes automatic scanning affordable against an 8 scans/hour anonymous quota.
  Entries older than 7 days are rescanned so new advisories are eventually seen.
- Lockfiles with known vulnerabilities are marked red in the Explorer with a
  severity badge, driven by the cache, so a file stays marked until it is
  actually patched rather than until the window is closed.
- Layered configuration: `<workspace>/.mlab/config.json`, then
  `~/.mlab/config.json`, then VS Code `mlab.*` settings, then defaults. The mlab
  page edits these and shows which layer each value came from.
- The mlab page now edits every setting inline, with a User/Workspace target
  selector and a per setting Reset.

- Findings tree in the sidebar, grouped lockfile -> severity -> advisory. Clicking
  a lockfile opens it, clicking an advisory opens its vuln.mlab.sh page. The view
  carries a badge with the total finding count.
- `mlab: Open mlab`, a full width page in the editor area holding the quota
  status, the API token, the scan entry points and a jump to the native settings
  editor. The Activity Bar icon can only open a sidebar, so the sidebar now holds
  results and pushes here for everything else.
- `Rescan` and `Clear results` are implemented and only appear once there are
  results to act on.

### Fixed

- Cached results were not restored when a folder was opened. The extension
  declared no `activationEvents`, so it only activated on a command or when the
  mlab view was opened, which meant a lockfile known to be vulnerable looked
  clean until you scanned it again. It now activates on
  `workspaceContains:` a supported lockfile, and restores the tree and the
  Explorer marks from the cache with no network call.
- Rehydration restored every cached entry regardless of project. The cache is
  global, so opening one repository could list another one's findings. Entries
  are now filtered to the folders actually open, and entries whose lockfile has
  been deleted from an open folder are pruned.
- Debugging was broken: `F5` ran the production build, which is minified and has
  no sourcemap, so breakpoints in `src/**/*.ts` never bound. The launch config now
  uses `npm: watch`, which emits sourcemaps and rebuilds on change.

### Changed

- **Behaviour change.** Earlier versions promised no automatic scanning at all.
  Scanning can now be automatic, but the guarantee that nothing is uploaded
  without agreement is unchanged and now enforced in one place: every path to the
  network goes through the privacy consent, so the watcher produces no traffic
  until you have accepted once. `activate()` still makes zero network calls. Set
  `mlab.autoScan` to `false` to restore the fully manual behaviour.
- Rebranded around **mlab** rather than the vuln.mlab.sh product name: display
  name is now `mlab security`, the Activity Bar container and the webview
  wordmark read `mlab`, and the report and token panels are titled `mlab scan
  report` and `mlab API token`.
- No identifiers changed. The Marketplace id stays `mlab-sh.vuln-scan`, and the
  command ids, setting keys, view ids and webview types were already under the
  `mlab.` namespace, so existing installs and settings are unaffected.
- References to `vuln.mlab.sh` as the host that receives a lockfile are kept
  verbatim in the privacy consent dialog, the API endpoint and the token page
  links, since those are factual disclosures rather than branding.

## [0.1.0] - 2026-07-25

Initial release.

### Added

- Manual, on-demand lockfile scanning via [vuln.mlab.sh](https://vuln.mlab.sh).
  No automatic scanning: no file watcher, no scan on save/open/startup, no
  background polling, and no network call on activation.
- Triggers: Explorer context menu, editor context menu (both only on recognized
  lockfiles), Command Palette, and a Rescan button in the results view.
- Detection of `Cargo.lock`, `package-lock.json`, `npm-shrinkwrap.json`,
  `composer.lock`, `Gemfile.lock`, `go.sum`, `requirements.txt`, `mise.lock`.
- Report panel with a loading state, a genuinely cancellable progress
  (cancellation aborts the HTTP request), a per-severity summary, and a findings
  table (package, CVE linking to its vuln.mlab.sh page, fixed-in version,
  summary). Findings are deduplicated per package and CVE.
- API token management via SecretStorage, with a dedicated token and quota page
  (anonymous 8/hour, token 25/hour) and actionable handling of HTTP 429.
- First-scan privacy consent dialog, remembered in globalState.
- Workspace Trust support: scanning disabled in Restricted Mode.
- Settings: `mlab.apiUrl`, `mlab.severityFloor`, `mlab.timeoutMs`.
- mlab-branded UI derived from the vuln.mlab.sh design system.

[0.1.0]: https://github.com/mlab-sh/vuln-scan-vscode/releases/tag/v0.1.0
