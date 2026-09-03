# Changelog

All notable changes to this extension are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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

- Debugging was broken: `F5` ran the production build, which is minified and has
  no sourcemap, so breakpoints in `src/**/*.ts` never bound. The launch config now
  uses `npm: watch`, which emits sourcemaps and rebuilds on change.

### Changed

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
