# Changelog

All notable changes to this extension are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
