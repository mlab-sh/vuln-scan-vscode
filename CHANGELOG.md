# Changelog

All notable changes to this extension are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.1] - 2026-09-03

First release since 0.1.0, and a large one. Two things change behaviour rather
than adding to it, so they are worth reading before upgrading: scanning can now
happen automatically (still never before you have agreed once), and a severity
parsing fix reclassifies findings that used to read as `unknown`.

### Added

- **Analyze selection** (`mlab.analyzeSelection`, on by default). Select a URL,
  IP address, email, file hash or MAC address, right-click, and look it up on the
  mlab platform. The type is worked out **locally** and only then does the value
  reach the endpoint that handles it, so nothing is uploaded merely to find out
  what something is. A selection over 2048 characters is refused: that is a chunk
  of file, not an indicator.
- Lookups work with no credential at the anonymous quota. The mlab page gained a
  second field for a platform API key, which raises that quota. It is a separate
  credential from the vuln.mlab.sh scan token and the page says so.
- Domain scanning, wired into the same right-click as the rest. **An existing
  completed scan is reused instead of launching a new one**, which matters
  because `POST /scan/domain` checks the quota and then purges and relaunches:
  it spends one of the 25 daily organisation-wide scans even when a perfectly
  good recent report already exists. Reading that report is a plain GET and costs
  nothing, verified against the live API. The panel shows the scan date so a
  reused report is never mistaken for a fresh one.
- When there is nothing to reuse, the scan is launched, polled and then read, so it runs behind a cancellable
  progress notification with a backing-off poll. It is also the only kind that
  **contacts the target** rather than reading a database, and it spends one of
  25 daily organisation-wide scans.
- **See the full scan on mlab** on every result, opening the indicator's page in
  a browser. Every kind has a page: five take the value in the path, the URL page
  takes it as a `q` parameter, which was checked against the live site.
- `mlab.platformUrl` for pointing indicator lookups at a self-hosted instance.
- 38 tests for the local type detection, the routing and the response
  normalisation, including the cases where formats collide: a colon separated MAC
  against an IPv6 address, and a bare MAC against a short hash.

- **Findings are enriched with exploitation intelligence.** Every CVE now carries
  its EPSS score (probability of exploitation in the next 30 days) and whether it
  sits in the CISA or EU known-exploited catalogues, from the public
  `/api/v1/cve` endpoint. The report gains an Exploit column, a banner naming
  anything actively exploited, and sorts by real exploitation before CVSS band:
  a high that is being exploited outranks a critical that is not.
- **CVE details on hover** (`mlab.cveHover`, on by default). Hovering a CVE
  identifier in any file shows CVSS, EPSS with its percentile, known-exploited
  status with its remediation deadline, the mlab risk score and the CWE
  weaknesses. Works in comments and changelogs, not just lockfiles.
- Both need **no authentication and no quota**, and send only a CVE identifier,
  never anything about your code, so neither changes what the privacy consent
  covers. Results are cached for a day and dropped after 30 days.
- 22 tests for the intelligence client and its cache, including the exact-id
  matching that the search endpoint makes necessary.

- Diagnostics in the Problems panel for every finding, anchored on the line of the
  lockfile that declares the package. This is what `mlab.severityFloor` has always
  described and never had: the setting was declared and documented, but no
  `DiagnosticCollection` existed for it to tune. Republished when the floor changes.
- `Scan all lockfiles in workspace` is implemented. It was a stub that only listed
  what it found while being the most prominent entry point in the UI. It is quota
  aware: cached lockfiles cost nothing, the confirmation names how many files need
  a fresh scan, the run is cancellable, and it stops early on a rate limit instead
  of spending the rest of the run on the same error.
- 15 tests covering the severity floor mapping and the lockfile line location,
  using the fixtures that had until now been referenced by no test at all.
- CVSS v3.x base score computation, so an advisory carrying only a vector gets a
  real severity band. Verified against the v3.1 specification and NVD's published
  scores.
- Cache retention: entries are dropped 30 days after their scan, on startup and
  on every write. Storage previously grew forever, since the existing 7 day bound
  only decided whether a hit was trusted, never whether it was kept. The two
  bounds are now named and documented separately.
- 12 tests for the cache, including the eviction rule and its boundary. `cache.ts`
  no longer imports `vscode` (the one use was a type), so it is unit testable like
  `detect.ts` and `api/client.ts`.
- 28 tests for `api/client.ts`, previously the largest untested module: the
  severity model, CVE alias preference, fixed version resolution, the per CVE
  collapsing, and the summary line.

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
  Entries are rescanned 7 days after their scan so new advisories are eventually
  seen, and dropped from storage entirely after 30 days.
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

### Changed

- Removed `jsonc-parser`, a runtime dependency that was imported nowhere. The
  extension now has no runtime dependencies at all.

- The supported lockfile list now lives in exactly one place, `LOCKFILES` in
  `src/detect.ts`. It used to be spread over nine: two copies inside `detect.ts`
  itself, a hardcoded glob in the watcher, another in the workspace sweep, four
  menu `when` regexes and the welcome text. Everything is derived from the array
  now, and `npm run sync:manifest` writes the parts of package.json that cannot
  import TypeScript. `sync:manifest -- --check` runs in CI, and six tests fail if
  the manifest drifts, so adding a format is a one line edit again.

- The scan path is now a single primitive shared by the command, the file watcher
  and the workspace sweep, so the cache is always consulted first and consent is
  always checked before anything leaves the machine, on every path.

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

### Fixed

- Two scans started in quick succession fought over the shared report panel: the
  second overwrote the first's cancel handler, leaving the first request
  unreachable so its Cancel button did nothing. Scans are now generation stamped.
  Claiming the panel cancels whatever was showing, and a superseded scan can no
  longer write its result over a newer one.
- Editing `.mlab/config.json` by hand had no effect until a reload. These files
  are outside the VS Code configuration system, so `onDidChangeConfiguration`
  never fires for them. Both the workspace and the home file are now watched, and
  a change refreshes the settings page, the diagnostics and the auto scanner.

- **Severity was silently under-reported.** OSV advisories very often carry their
  severity only as a CVSS vector, with no `database_specific.severity`. The
  parser did `parseFloat` on the last `/` separated segment of the score, which
  for `CVSS:3.1/AV:L/.../A:H` is `A:H`, so it produced `NaN` and the finding fell
  through to `unknown`. Confirmed against the live API: CVE-2020-26235 in
  `time 0.1.43` returns exactly this shape and was reported as `unknown` instead
  of `medium` (NVD scores it 6.2). Since `unknown` ranks below `low`, such
  findings also sorted last and were demoted to Information in the Problems panel.
  Vectors are now scored properly; CVSS v2 and v4 vectors, which this does not
  compute, fall through to the next severity entry rather than being guessed.

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

[1.0.1]: https://github.com/mlab-sh/vuln-scan-vscode/releases/tag/v1.0.1
[0.1.0]: https://github.com/mlab-sh/vuln-scan-vscode/releases/tag/v0.1.0
