# Changelog

All notable changes to PatchRadar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses **CalVer** (`YYYY.M.PATCH`), not SemVer.

---

## [2026.9.6] — 2026-09-24

### Fixed

- **The Debian tracker snapshot is no longer a boolean that promises a value.**
  `_is_fresh()` returned `True` while guaranteeing that `_snapshot` is not
  `None` — a guarantee visible only to a reader who opened the function. It is
  now `_fresh_snapshot()`, which returns the value or `None`, so "fresh" and
  "present" cannot drift apart: a caller cannot act on one without holding the
  other.
- **A law that could not be verified now says what that costs.** The report
  warned that an act could not be fetched and, separately, printed
  `SHA256: not available` against each citation, with nothing joining the two —
  so a missing hash read as a defect in the hashing. It is not: with no
  verified text there is nothing to hash, and printing one anyway would assert
  a verification that never happened. The warning now states the consequence,
  and the three states are pinned by test: `verified` and `cache` both keep the
  hash, only `unavailable` loses it.
- **`PATCHRADAR_HOME` is no longer taken literally.** `~/cache` made a
  directory actually named `~`, which is what anyone writing that in a
  Dockerfile `ENV` got. A relative value resolved against the working
  directory, so the cache landed somewhere different depending on where the
  command ran from and quietly stopped being one cache. And `"   "` is truthy,
  so whitespace became a directory name. A tilde is expanded, a blank value
  means unset, and a relative value is read against `$HOME`.
- `get_cves` declared `software: str` and defaulted it to `None`.
- The release scripts read and rewrote `pyproject.toml` and `__init__.py` with
  the locale deciding the encoding both ways: on a host that is not UTF-8, a
  release would have rewritten every non-ASCII character in the file it was
  bumping.

### Changed

- ruff, mypy, hypothesis and mutmut are development dependencies. A `Quality`
  workflow runs ruff and mypy on every push and pull request; mutation testing
  runs on Saturdays and never blocks, because a surviving mutant is a finding
  rather than a failure.
- Twelve new properties over generated input. `date_windows` is checked across
  its whole range rather than at the eight parametrised values: no window can
  ever be wide enough for NVD to refuse it, no gap is left between chunks, and
  the number of requests is the fewest the arithmetic allows. `sanitize_cve` is
  checked against generated text because a CVE description is
  attacker-influenced.
- A contract test refuses any code that lets the locale choose a text encoding.
  The check uses the AST rather than a regular expression, so an argument
  written on its own line is still seen.
- The host-timezone case called `time.tzset()`, which exists only on POSIX: on
  Windows it failed with `AttributeError` and took the Sonar contract test down
  with it, since that one runs this file in a subprocess. The assertion is
  split out so it runs on every platform; only the POSIX mechanism is skipped,
  with a stated reason.
- **This CHANGELOG, and every string the tool writes itself, are now in
  English** — which the other four Radar already were. The report's section is
  `Provisions applied` rather than `Norme applicate`, and finding titles, scope
  notes and evidence lines follow. The 36 earlier entries were translated with
  it, so the file reads as one document rather than two. What the tool *quotes*
  is unchanged: a provision's text is fetched from the official Italian version
  of each act and hashed, so translating it would change every SHA-256 in every
  cache and report "the law changed" for every citation on the next run, for
  nothing.

---

## [2026.9.5] — 2026-09-19

### Added

- **Provisions applied.** `patchradar scan` ends with the provisions that
  concern the CVEs it found, each with the SHA-256 of the exact text applied
  and the date of that version. The text is downloaded from EUR-Lex on every
  scan and saved in `~/.patchradar/law_cache.json` (`PATCHRADAR_HOME` changes
  the directory); a text that has changed is reported with its previous hash.
  With no network the cached copy is cited, or else "SHA256: not available". A
  failure of the check never fails the scan.
  - GDPR art. 32(2): critical CVEs; art. 25: CVEs with no patch (analysed by
    NVD and with no reference tagged "Patch"); art. 32: CVEs with a high impact
    on confidentiality (CVSS `C:H`).
  - NIS2, directive (EU) 2022/2555, art. 21: critical and unpatched CVEs. The
    report notes that NIS2 binds only essential and important entities.
- **NVD and MSRC collectors**: new fields `patch_available` (patch present,
  absent or unknown) and `confidentiality_impact` (HIGH/LOW/NONE from CVSS).
  Neither is stored in the database.

---

## [2026.9.4] — 2026-09-19

### Added

- **A `--version` option.** `patchradar --version` prints
  `PatchRadar <version>` and exits without initialising the database. The
  version is read from `patchradar.__version__`, which
  `scripts/bump_version.py` keeps in step with `pyproject.toml`.

---

## [2026.9.3] — 2026-09-18

Closes the warnings from the audit: a failed scan no longer presents itself as
"no CVEs", the CSP actually blocks injected scripts, dates from different
sources sort chronologically, and SonarCloud measures coverage again.

### Security

- **CSP with `'unsafe-inline'` on `script-src`.** The page used inline handlers
  (`onclick=`, `onkeydown=`, `oninput=`, `onchange=`) and an inline `<script>`
  block, so the policy had to allow inline script and stopped nothing: an `on*=`
  attribute that escaped escaping would have run. The script moved to
  `/static/app.js` and every handler is attached with `addEventListener`, so
  `script-src` is now just `'self'`. `object-src 'none'` and `base-uri 'none'`
  were added too. Removing only the handlers would not have been enough: under
  `script-src 'self'` the inline `<script>` block is refused as well, and the
  page would have run nothing at all.
- **Control characters in API responses.** `sanitize_cve` claimed to remove
  "null bytes and control characters" but removed only `\x00`. ESC, BEL,
  backspace and the C1 controls — including `\x9b`, the 8-bit CSI — reached the
  response, and the same records are printed to a terminal by the CLI, where ESC
  opens an ANSI sequence. All C0 controls, DEL and C1 are now removed except tab
  and newline; `\r\n` and `\r` are normalised to `\n`.

### Fixed

- **A failure of the source looked like "no CVEs".** Every collector caught any
  exception and returned `[]`: a 403/429 from NVD (which limits keyless clients
  to five requests every 30 seconds), a 503 from Debian, a DNS error or a proxy
  answering in HTML all produced the same output as a clean scan —
  `nginx — no CVEs found`. For a vulnerability monitor that is the worst way to
  fail. Collectors now raise `CollectorError` with the source, a reason
  (`rate_limited`, `forbidden`, `server_error`, `http_error`, `network`,
  `bad_payload`) and the HTTP code; the CLI names the source that failed and
  declares the results incomplete, and the UI shows "Scan incomplete" instead of
  "Found 0 CVEs".
- **CVEs did not sort chronologically.** Each source stored its date in its own
  format: NVD `2026-08-15T00:00:00.000` with no zone, Debian with `+00:00` and
  microseconds, MSRC with no zone, with `Z`, or with an offset. The column is
  TEXT, so `ORDER BY published_at DESC` compared strings:
  `…T20:00:00-07:00` (03:00 UTC the next day) sorted after `…T23:00:00+00:00`,
  and with `LIMIT` the newest CVEs could fall off the page. Dates are now
  normalised on save to one fixed-width UTC form, `YYYY-MM-DDTHH:MM:SSZ`; times
  with no zone are read as UTC, which is how NVD and MSRC publish them, whatever
  the host's zone.
- **The UI froze on any API error.** `api()` reported the error and then
  returned `{}`, and almost every caller dereferenced it: `loadWatchlist` raised
  `TypeError` and stopped the page loading, `loadStats` wrote `undefined` into
  the cards, `addSoftware` replaced the real error with "already in watchlist",
  `removeSoftware` confirmed "Removed" when nothing had been, `openCveDetail`
  opened an empty modal on a 404. A non-JSON 200 escaped as an unhandled
  rejection, because `r.json()` was not awaited inside the `try`.
- **`patchradar status` crashed on a null severity.**
  `cve.get("severity", "UNKNOWN").upper()` uses the default only when the key is
  absent; the column is nullable, so a row with severity `NULL` raised
  `AttributeError`.
- **A CVSS score of 0.0 shown as "N/A".** In both the CLI and the UI the test
  was on the value's truthiness, and `0.0` is false: a real score of zero was
  indistinguishable from "no score". A score arriving as a string also raised
  `ValueError` in the CLI.

### Changed

- **A new collector contract:** an empty list means only that the source
  answered with no CVEs. Results already gathered before an error are kept in
  `CollectorError.partial` and saved; if MSRC fails on one month, the months
  already downloaded are not lost.
- A 200 response with an empty or non-JSON body is now a `bad_payload` error,
  not zero CVEs.
- A 404 from MSRC still means a month not yet published and is not an error.
- NVD's 403 is classified `forbidden` rather than `rate_limited`: NVD uses it
  for exceeding the keyless quota, but the same code can mean an invalid key.
- The response from `POST /api/scan` includes an `errors` field with the
  software, source, reason and HTTP code of every source that failed.
- At start-up, `init_db()` rewrites dates saved before this release into the
  canonical form; values that cannot be parsed become `NULL` and sort last. The
  operation is idempotent.
- The web page loads its script from `/static/app.js`, served from the same
  origin. `style-src` keeps `'unsafe-inline'`: the page uses `style=` attributes,
  and CSS cannot execute script.

### CI

- **SonarCloud was measuring no coverage at all.**
  `sonar.coverage.exclusions=**/*` excluded every file, and the workflow
  produced no report anyway: removing only the exclusion would have shown 0%.
  The workflow now runs the suite with `pytest --cov` and produces
  `coverage.xml` before the scan, Sonar reads it through
  `sonar.python.coverage.reportPaths`, and the exclusion is narrowed to
  `static/**` and `templates/**` (JS and HTML, exercised by the Node harness,
  which produces no coverage report). `relative_files = true` makes the report's
  paths relative to the checkout, so SonarCloud resolves them. The quality gate
  may go red on the first analysis, now that it sees real coverage.

### Added

- A Node harness (`tests/js/ui_harness.js`) that runs the page's real script
  against a minimal DOM with a stubbed `fetch`. It does not execute `on*=`
  attributes, just as a browser under the new CSP would not, so a control counts
  as working only if the script really attached it.
- Test suite grown from 370 to **912 tests**.

---

## [2026.9.2] — 2026-09-17

Closes the logic defects the code audit turned up: false positives and false
negatives in the collectors, missing validation on import, and database
isolation in the tests.

### Security

- **Watchlist import with no validation at all.**
  `POST /api/watchlist/import` applied only `strip().lower()[:100]`, while
  `POST /api/watchlist/{software}` enforced `^[\w\s\-\.]+$` and
  `max_length=100`. Everything the path route refused could be introduced
  through import: `evil<script>alert(1)</script>` and `evil[bold]x` both reached
  the database. Both routes now share `normalise_software_name()`, so they can
  no longer diverge.
- **Multi-line names accepted by the validator.** The pattern used `\s`, which
  includes newline and tab: `"a\nb"` was a valid name on both routes. Replaced
  with a literal space (`^[\w \-\.]+$`).
- **`DELETE /api/watchlist/<name>` deleted data nobody asked it to.** The
  cascading deletion of CVEs ran unconditionally, even when the software was not
  in the watchlist: the call returned `false` while emptying the CVE history for
  that name. The cascade now runs only if a row was really removed.

### Fixed

- **Container data lost on every restart.** `docker-compose.yml` mounted the
  volume on `/root/.patchradar`, but the image runs as the unprivileged
  `patchradar` user and the application writes to `/home/patchradar/.patchradar`.
  The volume stayed empty and the watchlist and CVE history vanished whenever
  the container was recreated — silently, because the database was created in
  the internal filesystem regardless. Verified end to end on the published
  image.
- **7,924 phantom CVEs from the Debian Security Tracker.** When a package had no
  entry for the target release, `releases.get(release, {})` returned an empty
  dict, `status` came out `""` — which is not `"resolved"` — and the CVE was
  reported as **open**. Measured against the real feed: 7,924 CVEs with no
  `trixie` entry across the whole tracker. Per package: **postgresql 109 → 0**
  (100% noise), **python 332 → 173** (47%), **linux 2,226 → 1,631** (26%).
  Status also moves from a blacklist to the whitelist `{open, undetermined}`.
- **A whole Patch Tuesday missing.** MSRC months were derived in steps of 30
  days, which cannot enumerate calendar months: from 2026-03-31 with
  `days_back=90` the sequence was `Dec, Jan, Mar` — **February skipped
  entirely**, so a complete Patch Tuesday was never downloaded. Replaced with a
  walk over calendar months, contiguous by construction.
- **Debian severity always UNKNOWN for the urgencies that matter.** The mapping
  table was built on Debian BTS *bug severities* (`grave`, `serious`,
  `important`, `moderate`, `critical`), which the Security Tracker never emits.
  The real values — verified against the feed: `not yet assigned`,
  `unimportant`, `low`, `medium`, `high`, `end-of-life` — fell through to
  UNKNOWN, making `high` and `medium` invisible to the CRITICAL/HIGH filters and
  to the severity chart.
- **One malformed field aborted the entire scan.** Collectors wrapped only the
  HTTP call in `try/except`; all the parsing after it indexed the JSON directly.
  `d["lang"]` raised `KeyError` on an NVD description missing that key;
  `item.get("cve", {})` returned `None` when the key was present but null,
  because the default does not apply; `vuln.get("RevisionHistory", [{}])[0]`
  raised `IndexError` on a list that was present but empty.
- **One malformed MSRC entry discarded the whole month.** The `try/except` sat
  *outside* the loop over vulnerabilities, so a single exception silently lost
  every later CVE in that monthly document. Moved to per-record.
- **HTTP 500 on non-string elements in an import.** `sw.strip()` assumed a
  string: `{"software": [123]}` produced `AttributeError` and a 500 rather than
  a validation error.
- **Locale-dependent month names.** `strftime('%b')` follows `LC_TIME`: on an
  Italian machine it produced `set` instead of `Sep`, every MSRC request
  answered non-200, and the collector returned zero CVEs without reporting
  anything. Replaced with the `MONTH_ABBR` constant.
- **The test suite wrote to the user's real database.** Tests ran against
  `~/.patchradar/patchradar.db`, leaving fixtures in it (`testapp`,
  `duplicate-test`, a 101-character name) and deleting rows from it. A session
  fixture now redirects `DB_PATH` to a temporary directory. Verified: the real
  database is byte-identical (sha256 and mtime) after a full suite.

### Changed

- Over-long names are **refused** rather than silently truncated to 100
  characters: monitoring a name other than the one asked for is worse than
  refusing it.
- CVEs with no `id` are discarded rather than saved with `id=""`: the id is the
  primary key, and several records without one collided with each other.
- `days_back` now really determines which MSRC months are queried. The old fixed
  margin of 30 days cost roughly 276 needless HTTP requests a year with
  `days_back=7`.
- The response from `/api/watchlist/import` exposes a third set, `rejected`,
  alongside `added` and `skipped`; the UI reports it.
- Both watchlist routes normalise the name the same way, so they write the same
  canonical value to the database.
- `database.py` exposes `DEFAULT_DB_PATH` alongside `DB_PATH`, so the production
  location stays known when the active value is redirected.
- The `DELETE` route stays deliberately permissive (no pattern,
  `max_length=200`): tightening it would make it impossible to delete the names
  that reached the database before this release.

### Added

- `logger.debug`/`logger.warning` on discarded records and on payloads of an
  unexpected shape, in place of silent failure.
- Test suite grown from 105 to **370 tests**, with dedicated files for escaping,
  scan hardening, the Docker contract, Debian release scope, MSRC month
  enumeration, parser robustness, watchlist removal, import validation and
  database isolation.

---

## [2026.9.1] — 2026-09-17

The first round of fixes from the audit: markup injection in the CLI, a missing
health endpoint, hardening of `/api/scan`, and turning the tests on in CI.

### Security

- **Markup injection in the CLI's output.** Every value of external origin
  reached an f-string interpreted by Rich: CVE descriptions, software names and
  scan targets. A hostile description could apply colours, hide a CRITICAL CVE,
  or place a clickable OSC-8 hyperlink inside a security tool. Fixed with
  `escape()` on the f-strings and `Text()` on table cells, which Rich always
  renders verbatim.
- **`/api/scan` with no authentication and no limits.** The endpoint had no
  authentication dependency at all, while the Docker image binds to `0.0.0.0`.
  An optional API key was introduced via `PATCHRADAR_API_KEY`, compared with
  `hmac.compare_digest`, and applied to `/api/scan` and the watchlist write
  routes. When the variable is unset the endpoints stay open, for compatibility
  with local use, and a warning is emitted at start-up.
- **No deadline on a scan.** A slow feed could hold a worker indefinitely
  (MSRC 4×30s + NVD 30s + Debian 60s per package, over an unbounded watchlist).
  Added `asyncio.timeout()` with a budget configurable through
  `PATCHRADAR_SCAN_TIMEOUT` (default 600s) and an explicit `timed_out` flag in
  the response, so a truncated scan does not look complete.

### Fixed

- **Crashes on entirely legitimate CVE descriptions.** Unix paths in square
  brackets (`[/tmp]`, `[/etc/passwd]`) raised `MarkupError` and aborted
  `patchradar scan`; references such as `[i]` were silently stripped from the
  text, corrupting the description of the vulnerability.
- **375 MB downloaded per scan instead of 75 MB.** The Debian Security Tracker
  dump (measured: 75,173,966 bytes) was re-downloaded **once per monitored
  package**: with five items in the watchlist, five identical downloads. A cache
  with a one-hour TTL and an `asyncio.Lock` reduces the cost to a single
  download per scan and stops concurrent scans each starting their own. A failed
  download is never cached.
- **The Docker healthcheck always failed.** The Dockerfile and docker-compose
  probed `http://localhost:8000/health`, which did not exist: the container was
  permanently `unhealthy`, causing restart loops under
  `restart: unless-stopped` and blocking any `depends_on: service_healthy`.
- **CI never ran the tests.** The `Tests` workflow ran only
  `patchradar --help` and `patchradar list`; `pytest` was never invoked. On top
  of that `respx`, imported by the suite, was declared in no dependency group,
  so the tests were not even installable from `pyproject.toml`.
- **Five tests failed on a clean machine.** `ASGITransport` does not run the
  `lifespan` handler, so `init_db()` was never called during the API tests: they
  passed only when an earlier test had already created the database.
- **Crash on `description=None`.** The truncation expression called `len()` on a
  value the Debian collector can return as null. Replaced by the `_truncate()`
  helper.

### Added

- A `GET /health` endpoint that checks the database is reachable and answers 503
  when it is not writable. Deliberately unauthenticated: a healthcheck should
  not have to carry a credential.
- Environment variables `PATCHRADAR_API_KEY` and `PATCHRADAR_SCAN_TIMEOUT`.
- A `Run test suite` step in the CI workflow, across all five Python versions in
  the matrix; `respx` added to the `dev` dependency group.
- `tests/conftest.py` with session-level database initialisation and a reset of
  the Debian cache between tests.

### Changed

- The UI keeps the API key in `localStorage` and asks for it on the first 401.
- The UI reports a truncated scan explicitly rather than showing it as complete.

---

## [2026.8.34] — 2026-08-26

### Fixed

- Documented the `HTTPException` responses on the API endpoints (SonarQube
  S8415).
- `CHANGELOG_FILE` defined as a constant instead of repeating the literal, and a
  self-assignment corrected (S1656).
- `days_back` bounded to a safe range in the MSRC collector.
- UI accessibility: `aria-label` on the add field, file import and search;
  `role="dialog"` and `aria-modal` on the modal overlay (S6848);
  `Number.parseInt` in place of the global `parseInt` (S7773).

### Changed

- Extracted `_scan_target` in the CLI and dedicated helpers in `msrc.py` to
  reduce cognitive complexity (S3776).

### Added

- A CI-based SonarCloud analysis workflow, with `pytest-cov` for the coverage
  report.

---

## [2026.8.33] — 2026-08-25

### Security

- The Docker container runs as a non-root user.
- `setuptools` and `msgpack` pinned to exact versions; `msgpack` moved to 1.2.1
  to fix a HIGH CVE; `--only-binary :all:` on the pip installs.
- Every GitHub Action in the workflows pinned to a full commit SHA.

### Fixed

- The PatchRadar version pinned and passed through `ARG` from CI to the Docker
  build.
- A 60-second wait for PyPI propagation before the Docker build.
- Fixed publishing to PyPI (`release/v1` pinned to a SHA, `pip install` flags
  corrected, wheel metadata verification disabled).

### Added

- `sonar-project.properties` for an accurate Python analysis.

---

## [2026.8.32] — 2026-08-22

### Changed

- Removed the global `asyncio` marker from the tests, applying it only to the
  asynchronous ones.

---

## [2026.8.31] — 2026-08-21

### Added

- Tests for the Debian Security Tracker collector.

---

## [2026.8.30] — 2026-08-20

### Added

- Debian Security Tracker collector.

---

## [2026.8.29] — 2026-08-20

### Fixed

- Error handling in the UI's `api()` function.

---

## [2026.8.28] — 2026-08-20

### Security

- Added a Trivy security scanner workflow.
- Added Dependabot configuration and a security policy.

### Fixed

- `pkg_version` used for the application version, duplicate imports removed.
- `save_cve` assigns the cursor, so `rowcount` is returned correctly.

### Added

- Python 3.14 in the CI matrix, and 3.15-dev as experimental.
- Renovate configuration.

### Changed

- Minimum dependency versions raised to the latest stable.
- Five GitHub Actions updated to the next major (Dependabot #14-#18).

---

## [2026.8.27] — 2026-08-19

### Fixed

- Assorted UI corrections.

### Added

- A PowerShell script for winget integration.

---

## [2026.8.26] — 2026-08-19

### Added

- Bulk import of software into the watchlist from a file.

---

## [2026.8.25] — 2026-08-19

### Added

- A search filter on the CVE table.

---

## [2026.8.24] — 2026-08-19

### Security

- CVE scanning with Docker Scout in the Docker workflow.
- Explicit permissions in the workflows, for compatibility with CodeQL.

---

## [2026.8.23] — 2026-08-19

### Security

- Base image moved to Debian trixie, and PyPI dependencies pinned to safe
  versions.

---

## [2026.8.22] — 2026-08-19

### Security

- `apt-get upgrade` in the Dockerfile, to fix a HIGH OpenSSL vulnerability.

---

## [2026.8.21] — 2026-08-19

### Fixed

- Orphaned CVEs are deleted when the software is removed from the watchlist.

### Added

- CodSpeed performance benchmarks.

---

## [2026.8.20] — 2026-08-16

### Changed

- CHANGELOG rewritten with the full history from 2026.8.4 to 2026.8.19.

---

## [2026.8.19] — 2026-08-16

### Added

- A CVE detail modal in the UI.

### Fixed

- Watchlist overflow in the UI.

---

## [2026.8.18] — 2026-08-16

### Changed

- README updated: MSRC live, inline changelog removed.

---

## [2026.8.17] — 2026-08-16

### Added

- MSRC collector for Microsoft's Patch Tuesday.

---

## [2026.8.16] — 2026-08-16

### Changed

- GitHub Actions updated to versions compatible with Node.js 24.

---

## [2026.8.15] — 2026-08-16

### Fixed

- Replaced the deprecated `@app.on_event` with the `lifespan` handler.

---

## [2026.8.14] — 2026-08-16

### Added

- A complete test suite: CLI, mocked NVD collector, database CRUD.

---

## [2026.8.13] — 2026-08-16

### Added

- Docker support: Dockerfile, docker-compose and `.dockerignore`.
- A build-and-push workflow for Docker Hub.
- `RELEASING.md` with a checklist and the release process.

---

## [2026.8.12] — 2026-08-16

### Security

- Fixed a DOM XSS (CWE-79) in the UI's severity chart.

### Added

- git-cliff integration for automatic changelog generation.

---

## [2026.8.11] — 2026-08-16

A version-only release; no code changes.

---

## [2026.8.10] — 2026-08-16

### Security

- Middleware with a Content-Security-Policy and security headers.
- Input validation on every endpoint.
- Output sanitisation for CVE data.

### Added

- A real test suite in place of the placeholder.
- `bump_version.py` and `release.py` scripts.

---

## [2026.8.7] — 2026-08-15

### Security

- Fixed a DOM XSS (CWE-79) in the UI: `innerHTML` replaced with
  `createElement`/`textContent`.

### Fixed

- `api/main.py` rewritten, dynamic version in the UI.

---

## [2026.8.6] — 2026-08-14

### Fixed

- Dynamic version in the UI, and the version badge updated.

---

## [2026.8.5] — 2026-08-14

### Fixed

- UTF-8 encoding for the HTML template on Windows.

---

## [2026.8.4] — 2026-08-14

### Changed

- README badges updated.

---

## [2026.8.3] — 2026-08-14

A version-only release; no code changes.

---

## [2026.8.2] — 2026-08-14

First public release.

### Added

- The first working release: CLI, NVD collector, SQLite database.
- A web UI with a dashboard, watchlist, CVE table and charts.
- GitHub Actions for publishing to PyPI and for the tests.

---

### A note on the version numbers

Versions `2026.8.1`, `2026.8.8` and `2026.8.9` were never released: the number
in `pyproject.toml` was incremented but no tag was ever created. The jump from
`2026.8.34` to `2026.9.1` follows CalVer, which resets the patch when the month
changes.

[2026.9.6]: https://github.com/maksimtech/patchradar/compare/2026.9.5...2026.9.6
[2026.9.5]: https://github.com/maksimtech/patchradar/compare/2026.9.4...2026.9.5
[2026.9.4]: https://github.com/maksimtech/patchradar/compare/2026.9.3...2026.9.4
[2026.9.3]: https://github.com/maksimtech/patchradar/compare/2026.9.2...2026.9.3
[2026.9.2]: https://github.com/maksimtech/patchradar/compare/2026.9.1...2026.9.2
[2026.9.1]: https://github.com/maksimtech/patchradar/compare/2026.8.34...2026.9.1
[2026.8.34]: https://github.com/maksimtech/patchradar/compare/2026.8.33...2026.8.34
[2026.8.33]: https://github.com/maksimtech/patchradar/compare/2026.8.32...2026.8.33
[2026.8.32]: https://github.com/maksimtech/patchradar/compare/2026.8.31...2026.8.32
[2026.8.31]: https://github.com/maksimtech/patchradar/compare/2026.8.30...2026.8.31
[2026.8.30]: https://github.com/maksimtech/patchradar/compare/2026.8.29...2026.8.30
[2026.8.29]: https://github.com/maksimtech/patchradar/compare/2026.8.28...2026.8.29
[2026.8.28]: https://github.com/maksimtech/patchradar/compare/2026.8.27...2026.8.28
[2026.8.27]: https://github.com/maksimtech/patchradar/compare/2026.8.26...2026.8.27
[2026.8.26]: https://github.com/maksimtech/patchradar/compare/2026.8.25...2026.8.26
[2026.8.25]: https://github.com/maksimtech/patchradar/compare/2026.8.24...2026.8.25
[2026.8.24]: https://github.com/maksimtech/patchradar/compare/2026.8.23...2026.8.24
[2026.8.23]: https://github.com/maksimtech/patchradar/compare/2026.8.22...2026.8.23
[2026.8.22]: https://github.com/maksimtech/patchradar/compare/2026.8.21...2026.8.22
[2026.8.21]: https://github.com/maksimtech/patchradar/compare/2026.8.20...2026.8.21
[2026.8.20]: https://github.com/maksimtech/patchradar/compare/2026.8.19...2026.8.20
[2026.8.19]: https://github.com/maksimtech/patchradar/compare/2026.8.18...2026.8.19
[2026.8.18]: https://github.com/maksimtech/patchradar/compare/2026.8.17...2026.8.18
[2026.8.17]: https://github.com/maksimtech/patchradar/compare/2026.8.16...2026.8.17
[2026.8.16]: https://github.com/maksimtech/patchradar/compare/2026.8.15...2026.8.16
[2026.8.15]: https://github.com/maksimtech/patchradar/compare/2026.8.14...2026.8.15
[2026.8.14]: https://github.com/maksimtech/patchradar/compare/2026.8.13...2026.8.14
[2026.8.13]: https://github.com/maksimtech/patchradar/compare/2026.8.12...2026.8.13
[2026.8.12]: https://github.com/maksimtech/patchradar/compare/2026.8.11...2026.8.12
[2026.8.11]: https://github.com/maksimtech/patchradar/compare/2026.8.10...2026.8.11
[2026.8.10]: https://github.com/maksimtech/patchradar/compare/2026.8.7...2026.8.10
[2026.8.7]: https://github.com/maksimtech/patchradar/compare/2026.8.6...2026.8.7
[2026.8.6]: https://github.com/maksimtech/patchradar/compare/2026.8.5...2026.8.6
[2026.8.5]: https://github.com/maksimtech/patchradar/compare/2026.8.4...2026.8.5
[2026.8.4]: https://github.com/maksimtech/patchradar/compare/2026.8.3...2026.8.4
[2026.8.3]: https://github.com/maksimtech/patchradar/compare/2026.8.2...2026.8.3
[2026.8.2]: https://github.com/maksimtech/patchradar/releases/tag/2026.8.2
