# Changelog

All notable changes to PatchRadar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses **CalVer, Apple style**: `YYYY.count[.fix]`, not SemVer.
`YYYY` is the generation, shared by the five Radar; the count belongs to each of
them and moves when its code moves; the third segment is for something urgent on
what has already shipped, and for nothing else. See `RELEASING.md`.

---

## [Unreleased]

### Changed

- **ruff now lints `tools/` as well, because it never did.** Every one of the five
  Radar lints its package and its tests and stops there, which left
  `tools/security_exceptions.py` outside the check — the script that refuses a build
  over an unexplained alert had never been seen by the linter that gates the build.
  Found on 2026-10-02 by running ruff over the whole tree by hand while working on
  something else, which is not a way of finding things that scales.

- **`scripts/` is linted too, and had eight findings waiting.** Two unsorted import
  blocks and six f-strings with no placeholders, in `scripts/release.py` and
  `scripts/bump_version.py`, dating from 2026-08-16 and 2026-09-17 — checked with
  `git blame`, because the first guess was that this morning's encoding change had
  introduced them and it had not. All eight are mechanical and ruff's own fix was
  taken; `tests/test_release_script_encoding.py` and `tests/test_ci_scripts.py`
  still pass, which is what makes that safe to say.

### Removed

- **Five settled entries out of `SECURITY-EXCEPTIONS.toml`; `CVE-2026-82560` kept
  on purpose.** `CVE-2026-57585` and `GHSA-6v7p-g79w-8964` (one msgpack copy under
  two ids), `CVE-2025-47273`, `CVE-2026-24049` and `CVE-2026-23949` were all copies
  vendored inside pip and setuptools in the published image, which no pin could
  reach. The Dockerfile removed the build tooling from the runtime image on
  2026-09-28 and each entry said it would close when the next image was published.
  It was: GitHub closed all five at **2026-09-30T17:25:27Z**, one timestamp, and
  Docker Scout has not mentioned any of them since. Their return would now mean the
  removal regressed, and `tests/docker/inspect.sh` — which is what proved the
  absence inside the built image on 2026-09-29 — is the only thing left watching
  for that.

  `CVE-2026-82560` stays, and the reason is not how long it has been quiet: it went
  quiet *earlier* than the five, at 2026-09-29T15:26:56Z, on its own and with
  nothing done to the image. `patchradar debian CVE-2026-82560` on 2026-10-02 still
  reports perl no-dsa in trixie at `5.40.1-6+deb13u1`, no fix in any suite, Debian
  bug 1148455. perl-base is still installed and still unfixed; only the reporting
  changed, and Docker Scout has already changed its mind about this exact id once —
  which is why the gate reads closed alerts at all. Deleting a flaw that is
  demonstrably present because a scanner fell silent is the one direction this file
  must not drift in, so the entry now says that.

  Sixteen entries down to eleven. Checked by running `tools/security_exceptions.py`
  against this repository's live open and closed alerts rather than by inference:
  exit 0, with `CVE-2026-82560` the one settled entry it names. The same decision
  was taken in exeradar, apkradar and cookieradar the same day.

### Added

- **The gate reads FIRST's forecast on the CVEs it already holds.** EPSS is indexed
  by CVE, and the question was where to put it outside patchradar's scan. Measured
  on 2026-10-02: exeradar carries no CVE ids at all, and apkradar, mailradar and
  cookieradar one incidental mention each — so there was nothing to attach a
  forecast to, and building a CVE surface in order to justify one would have been
  the wrong way round.

  One surface already exists in all five, and it is the one we have spent two days
  feeding: `SECURITY-EXCEPTIONS.toml` and the code-scanning alerts it answers.
  Docker Scout names its alerts by CVE, so the record holds CVE ids with a written
  reason and a review date against each — and a forecast is the one thing those
  records lacked. "No fix in any suite", accepted until December, is comfortable at
  an EPSS of 0.1% and is something else at 40%.

  Run against this repository's live alerts the moment it was written:

  ```
  8 accepted finding(s), with FIRST's forecast:
    CVE-2025-47273   (EPSS 1.5%, p74)
    CVE-2026-82560   (EPSS 0.6%, p48)
    CVE-2026-85091   (EPSS 0.6%, p46)
    CVE-2026-95619   (EPSS 0.4%, p27)
    CVE-2026-102010  (EPSS 0.2%, p14)
  ```

  Every acceptance in the record is under 2%, the highest being setuptools'
  CVE-2025-47273 at 1.5% and the 74th percentile. That is the reassurance the
  record needed, and it is now measured rather than assumed.

  Three rules, each with a test:

  - **The forecast changes no verdict.** The gate fails on a blocking alert with no
    entry and on an entry past its date, and on nothing else. A 90% probability on
    something accepted with a reason is not a third failure mode — it is a reason
    to re-read the entry. `exit_code` takes the forecasts and ignores them, so the
    signature says they were available and did not enter the decision.
  - **Only ids that are CVE ids are looked up.** `SNYK-DEBIAN13-GCC14-20386241` is
    CVE-2026-95619, and its description says so in prose; reading the id is reading
    what the scanner stated, and reading the description is guessing. A forecast
    attached to the wrong flaw is worse than none.
  - **An absent score is absent.** FIRST not scoring a CVE prints "not scored by
    FIRST", never 0.0% — the floor of the scale is a real reading that tens of
    thousands of CVEs sit on. FIRST unreachable prints nothing at all and the
    report is the one this script produced before EPSS existed: `urllib` with a ten
    second timeout, every failure mapping to `{}`, because this runs on a bare
    checkout in a workflow that installs nothing.

  The accepted findings are listed on a **passing** run, worst first, because that
  is where somebody decides whether to renew a date and nothing else prompts it.
  That block exists because the first version printed forecasts only beside lines
  the verdict already had — and a passing verdict has one line.

- **CVSS v4.0 has a scale, and the threat metric inside it is read.**
  `severity_for(score, "4.0")` answered UNKNOWN, with a comment saying the honest
  answer was that rather than "I will use the v3 one, which looks similar". That
  was right while nobody had read the specification: FIRST publishes a qualitative
  scale for v4.0 and its boundaries are the same as v3's, so the table is written
  out now **because the standard says so** and not because the numbers resemble
  each other.

  Comparability does not follow. A 6.8 under v4.0 and a 6.8 under v3.1 are
  different measurements that land in the same band, the way a 10.0 under v2 and
  under v3 are different measurements that do not — so the module's rule stands:
  never a label without its version, never an ordering by label.
  `test_v2_still_disagrees_with_v4_where_the_bands_differ` keeps that visible at
  9.5, which is CRITICAL on v4 and HIGH on v2.

  Measured against NVD on 2026-10-02, 200 CVEs published in the preceding week:

  | block | records |
  |---|---|
  | `cvssMetricV31` | 104 |
  | `cvssMetricV40` | 24 |
  | `cvssMetricV2` | 6 |

  So v4.0 is already 12% of recent records. Two things about that block differ
  from v3.1: `baseSeverity` sits inside `cvssData` rather than on the entry, and
  the vector carries `E:` — `exploitMaturity`, FIRST's own statement about whether
  exploitation has been seen. The scan was discarding it.

  It is carried now, as `cvss_exploit_maturity`, and said in the reason: *the
  provider reports it attacked (CVSS v4.0 E:A)*. **It does not move the rank.**
  KEV is CISA's observation and EPSS is FIRST's forecast; where a provider's own
  "attacked" belongs against those is a decision, not a parse, and
  `test_priority_is_not_moved_by_the_threat_metric` is what would notice a quiet
  promotion.

  `E:X` leaves the field off the record entirely. `E:U` does not: "the provider
  looked and saw nothing" is information, and it is not the same as the provider
  saying nothing at all. Measured by mutation — making an undefined metric read as
  UNREPORTED fails five tests — because that collapse is the one this whole tool is
  built to avoid. v3.1's `E:` vocabulary (U/P/F/H) is refused rather than
  translated: the letters overlap in form and not in meaning, and the vector's
  prefix says which version is speaking.


- **FIRST EPSS, as a rank between CVSS and KEV.** 2026.41 made the scan read
  CISA KEV, which answers "is this being exploited" — but KEV is 1,726 entries
  and a record of the past, so every CVE not on it was still ordered by severity
  alone. EPSS is the probability FIRST assigns to a CVE being exploited in the
  next 30 days, and it is the measure a patch window is actually scheduled
  against: a 9.8 nobody is going to touch now sorts under a 5.0 that is about to
  go. `priority.RANK_EPSS` sits below the two KEV ranks and above `RANK_SCORED`,
  at a threshold of 10% — the distribution is heavily skewed, most scored CVEs
  are under 1%, and a rank triggering there would have covered a third of the
  scan and ordered nothing.

  It is an enrichment and not a collector, which is why it lives in
  `patchradar/epss.py` rather than under `collectors/`: asked about a CVE, FIRST
  returns a probability, so it finds nothing the other four sources had not
  already reported and has no keyword search to offer. `_scan_target` and
  `_scan_one` now merge, then ask FIRST once about the CVEs they found, then
  sort — in that order, which `tests/test_priority_wiring.py` pins: enriching
  after the sort would leave the forecast in the table's reasons while playing
  no part in its order, which is the one failure mode a reader cannot see.

  A CVE FIRST does not score carries no EPSS field at all rather than a zero.
  0.0 is a real reading — the floor of the scale, where tens of thousands of
  CVEs sit — and would be indistinguishable from a CVE published yesterday that
  the model has not scored. For the same reason a percentile outside [0, 1] is
  refused rather than clamped: clamped to 1.0 it would put the row at the top of
  the scan on the strength of a parse error. A failed lookup leaves the scan
  complete and says the ranking is poorer, and is not cached, so one outage does
  not cost the forecast for the whole TTL.

- **`cves.epss_score` and `cves.epss_percentile`.** Both nullable and without a
  default, so a CVE stored before EPSS existed does not acquire a reading of
  zero. `init_db` migrates an existing database with `ALTER TABLE` — the
  `CREATE TABLE` is `IF NOT EXISTS` and does nothing to one that already exists —
  and `save_cve` refreshes the pair on a row it already holds while leaving every
  other column alone: FIRST re-runs the model daily, so a probability is a
  reading taken on a date rather than a fact about the CVE, and `COALESCE` keeps
  a scan that could not reach FIRST from erasing yesterday's with NULL.

### Fixed

- **`number != number` is gone from the EPSS parsers.** Both `epss.py` and
  `priority.py` refused a NaN with an explicit identical-sides comparison, and
  SonarCloud reads that as a bug (`python:S1764`) — which is what turned main red
  after the EPSS merge, on `new_reliability_rating`, with coverage at 94.8% and
  every other condition green.

  The clause was redundant, and that was measured rather than assumed — across
  nan, ±inf, −0.5, 1.5 and the values inside the range: every comparison with NaN
  is false, so `0.0 <= number <= 1.0` is already False for it and the range test
  refuses it. Removing it changes no behaviour, which is what the existing tests
  for `"nan"` in `test_epss.py` and `float("nan")` in `test_priority.py` were
  there to prove: green before, green after.

- **CVE-2026-95619 and CVE-2026-102010 are recorded under each scanner's id.** The
  gcc advisories reached this image on 2026-10-01 and 2026-10-02. Snyk and Docker
  Scout give one flaw two ids, and the gate matches by id, so one flaw needs two
  entries — zlib has been in that position since September. CVE-2026-95619 arrived
  between one morning's survey and that afternoon's CI run, which is why it was
  not written earlier: an entry that matches nothing fails the build too, and that
  is deliberate.

  `tests/docker/inspect.sh` now prints the gcc, g++, cpp, libgcc and libstdc++
  packages. The entries say libstdc++6 is what is installed rather than the
  compiler, and that sentence had been asserted and never measured; a flaw in cc1
  needs something to compile, and nothing in this image compiles anything.

- **`patchradar debian` printed two sentences spliced into one.** The clause
  naming where evidence goes was a whole sentence when the tracker recorded no
  Debian bug, and both callers put it after a preposition:

      What moves it is evidence on No Debian bug is recorded; the tracker page is
      https://security-tracker.debian.org/tracker/CVE-2026-102010

  One of the two also lowercased it, bug URL and the word Debian included, in a
  line offered as the address to write to. Read on 2026-09-30 while quoting that
  advice into exeradar's `SECURITY-EXCEPTIONS.toml`, which is where these
  sentences end up: they are the written reason a finding was accepted, and the
  next reviewer reads them rather than the tracker.


- **A test was pinning Rich's output stream for every test that ran after it.**
  `test_the_console_is_flushed_even_when_the_body_raises` saved
  `cli.console.file` and assigned it back, which looks like a restore and is not:
  Rich's `file` is a property that falls back to `sys.stdout` when nothing was
  set, so writing the current value into it fixes that stream for good, and every
  later test rendering through this console wrote to the terminal instead of to
  the CliRunner's buffer. Found on apkradar, where the sibling of this test left
  `tests/test_hash_is_verifiable.py` asserting against an empty `result.output`;
  all four Radar carrying the test had it. It builds a console of its own now and
  monkeypatches it in, and still fails against the pre-2026-09-29 `_status`.

- **The Italian comments are in English** — three section headers in
  `tests/test_kev.py` and the comment inside the subprocess script of
  `tests/test_shutdown_flush.py`.

- **The release tool no longer dies on its own banner.** `patchradar/cli.py` has
  had `enable_utf8_output()` since 2026-09-24, and the two scripts under
  `scripts/` never got it. So the CLI printed its shield fine while the
  documented release path — `python3 scripts/release.py`, step four of
  RELEASING.md — ended in `UnicodeEncodeError: 'charmap' codec can't encode
  character '\U0001f6e1'` on a Windows console, where the code page is cp1252.
  The same applied to `scripts/bump_version.py`.

  Reached on 2026-09-30 while releasing 2026.42 and worked around with
  `PYTHONIOENCODING=utf-8` set by hand. The workaround is the defect: the next
  person on the next machine does not know it, and what fails is the one script
  nobody runs except at release time.

  `scripts/console_encoding.py` now carries the helper for the scripts, which
  deliberately do not import the package's copy — they have to run in a plain
  checkout with nothing installed, and `patchradar.cli` reaches for typer and
  rich at import time. `tests/test_release_script_encoding.py` measures both
  copies against the same cp1252 stream so they cannot drift apart, runs each
  script through its banner under `PYTHONIOENCODING=cp1252` answering "n" at the
  prompt, and asserts that declining changes nothing. Confirmed against the old
  code by mutation: commenting the call out reproduces the original error.

- **Two collector tests stopped depending on today's date.** The MSRC collector
  derives its month list from `datetime.now()`, so `days_back=60` covered three
  months on 2026-09-29 and two on 2026-09-30 — and with two, the third mocked
  response was never requested, so
  `test_msrc_partial_failure_keeps_the_months_that_worked` failed on the calendar
  rather than on a defect. It went red on 2026-09-30 on a suite that had been
  green the evening before, with nothing in the diff to explain it, and would
  have turned CI red on the next push.

  `test_partial_results_are_saved` carried the same latent fault under the
  comment "days=30 always spans at least two months", which is false on the 31st
  of a month: one document is fetched, the mocked failure is never reached, and
  the test would have passed while measuring nothing. Both now pin the month list
  through a fixture and say why. The arithmetic itself is still measured directly,
  against fixed dates, in `tests/test_msrc_months.py`.

- **The PyPI wait has tests.** `.github/scripts/wait_for_pypi.sh` was ported from
  cookieradar for 2026.42 and arrived without any, on a release path where a
  broken wait either blocks a publish or lets the build start too early.
  `tests/test_ci_scripts.py` drives it with a fake pip — first answer, third
  answer, never, called wrong — and pins that the step runs after the version is
  known and before the build, that it is given the version without the tag
  prefix, and that nothing in the workflow goes back to waiting by sleeping.

---

## [2026.42] — 2026-09-28
### Added

- **The exploited ones come first.** 2026.41 put the CISA KEV fact in every
  scan and nothing read it: the report printed what the sources had returned, in
  the order the fan-out happened. `patchradar.priority` now ranks four steps —
  in KEV with known ransomware use, in KEV, scored, unscored — and the report
  leads with the first.

  The measurement this exists for, taken on a real machine on 2026-09-26 across
  695 CVEs: ordering by CVSS put five 10.0 entries on top, **none of them
  exploited**, while the four listed in KEV scored 9.8, 8.8, 8.6 and 7.8. The
  operational question is what is being used against you now, and CVSS does not
  answer it.

  The rank never travels alone. Each row says which catalogue, since when, and
  CISA's remediation date where one is stated — a rank on its own is a number to
  be taken on trust.

- **`patchradar import <snapshot>` — what a machine has, and what could be
  watched.** Reads the JSON an inventory collector writes and reports, per
  product: a vendor source that answers by version, a source whose product has
  to be confirmed by hand, a component updated by whatever installed it, or no
  source by version at all.

  It writes nothing, queries nothing and decides nothing, and that is the point:
  translating what the registry writes into what a vendor API wants cannot be
  deduced from a name. Measured on this corpus, 30% mapped by themselves, and a
  guess let through produced `MX5` → a Juniper router and `Visual C++ 2012` →
  `visual_c++:2008`. So it proposes and a person confirms.

  Registry rows are not products, and the difference is large: on the machine
  measured on 2026-09-27 the 147 entries are **109 products** — 24 rows are one
  Python install, 14 are Visual C++ runtimes, 28 are NVIDIA of which three are
  products and twenty-five are containers and plugins. The largest groups are
  printed, so a product that arrived as 24 rows cannot hide inside a total.

  The result of that first run is worth stating: of 109 products, 2 can be
  answered by version today, 3 need one confirmation each, 32 are components and
  72 have no source that answers by version. On a home machine the vendor route
  covers five products out of 109; a company fleet is a different mix, and this
  command is how to find out before building anything on top.

- **`patchradar.affected` reads the NVD `configurations` nobody was reading.**
  Which versions a CVE affects and where NVD states the fix, with the one
  distinction the honesty of the answer rests on: `versionEndExcluding: X` **is**
  the fixed version, while `versionEndIncluding: X` only names the last affected
  release — deducing "fixed in 8.5.7" from `versionEndIncluding: 8.5.6` would
  publish a number no source ever stated.

  On the real Notepad++ payload: 8.9.5 has five known, all five closed by
  8.9.6.4; 8.5.0 has ten, six closed, and the four left open are open because
  NVD does not say where they were fixed, not because the update is
  insufficient.

  **Not wired into the scan yet, deliberately.** "Fixed in X" is a fact about a
  product, and a keyword scan has neither a CPE nor an installed version to ask
  about; that needs watchlist columns this release does not add. It ships as a
  tested module with the boundary pinned by a test, not as a promise.

- **`patchradar debian <cve>…` — what Debian says, and what that leaves us to
  do.** Every container scanner prints the same line for anything it cannot see a
  fixed version for: *no fix available*. That line covers situations with nothing
  in common, and the difference decides whether waiting is a plan or a way of
  never shipping again.

  The Debian security tracker states the difference in fields the collector was
  reading past — `fixed_version`, `nodsa`, `nodsa_reason`, `debianbug` and the
  status in the other suites. `patchradar.debian_status` turns them into seven
  positions, each with one next step: fixed here (rebuild, the image is stale),
  fixed in another suite (a fix exists — ask for a stable update), scheduled for a
  point release (waiting ends at a dated event), no-dsa postponed or ignored
  (later, or never — two opposite verdicts in a two-word vocabulary), open in
  every suite (nothing to ask for; evidence on the bug is what moves it),
  undetermined (nobody has checked — ours to settle), and untracked.

  Run against our own five Debian findings on 2026-09-29, it corrected two of
  them. `attr` and `acl` were recorded here as *no fix published*; they are in
  fact fixed in unstable (attr 1:2.6.0-1, acl 2.4.0-1) and filed no-dsa for
  trixie with Debian's own note that the fix arrives in a **point release** and
  cannot be backported piecemeal. So the wait has an end and a date, and the
  entries in `SECURITY-EXCEPTIONS.toml` now say so, with shorter review dates.
  `zlib` CVE-2026-85091 and `perl` CVE-2026-82560 are the other case: open in
  bookworm, trixie, sid and forky alike, nothing scheduled, Debian bugs 1146895
  and 1148455 — where a reachability note from us would be worth more than
  another rebuild.

  `--file` reads a saved snapshot, because the tracker is ~75 MB and asking the
  same question twice should not download it twice. The tests use fixtures and
  never touch the network.

- **`tools/inventory.ps1` — the collector that writes what `import` reads.** The
  command above documented its input as "the JSON an inventory collector writes",
  and that collector lived in one folder on one laptop, in no repository at all. A
  command whose input nobody else can produce is half a feature, and every number
  the entry above cites from it — 147 registry entries, 109 products, 5 answerable
  by version — was unreproducible by anyone.

  It is not packaged and not installed: a fixture recorder, run by hand from the
  checkout on the machine being surveyed, writing one JSON file and taking no
  decisions. The file boundary is why any of this can be tested — the analysis is
  Python, reading recorded snapshots on a machine that never saw the subject.

  Fourteen tests pin the seam, which nothing was watching: the two halves are in
  different languages and cannot import each other, so renaming `installedSoftware`
  in the script would leave every existing test green while `import` surveyed
  nothing. They also pin the two properties that make it safe to run on a machine
  under diagnosis — no `Win32_Product` enumeration, which would reconfigure every
  installed MSI, and no mutating verb anywhere.

### Changed

- **The CVE count means something different.** The three collectors were
  concatenated and de-duplicated nothing, so a CVE that NVD scored and CISA
  lists arrived twice — once with a score, once exploited with
  `severity: "UNKNOWN"`. They are now merged into one row, which keeps the real
  score and the exploitation fact together.

  So the number a scan reports changes from records returned to CVEs found. On a
  machine where the sources overlap it will be **smaller than it was**, not
  because anything improved but because it used to count some of them twice.
  Anything reading that number will see it move.

- The report has a `Priority` column, and the rows are no longer in the order
  the sources answered.

### Fixed

- **A scanner going quiet is no longer read as a record gone stale.** The new gate
  fails when an exception matches nothing, so that the file cannot drift away from
  the product — and on 2026-09-29 Docker Scout simply stopped reporting
  CVE-2026-82560 against exeradar, GitHub marked that alert `fixed` with nobody
  having dismissed it, and the published image had not changed. Deleting the entry
  would have been wrong: patchradar and mailradar hold the same CVE both open and
  closed, having already lost and regained it the day before. A rule that demands
  one commit to remove an entry and another to put it back is a rule people stop
  reading.

  What separates drift from a quiet run is whether GitHub has the finding at all.
  An entry matching an alert that is *closed* is reported and does not fail; one
  matching nothing in either state still fails. A closed Scout alert does not
  settle a Snyk entry for the same CVE, because those two disagree about these
  packages routinely.

- **A successful scan ended in a traceback.** With the report printed in full
  and an exit code of 0, a terminal run could finish with
  `ImportError: sys.meta_path is None, Python is likely shutting down` from
  Rich's `FileProxy`. While the spinner runs, Rich replaces the streams with a
  proxy that holds text until it meets a newline, and restores them without
  flushing it; a partial line written by a library is then printed when the
  interpreter finalises the proxy, too late to import anything. Nothing about
  the result was wrong, and nobody watching could tell.

  Only on a terminal, which is why it never surfaced in runs redirected to a
  file. The fix was already in CookieRadar and had not been carried anywhere
  else.

- Two rows for one CVE, ranked differently, one of them claiming
  `severity: UNKNOWN` for a flaw a scoring body had scored. See **Changed**.

### Documentation

- `RELEASING.md`, two CHANGELOG entries and the docstrings and comments of
  `cvss.py`, `collectors/msrc.py`, `cli.py` and their tests are in English, like
  the rest of the repository. The quoted text of Italian law in
  `tests/test_law_sources.py` stays in Italian: the tests assert on those words.

---

## [2026.41] — 2026-09-27
### Added

- **CISA KEV is a source, not a promise.** It had been listed as "Coming soon"
  in the README since the first release. It now runs in every scan, served from
  a process-wide snapshot like the Debian tracker — the catalogue is one
  document of 1,726 entries, so a scan costs one download rather than one per
  package.

  KEV answers a question the other sources do not: not how bad a flaw would be,
  but whether it is **being exploited right now**, with CISA's own remediation
  deadline attached. Measured on a real machine on 2026-09-26, across 695 CVEs
  matched against installed software: ordering by CVSS put five 10.0 entries on
  top, **none of them exploited**, while the four listed in KEV scored 9.8,
  8.8, 8.6 and 7.8 — below all five. Severity alone ranks the wrong things
  first.

  The collector deliberately supplies **no severity of its own**. Mapping
  "exploited" to CRITICAL would manufacture a score CISA never gave and make it
  indistinguishable from one a scoring body assigned; the fact travels as
  `known_exploited`, alongside `kev_due_date` and `kev_ransomware`.

  One trap is pinned by a test: CISA writes the strings `"Known"` and
  `"Unknown"`, and `bool("Unknown")` is `True`. Passing that field through
  unconverted would mark 1,610 of the 1,726 entries as ransomware-linked.

### Fixed

- **The CVSS scales, as FIRST publishes them — and there are two.**
  `patchradar.cvss` now holds the v3.x thresholds and the v2 ones in a single
  place, and they are not the same: v2 has no `Critical` and calls everything
  from 7.0 to 10.0 `High`, while v3 reserves `None` for 0.0 and starts `Low` at
  0.1.

  The hand-written table in `collectors/msrc.py` returned `LOW` for a score of
  0.0, where the specification says `NONE`. No test pinned it.

  The difference is not academic. Among 695 CVEs measured on a real machine on
  2026-09-26, `CVE-2014-0566 10.0 HIGH` (v2) and `CVE-2018-4872 10.0 CRITICAL`
  (v3) sit side by side: two 10.0s with different labels, both correct on their
  own scale. Hence a rule for anyone displaying this data — **never a label
  without its version beside it, and never an ordering by label**, because a 9.8
  CRITICAL would end up above a 10.0 HIGH.

  v2 and v3 do not convert into one another: they are different metrics and
  FIRST publishes no conversion table. A score whose version is not among those
  tabulated here yields `UNKNOWN`, v4.0 included, instead of borrowing the scale
  it most resembles.

- **`UNKNOWN` had no colour.** Three collectors already produce it, and with no
  entry in the palette those rows came out white, indistinguishable from any
  other. It is now magenta and deliberately not dimmed: a grey row reads as
  "negligible" while the true statement is "not measured", and the two resemble
  each other closely enough to be confused.

- **The README understated the product.** `Debian Security` had shipped,
  complete and tested, while the source table still advertised it as "Coming
  soon". A contract test now asserts that every collector defining `fetch_cves`
  is imported by the API, called in `_scan_one`, and named in the README — a
  collector that exists but is never invoked passes all of its own tests.

  The same test surfaced `collectors/snyk.py`: a zero-byte file present since
  the beginning. It is recorded as a known placeholder rather than deleted, and
  the suite now fails if it grows code without being wired in.

---

## [2026.40] — 2026-09-26
### Changed

- **Baseline: the five Radar restart from a common number.** They had drifted to
  .32, .12, .11, .6 and .3 of the same generation, which left the shared part of
  the version meaning nothing at all. The highest count in the suite was taken,
  rounded up for headroom, and every Radar starts again from 2026.40 — a jump
  for most of them, and a number that means the same thing in all five.

  From here the count belongs to each Radar again, and something urgent gets a
  third segment on top: 2026.40.1 before 2026.41, the way a suite has always
  done it. 2026 is a settling year; from 2027 the count moves when the code
  moves.


### Fixed

- **An NVD API key, paced requests, and a scan that admits a source was
  silent.** Without a key NVD allows five requests per rolling thirty seconds,
  and the scanner sent them as fast as it could: the throttling that followed
  came back as empty results, which the report presented as "no CVEs" — the
  strongest possible claim, produced by not having asked. A key is read from the
  environment when present, requests are paced to what the tier actually allows,
  and a source that did not answer is reported as a source that did not answer
  rather than as an absence of findings.

### Changed

- **The Docker image builds from this repository instead of from a published
  release.** The Dockerfile could only install `patchradar==${PATCHRADAR_VERSION}`
  from PyPI, with a default of `2026.8.33` — an August release, while the package
  had moved on — so `docker build .` produced an image of old code and there was
  no way at all to build one from the working tree. `PATCHRADAR_SOURCE` now picks
  between `local` (the default, so a plain build tests what is in front of you)
  and `pypi`, which requires a version and fails without one. A new
  `docker-build-check` workflow builds the image and runs a smoke test inside it
  without publishing anything: it verifies that the container user can create the
  database where the volume actually is, which is the failure that once emptied
  the watchlist on every container recreation.

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
