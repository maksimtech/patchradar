# PatchRadar — design

Written on 2026-10-17. `affected.py`, `inventory.py` and the tests around them
referred to "the versionradar design, §5" for the watchlist columns a
version-aware scan needs; that text was never committed and could not be found.
This document is the design the code refers to, reconstructed from what those
modules already commit to — the column names in `inventory.py`, the rules in
`affected.py`, the boundary in `tests/test_priority_wiring.py` — so that every
reference to §5 now points at something that exists. Sections 1 to 4 describe
what PatchRadar already does; §5 is what the version-aware scan adds.

## 1. The question

"Which published vulnerabilities concern the software I run, and which first?"
A scan answers it for each entry of the watchlist, on demand: there is no
scheduler and no notification inside PatchRadar.

## 2. Sources

NVD, MSRC and CISA KEV answer every scan; VulDB only with `VULDB_API_KEY`; the
Debian Security Tracker on a scan started from the web UI. FIRST EPSS finds
nothing on its own: it scores the CVEs the sources returned. A source that
fails makes the scan *incomplete*, and only a scan every queried source answered
may say "no CVEs found".

## 3. Matching by name

Each source is asked by keyword, and a record is kept when the keyword names
the software as a word (`names.keyword_pattern`); MSRC also through the products
an entry lists as Known Affected. This finds the CVEs that **name** the software.
It cannot say whether they affect the version installed: a CVE fixed in 8.9.6.4
and a CVE that only ever affected 7.3.3 look the same. §5 is the answer to that.

## 4. Ranking

CISA KEV (exploited now) before FIRST EPSS (likely in 30 days, threshold 10%)
before CVSS, which only breaks ties. `priority.py` holds the order and the
reason printed beside each rank.

## 5. The installed version

### 5.1 Watchlist columns

Five columns on `watchlist`, every one nullable and without a default — a
missing version is an absence, and a default would be a claim:

| column | holds | set by |
|---|---|---|
| `cpe` | the CPE 2.3 name of the product, as NVD writes it: `cpe:2.3:a:notepad-plus-plus:notepad\+\+` | `add --cpe` |
| `vendor` | the CPE vendor field, `notepad-plus-plus` | derived from `cpe` |
| `product_id` | the CPE product field, escaped as NVD escapes it, `notepad\+\+` | derived from `cpe` |
| `installed_version` | the version installed, `8.5.0` | `add --version` |
| `channel` | the release channel a vendor source answers for (stable, ESR, LTS) | reserved for the inventory import (§5.6) |

An existing database gets them on the next start, as `cves` got its EPSS columns.

### 5.2 Nothing is guessed

The CPE is typed by a person, never derived from the name. Measured on a real
inventory, a name-to-CPE guess mapped `MX5` to a Juniper router and
`Visual C++ 2012` to `visual_c++:2008`, and nothing in the output said so
(`inventory.py`). `add` checks the form only: `cpe:2.3:`, a part, a vendor and a
product, neither `*` nor `-`. A product written with a CPE special character
unescaped — `notepad++` instead of `notepad\+\+` — is refused with the escaped
form shown, because NVD would match nothing and the scan would read as clean.

The version must be one `affected.py` can order. One it cannot read is refused
at `add`, not discovered as "not evaluable" on every CVE of every scan.

### 5.3 Three verdicts per CVE

For an entry with both `installed_version` and `cpe`, each CVE the scan finds by
name is judged against the installed version with NVD's own `configurations`:

- **affected** — a vulnerable `cpeMatch` for the vendor and product contains the
  version. "Fixed in X" only where NVD states `versionEndExcluding: X`.
- **not affected** — NVD lists the affected products and versions, and this
  version of this product is not among them.
- **not evaluable** — anything that cannot be decided: NVD has not yet stated
  which products the CVE affects (no `configurations`, the usual state of a CVE
  for weeks after publication), NVD could not be asked about a CVE that came
  from KEV or MSRC alone, or NVD's versions belong to another scheme than the
  installed one (`2.07` against `16.0.14334`).

A CVE that reached the scan only through KEV or MSRC, which carry no
`cpeMatch`, is looked up in NVD by id (`cveId=`) for an entry that can be judged,
and NVD's record is merged in — configurations and score with it. Paced like
every request to NVD; an entry matched by name costs no lookup.

"Not evaluable" never becomes "not affected": for a security tool an answer it
cannot give is not an absolution.

### 5.4 What the scan prints

- The table lists the CVEs that are **affected** or **not evaluable**, each with
  its verdict. The **not affected** ones are counted, not listed; `scan --all`
  lists them too, with their verdict.
- One line per entry says the split: found by name, how many affect the
  installed version, how many could not be evaluated, how many do not affect it.
- When NVD states fixes: which version closes how many of the affected ones, and
  that the rest stay open because NVD does not say where they were fixed — not
  because the update falls short (`affected.summarise`).
- Always, for a versioned entry: the caveat that a count from NVD is a count of
  identifiers requested, not of flaws (`affected.CAVEAT`).
- An entry without a version is scanned by name as before, and the scan says
  once which entries were matched by name only.

The total line keeps its meaning: CVEs found by name.

### 5.5 What is stored

The verdict is kept on the link between a CVE and a product, `cve_software`
(`verdict`, `verdict_reason`, `verdict_fixed_version`, `judged_version`), because
one CVE stored once can be affected for one watched product and not for another.
The latest scan decides it. It is read back only while the installed version is
still `judged_version`: after `add --version` with a new version, the old verdict
is not shown until a scan judges the new one. `status` and `/api/cves` show it;
the API records version and CPE (`POST /api/watchlist/{name}?version=&cpe=`) and
judges with the same function as the CLI (`affected.mark`).

What decides a rank is stored too: `known_exploited`, `kev_ransomware`,
`kev_date_added`, `kev_due_date` and the provider's `cvss_exploit_maturity`, in
`cves`, refreshed by every scan that brings them (CISA lists a CVE long after NVD
publishes it). `status` and `/api/cves` list most urgent first, with the order
`priority.sql_order` builds from the rules a scan ranks by, and an index on that
expression keeps a listing of 50 a read of 50 rows.

### 5.6 Order of work

1. **PR-01a** — the columns, `add --version --cpe`, the verdict for NVD records
   in the command-line scan, `--all`, the README.
2. **PR-01b** — in three parts: the verdict stored and the API (01b-1); KEV
   and MSRC entries judged through NVD's record of the same CVE (01b-2); the KEV
   fields stored, with the database-backed listings ranked by priority (01b-3).
3. **PR-01c** — the web UI; `patchradar import` writing the mappings a person
   confirmed, `channel` included.

## 6. What PatchRadar does not do

It does not read the machine it runs on: the inventory collector is a separate
script whose output is read elsewhere. It does not install, update or patch
anything, and a CVE count from any source is not a statement that the software
is safe.
