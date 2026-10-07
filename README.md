# PatchRadar

![Python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13%20|%203.14%20|%203.15--dev-blue)
[![CI](https://github.com/maksimtech/patchradar/actions/workflows/test.yml/badge.svg)](https://github.com/maksimtech/patchradar/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/patchradar)](https://pypi.org/project/patchradar/)
[![Docker](https://img.shields.io/docker/v/maksimtech/patchradar?label=docker)](https://hub.docker.com/r/maksimtech/patchradar)

# PatchRadar 🛡️

> Know when your software is vulnerable — before attackers do.

PatchRadar checks the CVE feeds for the software on your watchlist and tells you which vulnerabilities affect it, most urgent first. No more manually checking NVD, MSRC, or Snyk — just add your software and run a scan.

Scans run when you start one — `patchradar scan`, or **Scan** in the web UI. There is no scheduler and no notification inside PatchRadar: to scan on a schedule, run `patchradar scan` from cron or the Windows Task Scheduler.

![Python](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)
![CalVer](https://img.shields.io/badge/calver-2026.8.2-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![PyPI](https://img.shields.io/pypi/v/patchradar?style=flat-square![PyPI](https://img.shields.io/pypi/v/patchradar?style=flat-square)label=pypi)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/maksimtech/patchradar?utm_source=badge)

---

## ✨ Features

- 🔍 **On-demand CVE scans** — `patchradar scan` queries NVD, MSRC and CISA KEV; a scan from the web UI (`POST /api/scan`) also queries the Debian Security Tracker
- 🎯 **Ranked by what is actually a threat** — CISA KEV for observed exploitation, FIRST EPSS for the 30-day forecast, CVSS only to break the tie
- 📋 **Personal watchlist** — add any software you want to monitor
- 🎨 **Beautiful web UI** — dark theme dashboard with charts and filters
- 💻 **CLI first** — full command line interface for automation
- 📊 **CVSS scoring** — color-coded severity (Critical / High / Medium / Low)
- 🐧 **Debian Security Tracker** — monitors open CVEs for Debian/Ubuntu packages
- 💾 **Local SQLite** — all data stored locally, no cloud, no account needed
- 🐍 **Python 3.11+** — modern async architecture with httpx and FastAPI

---

## 🚀 Installation

```bash
pip install patchradar
```

---

## 📖 Usage

### CLI

```bash
# Add software to your watchlist
patchradar add proxmox
patchradar add bitwarden
patchradar add "windows 10"

# Show your watchlist
patchradar list

# Scan for CVEs (last 30 days)
patchradar scan --days 30

# Show latest CVEs in terminal
patchradar status

# Remove software
patchradar remove proxmox
```

### Asking Debian what it is actually doing

A container scanner prints one line for anything without a published fix — *no
fix available* — and that line covers cases with different answers. `debian`
reads the security tracker and says which case a finding is, and what is left to
do about it:

```bash
patchradar debian CVE-2026-85091 CVE-2026-54371
patchradar debian CVE-2026-54371 --release bookworm --package attr
patchradar debian CVE-2026-85091 --file tracker.json   # a snapshot saved earlier
```

Seven positions, one next step each: fixed here (the image is stale — rebuild),
fixed in another suite (a fix exists — ask for a stable update), scheduled for a
point release (the waiting has a date), no-dsa postponed or ignored (later, or
never), open in every suite (nothing to wait for — evidence on the Debian bug is
what moves it), undetermined (nobody has checked, so this one is ours to settle),
and untracked.

### Sizing the work on a real machine

Take the snapshot on the Windows machine you want to survey, then read it
anywhere:

```powershell
patchradar collector                     # writes inventory.ps1 beside you
Unblock-File .\inventory.ps1
powershell -ExecutionPolicy Bypass -File .\inventory.ps1
```

```bash
patchradar import inventory-20260929-120000.json
```

`patchradar collector` writes the script; it collects and judges nothing — it reads the registry, device
state, the driver store and the event log, and writes one JSON file. It ships inside the
package, because the machine worth surveying is the one without a checkout: run
`patchradar collector` there, elevated, and read the JSON anywhere. It never enumerates `Win32_Product`, which would trigger an MSI
reconfiguration of every installed product, and it changes nothing else either.

`patchradar import` then reports, per product, whether a vendor source can answer
by version. It writes nothing and guesses nothing: a name cannot be turned into a
vendor's product id by deduction, so it proposes and a person confirms.

The file boundary in the middle is the point. The analysis is Python, tested
against recorded snapshots, and runs on a machine that never saw the one being
examined — without it none of this could be tested in CI at all.

### Web UI

```bash
patchradar serve
# Open http://localhost:8000
```

Without `PATCHRADAR_API_KEY` the scan and watchlist endpoints need no key, which is
meant for use on the same machine: `patchradar serve` listens on 127.0.0.1 and the
`docker-compose.yml` publishes the port on 127.0.0.1 only. Set the key (see
`.env.example`) before exposing it any further. Either way, a write that a browser
sends on behalf of another web site (`Sec-Fetch-Site: cross-site`, or an `Origin`
that is not this server) is refused with 403, so a page you visit cannot add to your
watchlist or start scans through your browser.

### NVD API key (optional)

NVD limits clients without an API key to 5 requests per 30 seconds; a key raises
it to 50. A long scan needs several requests per keyword — NVD refuses any date
range wider than 120 days, so `--days 730` is split into seven windows — and a
watchlist of any size will reach the keyless limit. PatchRadar paces its requests
to stay under whichever limit applies, which makes a keyless scan slower rather
than incomplete.

```bash
export NVD_API_KEY=your-key   # https://nvd.nist.gov/developers/request-an-api-key
patchradar scan --days 365
```

The key is sent as a request header, never in the URL. If a source fails for
every entry in the watchlist, the scan says so after the total rather than
leaving one warning per entry: a count of CVEs that came from one source out of
two is not the same as a complete scan.

---

## 📡 Sources

| Source | Type | Status |
|--------|------|--------|
| [NVD](https://nvd.nist.gov) | CVE Database | ✅ Active |
| [MSRC](https://msrc.microsoft.com) | Microsoft Patch Tuesday | ✅ Active |
| [Debian Security](https://security-tracker.debian.org) | Linux packages | ✅ Active |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities | ✅ Active |
| [FIRST EPSS](https://www.first.org/epss/) | Exploitation forecast (enrichment) | ✅ Active |

KEV answers a different question from the others. They report what has been
published about a package; KEV reports what is **being exploited right now**,
with CISA's own remediation deadline. It carries no severity of its own and
PatchRadar does not invent one — the fact travels as `known_exploited`, which
is worth more than a score: on a sample of 695 CVEs matched against installed
software, sorting by CVSS put five 10.0 entries on top, none of them exploited,
while the four listed in KEV scored 9.8, 8.8, 8.6 and 7.8.

EPSS is the row marked *enrichment* because it finds nothing. The four sources
above answer "which CVEs affect this software"; FIRST answers "how likely is
this one to be exploited in the next 30 days", for a CVE you already have. So it
runs once per scan over the CVEs the sources returned, and adds `epss_score` and
`epss_percentile` to them.

It fills the gap between the other two measures. CVSS says how bad exploitation
would be *if* it happened; KEV says it **is** happening — but KEV is a short list
and a record of the past, so everything not on it came down to severity alone.
EPSS is a forecast, which is why it ranks below CISA having observed the thing
and above a score: a 9.8 nobody is going to touch now sorts under a 5.0 that is
about to go. The threshold for "likely" is a 10% probability
(`priority.EPSS_THRESHOLD`), chosen because the distribution is heavily skewed —
most scored CVEs sit below 1%, so a rank that triggered there would apply to a
third of the scan and order nothing.

A CVE FIRST does not score carries **no** EPSS field, rather than a zero: 0.0 is
a real reading — the floor of the scale, where tens of thousands of CVEs sit —
and a CVE published yesterday has no model output at all. The two must not look
alike. Needs no API key, and a scan whose EPSS lookup fails still reports every
CVE it found, ranked without the forecast and saying so.

---

## 🗓️ Versioning

PatchRadar uses [CalVer](https://calver.org) — `YYYY.MM.PATCH`.

---

## ⚡ Benchmarks

Performance is tracked continuously with [CodSpeed](https://codspeed.io). The benchmarks live in `benchmarks/` and cover the CVE collectors, the SQLite layer, the API endpoints and the CLI table rendering.

```bash
pip install --group dev -e .
pytest benchmarks/                       # correctness check, no measurement
codspeed run --mode simulation -- pytest benchmarks/ --codspeed
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or pull requests.

---

## 🛠️ How this is built

Developed with [Claude Code](https://claude.com/claude-code), reviewed and released by
[maksimtech](https://github.com/maksimtech). The suite is the contract: the release
script runs it with the new version already written and refuses to commit if it fails,
so nothing ships that it has not passed.

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with ❤️ by <a href="https://github.com/maksimtech">maksimtech</a>
</div>

---

