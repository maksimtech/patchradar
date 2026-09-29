# PatchRadar

![Python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13%20|%203.14%20|%203.15--dev-blue)
[![CI](https://github.com/maksimtech/patchradar/actions/workflows/test.yml/badge.svg)](https://github.com/maksimtech/patchradar/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/patchradar)](https://pypi.org/project/patchradar/)
[![Docker](https://img.shields.io/docker/v/maksimtech/patchradar?label=docker)](https://hub.docker.com/r/maksimtech/patchradar)

# PatchRadar 🛡️

> Know when your software is vulnerable — before attackers do.

PatchRadar monitors CVE feeds in realtime and alerts you when a new vulnerability affects your software stack. No more manually checking NVD, MSRC, or Snyk — just add your software and let PatchRadar watch for you.

![Python](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)
![CalVer](https://img.shields.io/badge/calver-2026.8.2-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![PyPI](https://img.shields.io/pypi/v/patchradar?style=flat-square![PyPI](https://img.shields.io/pypi/v/patchradar?style=flat-square)label=pypi)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/maksimtech/patchradar?utm_source=badge)

---

## ✨ Features

- 🔍 **Realtime CVE monitoring** — scans NVD, MSRC and Debian Security Tracker for new vulnerabilities
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
powershell -ExecutionPolicy Bypass -File tools/inventory.ps1
```

```bash
patchradar import inventory-20260929-120000.json
```

`tools/inventory.ps1` collects and judges nothing — it reads the registry, device
state, the driver store and the event log, and writes one JSON file. It is not
installed with the package: run it by hand, from the checkout, on the machine
being surveyed. It never enumerates `Win32_Product`, which would trigger an MSI
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

KEV answers a different question from the others. They report what has been
published about a package; KEV reports what is **being exploited right now**,
with CISA's own remediation deadline. It carries no severity of its own and
PatchRadar does not invent one — the fact travels as `known_exploited`, which
is worth more than a score: on a sample of 695 CVEs matched against installed
software, sorting by CVSS put five 10.0 entries on top, none of them exploited,
while the four listed in KEV scored 9.8, 8.8, 8.6 and 7.8.

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

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with ❤️ by <a href="https://github.com/maksimtech">maksimtech</a>
</div>

---

