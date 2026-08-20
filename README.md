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

### Web UI

```bash
patchradar serve
# Open http://localhost:8000
```

---

## 📡 Sources

| Source | Type | Status |
|--------|------|--------|
| [NVD](https://nvd.nist.gov) | CVE Database | ✅ Active |
| [MSRC](https://msrc.microsoft.com) | Microsoft Patch Tuesday | ✅ Active |
| Debian Security | Linux packages | 🔜 Coming soon |
| CISA KEV | Known Exploited Vulnerabilities | 🔜 Coming soon |

---

## 🗓️ Versioning

PatchRadar uses [CalVer](https://calver.org) — `YYYY.MM.PATCH`.

---

## ⚡ Benchmarks

Performance is tracked continuously with [CodSpeed](https://codspeed.io). The benchmarks live in `benchmarks/` and cover the CVE collectors, the SQLite layer, the API endpoints and the CLI table rendering.

```bash
poetry install --with dev
poetry run pytest benchmarks/            # correctness check, no measurement
codspeed run --mode simulation -- poetry run pytest benchmarks/ --codspeed
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

