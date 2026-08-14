# PatchRadar 🛡️

> Know when your software is vulnerable — before attackers do.

PatchRadar monitors CVE feeds in realtime and alerts you when a new vulnerability affects your software stack. No more manually checking NVD, MSRC, or Snyk — just add your software and let PatchRadar watch for you.

![Python](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)
![CalVer](https://img.shields.io/badge/calver-2026.8.2-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![PyPI](https://img.shields.io/pypi/v/patchradar?style=flat-square![PyPI](https://img.shields.io/pypi/v/patchradar?style=flat-square)label=pypi)

---

## ✨ Features

- 🔍 **Realtime CVE monitoring** — scans NVD and other sources for new vulnerabilities
- 📋 **Personal watchlist** — add any software you want to monitor
- 🎨 **Beautiful web UI** — dark theme dashboard with charts and filters
- 💻 **CLI first** — full command line interface for automation
- 📊 **CVSS scoring** — color-coded severity (Critical / High / Medium / Low)
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
| MSRC | Microsoft Security | 🔜 Coming soon |
| Snyk | Package vulnerabilities | 🔜 Coming soon |
| Debian Security | Linux packages | 🔜 Coming soon |

---

## 🗓️ Versioning

PatchRadar uses [CalVer](https://calver.org) — `YYYY.MM.PATCH`.

| Version | Date | Notes |
|---------|------|-------|
| 2026.8.2 | 2026-08-14 | Web UI added |
| 2026.8.1 | 2026-08-14 | Initial release |

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

## 📝 Changelog

### 2026.8.5 — 2026-08-14
- 🐛 Fixed UTF-8 encoding error on Windows when serving the web UI

### 2026.8.4 — 2026-08-14
- 🎉 First stable public release on PyPI
- 🔍 NVD collector for realtime CVE monitoring
- 📋 Personal software watchlist
- 🎨 Web UI with dark theme dashboard
- 💻 Full CLI — `add`, `remove`, `list`, `scan`, `status`, `serve`
- 📊 CVSS scoring with severity breakdown
- 💾 Local SQLite storage

### 2026.8.1 — 2026.8.3 — 2026-08-14
- 🔧 Internal development versions — not published to PyPI
