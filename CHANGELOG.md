# Changelog

All notable changes to PatchRadar are documented here.

## 2026.8.19 — 2026-08-16

### ✨ Features
- Add CVE detail modal — click CVE ID for full details
- New API endpoint GET /api/cves/{cve_id}
- Fix watchlist overflow — long names truncated with ellipsis

## 2026.8.18 — 2026-08-16

### ✨ Features
- Add MSRC collector for Microsoft Patch Tuesday

### 📄 Documentation
- Update README — MSRC marked as Active
- Remove inline changelog from README

## 2026.8.17 — 2026-08-16

### ⚙️ CI/CD
- Update GitHub Actions to Node.js 24 (checkout v5, setup-python v6)

## 2026.8.16 — 2026-08-16

### 🐛 Bug Fixes
- Replace deprecated on_event with lifespan handler

## 2026.8.15 — 2026-08-16

### 🧪 Tests
- Complete test suite — 28 tests (CLI, NVD mock, database CRUD)

## 2026.8.14 — 2026-08-16

### ✨ Features
- Add Docker support — Dockerfile, docker-compose, multi-arch build
- Add RELEASING.md — pre-release checklist

### ⚙️ CI/CD
- Add Docker Hub build and push workflow (multi-arch amd64 + arm64)

## 2026.8.13 — 2026-08-15

### 🔧 Maintenance
- Integrate git-cliff for automatic changelog generation

## 2026.8.12 — 2026-08-15

### 🔒 Security
- Fix CWE-79 DOM XSS in severity chart (data flow from API)

## 2026.8.11 — 2026-08-15

### 🔒 Security
- Add CSP and security headers middleware
- Add input validation on all API endpoints
- Add output sanitization for CVE data
- Add bump_version.py and release.py scripts

### 🧪 Tests
- Add real test suite replacing placeholder (15 tests)

## 2026.8.10 — 2026-08-14

### 🔒 Security
- Fix CWE-79 DOM XSS — replaced innerHTML with createElement/textContent
- Complete security hardening

## 2026.8.7 — 2026-08-15

### 🔒 Security
- Fix CWE-79 DOM XSS in web UI (#1)

## 2026.8.6 — 2026-08-14

### 🐛 Bug Fixes
- Dynamic version badge via importlib.metadata
- UTF-8 encoding fix for Windows

## 2026.8.5 — 2026-08-14

### 🐛 Bug Fixes
- UTF-8 encoding error on Windows when serving web UI

## 2026.8.4 — 2026-08-14

### ✨ Features
- First public release on PyPI
- CLI with add, remove, list, scan, status, serve commands
- Web UI with dark theme dashboard
- NVD collector for realtime CVE monitoring
- Local SQLite storage — no cloud, no account, no telemetry
