# Changelog

All notable changes to PatchRadar are documented here.

## Unreleased

### ✨ Features

- Complete security hardening and test suite (#2) ([32323ae](https://github.com/maksimtech/patchradar/commit/32323aeda560fccabd3caeffdffed00d60b31c91))

### 🐛 Bug Fixes

- Rewrite api/main.py cleanly, dynamic version in UI ([0d2331c](https://github.com/maksimtech/patchradar/commit/0d2331c297edff8385a78468dc67c9eb482bf16a))

### 🔒 Security

- Fix CWE-79 DOM XSS — replace innerHTML with createElement/textContent ([b5ead88](https://github.com/maksimtech/patchradar/commit/b5ead88ef49a16af49d6f857d70cd14fc188b94c))
- Fix CWE-79 DOM XSS in web UI (#1) ([9d76260](https://github.com/maksimtech/patchradar/commit/9d762609424ff26ee3356b364fce5dcfc1608762))
- Add CSP and security headers middleware ([7fc5af6](https://github.com/maksimtech/patchradar/commit/7fc5af6b0d0a2ac058d88800e7c4e2f4738420be))
- Add input validation to all endpoints ([268bbf0](https://github.com/maksimtech/patchradar/commit/268bbf0ead173339356e4eb3ce046b4df55bb83e))
- Add output sanitization for CVE data ([d65cc89](https://github.com/maksimtech/patchradar/commit/d65cc89e9b81ac7ecffb88f435f5be6ad8227768))
- Fix CWE-79 DOM XSS in severity chart ([5c4f305](https://github.com/maksimtech/patchradar/commit/5c4f305580bac7145790f5f891476e86ba8c2071))

### 🔧 Maintenance

- Bump version to 2026.8.7 ([ff031d7](https://github.com/maksimtech/patchradar/commit/ff031d7fd51fa38848fe59fa4761cb1c237162c8))
- Bump version to 2026.8.8 ([6394602](https://github.com/maksimtech/patchradar/commit/639460277e8d7d8c9777d4f7b6dd0abf040c9687))
- Add bump_version.py script ([e61eb2e](https://github.com/maksimtech/patchradar/commit/e61eb2e0a08dae3461f064558d71d30ed1d8d813))
- Bump version to 2026.8.9 ([188ccf7](https://github.com/maksimtech/patchradar/commit/188ccf756105a80e73c9650b50919480e3f48a2f))
- Bump version to 2026.8.10 ([07d775f](https://github.com/maksimtech/patchradar/commit/07d775ffa2f4c8f397048c7bec1d634a0f1ee557))
- Add release.py script ([4c15240](https://github.com/maksimtech/patchradar/commit/4c1524053f090d57dd040caca17bbc48f38590af))
- Bump version to 2026.8.11 ([b4c0f6a](https://github.com/maksimtech/patchradar/commit/b4c0f6a7789c9ac4dd9ace47a89183c34eb2e555))

### 🧪 Tests

- Add real test suite replacing placeholder ([a24105d](https://github.com/maksimtech/patchradar/commit/a24105d3455c5bedfde82bd7c4d7d811666ed02c))

## 2026.8.6 — 2026-08-14

### 🐛 Bug Fixes

- Dynamic version in UI + update version badge ([c88fd52](https://github.com/maksimtech/patchradar/commit/c88fd526b66794d5886c49465bff2a3c48013d74))

## 2026.8.5 — 2026-08-14

### 🐛 Bug Fixes

- Use UTF-8 encoding for HTML template on Windows ([cb7a7f8](https://github.com/maksimtech/patchradar/commit/cb7a7f88e9fbaa1ca944ef923325630c1f5f60a6))

### 📄 Documentation

- Add changelog to README ([1199114](https://github.com/maksimtech/patchradar/commit/1199114bd67423c653013e618f2b1fe86e6d70cb))

## 2026.8.4 — 2026-08-14

### 📄 Documentation

- Update README badges ([8ae31c0](https://github.com/maksimtech/patchradar/commit/8ae31c023c867e00fafe05025067b04bd531a4c8))

### 🔧 Maintenance

- Bump version to 2026.8.4 ([c7bc88f](https://github.com/maksimtech/patchradar/commit/c7bc88f5b92029120b8547c036d095b8d4cbe398))

## 2026.8.3 — 2026-08-14

### 🔧 Maintenance

- Bump version to 2026.8.2 ([6553017](https://github.com/maksimtech/patchradar/commit/65530170f0045bd732fb15464cf7bbac9c92a167))
- Bump version to 2026.8.3 ([4bd63e9](https://github.com/maksimtech/patchradar/commit/4bd63e95f95936dfd3b01c7d047428d16b3eb69e))

## 2026.8.2 — 2026-08-14

### ⚙️ CI/CD

- Add GitHub Actions for PyPI publish and tests ([682e1f7](https://github.com/maksimtech/patchradar/commit/682e1f7c6a38548066aa724c01a453c72ab94fd0))

### ✨ Features

- Initial working release ([9f1da3f](https://github.com/maksimtech/patchradar/commit/9f1da3f8f46a73f2366491edf9df6de5c7b031d1))
- Add web UI with dashboard, watchlist, CVE table and charts ([9a3bad7](https://github.com/maksimtech/patchradar/commit/9a3bad7924506441978bd084ecab35c35c35c52b))
- Add web UI, README and CalVer 2026.8.2 ([839df3d](https://github.com/maksimtech/patchradar/commit/839df3dd0bca7197b8aecfef34da6f1c72a519a3))


