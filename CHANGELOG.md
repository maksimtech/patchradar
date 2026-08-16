# Changelog

All notable changes to PatchRadar are documented here.

## Unreleased

### ⚙️ CI/CD

- Add Docker Hub build and push workflow ([5e4e003](https://github.com/maksimtech/patchradar/commit/5e4e003852e86356fbd0f4644f04ff830ad5fd7b))
- Update GitHub Actions to Node.js 24 compatible versions ([66a985b](https://github.com/maksimtech/patchradar/commit/66a985b884e14b19efc5166046b075a857ea71ab))
- Update GitHub Actions to Node.js 24 compatible versions (#8) ([2d04f55](https://github.com/maksimtech/patchradar/commit/2d04f55f4528bd9400dc3cfd2c9db8202dec1fe5))

### ✨ Features

- Complete security hardening and test suite (#2) ([32323ae](https://github.com/maksimtech/patchradar/commit/32323aeda560fccabd3caeffdffed00d60b31c91))
- Add Dockerfile, docker-compose and .dockerignore ([b4e8f8d](https://github.com/maksimtech/patchradar/commit/b4e8f8d3711317583ee8aa469df55c618d16bac0))
- Add Docker support (#4) ([27896b0](https://github.com/maksimtech/patchradar/commit/27896b0e72cfc45d8dbe6bdff96580818ac7e080))
- Add Docker support and RELEASING.md (#5) ([179f395](https://github.com/maksimtech/patchradar/commit/179f395e9dce82ec75e13d4189bc7f63cc288ccb))

### 🐛 Bug Fixes

- Rewrite api/main.py cleanly, dynamic version in UI ([0d2331c](https://github.com/maksimtech/patchradar/commit/0d2331c297edff8385a78468dc67c9eb482bf16a))
- Replace deprecated on_event with lifespan handler ([7827afb](https://github.com/maksimtech/patchradar/commit/7827afb57ef0c0741b5c9b55c399bb359f92f3ee))
- Replace deprecated on_event with lifespan handler (#7) ([9c8fcf0](https://github.com/maksimtech/patchradar/commit/9c8fcf044402d3c7a7f047f73370896184a1c4ae))

### 📄 Documentation

- Update CHANGELOG ([2dd00c4](https://github.com/maksimtech/patchradar/commit/2dd00c479986b456ae9cb30aad576349b9fb9437))
- Add RELEASING.md with pre-release checklist and process ([7466f82](https://github.com/maksimtech/patchradar/commit/7466f82621ed8fe88fe98986ca70ab1c3a6adabb))
- Update CHANGELOG ([96250ef](https://github.com/maksimtech/patchradar/commit/96250ef47d641a22e077b11a68d8d077bed4e25a))
- Update CHANGELOG ([34dc7c2](https://github.com/maksimtech/patchradar/commit/34dc7c24ba20791f728ca0b702c8022dd3174133))
- Update CHANGELOG ([e795abc](https://github.com/maksimtech/patchradar/commit/e795abca64bc021680e76dfcb149b78bbf5c70c5))

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
- Integrate git-cliff for automatic changelog generation ([0820aca](https://github.com/maksimtech/patchradar/commit/0820aca32fb0711668c6d4a1782d638b8ea28223))
- Integrate git-cliff for automatic changelog generation (#3) ([78f60fd](https://github.com/maksimtech/patchradar/commit/78f60fd6e7031ba6e8f84ec18ef68b426d52db2c))
- Bump version to 2026.8.12 ([812b0a4](https://github.com/maksimtech/patchradar/commit/812b0a4fe7e75ea4221bbb0c0780b43bde3f476d))
- Bump version to 2026.8.13 ([1c8f320](https://github.com/maksimtech/patchradar/commit/1c8f320237142d6892e1712205eab48641157f9b))
- Bump version to 2026.8.14 ([df51440](https://github.com/maksimtech/patchradar/commit/df514400c4d0d86715b7488db2881014dbcb2ffb))
- Bump version to 2026.8.15 ([06e78a9](https://github.com/maksimtech/patchradar/commit/06e78a9000d92048f6a11ab51f96540e7bd2413d))
- Bump version to 2026.8.16 ([6a40e98](https://github.com/maksimtech/patchradar/commit/6a40e9868778e79f2c57ab79dfff5747f4106ed1))

### 🧪 Tests

- Add real test suite replacing placeholder ([a24105d](https://github.com/maksimtech/patchradar/commit/a24105d3455c5bedfde82bd7c4d7d811666ed02c))
- Complete test suite — CLI, NVD collector mock, database CRUD ([82c96fe](https://github.com/maksimtech/patchradar/commit/82c96fe444c6a993a578439bfdfc5bd63e8933a2))
- Complete test suite with CLI, NVD mock and database CRUD (#6) ([2acd294](https://github.com/maksimtech/patchradar/commit/2acd294a4f00bb69612b5ecd9a42398ad52c0d7c))

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


