# Changelog

All notable changes to PatchRadar are documented here.

## Unreleased

### 🐛 Bug Fixes

- G1-G4+G6 — health endpoint, markup escape, Debian cache, scan auth+timeout, pytest in CI ([8a3499c](https://github.com/maksimtech/patchradar/commit/8a3499c712236b8aecf910d49d5b7d8e1b5e1f1c))

### 🔧 Maintenance

- Bump version to 2026.9.1 ([9150200](https://github.com/maksimtech/patchradar/commit/915020094ac7034a7f11cfde87f3695ccbee44b5))

## 2026.8.34 — 2026-08-26

### ♻️ Refactoring

- Extract _scan_target to reduce cognitive complexity (S3776) ([a9712e5](https://github.com/maksimtech/patchradar/commit/a9712e566f7724982b9a3ee89c1d3ad979b928d9))
- Extract helpers to reduce cognitive complexity in msrc.py (S3776) ([55f8fe8](https://github.com/maksimtech/patchradar/commit/55f8fe815000aba865a71d339c67de1a16e967db))

### ⚙️ CI/CD

- Add SonarCloud CI-based analysis workflow ([61729f3](https://github.com/maksimtech/patchradar/commit/61729f36424dbd81addb174b02f04ab9c7dd850a))
- Add pytest-cov for SonarCloud coverage reporting ([1714ce3](https://github.com/maksimtech/patchradar/commit/1714ce3793381ed4847cf6d88f5104d99f33911b))
- Exclude all files from coverage requirement in SonarCloud ([d51231e](https://github.com/maksimtech/patchradar/commit/d51231e15a43e2754381d997697e89f0aa547309))

### 🐛 Bug Fixes

- Define CHANGELOG_FILE constant instead of duplicating literal ([c016250](https://github.com/maksimtech/patchradar/commit/c016250a150cdbb1f6c64c4de63846e02efd695a))
- Correct CHANGELOG_FILE self-assignment (S1656) ([bf84240](https://github.com/maksimtech/patchradar/commit/bf842405fb58d4da247ddf4b9b2e39866dc2e248))
- Document HTTPException responses in API endpoints (S8415) ([4246026](https://github.com/maksimtech/patchradar/commit/4246026aa8f7ebde4fd8aa94df8db3e7d856922e))
- Add aria-label to add-input for accessibility (S8415) ([0c5b145](https://github.com/maksimtech/patchradar/commit/0c5b145b096271e2e774d6a9bcfb80a7ccdd024d))
- Add aria-label to file import input for accessibility ([068eb59](https://github.com/maksimtech/patchradar/commit/068eb5994b916f71dc6e949106fff55cb3c29a1a))
- Add aria-label to search input for accessibility ([597dcc6](https://github.com/maksimtech/patchradar/commit/597dcc6d1281e8f4b94d8e69794588206ce779c7))
- Use Number.parseInt instead of global parseInt (S7773) ([fbc73ad](https://github.com/maksimtech/patchradar/commit/fbc73ad196170ac3ddbd62c43529267648372773))
- Add role=dialog and aria-modal to modal overlay (S6848) ([f8ff44f](https://github.com/maksimtech/patchradar/commit/f8ff44f7daf83b41c4bc96b82d25d1ba56721c45))
- Clamp days_back to safe range in msrc collector ([b7a21f8](https://github.com/maksimtech/patchradar/commit/b7a21f88d1685039ad63e4ca6e49987adce4455b))

### 🔧 Maintenance

- Bump version to 2026.8.34 ([4d2d4a2](https://github.com/maksimtech/patchradar/commit/4d2d4a272c5f903a2a0c6126283b56b5e9457caa))
- Update poetry.lock after adding pytest-cov ([9689f74](https://github.com/maksimtech/patchradar/commit/9689f74e7943a5340a479523777f916313083a4f))
- Regenerate poetry.lock with pytest-cov ([a296c55](https://github.com/maksimtech/patchradar/commit/a296c552f03bb57200844ffc58abe3ef67d398ba))

## 2026.8.33 — 2026-08-25

### ⚙️ CI/CD

- Add sonar-project.properties for accurate Python analysis ([0a7a7ba](https://github.com/maksimtech/patchradar/commit/0a7a7ba22d82fe7f85cb42102f0b52ab235af260))
- Add wheel metadata verification step ([c4ddd4e](https://github.com/maksimtech/patchradar/commit/c4ddd4e882be488ddef92be5e36ca1da532b104a))
- Debug wheel metadata content ([726a21b](https://github.com/maksimtech/patchradar/commit/726a21b5aceec8511a533a1ac76189f73cf34f61))
- Debug dist contents after build ([6b839a9](https://github.com/maksimtech/patchradar/commit/6b839a9734b375f1d2233c765c4a91b40ae20d2d))

### 🐛 Bug Fixes

- Add NOSONAR comment for poetry install SonarCloud finding ([6a8bc85](https://github.com/maksimtech/patchradar/commit/6a8bc858719bce0dadba6f19e36bb7c41ab2e282))
- Pin CodSpeed workflow actions to full commit SHA ([291c909](https://github.com/maksimtech/patchradar/commit/291c909c1966e60373fd62da565d030237a2ce16))
- Pin Docker workflow actions to full commit SHA ([f8c0fc0](https://github.com/maksimtech/patchradar/commit/f8c0fc00959e461f6f027196abc6b48d0d994236))
- Pin publish workflow actions to SHA and fix pip install flags ([d6197aa](https://github.com/maksimtech/patchradar/commit/d6197aa5172ad53d67249179bacf4f252e22f39c))
- Pin trivy and test workflow actions to full SHA ([b39a460](https://github.com/maksimtech/patchradar/commit/b39a460b081ee0695db769a6872cb7703c7807a7))
- Revert --no-build-isolation, add NOSONAR instead ([79dc0c2](https://github.com/maksimtech/patchradar/commit/79dc0c2d572a10f77925bc6a159b2541c91b9740))
- Pin trivy-action to full SHA (v0.36.0) ([1b60c60](https://github.com/maksimtech/patchradar/commit/1b60c60580487b2567c75160c4c6063311245cca))
- Run as non-root user for security ([4cc875b](https://github.com/maksimtech/patchradar/commit/4cc875b28b3bd68691cc8bff5e9215f7825b5061))
- Remove invalid --only-binary :all: from yaml ([e3dde9d](https://github.com/maksimtech/patchradar/commit/e3dde9d7e8cc6d233397a3a2272e274e401b8537))
- Correct SHA for docker setup actions ([84db99d](https://github.com/maksimtech/patchradar/commit/84db99d9c7d709fb49dd823151e4eda5277fbd4d))
- Bump msgpack to 1.2.1 to fix HIGH CVEs ([f6d8232](https://github.com/maksimtech/patchradar/commit/f6d8232b8d40d2c09f3ee483b6a6a6d104c820e4))
- Add --only-binary :all: to pip installs for security ([73c67c8](https://github.com/maksimtech/patchradar/commit/73c67c8cbff64d358788f9fcd0ed35fc09572508))
- Pin setuptools and msgpack to exact versions ([efd1f06](https://github.com/maksimtech/patchradar/commit/efd1f064e6ed593f154ac864b7318d94c7f856fa))
- Pin patchradar version and pass via ARG from CI ([cd2fe9e](https://github.com/maksimtech/patchradar/commit/cd2fe9e808c10cec41bfe8c4495010859506169b))
- Trigger Docker build after PyPI publish completes ([ab8dcf7](https://github.com/maksimtech/patchradar/commit/ab8dcf76285cb19ace630df88f92f1e10a860053))
- Wait 60s for PyPI propagation before Docker build ([0018250](https://github.com/maksimtech/patchradar/commit/00182503706c2c4623884fb968b8e2b2f08a70c5))
- Upgrade build tools before building package ([3adbbe8](https://github.com/maksimtech/patchradar/commit/3adbbe89aaf56485be4af368a1261ebf83868891))
- Disable metadata verification in pypi publish action ([37ec220](https://github.com/maksimtech/patchradar/commit/37ec22081518a63551b08b64f2dc783f433f8c4b))
- Use release/v1 tag for pypi-publish action ([6b42ca7](https://github.com/maksimtech/patchradar/commit/6b42ca769188c470181217cb72cdcd8a166c4e65))
- Pin pypi-publish to release/v1 SHA and clean up debug steps ([c762b31](https://github.com/maksimtech/patchradar/commit/c762b312b31fa6a166253d80637e2f841ddef5b0))

### 🔧 Maintenance

- Bump docker/login-action from 3 to 4 (#19) ([3740f7c](https://github.com/maksimtech/patchradar/commit/3740f7cc2633cfa128f49cee107e16483c67fffc))

## 2026.8.32 — 2026-08-22

### 🔧 Maintenance

- Bump version to 2026.8.32 ([4c7e136](https://github.com/maksimtech/patchradar/commit/4c7e13610e505ff9dc42744273b86e3fd7d929df))

### 🧪 Tests

- Remove global asyncio mark and apply only to async tests ([9917f77](https://github.com/maksimtech/patchradar/commit/9917f77e8472277bac3ebe07b378d8c6d96b93d7))

## 2026.8.31 — 2026-08-21

### 🔧 Maintenance

- Bump actions/checkout from 5 to 7 (#20) ([09ca826](https://github.com/maksimtech/patchradar/commit/09ca8267d4c642876ebf865ee6b94447d9b31fa1))

### 🧪 Tests

- Add Debian Security Tracker collector tests ([e87a087](https://github.com/maksimtech/patchradar/commit/e87a0875756ef729d6c3e2589bd5585290f14f61))

## 2026.8.30 — 2026-08-20

### ✨ Features

- Add Debian Security Tracker collector ([461ee1f](https://github.com/maksimtech/patchradar/commit/461ee1f39f16a5b533f58c1daac594cf67124d44))

### 📄 Documentation

- Update README with Debian Security Tracker collector ([cec1852](https://github.com/maksimtech/patchradar/commit/cec18527c19ab3f155e9ebb1b1ba321d3595fad5))

### 🔧 Maintenance

- Bump version to 2026.8.30 ([141bbe7](https://github.com/maksimtech/patchradar/commit/141bbe7e53c3e7e99d6742e59fb072fbe59ef34c))

## 2026.8.29 — 2026-08-20

### 🐛 Bug Fixes

- Add proper error handling to api() fetch function ([9e06f47](https://github.com/maksimtech/patchradar/commit/9e06f47a2fe02554bf32b14bf7cdfd384af4c3c3))

### 🔧 Maintenance

- Remove stale whitespace from button labels ([c60838c](https://github.com/maksimtech/patchradar/commit/c60838c8e6cc5a4fb5ab35f183b1784485997d4f))
- Remove stale whitespace from modal link labels ([18ffea7](https://github.com/maksimtech/patchradar/commit/18ffea741fa1c047a91a52c909385e272410e083))
- Bump version to 2026.8.29 ([b6d80cd](https://github.com/maksimtech/patchradar/commit/b6d80cd6fb3050e3c41f01d0e0fc35b5b645d971))

## 2026.8.28 — 2026-08-20

### ⚙️ CI/CD

- Add Python 3.14 to matrix and test 3.15-dev as experimental ([ceb0d10](https://github.com/maksimtech/patchradar/commit/ceb0d10ccb5c936795f6fa2e4fd31b0d13a41570))
- Add Renovate configuration ([a033dc3](https://github.com/maksimtech/patchradar/commit/a033dc3cfc29c0f1ef76e6bdc594ba5d68e0abf0))
- Remove schedule - let Renovate run on its own cadence ([c062d58](https://github.com/maksimtech/patchradar/commit/c062d589dcc537c4abf4e957300c2fc583b3b333))
- Add Dependabot config and security policy ([f7abe39](https://github.com/maksimtech/patchradar/commit/f7abe3997f35f39d6fa0963551d81d30c7d144fe))
- Add Trivy security scanner workflow ([65a0edd](https://github.com/maksimtech/patchradar/commit/65a0edd8705e38f388036d60335bca380ad4de22))

### 🐛 Bug Fixes

- Use pkg_version for app version and clean up duplicate imports ([849b71f](https://github.com/maksimtech/patchradar/commit/849b71f6fd6e5195577741183ec0633ae888ae9d))
- Assign cursor in save_cve to correctly return rowcount ([47a23ed](https://github.com/maksimtech/patchradar/commit/47a23edb1054d873d77ba431144ed4c2bf693875))

### 📄 Documentation

- Add Python version badges including 3.14 and 3.15-dev ([a4f585d](https://github.com/maksimtech/patchradar/commit/a4f585dc2acbe261170761e01dff7249329cb219))
- Add security policy ([9457a81](https://github.com/maksimtech/patchradar/commit/9457a8175f534b4eeddbc05e50ab053ee7a77634))

### 🔧 Maintenance

- Bump minimum dependency versions to latest stable ([d1454f7](https://github.com/maksimtech/patchradar/commit/d1454f79b084e11b296da2098e233a6b9325f764))
- Update poetry.lock after dependency version bump ([9f63db5](https://github.com/maksimtech/patchradar/commit/9f63db5aa690de870fb7c75813f943cc08ab2035))
- Bump github/codeql-action from 3 to 4 (#14) ([d8da563](https://github.com/maksimtech/patchradar/commit/d8da5633b66339fe9cd2d4baa4e3a19d16040be6))
- Bump docker/setup-qemu-action from 3 to 4 (#15) ([507ba7f](https://github.com/maksimtech/patchradar/commit/507ba7f581739f18274fc22648a56ef6294be1b5))
- Bump actions/setup-python from 6 to 7 (#16) ([e420359](https://github.com/maksimtech/patchradar/commit/e420359be34c1db813c29e058b7396c527239672))
- Bump docker/setup-buildx-action from 3 to 4 (#17) ([6965719](https://github.com/maksimtech/patchradar/commit/6965719435293fce0ce912b82700cdd84ca70535))
- Bump docker/build-push-action from 6 to 7 (#18) ([d0f638d](https://github.com/maksimtech/patchradar/commit/d0f638de0f659a53d27465e374b18304bbdfc29c))
- Remove unused asyncio import from database.py ([542d418](https://github.com/maksimtech/patchradar/commit/542d418e47e088c2986cd294d6f1221d6f37b6c7))
- Move timedelta import to top of msrc.py ([50a461c](https://github.com/maksimtech/patchradar/commit/50a461c9c446202fdbc3d8256f257fb35daea902))
- Clean up nvd.py ([8b7660f](https://github.com/maksimtech/patchradar/commit/8b7660ff322da269849451cbaf23ad353a998388))
- Bump version to 2026.8.28 ([92695f9](https://github.com/maksimtech/patchradar/commit/92695f9fc8e240c202f5e6dec736032bccb54338))

## 2026.8.27 — 2026-08-19

### ✨ Features

- Add PowerShell script for winget integration ([39ac929](https://github.com/maksimtech/patchradar/commit/39ac9299b245b216584dc1cfa248861f500718e3))

### 🐛 Bug Fixes

- Multiple UI fixes ([2a3585b](https://github.com/maksimtech/patchradar/commit/2a3585be11b4ea510f61cb4b59cb17387fba0efe))

### 🔧 Maintenance

- Bump version to 2026.8.27 ([b1d2849](https://github.com/maksimtech/patchradar/commit/b1d2849be804ec84367d2b769d0024b555bc9058))

## 2026.8.26 — 2026-08-19

### ✨ Features

- Bulk import software from file into watchlist ([dbd38b4](https://github.com/maksimtech/patchradar/commit/dbd38b4d5e489c86631e46221104d2ff536614b0))

### 🔧 Maintenance

- Bump version to 2026.8.26 ([a99f789](https://github.com/maksimtech/patchradar/commit/a99f78910717dffea4b8444f5eb545324b1cec92))

## 2026.8.25 — 2026-08-19

### 🐛 Bug Fixes

- Add search filter for CVEs table ([7267a5f](https://github.com/maksimtech/patchradar/commit/7267a5f24d7d053543b94d8956e885e387a973da))

## 2026.8.24 — 2026-08-19

### ⚙️ CI/CD

- Add Docker Scout CVE scan to Docker workflow ([098e700](https://github.com/maksimtech/patchradar/commit/098e700c02bed54829ad4bd56792c1ded9424e0b))
- Add explicit permissions to workflows for CodeQL compatibility ([ba78788](https://github.com/maksimtech/patchradar/commit/ba787884bbca168ff77923b3a13e06f5103e5229))

### 🔧 Maintenance

- Remove __pycache__ files and add to .gitignore ([701d4b6](https://github.com/maksimtech/patchradar/commit/701d4b65015b501fce79b12fe8bc256cf0204dba))
- Bump version to 2026.8.24 ([87465d9](https://github.com/maksimtech/patchradar/commit/87465d919eac90ec994e0a70cc2244ddb3183297))

## 2026.8.23 — 2026-08-19

### 🐛 Bug Fixes

- Switch to trixie and pin secure PyPI deps ([42e0965](https://github.com/maksimtech/patchradar/commit/42e09655d342127de9db25e3147eafd5db422d37))

## 2026.8.22 — 2026-08-19

### 🐛 Bug Fixes

- Apt-get upgrade to patch OpenSSL HIGH vulnerability ([9f0a007](https://github.com/maksimtech/patchradar/commit/9f0a00788d427f0dd4f826da8e616b25a2a5da08))

## 2026.8.21 — 2026-08-19

### ⚙️ CI/CD

- Add CodSpeed performance benchmarks ([2df2e5f](https://github.com/maksimtech/patchradar/commit/2df2e5f1bde681d078e3741612367f46f3b4e2ed))

### 🐛 Bug Fixes

- Delete orphan CVEs when software is removed from watchlist ([5753d42](https://github.com/maksimtech/patchradar/commit/5753d421f485544d3db78c00a9957f7d909ac06c))

### 🔧 Maintenance

- Bump version to 2026.8.21 ([19dde99](https://github.com/maksimtech/patchradar/commit/19dde997d581ffe955983806abda9c0aa708f1ad))

## 2026.8.20 — 2026-08-16

### 📄 Documentation

- Rewrite CHANGELOG with all versions from 2026.8.4 to 2026.8.19 ([e274514](https://github.com/maksimtech/patchradar/commit/e274514c7fe52982a65b6486a9b201a319451832))
- Rewrite CHANGELOG with complete version history (#12) ([f5c4ef6](https://github.com/maksimtech/patchradar/commit/f5c4ef6b149f49736b3a946b0bdf0951d6217558))
- Update CHANGELOG ([a74de43](https://github.com/maksimtech/patchradar/commit/a74de4311e6d0c5d8b825fb4b7540a809ed346bb))

### 🔧 Maintenance

- Bump version to 2026.8.20 ([ed029af](https://github.com/maksimtech/patchradar/commit/ed029af63d51e9b5c5251727579342f6ed72c419))

## 2026.8.19 — 2026-08-16

### ✨ Features

- Add CVE detail modal and fix watchlist overflow ([2526977](https://github.com/maksimtech/patchradar/commit/252697730d65948f835096eb1f826f4232f8b6d0))
- Add CVE detail modal and fix watchlist overflow (#11) ([5ca963a](https://github.com/maksimtech/patchradar/commit/5ca963afbbd346940fcb5d0c1432e9b6b258fa92))

### 📄 Documentation

- Update CHANGELOG ([5858edc](https://github.com/maksimtech/patchradar/commit/5858edc707e36a8440bdb5e14f51b0ce54c0855c))

### 🔧 Maintenance

- Bump version to 2026.8.19 ([7c17e50](https://github.com/maksimtech/patchradar/commit/7c17e5010a90c9a6415a9b5ed13498da92e78141))

## 2026.8.18 — 2026-08-16

### 📄 Documentation

- Update README — MSRC active, remove inline changelog ([544e72f](https://github.com/maksimtech/patchradar/commit/544e72fb54cf857a6ddde8a941727dcd3ba8685f))
- Update README with MSRC status and remove inline changelog (#10) ([083e9bb](https://github.com/maksimtech/patchradar/commit/083e9bbaf823bc1cdd5da648b98e22ca1d7a50d4))
- Update CHANGELOG ([51d1078](https://github.com/maksimtech/patchradar/commit/51d1078c988cf0a4bd158889e9378d2bf6ae7681))

### 🔧 Maintenance

- Bump version to 2026.8.18 ([090dd45](https://github.com/maksimtech/patchradar/commit/090dd4513f8f9f3c1d048970e13b186cc567fd74))

## 2026.8.17 — 2026-08-16

### ✨ Features

- Add MSRC collector for Microsoft Patch Tuesday ([b3ae63c](https://github.com/maksimtech/patchradar/commit/b3ae63ccbf36b41540fd8dddbf18e42a466faded))
- Add MSRC collector for Microsoft Patch Tuesday (#9) ([e64ac24](https://github.com/maksimtech/patchradar/commit/e64ac24eeac0d6e6fed9adf687f504a28ec279d1))

### 📄 Documentation

- Update CHANGELOG ([6b69230](https://github.com/maksimtech/patchradar/commit/6b692307020d914a8e632d6aa2b50bbaa793c63e))

### 🔧 Maintenance

- Bump version to 2026.8.17 ([9ebb4f2](https://github.com/maksimtech/patchradar/commit/9ebb4f28964efa9fe0ed8670b8b49fb93c392546))

## 2026.8.16 — 2026-08-16

### ⚙️ CI/CD

- Update GitHub Actions to Node.js 24 compatible versions ([66a985b](https://github.com/maksimtech/patchradar/commit/66a985b884e14b19efc5166046b075a857ea71ab))
- Update GitHub Actions to Node.js 24 compatible versions (#8) ([2d04f55](https://github.com/maksimtech/patchradar/commit/2d04f55f4528bd9400dc3cfd2c9db8202dec1fe5))

### 📄 Documentation

- Update CHANGELOG ([20421dc](https://github.com/maksimtech/patchradar/commit/20421dc2950cf737e1c4dd00a8e525247892698d))

### 🔧 Maintenance

- Bump version to 2026.8.16 ([6a40e98](https://github.com/maksimtech/patchradar/commit/6a40e9868778e79f2c57ab79dfff5747f4106ed1))

## 2026.8.15 — 2026-08-16

### 🐛 Bug Fixes

- Replace deprecated on_event with lifespan handler ([7827afb](https://github.com/maksimtech/patchradar/commit/7827afb57ef0c0741b5c9b55c399bb359f92f3ee))
- Replace deprecated on_event with lifespan handler (#7) ([9c8fcf0](https://github.com/maksimtech/patchradar/commit/9c8fcf044402d3c7a7f047f73370896184a1c4ae))

### 📄 Documentation

- Update CHANGELOG ([e795abc](https://github.com/maksimtech/patchradar/commit/e795abca64bc021680e76dfcb149b78bbf5c70c5))

### 🔧 Maintenance

- Bump version to 2026.8.15 ([06e78a9](https://github.com/maksimtech/patchradar/commit/06e78a9000d92048f6a11ab51f96540e7bd2413d))

## 2026.8.14 — 2026-08-16

### 📄 Documentation

- Update CHANGELOG ([34dc7c2](https://github.com/maksimtech/patchradar/commit/34dc7c24ba20791f728ca0b702c8022dd3174133))

### 🔧 Maintenance

- Bump version to 2026.8.14 ([df51440](https://github.com/maksimtech/patchradar/commit/df514400c4d0d86715b7488db2881014dbcb2ffb))

### 🧪 Tests

- Complete test suite — CLI, NVD collector mock, database CRUD ([82c96fe](https://github.com/maksimtech/patchradar/commit/82c96fe444c6a993a578439bfdfc5bd63e8933a2))
- Complete test suite with CLI, NVD mock and database CRUD (#6) ([2acd294](https://github.com/maksimtech/patchradar/commit/2acd294a4f00bb69612b5ecd9a42398ad52c0d7c))

## 2026.8.13 — 2026-08-16

### ⚙️ CI/CD

- Add Docker Hub build and push workflow ([5e4e003](https://github.com/maksimtech/patchradar/commit/5e4e003852e86356fbd0f4644f04ff830ad5fd7b))

### ✨ Features

- Add Dockerfile, docker-compose and .dockerignore ([b4e8f8d](https://github.com/maksimtech/patchradar/commit/b4e8f8d3711317583ee8aa469df55c618d16bac0))
- Add Docker support (#4) ([27896b0](https://github.com/maksimtech/patchradar/commit/27896b0e72cfc45d8dbe6bdff96580818ac7e080))
- Add Docker support and RELEASING.md (#5) ([179f395](https://github.com/maksimtech/patchradar/commit/179f395e9dce82ec75e13d4189bc7f63cc288ccb))

### 📄 Documentation

- Add RELEASING.md with pre-release checklist and process ([7466f82](https://github.com/maksimtech/patchradar/commit/7466f82621ed8fe88fe98986ca70ab1c3a6adabb))
- Update CHANGELOG ([96250ef](https://github.com/maksimtech/patchradar/commit/96250ef47d641a22e077b11a68d8d077bed4e25a))

### 🔧 Maintenance

- Bump version to 2026.8.13 ([1c8f320](https://github.com/maksimtech/patchradar/commit/1c8f320237142d6892e1712205eab48641157f9b))

## 2026.8.12 — 2026-08-16

### 📄 Documentation

- Update CHANGELOG ([2dd00c4](https://github.com/maksimtech/patchradar/commit/2dd00c479986b456ae9cb30aad576349b9fb9437))

### 🔒 Security

- Fix CWE-79 DOM XSS in severity chart ([5c4f305](https://github.com/maksimtech/patchradar/commit/5c4f305580bac7145790f5f891476e86ba8c2071))

### 🔧 Maintenance

- Integrate git-cliff for automatic changelog generation ([0820aca](https://github.com/maksimtech/patchradar/commit/0820aca32fb0711668c6d4a1782d638b8ea28223))
- Integrate git-cliff for automatic changelog generation (#3) ([78f60fd](https://github.com/maksimtech/patchradar/commit/78f60fd6e7031ba6e8f84ec18ef68b426d52db2c))
- Bump version to 2026.8.12 ([812b0a4](https://github.com/maksimtech/patchradar/commit/812b0a4fe7e75ea4221bbb0c0780b43bde3f476d))

## 2026.8.11 — 2026-08-16

### 🔧 Maintenance

- Bump version to 2026.8.11 ([b4c0f6a](https://github.com/maksimtech/patchradar/commit/b4c0f6a7789c9ac4dd9ace47a89183c34eb2e555))

## 2026.8.10 — 2026-08-16

### ✨ Features

- Complete security hardening and test suite (#2) ([32323ae](https://github.com/maksimtech/patchradar/commit/32323aeda560fccabd3caeffdffed00d60b31c91))

### 🔒 Security

- Add CSP and security headers middleware ([7fc5af6](https://github.com/maksimtech/patchradar/commit/7fc5af6b0d0a2ac058d88800e7c4e2f4738420be))
- Add input validation to all endpoints ([268bbf0](https://github.com/maksimtech/patchradar/commit/268bbf0ead173339356e4eb3ce046b4df55bb83e))
- Add output sanitization for CVE data ([d65cc89](https://github.com/maksimtech/patchradar/commit/d65cc89e9b81ac7ecffb88f435f5be6ad8227768))

### 🔧 Maintenance

- Bump version to 2026.8.8 ([6394602](https://github.com/maksimtech/patchradar/commit/639460277e8d7d8c9777d4f7b6dd0abf040c9687))
- Add bump_version.py script ([e61eb2e](https://github.com/maksimtech/patchradar/commit/e61eb2e0a08dae3461f064558d71d30ed1d8d813))
- Bump version to 2026.8.9 ([188ccf7](https://github.com/maksimtech/patchradar/commit/188ccf756105a80e73c9650b50919480e3f48a2f))
- Bump version to 2026.8.10 ([07d775f](https://github.com/maksimtech/patchradar/commit/07d775ffa2f4c8f397048c7bec1d634a0f1ee557))
- Add release.py script ([4c15240](https://github.com/maksimtech/patchradar/commit/4c1524053f090d57dd040caca17bbc48f38590af))

### 🧪 Tests

- Add real test suite replacing placeholder ([a24105d](https://github.com/maksimtech/patchradar/commit/a24105d3455c5bedfde82bd7c4d7d811666ed02c))

## 2026.8.7 — 2026-08-15

### 🐛 Bug Fixes

- Rewrite api/main.py cleanly, dynamic version in UI ([0d2331c](https://github.com/maksimtech/patchradar/commit/0d2331c297edff8385a78468dc67c9eb482bf16a))

### 🔒 Security

- Fix CWE-79 DOM XSS — replace innerHTML with createElement/textContent ([b5ead88](https://github.com/maksimtech/patchradar/commit/b5ead88ef49a16af49d6f857d70cd14fc188b94c))
- Fix CWE-79 DOM XSS in web UI (#1) ([9d76260](https://github.com/maksimtech/patchradar/commit/9d762609424ff26ee3356b364fce5dcfc1608762))

### 🔧 Maintenance

- Bump version to 2026.8.7 ([ff031d7](https://github.com/maksimtech/patchradar/commit/ff031d7fd51fa38848fe59fa4761cb1c237162c8))

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


