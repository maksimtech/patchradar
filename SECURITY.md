# Security Policy

## Reporting a vulnerability

Write to <security@maksimtech.com>; the GPG key for that address is on
keys.openpgp.org. GitHub's private vulnerability reporting is also open on this
repository: <https://github.com/maksimtech/patchradar/security/advisories/new>.
Please do not open a public issue for a vulnerability.

PatchRadar has a single maintainer, Massimo Moretti, who reads both.

## Supported versions

Only the latest release receives fixes. Versions follow CalVer (`YYYY.count[.fix]`):
a fix ships as the next release, never as a patch to an older one.

## How vulnerabilities are found

- **CodeQL, Bandit and Trivy** (repository files) run on every pull request, on
  every push to `main` and weekly.
- **Snyk** checks the code, the dependencies and an image built from the source on
  every pull request and push to `main`.
- **Docker Scout** checks the published image on every push to `main`, on every
  image build and weekly. The image is built on `python:3.14-slim-trixie` (Debian
  Trixie) when a release is cut; it is not rebuilt between releases unless the
  maintainer rebuilds it by hand, so Debian's security patches reach it with the next
  release.
- **Dependabot alerts** and Dependabot security updates are enabled on the
  repository.
- **Security Posture** reads the alerts the scanners above publish to GitHub code
  scanning and fails when a high or critical finding has no reasoned exception in
  `SECURITY-EXCEPTIONS.toml`. It also runs weekly, because an exception expires by
  date and not by commit.
- Reports sent to the addresses above.

## Response times

- A fix ships with the next release. Releases can be up to a month apart.
- For a vulnerability with a CVSS score of 9.0 or more, customers who have given a
  security contact are told within 48 hours of the report being taken in charge,
  even if the fix is not ready yet.
- A vulnerability that is accepted rather than fixed is recorded in
  `SECURITY-EXCEPTIONS.toml` with the reason and a review date; Security Posture
  fails once the review date has passed.

## Customer notification

Every fix is described in the release notes on GitHub, which are the CHANGELOG
section of that version. For a vulnerability with a CVSS score of 9.0 or more,
customers who have given a security contact also get a direct email.

## Rollback

Every version stays installable and pinnable:

- PyPI: `pip install patchradar==<version>`;
- Docker Hub: `maksimtech/patchradar:<version>`, the bare version with no `v`
  (for example `maksimtech/patchradar:2026.46`), and the SHA256 digest of that image,
  which cannot change. The repository's workflows rewrite a version tag only when the
  maintainer rebuilds that version by hand, so the digest is the reproducible pin.

Rolling back means pinning the previous version or digest. Releases are cut with
`scripts/release.py` (see `RELEASING.md`).

## The web interface

`patchradar serve` listens on 127.0.0.1 unless told otherwise; the Docker image
listens on all of the container's interfaces. The optional `PATCHRADAR_API_KEY`
protects only the endpoints that change the watchlist or start a scan: the watchlist
and the vulnerabilities found are readable by anyone who can reach the port, with or
without the key, over plain HTTP. Keep it on loopback, or put it behind a proxy that
adds TLS and authentication. The details are in question 2 of
[docs/nis2-compliance.md](docs/nis2-compliance.md).

## Evidence attached to every release

Each GitHub release carries CycloneDX SBOMs of the image and of the Python
environment, and dated Trivy reports of the image and of the repository at the
tag. The Trivy reports are an automated scan for known vulnerabilities, not a
penetration test; no penetration test has been carried out. What these files are,
and the answers to the questions a customer subject to NIS2 may ask, are in
[docs/nis2-compliance.md](docs/nis2-compliance.md).

Last reviewed: 2026-10-11
