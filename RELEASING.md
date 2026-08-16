# Release Process

## Pre-release checklist

Before every release, verify ALL of the following:

- [ ] All work is on `develop` branch
- [ ] All tests pass: `pytest tests/ -v`
- [ ] Snyk scan: 0 findings (SAST + SCA + Secrets)
- [ ] Tested on Windows (Python 3.14)
- [ ] Tested on Linux (Codespace, Python 3.12)
- [ ] README updated if needed
- [ ] CHANGELOG will be generated automatically by git-cliff
- [ ] No open critical/high security issues

## Release steps

```bash
# 1. PR develop → main
# Open PR on GitHub, review, merge

# 2. Switch to main
git checkout main
git pull origin main

# 3. Bump version (CalVer)
python3 scripts/bump_version.py

# 4. Release (generates CHANGELOG + GitHub release + PyPI)
python3 scripts/release.py
```

## CalVer formatYYYY.MM.PATCH
2026.8.1 → first release of August 2026
2026.8.2 → second release of August 2026
2026.9.1 → first release of September 2026


## Branch strategy

main → always stable, always tested
develop → work in progress
feat/xxx → new features
fix/xxx → bug fixes


## Rules

- Never commit directly to `main`
- Every release must pass the pre-release checklist
- One release per meaningful set of changes
- No "rattoppi" — debug before releasing
- Changelog is automatic — write good commit messages
