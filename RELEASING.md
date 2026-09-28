# Release Process

## Versioning

PatchRadar uses **CalVer, Apple style**: `YYYY.count[.fix]`.

```
2026.40      generation 2026, fortieth count
2026.41      the count moves because the code moved
2026.40.1    an out-of-band fix to what is already out
```

`YYYY` is the **generation**, shared by the five Radar: within one generation the
five speak of the same year. The count belongs to each of them and moves when its
own code moves.

### The third segment

It is not "the small release". It is **out of band and single-purpose**.

The model is iOS 11.2.6, February 2018: the Telugu character crashed any app that
received it, and eleven days after 11.2.5 Apple shipped a version containing that
fix and nothing else.

If a release carries even one thing that is not that urgency, then it is a count
and not a fix. Using the third segment for "the minor things" empties it of
meaning — which is exactly the drift the five Radar came out of on 2026-09-26,
when they found themselves at `.32`, `.12`, `.11`, `.6` and `.3` of the same
generation with that number no longer saying anything at all.

Carrying a feature and some fixes in the same count is normal and intended:
`2026.41` brings the CISA KEV source together with four resolved defects.

## The CHANGELOG is written by hand

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and is **written by hand**. git-cliff was used in the past and is not any more:
notes generated from commit messages say what changed and never why, which is the
only thing a reader is looking for.

`scripts/release.py` looks for the `## [<version>]` section and **fails before
touching anything** if it does not find it. So the entry goes in before the bump,
under a heading matching the version about to ship.

## Before releasing

- [ ] `pytest -q` — all green
- [ ] `ruff check src tests benchmarks` — clean
- [ ] `mypy src/patchradar` — clean
- [ ] `CHANGELOG.md` has the section for the version about to ship
- [ ] the tag does not exist yet: `git ls-remote --tags origin | grep <version>`
- [ ] no open critical or high security advisory
- [ ] tried on Windows and on Linux

## Releasing

```bash
# 1. Version bump (interactive: it asks for confirmation)
python scripts/bump_version.py          # the count goes up
python scripts/bump_version.py --fix    # or the third segment

# 2. Release (interactive: it asks for confirmation)
python scripts/release.py
```

`release.py` does, in this order:

1. `git push origin main`
2. `gh release create <version> --latest`, with the notes taken from the CHANGELOG
3. it stops: **`publish.yml` starts on its own** on `release: published` and
   publishes to PyPI with trusted publishing — no token to hand over

Step 3 is **irreversible**: a version on PyPI cannot be withdrawn, only marked
*yanked*. It is worth reading the CHANGELOG once more before confirming.

## Branches

`main` is the only permanent branch and is always releasable: release commits go
straight onto it. Longer or riskier work sits on short-lived branches (`feat/…`,
`fix/…`) until it is ready — that is how `feature/version-gap` stayed out of
2026.41, because it had the code and not yet a face.

There is no `develop` branch. Earlier versions of this document described one,
along with a `YYYY.MM.PATCH` versioning scheme the project has abandoned: both
were stuck at before 2026-09-26.

## Rules

- A release contains a set of changes that makes sense told together.
- No patching over: understand the defect before releasing, not after.
- The CHANGELOG is written for whoever reads it in six months, not for whoever
  has just written the code.
