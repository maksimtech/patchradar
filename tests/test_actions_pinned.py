"""Every action every workflow uses is pinned to a commit, with its full version beside it.

Until 2026-11-24, 22 uses in 8 workflows named refs that can move: `checkout@v7`,
`codeql-action@v4`, `docker/build-push-action@v7`, and `setup-python@v7.1.0`,
a full version but still a tag, which its owner can move. Whoever moves a tag
changes the code these jobs run without a pull request here: that day
`codeql-action@v4` moved to v4.39.5, released the same afternoon, which no
change in this repository had approved.

A full commit hash cannot be moved. The `# vX.Y.Z` after it says which release
it is, for a reader and for the dependency updater, which updates both together.
Each was pinned to the release its ref pointed at that day, except
codeql-action, whose v4.39.5 was younger than the 14 days a dependency waits
here: it went to v4.39.3, its newest release at least 14 days old and the one
apkradar pins. The PyPI publish action was on a commit already, but commented
`# release/v1`, a branch; it now says v1.14.3. This file is mailradar's
(alignment to apkradar, step 3).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.y*ml"))
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$", re.M)
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
# Major, minor and patch: `# v7` and `# v7.1` name lines of releases, not the one pinned
VERSION = re.compile(r"#\s*v?\d+\.\d+\.\d+\b")


def _uses(path: Path) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in USES.finditer(path.read_text(encoding="utf-8"))]


def test_there_are_workflows_to_check():
    assert len(WORKFLOWS) >= 10


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(path):
    loose = [ref for ref, _ in _uses(path) if not ref.startswith(("./", "docker://")) and not PINNED.match(ref)]
    assert loose == [], f"{path.name}: not pinned to a full commit: {loose}"


@pytest.mark.parametrize("comment,says_the_release", [
    ("# v7.0.1", True),
    ("# v1.14.3", True),
    ("# 2.1.0", True),
    ("# v7", False),          # a major is a moving tag, not a release
    ("# v7.1", False),        # nor is a minor: which patch?
    ("# release/v1", False),  # a branch
    ("", False),
])
def test_the_version_comment_names_a_full_release(comment, says_the_release):
    """The rule the Radars share is a commit plus its full version (alignment to
    apkradar, step 3): `vX.Y` names a line of releases, not the one pinned."""
    assert bool(VERSION.search(comment)) is says_the_release


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_pin_says_which_release_it_is(path):
    bare = [ref for ref, rest in _uses(path) if PINNED.match(ref) and not VERSION.search(rest)]
    assert bare == [], f"{path.name}: pinned without a '# vX.Y.Z' comment: {bare}"
