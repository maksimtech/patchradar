"""The release goes through a pull request, the owner's included.

Since 2026-10-12 main takes nothing but pull requests: the ruleset has no bypass,
because a cloud session had pushed straight to it with the owner's account and
left it red. Until then `bump_version.py` committed the bump on main and
`release.py` began with `git push origin main`, which that rule refuses.

Now `bump_version.py` commits the bump on release/<version> and pushes that
branch, and `release.py` pushes nothing: it checks that main, as it is on the
remote, already carries the version, and creates the GitHub release on that very
commit. These cases run the real functions against a real bare repository on
disk and a clone of it; nothing of git is simulated, and GitHub is not asked,
because origin is not github.com.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import bump_version as bump  # noqa: E402
import release  # noqa: E402


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", check=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    config = tmp_path / "gitconfig"
    config.write_text(
        "[user]\n\tname = Test\n\temail = test@example.com\n"
        "[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(remote), str(work))
    (work / "pyproject.toml").write_text('[project]\nversion = "2026.46"\n', encoding="utf-8")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "initial")
    _git(work, "push", "-q", "origin", "main")
    return work, remote


# --- release.py ---------------------------------------------------------------


def test_release_pushes_nothing_and_targets_the_commit_it_checked():
    source = (SCRIPTS / "release.py").read_text(encoding="utf-8")
    assert '"git", "push"' not in source
    assert '"--target", sha' in source


def test_a_published_main_is_accepted_and_its_commit_returned(repo):
    work, remote = repo
    assert release.check_main_published(cwd=work) == _git(remote, "rev-parse", "main")


def test_an_unpushed_bump_on_main_is_refused(repo):
    """What the old flow did: a bump committed on main, waiting to be pushed."""
    work, _ = repo
    (work / "pyproject.toml").write_text('[project]\nversion = "2026.47"\n', encoding="utf-8")
    _git(work, "commit", "-q", "-am", "chore: bump version to 2026.47")
    with pytest.raises(SystemExit, match="pull request"):
        release.check_main_published(cwd=work)


def test_a_main_behind_the_remote_is_refused(repo, tmp_path):
    work, remote = repo
    other = tmp_path / "other"
    _git(tmp_path, "clone", "-q", str(remote), str(other))
    (other / "CHANGELOG.md").write_text("merged elsewhere\n", encoding="utf-8")
    _git(other, "add", ".")
    _git(other, "commit", "-q", "-m", "merged elsewhere")
    _git(other, "push", "-q", "origin", "main")
    with pytest.raises(SystemExit, match="git pull"):
        release.check_main_published(cwd=work)


def test_another_branch_or_a_dirty_tree_is_refused(repo):
    work, _ = repo
    (work / "pyproject.toml").write_text('[project]\nversion = "2026.47"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="not clean"):
        release.check_main_published(cwd=work)
    _git(work, "checkout", "-q", "--", "pyproject.toml")
    _git(work, "switch", "-q", "-c", "elsewhere")
    with pytest.raises(SystemExit, match="Not on main"):
        release.check_main_published(cwd=work)


# --- bump_version.py ------------------------------------------------------------


def test_the_bump_is_committed_on_a_release_branch_and_main_is_left_alone(repo):
    work, remote = repo
    (work / "pyproject.toml").write_text('[project]\nversion = "2026.47"\n', encoding="utf-8")

    bump.git_commit("2026.47", files=["pyproject.toml"], cwd=work)
    bump.git_push("2026.47", cwd=work)

    assert _git(remote, "log", "-1", "--format=%s", "release/2026.47") == "chore: bump version to 2026.47"
    assert _git(remote, "log", "-1", "--format=%s", "main") == "initial", "main was pushed"
    assert _git(work, "rev-parse", "--abbrev-ref", "HEAD") == "main"


# --- who opens the pull request ----------------------------------------------------
#
# The pull request is opened with gh, with auto-merge, only when origin is this
# repository on GitHub. CodeQL alert #60 (py/incomplete-url-substring-sanitization)
# was right about the first version: it asked whether "github.com" and the repository
# name occurred anywhere in the URL, which a host of anyone's choosing satisfies.
# The URLs below are set on a real clone with `git remote set-url`; git does not
# contact them to answer `git remote get-url`.


@pytest.mark.parametrize("url", [
    "https://github.com/maksimtech/patchradar.git",
    "https://github.com/maksimtech/patchradar",
    "https://GitHub.com/maksimtech/patchradar.git",
    "git@github.com:maksimtech/patchradar.git",
    "ssh://git@github.com/maksimtech/patchradar.git",
])
def test_origin_on_github_is_recognised(repo, url):
    work, _ = repo
    _git(work, "remote", "set-url", "origin", url)
    assert bump._origin_is_github(work)


@pytest.mark.parametrize("url", [
    "https://evil.example/github.com/maksimtech/patchradar.git",
    "https://github.com.evil.example/maksimtech/patchradar.git",
    "https://evil.example/?github.com/maksimtech/patchradar",
    "git@evil.example:github.com/maksimtech/patchradar.git",
    "https://github.com/maksimtech/patchradar-fork.git",
    "https://github.com/someone/maksimtech/patchradar.git",
    "https://github.com/someone-else/patchradar.git",
])
def test_origin_that_only_mentions_github_is_not_trusted(repo, url):
    work, _ = repo
    _git(work, "remote", "set-url", "origin", url)
    assert not bump._origin_is_github(work)


def test_a_local_origin_is_not_github(repo):
    work, remote = repo
    assert _git(work, "remote", "get-url", "origin") == str(remote)
    assert not bump._origin_is_github(work)
