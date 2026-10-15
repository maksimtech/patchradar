#!/usr/bin/env python3
"""
PatchRadar — Automatic CalVer bump script
Usage: python3 scripts/bump_version.py [patch|minor]
"""

import re
import shutil
import subprocess
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path

from console_encoding import enable_utf8_output

# Same reason as in release.py: the banner and every result line below print a
# character cp1252 does not have.
enable_utf8_output()

PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"
INIT = Path(__file__).parent.parent / "src" / "patchradar" / "__init__.py"

def get_current_version() -> str:
    content = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version = "(.+)"', content, re.MULTILINE)
    if not match:
        raise ValueError("Version not found in pyproject.toml")
    return match.group(1)

def as_numbers(version: str) -> tuple[int, ...]:
    """The version as PEP 440 orders it, so two forms can be compared.

    Padding matters: 2026.7 against 2026.9.6 is (2026, 7, 0) against
    (2026, 9, 6), which is how PEP 440 reads them and why the second is the
    larger one.
    """
    return tuple(int(part) for part in version.split("."))


def is_after(candidate: str, current: str) -> bool:
    left, right = as_numbers(candidate), as_numbers(current)
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) > right + (0,) * (width - len(right))


def parse_version(version: str) -> tuple[int, int, int]:
    """(generation, count, fix).

    The generation is the year, shared with the other Radar. The count belongs
    to this one. The fix is a third segment for something urgent on top of a
    count that has already shipped — 2026.40.1 before 2026.41.

    Three segments are ambiguous for one more cycle, because the old form was
    YYYY.MONTH.PATCH and 2026.9.6 is September's sixth release rather than fix
    six of baseline nine. The baseline is 40, so a middle segment of twelve or
    less can only be a month. Whatever this decides, `is_after` is what
    actually guarantees the answer.
    """
    parts = version.split(".")
    if len(parts) == 2:
        return int(parts[0]), int(parts[1]), 0
    if len(parts) == 3:
        generation, middle, last = (int(part) for part in parts)
        if middle <= 12:
            return generation, last, 0
        return generation, middle, last
    raise ValueError(f"Cannot read a version out of: {version}")

def bump_version(current: str, fix: bool = False) -> str:
    """The next version — YYYY.COUNT, or YYYY.COUNT.FIX with fix=True.

    A new year restarts the count at one. Otherwise the number goes up and
    keeps going up until the result actually sorts after what is published:
    coming off the old scheme the month occupied the second segment, so 2026.7
    is *lower* than 2026.9.6, and a fix can never be .0 because PEP 440 reads
    2026.40.0 and 2026.40 as one version.
    """
    now = datetime.now()
    year, count, patch = parse_version(current)

    if year != now.year:
        new_version = f"{now.year}.1"
    elif fix:
        patch += 1
        while not is_after(f"{year}.{count}.{patch}", current):
            patch += 1
        new_version = f"{year}.{count}.{patch}"
    else:
        count += 1
        while not is_after(f"{year}.{count}", current):
            count += 1
        new_version = f"{year}.{count}"

    return new_version

def update_pyproject(old: str, new: str) -> None:
    content = PYPROJECT.read_text(encoding="utf-8")
    updated = content.replace(f'version = "{old}"', f'version = "{new}"')
    PYPROJECT.write_text(updated, encoding="utf-8")
    print(f"✅ pyproject.toml: {old} → {new}")

def update_init(old: str, new: str) -> None:
    content = INIT.read_text(encoding="utf-8")
    updated = content.replace(f'__version__ = "{old}"', f'__version__ = "{new}"')
    INIT.write_text(updated, encoding="utf-8")
    print(f"✅ __init__.py: {old} → {new}")


# What the gate runs. `sys.executable` rather than "python3": whoever releases is
# in a virtual environment, and that is the interpreter that has the suite.
SUITE_COMMAND = [sys.executable, "-m", "pytest", "-q"]


def check_suite(command: list | None = None, cwd=None) -> bool:
    """Whether the suite passes with the new version already written.

    True when it passes and true when there is nothing to run: a repository with no
    `tests/` is not held up by a suite it does not have. False only when a suite
    exists and fails.

    Called between writing the version and committing it. apkradar released 2026.42
    and 2026.43 with its README still naming the previous version, both times caught
    by CI on main after the tag had gone out — because a suite run before the bump
    cannot see what the bump breaks.
    """
    root = Path(cwd) if cwd else PYPROJECT.parent
    if not (root / "tests").is_dir():
        print("🧪 No tests/ directory — nothing to run")
        return True

    print("🧪 Suite, with the new version in place...")
    completed = subprocess.run(command or SUITE_COMMAND, cwd=root)
    return completed.returncode == 0


RELEASE_REPO = "maksimtech/patchradar"


def release_branch(version: str) -> str:
    return f"release/{version}"


def git_commit(version: str, files: list[str] | None = None, cwd: Path | None = None) -> None:
    """Commit the bump on release/<version>, not on main.

    Since 2026-10-12 main takes pull requests only, the owner's included: a cloud
    session had pushed straight to it with the owner's account and left it red, so
    the ruleset lost its bypass. The bump travels like any other change.
    """
    subprocess.run(["git", "switch", "-c", release_branch(version)], check=True, cwd=cwd)
    subprocess.run(["git", "add", *(files or ["pyproject.toml", str(INIT)])], check=True, cwd=cwd)
    subprocess.run(["git", "commit", "-m", f"chore: bump version to {version}"], check=True, cwd=cwd)
    print(f"✅ Git commit on {release_branch(version)}: chore: bump version to {version}")


def _github_repo(url: str) -> str | None:
    """owner/name when the remote URL points at github.com, otherwise None.

    The host and the path are read apart and compared whole: a substring test lets
    any host that mentions github.com in its path or its own name through (CodeQL
    py/incomplete-url-substring-sanitization, alert #60).
    """
    url = url.strip()
    if "://" in url:
        parts = urllib.parse.urlsplit(url)
        host, path = parts.hostname or "", parts.path
    else:
        # scp-like syntax: [user@]host:path
        scp = re.fullmatch(r"(?:[^@/:]+@)?([^@/:]+):(.+)", url)
        if not scp:
            return None
        host, path = scp.group(1).lower(), scp.group(2)
    if host != "github.com":
        return None
    path = path.strip("/")
    return path.removesuffix(".git") or None


def _origin_is_github(cwd: Path | None) -> bool:
    url = subprocess.run(
        ["git", "remote", "get-url", "origin"], capture_output=True, text=True, encoding="utf-8", check=True,
        cwd=cwd,
    ).stdout
    repo = _github_repo(url)
    return repo is not None and repo.lower() == RELEASE_REPO.lower()


def git_push(version: str, cwd: Path | None = None) -> None:
    """Push release/<version> only, back to main, and open the pull request.

    The pull request is opened with auto-merge only when origin is this repository
    on GitHub and gh is there to ask; otherwise the next step is printed.
    """
    branch = release_branch(version)
    subprocess.run(["git", "push", "-u", "origin", branch], check=True, cwd=cwd)
    subprocess.run(["git", "switch", "main"], check=True, cwd=cwd)
    print(f"✅ Pushed {branch} (main is not touched)")
    if shutil.which("gh") and _origin_is_github(cwd):
        title = f"chore: bump version to {version}"
        url = subprocess.run(
            ["gh", "pr", "create", "--repo", RELEASE_REPO, "--base", "main", "--head", branch,
             "--title", title, "--body", f"Version bump for PatchRadar {version}, made by bump_version.py."],
            capture_output=True, text=True, encoding="utf-8", check=True, cwd=cwd,
        ).stdout.strip()
        subprocess.run(["gh", "pr", "merge", url, "--auto", "--squash", "--subject", title], check=True, cwd=cwd)
        print(f"🔀 {url} will be merged when its checks pass")
    else:
        print(f"ℹ️  Open a pull request from {branch} to main.")
    print("   Once it is merged: git pull, then python scripts/release.py")

def main():
    # --fix: a third segment on the count that already shipped, for something
    # urgent. Without it the count itself goes up, which is the ordinary case.
    fix = "--fix" in sys.argv
    current = get_current_version()
    new = bump_version(current, fix=fix)

    print("\n🛡️  PatchRadar Version Bump")
    print(f"   Current: {current}")
    print(f"   New:     {new}")
    print()

    confirm = input("Proceed? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    update_pyproject(current, new)
    update_init(current, new)

    if not check_suite():
        print(
            f"\n❌ The suite fails with {new} in place. Nothing was committed:\n"
            f"   pyproject.toml and the package __init__ are left modified so you\n"
            f"   can see what broke. `git checkout` on both undoes the bump."
        )
        sys.exit(1)

    git_commit(new)

    push = input(f"Push {release_branch(new)} and open its pull request? [y/N] ").strip().lower()
    if push == "y":
        git_push(new)
    else:
        print(f"   Left on {release_branch(new)}: push it and open a pull request to main when ready.")

    print(f"\n✅ Done! Version bumped to {new}")

if __name__ == "__main__":
    main()
