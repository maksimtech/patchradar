#!/usr/bin/env python3
"""
PatchRadar — Automatic release script
Usage: python3 scripts/release.py
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from console_encoding import enable_utf8_output

# Before the first print, not inside main(): the banner below carries an emoji
# and a Windows console encodes with cp1252.
enable_utf8_output()

REPO_ROOT = Path(__file__).parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"

CHANGELOG_FILE = "CHANGELOG.md"
CHANGELOG_PATH = REPO_ROOT / CHANGELOG_FILE


def get_current_version() -> str:
    content = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version = "(.+)"', content, re.MULTILINE)
    if not match:
        raise ValueError("Version not found in pyproject.toml")
    return match.group(1)


def extract_release_notes(version: str) -> str:
    """Return just this version's section of the changelog.

    The changelog is written by hand (Keep a Changelog): git-cliff used to
    regenerate it here, which both destroyed the hand-written text and, because
    it ran before `gh release create` made the tag, filed every release under
    "Unreleased". Release notes are now the one relevant section rather than
    the whole file.
    """
    content = CHANGELOG_PATH.read_text(encoding="utf-8")
    match = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
        content,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise SystemExit(
            f"No '## [{version}]' section in {CHANGELOG_FILE}.\n"
            f"Write the changelog entry before releasing."
        )
    # Drop the trailing '---' separator between sections.
    return re.sub(r"\n-{3,}\s*$", "", match.group(1).strip()).strip()

def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=True, **kwargs)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", check=True
    ).stdout.strip()


def check_main_published(cwd: Path = REPO_ROOT) -> str:
    """The commit the release is made from: main, as the remote has it.

    Since 2026-10-12 main takes pull requests only, the owner's included, so this
    script no longer pushes it: the version bump reaches main through the pull
    request bump_version.py opens. What is checked here is that the local main is
    that main, clean and neither ahead nor behind, and its commit is returned so
    that the GitHub release is made on exactly it rather than on whatever main is
    by the time GitHub reads the request.
    """
    branch = _git(cwd, "rev-parse", "--abbrev-ref", "HEAD")
    if branch != "main":
        raise SystemExit(f"Not on main (current branch: {branch})")
    if _git(cwd, "status", "--porcelain"):
        raise SystemExit("Working tree not clean: commit or discard the changes first")
    _git(cwd, "fetch", "--quiet", "origin", "main")
    head = _git(cwd, "rev-parse", "HEAD")
    if head == _git(cwd, "rev-parse", "origin/main"):
        return head
    ahead = int(_git(cwd, "rev-list", "--count", "origin/main..HEAD"))
    if ahead:
        raise SystemExit(
            f"main has {ahead} commit(s) the remote does not: main takes pull requests only, "
            f"so the bump has to arrive through its pull request (python scripts/bump_version.py)"
        )
    raise SystemExit("main is behind the remote: git pull, then run this again")

def main():
    version = get_current_version()
    # Fail before anything is created if the entry is missing.
    notes = extract_release_notes(version)

    print("\n🛡️  PatchRadar Release")
    print(f"   Version: {version}")
    print(f"   Notes:   {CHANGELOG_FILE} § [{version}] ({len(notes.splitlines())} lines)")
    print("\nThis will:")
    print(f"  1. Check that main, as the remote has it, carries {version}")
    print(f"  2. Create GitHub release {version} on that commit")
    print("  3. GitHub Actions publishes to PyPI automatically")
    print()

    confirm = input("Proceed? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    sha = check_main_published()
    print(f"\n🚀 Creating GitHub release {version} on {sha[:12]}...")
    with tempfile.NamedTemporaryFile(
        "w", suffix=".md", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(notes)
        notes_path = handle.name
    try:
        run([
            "gh", "release", "create", version,
            "--target", sha,
            "--title", version,
            "--notes-file", notes_path,
            "--latest"
        ])
    finally:
        os.unlink(notes_path)

    print(f"\n✅ Release {version} created!")
    print("   Check: https://github.com/maksimtech/patchradar/actions")

if __name__ == "__main__":
    main()
