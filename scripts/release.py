#!/usr/bin/env python3
"""
PatchRadar — Automatic release script
Usage: python3 scripts/release.py
"""

import os
import re
import sys
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"

CHANGELOG_FILE = "CHANGELOG.md"
CHANGELOG_PATH = REPO_ROOT / CHANGELOG_FILE


def get_current_version() -> str:
    content = PYPROJECT.read_text()
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

def main():
    version = get_current_version()
    # Fail before anything is pushed if the entry is missing.
    notes = extract_release_notes(version)

    print(f"\n🛡️  PatchRadar Release")
    print(f"   Version: {version}")
    print(f"   Notes:   {CHANGELOG_FILE} § [{version}] ({len(notes.splitlines())} lines)")
    print(f"\nThis will:")
    print(f"  1. Push main to remote")
    print(f"  2. Create GitHub release {version}")
    print(f"  3. GitHub Actions publishes to PyPI automatically")
    print()

    confirm = input("Proceed? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    print("\n📤 Pushing to remote...")
    run(["git", "push", "origin", "main"])

    print(f"\n🚀 Creating GitHub release {version}...")
    with tempfile.NamedTemporaryFile(
        "w", suffix=".md", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(notes)
        notes_path = handle.name
    try:
        run([
            "gh", "release", "create", version,
            "--title", version,
            "--notes-file", notes_path,
            "--latest"
        ])
    finally:
        os.unlink(notes_path)

    print(f"\n✅ Release {version} created!")
    print(f"   Check: https://github.com/maksimtech/patchradar/actions")

if __name__ == "__main__":
    main()
