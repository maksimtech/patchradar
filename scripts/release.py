#!/usr/bin/env python3
"""
PatchRadar — Automatic release script
Usage: python3 scripts/release.py
"""

import re
import sys
import subprocess
from pathlib import Path

PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"

CHANGELOG_FILE = CHANGELOG_FILE


def get_current_version() -> str:
    content = PYPROJECT.read_text()
    match = re.search(r'^version = "(.+)"', content, re.MULTILINE)
    if not match:
        raise ValueError("Version not found in pyproject.toml")
    return match.group(1)

def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=True, **kwargs)

def main():
    version = get_current_version()

    print(f"\n🛡️  PatchRadar Release")
    print(f"   Version: {version}")
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

    # Genera CHANGELOG automaticamente
    print("\n📝 Generating CHANGELOG.md...")
    run(["git", "cliff", "--output", CHANGELOG_FILE])
    run(["git", "add", CHANGELOG_FILE])
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        capture_output=True
    )
    if result.returncode != 0:
        run(["git", "commit", "-m", "docs: update CHANGELOG"])
        run(["git", "push", "origin", "main"])

    print(f"\n🚀 Creating GitHub release {version}...")
    run([
        "gh", "release", "create", version,
        "--title", version,
        "--notes-file", CHANGELOG_FILE,
        "--latest"
    ])

    print(f"\n✅ Release {version} created!")
    print(f"   Check: https://github.com/maksimtech/patchradar/actions")

if __name__ == "__main__":
    main()
