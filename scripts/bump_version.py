#!/usr/bin/env python3
"""
PatchRadar — Automatic CalVer bump script
Usage: python3 scripts/bump_version.py [patch|minor]
"""

import re
import sys
import subprocess
from datetime import datetime
from pathlib import Path

PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"

def get_current_version() -> str:
    content = PYPROJECT.read_text()
    match = re.search(r'^version = "(.+)"', content, re.MULTILINE)
    if not match:
        raise ValueError("Version not found in pyproject.toml")
    return match.group(1)

def parse_calver(version: str) -> tuple[int, int, int]:
    """Parse YYYY.M.PATCH from version string."""
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid CalVer format: {version}")
    return int(parts[0]), int(parts[1]), int(parts[2])

def bump_version(current: str) -> str:
    """Bump CalVer version — YYYY.MM.PATCH"""
    now = datetime.now()
    year, month, patch = parse_calver(current)

    if year == now.year and month == now.month:
        # Same month — bump patch
        new_version = f"{now.year}.{now.month}.{patch + 1}"
    else:
        # New month — reset patch to 1
        new_version = f"{now.year}.{now.month}.1"

    return new_version

def update_pyproject(old: str, new: str) -> None:
    content = PYPROJECT.read_text()
    updated = content.replace(f'version = "{old}"', f'version = "{new}"')
    PYPROJECT.write_text(updated)
    print(f"✅ pyproject.toml: {old} → {new}")

def git_commit(version: str) -> None:
    subprocess.run(["git", "add", "pyproject.toml"], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"chore: bump version to {version}"],
        check=True
    )
    print(f"✅ Git commit: chore: bump version to {version}")

def git_push() -> None:
    subprocess.run(["git", "push"], check=True)
    print("✅ Pushed to remote")

def main():
    current = get_current_version()
    new = bump_version(current)

    print(f"\n🛡️  PatchRadar Version Bump")
    print(f"   Current: {current}")
    print(f"   New:     {new}")
    print()

    confirm = input("Proceed? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    update_pyproject(current, new)
    git_commit(new)

    push = input("Push to remote? [y/N] ").strip().lower()
    if push == "y":
        git_push()

    print(f"\n✅ Done! Version bumped to {new}")
    print(f"   Next: create release {new} on GitHub")

if __name__ == "__main__":
    main()
