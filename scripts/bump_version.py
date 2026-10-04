#!/usr/bin/env python3
"""
PatchRadar — Automatic CalVer bump script
Usage: python3 scripts/bump_version.py [patch|minor]
"""

import re
import subprocess
import sys
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


def git_commit(version: str) -> None:
    subprocess.run(["git", "add", "pyproject.toml", str(INIT)], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"chore: bump version to {version}"],
        check=True
    )
    print(f"✅ Git commit: chore: bump version to {version}")

def git_push() -> None:
    subprocess.run(["git", "push"], check=True)
    print("✅ Pushed to remote")

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

    push = input("Push to remote? [y/N] ").strip().lower()
    if push == "y":
        git_push()

    print(f"\n✅ Done! Version bumped to {new}")
    print(f"   Next: create release {new} on GitHub")

if __name__ == "__main__":
    main()
