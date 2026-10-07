"""What PatchRadar says it is, wherever it says it.

The tagline called it "Realtime CVE intelligence", in pyproject (so on PyPI), on the
image label (so on Docker Hub), at the top of `patchradar --help` and in the package
docstring. Nothing in it runs on its own: a scan happens when one is started, from the
CLI or the web UI, and the README already says so. A description is a claim about the
product, and this one was the first a reader met and the one that was not true.

The word is checked in every tracked file rather than in the four places it used to
be, because the next copy of a tagline goes somewhere new. Two exceptions, each named:
the CHANGELOG entries already released, which record what was shipped and are not
rewritten; and Windows Defender's own `RealTimeProtectionEnabled`, which the inventory
script reads and reports under that name — a property of Defender, not a claim about
PatchRadar.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchradar.cli import app as cli_app

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
DOCKERFILE = ROOT / "Dockerfile"
CHANGELOG = "CHANGELOG.md"
THIS_FILE = Path(__file__).resolve().relative_to(ROOT).as_posix()

# "Realtime", "real-time", "real time", "real_time", across a line break too.
CLAIM = re.compile(r"real[\s_-]*time", re.IGNORECASE)

# Text that names someone else's real-time feature, by file. Removed before the search.
NOT_A_CLAIM = {
    "src/patchradar/data/inventory.ps1": ("RealTimeProtectionEnabled", "realTime "),
}

DESCRIPTION_LABEL = re.compile(
    r'^\s*LABEL\s+org\.opencontainers\.image\.description="([^"]*)"', re.MULTILINE
)


def _pyproject_description() -> str:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["description"]


def _image_description() -> str:
    found = DESCRIPTION_LABEL.search(DOCKERFILE.read_text(encoding="utf-8"))
    assert found, "the Dockerfile has no org.opencontainers.image.description label"
    return found.group(1)


def _tracked_files() -> list[str]:
    try:
        listed = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout: there is no list of tracked files to sweep")
    return [name for name in listed.decode("utf-8").split("\0") if name]


def _unreleased(changelog: str) -> str:
    """Only the part of the changelog that has not shipped yet."""
    found = re.search(r"^## \[Unreleased\].*?(?=^## \[)", changelog, re.MULTILINE | re.DOTALL)
    return found.group(0) if found else ""


def test_the_package_description_does_not_claim_realtime():
    assert not CLAIM.search(_pyproject_description()), _pyproject_description()


def test_the_image_description_does_not_claim_realtime():
    assert not CLAIM.search(_image_description()), _image_description()


def test_the_cli_help_does_not_claim_realtime():
    result = CliRunner().invoke(cli_app, ["--help"])
    assert result.exit_code == 0, result.output
    assert not CLAIM.search(result.output), result.output


def test_the_package_and_the_image_describe_the_same_product():
    assert _image_description() == _pyproject_description()


def test_no_tracked_file_describes_the_product_as_realtime():
    offenders = []
    for name in _tracked_files():
        if name == THIS_FILE:
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        if name == CHANGELOG:
            text = _unreleased(text)
        for allowed in NOT_A_CLAIM.get(name, ()):
            text = text.replace(allowed, "")
        offenders += [f"{name}: {line.strip()}" for line in text.splitlines() if CLAIM.search(line)]
    assert offenders == []


def test_the_exceptions_still_have_something_to_except():
    """An exception for text that is gone would quietly widen the sweep's blind spot."""
    for name, allowed in NOT_A_CLAIM.items():
        text = (ROOT / name).read_text(encoding="utf-8")
        for literal in allowed:
            assert literal in text, f"{name} no longer contains {literal!r}"


def test_the_sweep_finds_the_word_in_its_spellings():
    for spelling in ("Realtime", "real-time", "REAL TIME", "real_time", "real\ntime"):
        assert CLAIM.search(f"PatchRadar: {spelling} CVE intelligence"), spelling
    assert not CLAIM.search("CVE intelligence for your software stack")
