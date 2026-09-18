"""
PatchRadar — `patchradar --version`

The version string must come from `patchradar.__version__`, never from a
literal in cli.py, and `__version__` must stay in sync with pyproject.toml
(scripts/bump_version.py updates both).
"""
import tomllib
from pathlib import Path

from typer.testing import CliRunner

import patchradar
import patchradar.cli as cli

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

runner = CliRunner()


def test_version_prints_name_and_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.stdout == f"PatchRadar {patchradar.__version__}\n"


def test_version_exit_code_is_zero():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0


def test_version_is_read_from_dunder_version(monkeypatch):
    monkeypatch.setattr(patchradar, "__version__", "1999.01.1")
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout == "PatchRadar 1999.01.1\n"


def test_dunder_version_matches_pyproject():
    with PYPROJECT.open("rb") as f:
        declared = tomllib.load(f)["project"]["version"]
    assert patchradar.__version__ == declared
