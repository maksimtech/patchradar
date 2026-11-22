"""The Python versions the suite runs on are the ones the package claims.

test.yml listed its matrix with nothing tying it to the classifiers in
pyproject.toml, and nothing checked the `-dev` row either: when 3.15.0 went
final on 2026-10-09 the classifiers still stopped at 3.14 and 3.15 was still the
row allowed to fail, with no test to say so. The same tests exist in apkradar
(tests/test_ci_dependencies.py), whose matrix the other Radars follow.

The classifiers are the versions the package says it supports, and the matrix
is where that is checked, so the two are one list. One more row runs the version
after the last stable one, from its development branch, and may fail. A new
Python goes final every October (PEP 602), and a dependency without a wheel for
it should turn up there before the classifier promises it.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TEST_WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
PYPROJECT = ROOT / "pyproject.toml"
CLASSIFIED = re.compile(r"^Programming Language :: Python :: (3\.\d+)$")


def _classified_versions() -> list[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    found = [m.group(1) for c in data["project"]["classifiers"] if (m := CLASSIFIED.match(c))]
    assert found, "pyproject.toml names no Python version"
    return found


def _test_job() -> dict:
    return yaml.safe_load(TEST_WORKFLOW.read_text(encoding="utf-8"))["jobs"]["test"]


def _next_minor(version: str) -> str:
    major, minor = version.split(".")
    return f"{major}.{int(minor) + 1}"


def test_the_suite_runs_on_every_version_the_classifiers_claim_and_no_other():
    matrix = _test_job()["strategy"]["matrix"]
    # str(): an unquoted 3.10 reaches here as the float 3.1, and is then the
    # version the classifier does not name, which is the right outcome.
    assert [str(v) for v in matrix["python-version"]] == _classified_versions()
    assert matrix.get("experimental") == [False], "the stable rows have to say they are not experimental"


def test_the_next_python_runs_as_a_row_that_may_fail():
    job = _test_job()
    stable = _classified_versions()
    rows = [row for row in job["strategy"]["matrix"].get("include", []) if row.get("experimental") is True]

    assert rows == [{"python-version": f"{_next_minor(stable[-1])}-dev", "experimental": True}], (
        f"the experimental row is the version after {stable[-1]}, from its development branch"
    )
    assert job.get("continue-on-error") == "${{ matrix.experimental }}", (
        "the experimental row has to be allowed to fail, and the stable rows must not be"
    )


def test_each_row_reports_under_a_name_the_ruleset_can_require():
    """The ruleset of main requires the stable rows by name, "Tests (Python
    3.11)" and so on, as in every Radar. Without a job name GitHub reports the
    raw matrix values, "test (3.11, false)", and a renamed row is a required
    check that never arrives."""
    assert _test_job()["name"] == "Tests (Python ${{ matrix.python-version }})"
