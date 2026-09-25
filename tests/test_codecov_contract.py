"""The coverage upload, and its three silent failures.

Added on 2026-09-25, when only apkradar was sending coverage anywhere. The three
ways this arrangement breaks without reddening anything:

* no XML is produced, and the upload step sends a file that is not there;
* an XML is produced at one path and another is uploaded;
* the step is guarded to a Python version the matrix does not contain, so it
  never runs.

`fail_ci_if_error: false` is deliberate — a failed upload loses a metric and does
not invalidate a suite that just passed — and it is exactly what makes all three
invisible. Hence these.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEST_WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"


@pytest.fixture(scope="module")
def workflow() -> str:
    return TEST_WORKFLOW.read_text(encoding="utf-8")


def test_the_suite_writes_a_coverage_report(workflow):
    assert "--cov-report=xml" in workflow, "no XML is produced, so nothing can be uploaded"


def test_the_file_uploaded_is_the_file_written(workflow):
    """A path typo here reads as zero coverage, not as a broken upload."""
    written = re.search(r"--cov-report=xml(?::(\S+))?", workflow)
    assert written, "no XML report is written"
    produced = written.group(1) or "coverage.xml"

    uploaded = re.search(r"^\s*files?:\s*(\S+)", workflow, re.MULTILINE)
    assert uploaded, "the upload step names no file"
    assert uploaded.group(1) == produced


def test_the_upload_runs_once_on_a_version_the_matrix_has(workflow):
    import yaml

    parsed = yaml.safe_load(workflow)
    versions = {
        str(version)
        for job in parsed["jobs"].values()
        for version in (job.get("strategy", {}).get("matrix", {}).get("python-version") or [])
    }

    guard = re.search(r"matrix\.python-version\s*==\s*'([^']+)'", workflow)
    assert guard, "the upload is not guarded to a single matrix entry"
    assert guard.group(1) in versions, (
        f"the upload is pinned to Python {guard.group(1)}, absent from {sorted(versions)}"
    )


def test_the_upload_is_given_a_token(workflow):
    """Codecov wants one even for a public repository; without it the upload is
    rejected, and quietly."""
    assert "CODECOV_TOKEN" in workflow


def test_the_coverage_is_measured_on_this_package(workflow):
    assert "--cov=patchradar" in workflow
