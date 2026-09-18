"""
PatchRadar — SonarCloud coverage contract (W9)

sonar-project.properties had `sonar.coverage.exclusions=**/*`, which removes
every file from coverage: SonarCloud showed no coverage at all and its quality
gate could never flag untested new code. The Sonar workflow did not produce a
coverage report either, so dropping the exclusion alone would have turned
"excluded" into "0 %".

The fix: the workflow runs the suite with pytest-cov and writes coverage.xml
before the scan, Sonar is pointed at it, and the exclusion is narrowed to what
has no Python coverage report (the page's JS and HTML, which are exercised by
the Node harness instead).
"""
import os
import re
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROPERTIES = REPO / "sonar-project.properties"
WORKFLOW = REPO / ".github" / "workflows" / "sonarcloud.yml"
PYPROJECT = REPO / "pyproject.toml"


def sonar_properties() -> dict[str, str]:
    props = {}
    for line in PROPERTIES.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
    return props


def sonar_glob(pattern: str) -> re.Pattern:
    """Sonar wildcard: ** = any directories, * = anything but '/', ? = one char."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out + r"\Z")


def coverage_exclusions() -> list[re.Pattern]:
    raw = sonar_properties().get("sonar.coverage.exclusions", "")
    return [sonar_glob(p.strip()) for p in raw.split(",") if p.strip()]


def python_sources() -> list[str]:
    return sorted(p.relative_to(REPO).as_posix() for p in (REPO / "src").rglob("*.py"))


# ─── the properties ─────────────────────────────────────────────────────────

def test_glob_helper_matches_like_sonar():
    assert sonar_glob("**/*").match("src/patchradar/cli.py")
    assert sonar_glob("src/patchradar/api/static/**").match("src/patchradar/api/static/app.js")
    assert not sonar_glob("src/patchradar/api/static/**").match("src/patchradar/api/main.py")
    assert not sonar_glob("*.py").match("src/patchradar/cli.py")


def test_no_python_source_is_excluded_from_coverage():
    excluded = [f for f in python_sources() if any(p.match(f) for p in coverage_exclusions())]
    assert excluded == [], f"excluded from Sonar coverage: {excluded}"


def test_sonar_reads_a_python_coverage_report():
    assert sonar_properties().get("sonar.python.coverage.reportPaths") == "coverage.xml"


# ─── the workflow produces that report before scanning ──────────────────────

def test_workflow_generates_coverage_before_the_scan():
    text = WORKFLOW.read_text()
    scan = text.find("sonarqube-scan-action")
    run = re.search(r"pytest\b[^\n]*--cov\b[^\n]*--cov-report[= ]xml(?::coverage\.xml)?(?=\s|$)", text)
    assert run, "the Sonar workflow never runs pytest with an XML coverage report"
    assert scan != -1 and run.start() < scan, "coverage.xml must exist before the scan step"


def test_workflow_installs_the_dev_group():
    """pytest-cov lives in the dev dependency group."""
    assert re.search(r"pip install --group dev", WORKFLOW.read_text())


def test_workflow_does_not_fail_the_scan_on_a_red_suite_silently():
    """A failing suite must fail the job, not upload a partial report."""
    text = WORKFLOW.read_text()
    line = re.search(r"^.*pytest\b.*--cov.*$", text, re.M).group(0)
    assert "|| true" not in line and "continue-on-error" not in text


# ─── the report's paths resolve against sonar.sources ───────────────────────

def test_coverage_uses_relative_paths():
    """Absolute paths in coverage.xml only resolve if the scanner runs in the
    exact same directory; relative ones resolve against the checkout."""
    run = tomllib.loads(PYPROJECT.read_text())["tool"]["coverage"]["run"]
    assert run.get("relative_files") is True


def test_generated_report_points_at_real_source_files(tmp_path):
    report = tmp_path / "coverage.xml"
    subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "tests/test_date_ordering.py", "--cov", f"--cov-report=xml:{report}"],
        cwd=REPO, check=True, capture_output=True, timeout=120,
        # keep the data file out of the checkout
        env={**os.environ, "COVERAGE_FILE": str(tmp_path / ".coverage")},
    )
    root = ET.parse(report).getroot()
    sources = [s.text for s in root.iter("source")]
    files = [c.get("filename") for c in root.iter("class")]
    assert files, "coverage.xml lists no files"
    for name in files:
        candidates = [REPO / name] + [REPO / s / name for s in sources if not Path(s).is_absolute()]
        assert any(c.is_file() for c in candidates), f"{name} does not resolve under {sources}"
        assert not Path(name).is_absolute()
    assert all(not Path(s).is_absolute() for s in sources), sources
    # Sonar resolves each filename against the <source> entries
    resolved = {(REPO / s / n).resolve() for s in sources for n in files if (REPO / s / n).is_file()}
    assert (REPO / "src/patchradar/db/database.py").resolve() in resolved
