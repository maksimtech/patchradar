"""
PatchRadar — CLI rendering of severity and score (W1, W3)

* W1 — `cve.get("severity", "UNKNOWN").upper()`: the default only applies when
  the key is absent. The column is nullable, so a row with severity NULL raised
  AttributeError and took `patchradar status` down with it.
* W3 — `f"{score:.1f}" if score else "N/A"`: 0.0 is falsy, so a genuine CVSS
  score of zero was shown as "N/A", indistinguishable from "no score at all".
  A score arriving as a string raised ValueError on the format spec.

Both bugs were duplicated in _print_cves and _print_cves_table.
"""
from io import StringIO

import pytest
from rich.console import Console

import patchradar.cli as cli


def render(fn, *args) -> str:
    buf = StringIO()
    original = cli.console
    cli.console = Console(file=buf, width=300, force_terminal=False)
    try:
        fn(*args)
    finally:
        cli.console = original
    return buf.getvalue()


def row(**overrides):
    cve = {"id": "CVE-2026-0001", "software": "nginx", "description": "d",
           "cvss_score": 5.0, "severity": "MEDIUM", "source": "NVD"}
    cve.update(overrides)
    return cve


RENDERERS = [
    pytest.param(lambda cves: cli._print_cves("nginx", cves), id="_print_cves"),
    pytest.param(cli._print_cves_table, id="_print_cves_table"),
]


# ─── W1: severity ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("renderer", RENDERERS)
@pytest.mark.parametrize("severity", [None, "", 42])
def test_missing_or_odd_severity_does_not_crash(renderer, severity):
    out = render(renderer, [row(severity=severity)])
    assert "UNKNOWN" in out


@pytest.mark.parametrize("renderer", RENDERERS)
def test_absent_severity_key_shows_unknown(renderer):
    cve = row()
    del cve["severity"]
    assert "UNKNOWN" in render(renderer, [cve])


@pytest.mark.parametrize("value, expected", [
    ("critical", "CRITICAL"), ("High", "HIGH"), (None, "UNKNOWN"),
    ("", "UNKNOWN"), (7, "UNKNOWN"), ("banana", "BANANA"),
])
def test_normalise_severity(value, expected):
    assert cli._normalise_severity(value) == expected


# ─── W3: score ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value, expected", [
    (0.0, "0.0"),        # the bug: a real zero shown as N/A
    (0, "0.0"),
    (9.8, "9.8"),
    (10, "10.0"),
    (None, "N/A"),
    ("7.5", "7.5"),      # numeric string: used to raise ValueError
    ("n/a", "N/A"),
    ("", "N/A"),
    (True, "N/A"),       # bool is an int subclass; not a score
    (float("nan"), "N/A"),
])
def test_format_score(value, expected):
    assert cli._format_score(value) == expected


@pytest.mark.parametrize("renderer", RENDERERS)
def test_zero_score_is_rendered_as_zero(renderer):
    out = render(renderer, [row(cvss_score=0.0)])
    assert "0.0" in out
    assert "N/A" not in out


@pytest.mark.parametrize("renderer", RENDERERS)
def test_missing_score_is_rendered_as_na(renderer):
    assert "N/A" in render(renderer, [row(cvss_score=None)])


@pytest.mark.parametrize("renderer", RENDERERS)
def test_string_score_does_not_crash(renderer):
    assert "7.5" in render(renderer, [row(cvss_score="7.5")])
