"""
PatchRadar — the qualitative CVSS scales, as FIRST publishes them

Two scales, not one, and they do not convert into one another: they are different
metrics and FIRST publishes no conversion table.

CVSS v3.x (specification, section 5)  CVSS v2 (guide, section 2.3)
    None      0.0                         Low       0.0 – 3.9
    Low       0.1 – 3.9                   Medium    4.0 – 6.9
    Medium    4.0 – 6.9                   High      7.0 – 10.0
    High      7.0 – 8.9
    Critical  9.0 – 10.0

The difference is not academic. Among the 695 CVEs measured on a real machine on
2026-09-26, these sit side by side:

    CVE-2014-0566   10.0  HIGH        v2
    CVE-2018-4872   10.0  CRITICAL    v3

Two 10.0s with different labels, both correct. Whoever orders by label puts a
9.8 CRITICAL above a 10.0 HIGH.
"""
import pytest

from patchradar.cvss import SEVERITIES, severity_for

# ── v3.x: the five steps and their bounds ───────────────────────────────────

@pytest.mark.parametrize("score, expected", [
    (0.0, "NONE"),
    (0.1, "LOW"), (3.9, "LOW"),
    (4.0, "MEDIUM"), (6.9, "MEDIUM"),
    (7.0, "HIGH"), (8.9, "HIGH"),
    (9.0, "CRITICAL"), (10.0, "CRITICAL"),
])
def test_v3_scale(score, expected):
    assert severity_for(score, "3.1") == expected
    assert severity_for(score, "3.0") == expected


def test_zero_is_none_not_low():
    """The defect this module fixes.

    `msrc._score_to_severity` returned LOW for 0.0, while v3 starts at 0.1 and
    reserves NONE for zero. No test pinned the wrong behaviour.
    """
    assert severity_for(0.0, "3.1") == "NONE"


# ── v2: three steps, and no Critical ────────────────────────────────────────

@pytest.mark.parametrize("score, expected", [
    (0.0, "LOW"), (3.9, "LOW"),
    (4.0, "MEDIUM"), (6.9, "MEDIUM"),
    (7.0, "HIGH"), (10.0, "HIGH"),
])
def test_v2_scale(score, expected):
    assert severity_for(score, "2.0") == expected


def test_v2_has_no_critical():
    """v2 calls everything from 7.0 to 10.0 High.

    Applying the v3 thresholds to a v2 score would promote some thirty entries in
    the data of 2026-09-26 to CRITICAL, giving them a severity their own standard
    does not provide for.
    """
    assert severity_for(10.0, "2.0") == "HIGH"
    assert "CRITICAL" not in {severity_for(s / 10, "2.0") for s in range(0, 101)}


def test_the_same_score_differs_between_versions():
    """The observed case: two 10.0s, two labels, both right."""
    assert severity_for(10.0, "2.0") == "HIGH"
    assert severity_for(10.0, "3.1") == "CRITICAL"


# ── what cannot be said ─────────────────────────────────────────────────────

@pytest.mark.parametrize("score", [None, -0.1, 10.1, float("nan")])
def test_a_score_outside_the_scale_is_unknown(score):
    """Outside the range there is no step, and inventing one would be worse than
    admitting it."""
    assert severity_for(score, "3.1") == "UNKNOWN"


@pytest.mark.parametrize("version", [None, "", "4.0", "boh"])
def test_an_unknown_cvss_version_is_unknown(version):
    """Without knowing WHICH scale, a score has no step.

    v4.0 is left out deliberately: it has its own scale, and until that is written
    here the honest answer is UNKNOWN rather than "I will use the v3 one, which
    looks similar".
    """
    assert severity_for(7.5, version) == "UNKNOWN"


def test_severities_are_the_ones_the_ui_knows():
    """A step the interface does not colour comes out white and goes unnoticed."""
    from patchradar.cli import SEVERITY_STYLES
    assert set(SEVERITIES) <= set(SEVERITY_STYLES)
