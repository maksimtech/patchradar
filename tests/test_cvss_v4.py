"""CVSS v4.0: the scale this module refused to know, and the metric nobody read.

`severity_for(score, "4.0")` answered UNKNOWN by choice, with the comment saying
the honest answer was that rather than "I will use the v3 one, which looks
similar". That was right while nobody had read the specification. FIRST's v4.0
specification does publish a qualitative scale, and its boundaries are the same as
v3's — None 0.0, Low 0.1, Medium 4.0, High 7.0, Critical 9.0. So the table is
written out here because the standard says so, not because the numbers resemble
each other.

What does **not** follow is comparability. A v4.0 base score and a v3.1 base score
come from different metrics, the way v2 and v3 do, so the rule in cvss.py's
docstring still holds: never a label without its version, and never an ordering by
label.

Measured on 2026-10-02 against NVD, 200 CVEs published in the preceding week:

    cvssMetricV31   104        cvssMetricV40    24        cvssMetricV2    6

so v4.0 is 12% of recent records and rising. Two things about that block differ
from v3.1 and both matter:

- `baseSeverity` is **not** on the entry, only inside `cvssData`. A reader that
  looks only at the entry finds nothing and falls back to deriving the label from
  the score — which is where UNKNOWN surfaced.
- the vector carries `E:`, `exploitMaturity`, which is FIRST's own statement about
  whether exploitation has been seen: `A` attacked, `P` proof-of-concept, `U`
  unreported, `X` not defined. patchradar ranks by CISA KEV and by EPSS, and this
  is a third claim of the same kind from the CVE's own provider. Reading it is not
  the same as ranking on it; this file covers reading.
"""

from __future__ import annotations

import pytest

from patchradar.cvss import SEVERITIES, UNKNOWN, exploit_maturity, severity_for

# From NVD, CVE-2026-84283, 2026-10-02. E:X means the provider defined no threat
# metric, which is the common case and is not the same as "not attacked".
REAL_VECTOR = (
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    "/E:X/CR:X/IR:X/AR:X"
)


# ── the scale ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, "NONE"),
        (0.1, "LOW"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
        (10.0, "CRITICAL"),
        (6.8, "MEDIUM"),        # CVE-2026-84283, where NVD says MEDIUM too
    ],
)
def test_the_v4_scale_is_the_one_first_publishes(score, expected):
    assert severity_for(score, "4.0") == expected


def test_v4_agrees_with_nvd_on_the_record_that_was_measured():
    """NVD's own label for CVE-2026-84283 is MEDIUM at 6.8. Deriving it has to
    give the same answer, or one of the two is wrong and a report shows both."""
    assert severity_for(6.8, "4.0") == "MEDIUM"


@pytest.mark.parametrize("version", ["4.0", " 4.0 ", "4.0.0"])
def test_the_version_is_read_the_way_providers_write_it(version):
    """NVD sends "4.0". A provider writing "4.0.0" means the same scale, and
    refusing it would answer UNKNOWN for a score that has a step."""
    assert severity_for(5.0, version) == "MEDIUM"


@pytest.mark.parametrize("version", ["5.0", "4", "v4.0", "", None, "banana"])
def test_a_version_nobody_published_is_still_unknown(version):
    """The refusal this module exists for. CVSS 5.0 does not exist yet, and when
    it does its scale will be written here rather than assumed from v4's."""
    assert severity_for(5.0, version) == UNKNOWN


@pytest.mark.parametrize("score", [-0.1, 10.1, float("nan"), None, "high"])
def test_a_score_off_the_scale_is_unknown_on_v4_too(score):
    assert severity_for(score, "4.0") == UNKNOWN


def test_v4_and_v3_give_the_same_step_and_that_is_not_a_conversion():
    """The boundaries coincide with v3's; the metrics do not. A 6.8 under v4.0 and
    a 6.8 under v3.1 both read MEDIUM and are not the same measurement — which is
    why the version travels with the label everywhere it is printed."""
    assert severity_for(6.8, "4.0") == severity_for(6.8, "3.1") == "MEDIUM"


def test_v2_still_disagrees_with_v4_where_the_bands_differ():
    """9.5 is CRITICAL on v4.0 and on v3.x, and HIGH on v2, which has no
    Critical at all. The same number, two labels, both correct on their own
    scale — the measurement this module's docstring records from a real scan.

    At 6.8 all three say MEDIUM, and that agreement is a coincidence of the
    bands rather than a conversion between the metrics.
    """
    assert severity_for(9.5, "4.0") == "CRITICAL"
    assert severity_for(9.5, "2.0") == "HIGH"
    assert severity_for(6.8, "2.0") == severity_for(6.8, "4.0") == "MEDIUM"


def test_every_step_v4_can_return_is_in_the_published_palette():
    steps = {severity_for(score / 10, "4.0") for score in range(0, 101)}

    assert steps <= set(SEVERITIES)
    assert UNKNOWN not in steps


# ── the threat metric, which is a third voice on exploitation ───────────────


@pytest.mark.parametrize(
    "vector, expected",
    [
        (REAL_VECTOR, None),                                   # E:X — undefined
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/E:A", "ATTACKED"),
        ("CVSS:4.0/AV:N/AC:L/E:P", "PROOF_OF_CONCEPT"),
        ("CVSS:4.0/AV:N/AC:L/E:U", "UNREPORTED"),
        ("CVSS:4.0/AV:N/E:X", None),
    ],
)
def test_the_exploit_maturity_is_read_out_of_the_vector(vector, expected):
    assert exploit_maturity(vector) == expected


def test_undefined_is_none_and_never_unreported():
    """`E:X` means the provider said nothing; `E:U` means it said "not seen".
    Collapsing the two would turn silence into a statement, which is the
    distinction this whole tool is built around."""
    assert exploit_maturity("CVSS:4.0/AV:N/E:X") is None
    assert exploit_maturity("CVSS:4.0/AV:N/E:U") == "UNREPORTED"


def test_a_vector_with_no_threat_metric_at_all_is_none():
    assert exploit_maturity("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N") is None


@pytest.mark.parametrize(
    "vector",
    [
        None,
        "",
        "   ",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F",     # v3's E: is a different vocabulary
        "not a vector",
        "CVSS:4.0",
        "CVSS:4.0/E:Z",                                         # not a value the standard defines
    ],
)
def test_anything_that_is_not_a_v4_threat_metric_is_none(vector):
    assert exploit_maturity(vector) is None


def test_v3_exploit_codes_are_refused_rather_than_translated():
    """v3.1 used E:F (Functional) and E:H (High); v4.0 uses A, P, U. The letters
    overlap in form and not in meaning, and the vector says which version it is."""
    assert exploit_maturity("CVSS:3.1/AV:N/E:H") is None
    assert exploit_maturity("CVSS:4.0/AV:N/E:A") == "ATTACKED"
