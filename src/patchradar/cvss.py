"""The qualitative CVSS scales, as FIRST publishes them.

Two scales, not one, and they are **not convertible**: v2 and v3 are different
metrics and FIRST publishes no conversion table between them. So a score without
its version has no step, and this module says so instead of picking one.

    CVSS v3.x                        CVSS v2
        None      0.0                    Low       0.0 - 3.9
        Low       0.1 - 3.9              Medium    4.0 - 6.9
        Medium    4.0 - 6.9              High      7.0 - 10.0
        High      7.0 - 8.9
        Critical  9.0 - 10.0

The difference shows in the data. Among the 695 CVEs measured on a real machine
on 2026-09-26, `CVE-2014-0566 10.0 HIGH` (v2) and `CVE-2018-4872 10.0 CRITICAL`
(v3) sit side by side: two 10.0s with different labels, both correct on their own
scale. A rule follows for anyone displaying this data: **never a label without
its version beside it, and never an ordering by label.**
"""
from __future__ import annotations

import math

UNKNOWN = "UNKNOWN"

# Every step this module can return, UNKNOWN included. It exists to keep the
# interface palette in step: a step with no colour comes out white and cannot be
# told apart from any other row.
SEVERITIES = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", UNKNOWN)

# Thresholds as inclusive LOWER bounds, worst first. Written this way rather than
# as intervals because the specification's upper bounds (3.9, 6.9, 8.9) are an
# artefact of decimal notation: the real boundary is the next step.
_V3 = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"), (0.0, "NONE"))

# v2 has no Critical and its Low starts at 0.0: there is no "None".
_V2 = ((7.0, "HIGH"), (4.0, "MEDIUM"), (0.0, "LOW"))

_SCALES = {"2.0": _V2, "3.0": _V3, "3.1": _V3}


def severity_for(score: float | None, cvss_version: str | None) -> str:
    """The qualitative step of `score` on the scale of `cvss_version`.

    UNKNOWN when the score is missing, when it falls outside 0-10, or when the
    version is not one of those tabulated here. v4.0 falls into that last case
    deliberately: it has a scale of its own, and until that is written above, the
    honest answer is UNKNOWN rather than "I will use the v3 one, which looks
    similar".
    """
    scale = _SCALES.get(str(cvss_version or "").strip())
    if scale is None:
        return UNKNOWN
    try:
        value = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return UNKNOWN
    if math.isnan(value) or not (0.0 <= value <= 10.0):
        return UNKNOWN
    for threshold, label in scale:
        if value >= threshold:
            return label
    return UNKNOWN
