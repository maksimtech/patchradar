"""The qualitative CVSS scales, as FIRST publishes them.

Two scales, not one, and they are **not convertible**: v2 and v3 are different
metrics and FIRST publishes no conversion table between them. So a score without
its version has no step, and this module says so instead of picking one.

    CVSS v3.x and v4.0               CVSS v2
        None      0.0                    Low       0.0 - 3.9
        Low       0.1 - 3.9              Medium    4.0 - 6.9
        Medium    4.0 - 6.9              High      7.0 - 10.0
        High      7.0 - 8.9
        Critical  9.0 - 10.0

v4.0 shares those boundaries, and shares them *by specification*: FIRST publishes
the same qualitative scale for it, which is why the table above has two headings
and not three. What v4.0 does not share is the metric underneath — a 6.8 under
v4.0 and a 6.8 under v3.1 are different measurements that happen to land in the
same band, exactly as 10.0 under v2 and under v3 are different measurements that
do not.

The difference shows in the data. Among the 695 CVEs measured on a real machine
on 2026-09-26, `CVE-2014-0566 10.0 HIGH` (v2) and `CVE-2018-4872 10.0 CRITICAL`
(v3) sit side by side: two 10.0s with different labels, both correct on their own
scale. A rule follows for anyone displaying this data: **never a label without
its version beside it, and never an ordering by label.**
"""
from __future__ import annotations

import math
import re

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

# v4.0 is tabulated here because FIRST's v4.0 specification publishes this scale,
# not because it resembles v3's. "4.0.0" is accepted alongside "4.0": NVD sends
# the short form, and a provider writing the long one means the same scale — while
# answering UNKNOWN for it would hide a step that exists.
_SCALES = {"2.0": _V2, "3.0": _V3, "3.1": _V3, "4.0": _V3, "4.0.0": _V3}

# ─── the threat metric, which is a third voice on exploitation ───────────────
#
# v4.0 carries `E:` in the vector, `exploitMaturity`, and it is FIRST's own
# statement about whether exploitation has been seen:
#
#     E:A   attacked — exploitation has been observed
#     E:P   a proof of concept is public
#     E:U   unreported — no exploitation and no public proof of concept
#     E:X   not defined, which is the common case and says nothing at all
#
# patchradar already ranks by CISA KEV (observed) and by EPSS (forecast). This is
# a third claim of the same kind, from the CVE's own provider, and reading it is
# not the same as ranking on it: where a provider's E:A belongs against CISA's
# catalogue is a decision, not a parse.
#
# v3.1 also had an `E:` with the values U/P/F/H, a different vocabulary for the
# same letter. The prefix of the vector says which version is speaking, and this
# reads v4.0 only — translating F into one of v4's three would be inventing a
# claim nobody made.
_V4_PREFIX = "CVSS:4.0/"
_EXPLOIT_MATURITY = {"A": "ATTACKED", "P": "PROOF_OF_CONCEPT", "U": "UNREPORTED"}
_E_METRIC = re.compile(r"(?:^|/)E:([A-Z])(?:/|$)")


def exploit_maturity(vector: str | None) -> str | None:
    """What a v4.0 vector says about exploitation, or None if it says nothing.

    None covers three different silences on purpose — no vector, no `E:` metric,
    and `E:X` — because none of them is a statement. `E:U` *is* a statement, that
    the provider looked and saw nothing, and it comes back as UNREPORTED.
    """
    if not isinstance(vector, str):
        return None
    text = vector.strip()
    if not text.startswith(_V4_PREFIX):
        return None
    found = _E_METRIC.search(text[len(_V4_PREFIX):])
    if found is None:
        return None
    return _EXPLOIT_MATURITY.get(found.group(1))


def severity_for(score: float | None, cvss_version: str | None) -> str:
    """The qualitative step of `score` on the scale of `cvss_version`.

    UNKNOWN when the score is missing, when it falls outside 0-10, or when the
    version is not one of those tabulated here. v4.0 was in that last case until
    2026-10-02, with the comment saying the honest answer was UNKNOWN rather than
    "I will use the v3 one, which looks similar" — right, until somebody read the
    specification. FIRST publishes the same qualitative boundaries for v4.0, so it
    is tabulated now because the standard says so.

    A version nobody has published is still UNKNOWN, and that is the point of the
    table: CVSS 5.0 will have its scale written here rather than inherited from
    v4's.
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
