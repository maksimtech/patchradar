"""
PatchRadar — "is the version I have affected, and where is it fixed?"

The data is already in the NVD payload the scan downloads, in the `cpeMatch`
nodes of `configurations`, and nothing reads it: `grep configurations src/`
returns nothing. A scan can say a CVE mentions Notepad++ and cannot say whether
8.9.8 is one of the versions it affects.

Every shape below was observed on the real payloads (Notepad++, QTS 5.1.0):

    versionEndExcluding: 8.9.6.4                       fixed in 8.9.6.4
    versionEndIncluding: 8.5.6                         last affected 8.5.6
    versionStartIncluding 8.9.4 + EndExcluding 8.9.6   8.9.4 <= v < 8.9.6
    criteria ...:notepad\\+\\+:8.9.3:*:*                that version only
    vulnerable: false                                  not an affected entry

The distinction the honesty of the whole answer rests on: `versionEndExcluding`
**is** the fixed version — NVD states there is nothing from X on. Deducing
"fixed in 8.5.7" from `versionEndIncluding: 8.5.6` would invent a release number
no source published, so `fixed_version` stays None and the note says what is
actually known.
"""
from __future__ import annotations

import pytest

from patchradar.affected import Range, affects, ranges_in, summarise, target_version

VENDOR = "notepad-plus-plus"
# The product field as NVD really writes it. CPE 2.3 requires the special
# characters to be escaped, so the field holds `notepad\+\+` and the API answers
# 404 to the unescaped spelling. Using the readable name here would make every
# test below agree with itself and with nothing else.
PRODUCT = "notepad\\+\\+"
DISPLAY_NAME = "Notepad++"


def match(**kwargs) -> dict:
    """One `cpeMatch` node. `vulnerable` defaults to what NVD sets on an
    affected entry, so a test that means the opposite has to say so."""
    version = kwargs.pop("version", "*")
    node = {
        "vulnerable": kwargs.pop("vulnerable", True),
        "criteria": f"cpe:2.3:a:{kwargs.pop('vendor', VENDOR)}:"
                    f"{kwargs.pop('product', PRODUCT)}:{version}:*:*:*:*:*:*:*",
    }
    node.update(kwargs)
    return node


def cve(cve_id: str, *matches, score: float | None = 7.8, version: str = "3.1",
        severity: str | None = "HIGH", published: str = "2026-05-04T00:00:00.000") -> dict:
    metrics: dict = {}
    if score is not None:
        entry: dict = {"cvssData": {"baseScore": score, "version": version}}
        if severity is not None:
            entry["baseSeverity"] = severity
        metrics = {"cvssMetricV31": [entry]}
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "descriptions": [{"lang": "en", "value": f"description of {cve_id}"}],
            "metrics": metrics,
            "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}],
        }
    }


def payload(*items) -> dict:
    return {"vulnerabilities": list(items)}


# ── the four shapes ─────────────────────────────────────────────────────────

def test_end_excluding_is_the_fixed_version():
    """CVE-2026-52885 on the real payload: `versionEndExcluding: 8.9.6.4`."""
    hits = affects(payload(cve("CVE-2026-52885", match(versionEndExcluding="8.9.6.4"))),
                   version="8.9.5", vendor=VENDOR, cpe_product=PRODUCT)

    assert len(hits) == 1
    assert hits[0].fixed_version == "8.9.6.4"
    assert "8.9.6.4" in hits[0].note


def test_end_including_names_the_last_affected_and_no_fix():
    """CVE-2023-40031: `versionEndIncluding: 8.5.6`. The release that fixed it
    exists and NVD does not name it; inventing 8.5.7 here would be a number no
    source published."""
    hits = affects(payload(cve("CVE-2023-40031", match(versionEndIncluding="8.5.6"))),
                   version="8.5.0", vendor=VENDOR, cpe_product=PRODUCT)

    assert hits[0].fixed_version is None
    assert "8.5.6" in hits[0].note
    assert "does not" in hits[0].note.lower() or "not stated" in hits[0].note.lower()


def test_a_start_and_an_end_bound_the_affected_versions():
    """CVE-2026-46710: 8.9.4 <= v < 8.9.6."""
    node = match(versionStartIncluding="8.9.4", versionEndExcluding="8.9.6")
    data = payload(cve("CVE-2026-46710", node))

    assert affects(data, version="8.9.5", vendor=VENDOR, cpe_product=PRODUCT)
    assert affects(data, version="8.9.4", vendor=VENDOR, cpe_product=PRODUCT), "start is inclusive"
    assert not affects(data, version="8.9.6", vendor=VENDOR, cpe_product=PRODUCT), "end is exclusive"
    assert not affects(data, version="8.9.3", vendor=VENDOR, cpe_product=PRODUCT)


def test_a_version_in_the_criteria_affects_only_that_version():
    data = payload(cve("CVE-2026-1", match(version="8.9.3")))

    assert affects(data, version="8.9.3", vendor=VENDOR, cpe_product=PRODUCT)
    assert not affects(data, version="8.9.4", vendor=VENDOR, cpe_product=PRODUCT)


def test_a_wildcard_version_with_no_bounds_affects_every_version():
    """`criteria ...:*:*` with no range is NVD saying "all of them"."""
    data = payload(cve("CVE-2026-2", match(version="*")))
    assert affects(data, version="1.0", vendor=VENDOR, cpe_product=PRODUCT)
    assert affects(data, version="99.9", vendor=VENDOR, cpe_product=PRODUCT)


# ── what must not be counted ────────────────────────────────────────────────

def test_a_node_that_is_not_vulnerable_is_not_a_hit():
    """CVE-2017-8803: the Notepad++ node carries `vulnerable: false` because it
    describes the context in which another component is vulnerable. Counting it
    reports a CVE that does not concern the program."""
    data = payload(cve("CVE-2017-8803", match(version="*", vulnerable=False)))
    assert affects(data, version="7.3.3", vendor=VENDOR, cpe_product=PRODUCT) == []


def test_another_vendor_of_the_same_program_is_not_this_one():
    """NVD holds both `notepad-plus-plus:notepad++` (21 CVEs) and
    `don_ho:notepad++` (one, from 2014, under the author's name). Whoever asks
    for one must not silently receive the other's."""
    data = payload(cve("CVE-2014-1", match(vendor="don_ho", version="*")))
    assert affects(data, version="6.5", vendor=VENDOR, cpe_product=PRODUCT) == []
    assert affects(data, version="6.5", vendor="don_ho", cpe_product=PRODUCT)


def test_the_product_filter_is_the_cpe_field_not_the_display_name():
    """Passing "Notepad++" where `notepad\\+\\+` belongs raises nothing and
    returns zero results, which reads as "no vulnerabilities". It caught the
    prototype, and it caught this module the first time it met the real payload:
    21 CVEs in, zero out, because the test fixtures spelled the field the way a
    person writes it."""
    data = payload(cve("CVE-2026-3", match(version="*")))
    assert affects(data, version="8.9.5", vendor=VENDOR, cpe_product=DISPLAY_NAME) == []
    assert affects(data, version="8.9.5", vendor=VENDOR, cpe_product=PRODUCT)


def test_one_cve_is_counted_once_even_when_two_nodes_match():
    data = payload(cve("CVE-2026-4",
                       match(versionEndExcluding="9.0"),
                       match(versionStartIncluding="8.0", versionEndExcluding="8.9.9")))
    assert len(affects(data, version="8.5.0", vendor=VENDOR, cpe_product=PRODUCT)) == 1


def test_an_incomparable_version_is_not_a_match_and_not_an_error():
    """'2010' against a four-component build is not a question with a wrong
    answer, it is a question with no meaning. Office writes versions like
    16.0.14334.20918 and some installers write a year."""
    data = payload(cve("CVE-2026-5", match(versionEndExcluding="16.0.14334.20906")))
    assert affects(data, version="2010", vendor=VENDOR, cpe_product=PRODUCT) == []


def test_a_version_that_is_not_a_version_is_not_a_match():
    data = payload(cve("CVE-2026-6", match(versionEndExcluding="8.9.6")))
    for nonsense in ("", "*", "-", "unknown", "5, 1, 2, 3000"):
        assert affects(data, version=nonsense, vendor=VENDOR, cpe_product=PRODUCT) == []


# ── the score ───────────────────────────────────────────────────────────────

def test_the_severity_is_derived_when_the_payload_omits_it():
    """Some entries carry `baseScore` without `baseSeverity`. `cvss.severity_for`
    is the one place that maps a score to a step, and it knows the two scales
    are different."""
    data = payload(cve("CVE-2026-7", match(version="*"), score=9.8, severity=None))
    hit = affects(data, version="1.0", vendor=VENDOR, cpe_product=PRODUCT)[0]
    assert hit.severity == "CRITICAL"


def test_a_v2_score_is_read_on_the_v2_scale():
    """7.0 is HIGH on v2 and HIGH on v3 — but 9.0 is HIGH on v2 and CRITICAL on
    v3, and the scales are not convertible."""
    data = payload(cve("CVE-2026-8", match(version="*"), score=9.0, version="2.0", severity=None))
    hit = affects(data, version="1.0", vendor=VENDOR, cpe_product=PRODUCT)[0]
    assert hit.severity == "HIGH"


def test_an_unscored_cve_is_still_a_hit():
    """No score is not no vulnerability. It is the state 708 of the 806 Chrome
    CVEs were in."""
    data = payload(cve("CVE-2026-9", match(version="*"), score=None))
    hits = affects(data, version="1.0", vendor=VENDOR, cpe_product=PRODUCT)
    assert len(hits) == 1
    assert hits[0].score is None
    assert hits[0].severity == "UNKNOWN"


def test_the_worst_comes_first_and_the_unscored_last():
    data = payload(cve("CVE-LOW", match(version="*"), score=4.0),
                   cve("CVE-NONE", match(version="*"), score=None),
                   cve("CVE-HIGH", match(version="*"), score=9.1))
    order = [h.cve for h in affects(data, version="1.0", vendor=VENDOR, cpe_product=PRODUCT)]
    assert order == ["CVE-HIGH", "CVE-LOW", "CVE-NONE"]


# ── where to go ─────────────────────────────────────────────────────────────

def test_the_target_is_the_highest_declared_fix():
    data = payload(cve("CVE-A", match(versionEndExcluding="8.9.6")),
                   cve("CVE-B", match(versionEndExcluding="8.9.6.4")),
                   cve("CVE-C", match(versionEndIncluding="8.5.6")))
    hits = affects(data, version="8.5.0", vendor=VENDOR, cpe_product=PRODUCT)
    assert target_version(hits) == "8.9.6.4"


def test_there_is_no_target_when_no_source_declares_one():
    hits = affects(payload(cve("CVE-D", match(versionEndIncluding="8.5.6"))),
                   version="8.5.0", vendor=VENDOR, cpe_product=PRODUCT)
    assert target_version(hits) is None


def test_the_summary_says_how_many_the_update_closes_and_how_many_it_does_not():
    """"6 of 10" is the sentence that matters: the other four stay open because
    NVD does not state where they were fixed, not because the update is
    insufficient."""
    data = payload(cve("CVE-A", match(versionEndExcluding="8.9.6"), score=7.8),
                   cve("CVE-B", match(versionEndExcluding="8.9.6.4"), score=7.5),
                   cve("CVE-C", match(versionEndIncluding="8.5.6"), score=6.1))
    summary = summarise(data, version="8.5.0", vendor=VENDOR, cpe_product=PRODUCT)

    assert summary.total == 3
    assert summary.target == "8.9.6.4"
    assert summary.closed_by_target == 2
    assert summary.unresolved == 1
    assert summary.worst == 7.8


def test_a_clean_version_is_not_reported_as_absolution():
    """Notepad++ 8.9.8 has zero CVEs in NVD and five vulnerabilities the author
    declared in the 8.9.8.1 release notes, none with an identifier. A summary
    that reads "no known vulnerabilities" says something no source supports."""
    summary = summarise(payload(cve("CVE-E", match(versionEndExcluding="8.9.6"))),
                        version="8.9.8", vendor=VENDOR, cpe_product=PRODUCT)

    assert summary.total == 0
    assert summary.target is None
    assert "nvd" in summary.caveat.lower()
    assert summary.caveat, "zero must carry the reason it is not an all-clear"


# ── the ranges themselves ───────────────────────────────────────────────────

def test_ranges_are_read_from_every_configuration_node():
    """A CVE can carry several configurations, and the affected range may be in
    any of them."""
    item = cve("CVE-F", match(versionEndExcluding="8.0"))
    item["cve"]["configurations"].append(
        {"nodes": [{"cpeMatch": [match(versionStartIncluding="9.0", versionEndExcluding="9.5")]}]}
    )
    assert len(ranges_in(item["cve"], vendor=VENDOR, cpe_product=PRODUCT)) == 2


def test_a_payload_without_configurations_yields_nothing_rather_than_raising():
    assert ranges_in({"id": "CVE-G"}, vendor=VENDOR) == []
    assert affects({"vulnerabilities": [{"cve": {"id": "CVE-G"}}]},
                   version="1.0", vendor=VENDOR) == []


def test_the_range_describes_itself_in_the_terms_nvd_used():
    assert "8.9.3" in Range(exact="8.9.3").describe()
    assert "<" in Range(end="8.9.6", end_inclusive=False).describe()
    assert "<=" in Range(end="8.5.6", end_inclusive=True).describe()
    assert ">=" in Range(start="8.9.4").describe()


@pytest.mark.parametrize("version", ["8.9.6", "8.9.7", "9.0"])
def test_at_or_above_the_fix_is_not_affected(version):
    data = payload(cve("CVE-H", match(versionEndExcluding="8.9.6")))
    assert affects(data, version=version, vendor=VENDOR, cpe_product=PRODUCT) == []
