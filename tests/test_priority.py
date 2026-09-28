"""
PatchRadar — what to look at first, and why it is not the CVSS score.

Measured on a real machine on 2026-09-26: ordering 695 matched CVEs by CVSS put
five 10.0 entries on top, none of them being exploited, while the four listed in
CISA KEV scored 9.8, 8.8, 8.6 and 7.8 — below all five. The operational question
is "what is being used against me now", not "how bad would it be".

2026.41 added the KEV collector, so the fact is in the scan. Nothing reads it:
the report prints what the sources returned, in the order the fan-out happened.

The other half is the merge. `_scan_target` concatenates three collectors and
de-duplicates nothing, so a CVE that NVD scored and CISA lists arrives twice:
once with a score and no exploitation, once exploited with `severity: UNKNOWN`.
Ranking that list without merging first produces two rows for one CVE, ranked
differently, and neither of them is right.
"""
from __future__ import annotations

import pytest

from patchradar.priority import (
    RANK_KEV,
    RANK_KEV_RANSOMWARE,
    RANK_SCORED,
    RANK_UNSCORED,
    merge_by_cve,
    order_by_priority,
    priority,
)


def nvd(cve_id: str, score: float | None = 7.5, severity: str = "HIGH") -> dict:
    return {
        "id": cve_id, "software": "chrome", "description": "from NVD",
        "cvss_score": score, "cvss_version": "3.1", "severity": severity,
        "published_at": "2026-09-01T00:00:00Z", "source": "NVD",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def kev(cve_id: str, *, ransomware: bool = False, added: str = "2026-09-09") -> dict:
    """A record shaped like `collectors.kev._to_record` builds it."""
    return {
        "id": cve_id, "software": "chrome", "description": "from CISA",
        "cvss_score": None, "cvss_version": None, "severity": "UNKNOWN",
        "published_at": added, "source": "CISA KEV",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "known_exploited": True, "kev_date_added": added,
        "kev_due_date": "2026-09-23", "kev_ransomware": ransomware,
    }


# ── the four ranks ──────────────────────────────────────────────────────────

def test_exploited_in_ransomware_campaigns_ranks_highest():
    assert priority(kev("CVE-2026-59310", ransomware=True)).rank == RANK_KEV_RANSOMWARE


def test_exploited_ranks_above_scored():
    assert priority(kev("CVE-2026-87491")).rank == RANK_KEV
    assert RANK_KEV > RANK_SCORED


def test_a_score_is_worth_more_than_no_score():
    assert priority(nvd("CVE-2026-77901", 8.8)).rank == RANK_SCORED
    assert priority(nvd("CVE-2026-19137", None, "UNKNOWN")).rank == RANK_UNSCORED


def test_the_reason_names_the_fact_that_decided_the_rank():
    """A rank without its reason is a number to be taken on trust."""
    assert "ransomware" in priority(kev("CVE-1", ransomware=True)).reason.lower()
    assert "kev" in priority(kev("CVE-2")).reason.lower()
    assert "8.8" in priority(nvd("CVE-3", 8.8)).reason
    assert priority(nvd("CVE-4", None, "UNKNOWN")).reason


def test_the_kev_date_travels_in_the_reason():
    """Exploited since when is what decides whether this is already overdue."""
    assert "2026-08-18" in priority(kev("CVE-5", added="2026-08-18")).reason


# ── the trap CISA sets ──────────────────────────────────────────────────────

def test_the_string_unknown_is_not_a_ransomware_yes():
    """CISA writes "Known" and "Unknown", never a boolean, and
    `bool("Unknown")` is True. `collectors.kev` converts it; a record reaching
    here from anywhere else may still carry the string, and truthiness on it
    would promote 1,610 of the 1,726 catalogue entries to the top rank."""
    raw = kev("CVE-6")
    raw["kev_ransomware"] = "Unknown"
    assert priority(raw).rank == RANK_KEV

    known = kev("CVE-7")
    known["kev_ransomware"] = "Known"
    assert priority(known).rank == RANK_KEV_RANSOMWARE


def test_exploitation_is_not_inferred_from_the_source_name():
    """A record whose source string happens to mention CISA, without the fact,
    is not evidence of exploitation."""
    pretender = nvd("CVE-8")
    pretender["source"] = "CISA KEV"
    assert priority(pretender).rank == RANK_SCORED


# ── ordering ────────────────────────────────────────────────────────────────

def test_an_exploited_cve_without_a_score_outranks_a_ten():
    """The measurement of 2026-09-26, in one assertion."""
    ten = nvd("CVE-2026-10000", 10.0, "CRITICAL")
    exploited = kev("CVE-2026-87491")

    assert order_by_priority([ten, exploited])[0]["id"] == "CVE-2026-87491"


def test_within_one_rank_the_higher_score_comes_first():
    low, high = nvd("CVE-LOW", 4.0, "MEDIUM"), nvd("CVE-HIGH", 9.1, "CRITICAL")
    assert [c["id"] for c in order_by_priority([low, high])] == ["CVE-HIGH", "CVE-LOW"]


def test_ordering_is_stable_for_equals():
    """Two runs over the same scan must print the same report, or a diff of the
    two means nothing."""
    first, second = nvd("CVE-A", None, "UNKNOWN"), nvd("CVE-B", None, "UNKNOWN")
    assert [c["id"] for c in order_by_priority([first, second])] == ["CVE-A", "CVE-B"]


def test_ordering_merges_first():
    """One CVE, one row — otherwise the same id is ranked twice, differently."""
    ordered = order_by_priority([nvd("CVE-2026-87491", 6.5), kev("CVE-2026-87491")])
    assert len(ordered) == 1
    assert ordered[0]["cvss_score"] == 6.5
    assert ordered[0]["known_exploited"] is True


# ── the merge ───────────────────────────────────────────────────────────────

def test_the_score_survives_the_merge_and_so_does_the_exploitation():
    merged = merge_by_cve([nvd("CVE-2026-87491", 8.8), kev("CVE-2026-87491")])

    assert len(merged) == 1
    row = merged[0]
    assert row["cvss_score"] == 8.8
    assert row["severity"] == "HIGH"
    assert row["known_exploited"] is True
    assert row["kev_due_date"] == "2026-09-23"


def test_unknown_severity_never_overwrites_a_real_one():
    """KEV states no severity and says so with "UNKNOWN". Letting it win would
    erase a score a scoring body actually assigned."""
    merged = merge_by_cve([kev("CVE-9"), nvd("CVE-9", 9.8, "CRITICAL")])
    assert merged[0]["severity"] == "CRITICAL"
    assert merged[0]["cvss_score"] == 9.8


def test_the_merged_row_names_every_source_that_spoke():
    """A row that two sources agreed on must not be reported as one source's
    finding: the provenance is what a reader checks."""
    merged = merge_by_cve([nvd("CVE-10"), kev("CVE-10")])
    assert merged[0]["source"] == "NVD, CISA KEV"


def test_ids_differing_only_in_case_are_the_same_cve():
    merged = merge_by_cve([nvd("CVE-2026-1"), kev("cve-2026-1")])
    assert len(merged) == 1
    assert merged[0]["id"] == "CVE-2026-1", "the first spelling is kept"


def test_the_order_of_first_appearance_is_kept():
    merged = merge_by_cve([nvd("CVE-B"), nvd("CVE-A"), kev("CVE-B")])
    assert [row["id"] for row in merged] == ["CVE-B", "CVE-A"]


def test_a_field_absent_from_both_stays_absent():
    """The merge combines what the sources said; it does not fill in defaults.
    A `known_exploited: False` invented here would be indistinguishable from
    CISA having been consulted and having said no."""
    merged = merge_by_cve([nvd("CVE-11")])
    assert "known_exploited" not in merged[0]
    assert "kev_due_date" not in merged[0]


def test_a_longer_description_is_not_preferred_over_the_first_one():
    """Nothing here judges prose. The first source to describe the CVE keeps the
    description, so the same scan always reads the same way."""
    second = kev("CVE-12")
    second["description"] = "a much longer description from the other source"
    assert merge_by_cve([nvd("CVE-12"), second])[0]["description"] == "from NVD"


def test_merging_an_empty_scan_is_an_empty_scan():
    assert merge_by_cve([]) == []
    assert order_by_priority([]) == []


def test_a_record_without_an_id_is_kept_rather_than_merged_into_the_others():
    """An id-less record cannot be identified with any other, and dropping it
    would silently reduce the count the scan reports."""
    blank = nvd("")
    merged = merge_by_cve([nvd("CVE-13"), blank])
    assert len(merged) == 2


# ── the sort key ────────────────────────────────────────────────────────────

def test_the_sentinel_score_never_leaves_the_sort():
    """An absent score must not become 0.0 anywhere a reader can see it: that
    reads as a measured bottom of scale. It may only exist inside the key."""
    row = nvd("CVE-14", None, "UNKNOWN")
    assert priority(row).score is None
    assert order_by_priority([row])[0]["cvss_score"] is None


@pytest.mark.parametrize("score", [0.0, 10.0])
def test_the_extremes_of_the_scale_are_scores_like_any_other(score):
    """CVSS 0.0 is a measurement — "None" severity — not a missing value."""
    assert priority(nvd("CVE-15", score)).rank == RANK_SCORED
