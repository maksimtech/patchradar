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

KEV is 1,726 entries and a record of the past, though, so everything not on it
still came down to CVSS. EPSS closes that gap from FIRST — a forecast, which is
why it ranks below CISA having observed the exploitation and above a severity.
"""
from __future__ import annotations

import pytest

from patchradar.priority import (
    EPSS_THRESHOLD,
    RANK_EPSS,
    RANK_KEV,
    RANK_KEV_RANSOMWARE,
    RANK_SCORED,
    RANK_UNSCORED,
    merge_by_cve,
    order_by_priority,
    priority,
    sort_by_priority,
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


def epss(cve_id: str, score: float, percentile: float | None = 0.99,
         cvss: float | None = 5.0) -> dict:
    """An NVD record after `patchradar.epss.enrich` has been over it."""
    record = nvd(cve_id, cvss, "MEDIUM" if cvss else "UNKNOWN")
    record["epss_score"] = score
    if percentile is not None:
        record["epss_percentile"] = percentile
    return record


# ── the five ranks ──────────────────────────────────────────────────────────

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


# ── the forecast, between the score and the observation ─────────────────────

def test_a_likely_cve_ranks_above_a_merely_scored_one():
    assert priority(epss("CVE-2026-30001", 0.42)).rank == RANK_EPSS
    assert RANK_SCORED < RANK_EPSS < RANK_KEV


def test_an_observation_still_beats_a_forecast():
    """A 90% forecast is not a sighting, and CISA's list is sightings."""
    likely = epss("CVE-2026-30002", 0.90)
    likely["known_exploited"] = True
    assert priority(likely).rank == RANK_KEV


def test_a_low_forecast_does_not_promote_the_row():
    assert priority(epss("CVE-2026-30003", 0.004)).rank == RANK_SCORED


def test_the_threshold_is_inclusive_and_nothing_sits_either_side_of_it():
    assert priority(epss("CVE-2026-30004", EPSS_THRESHOLD)).rank == RANK_EPSS
    assert priority(epss("CVE-2026-30005", EPSS_THRESHOLD - 0.001)).rank == RANK_SCORED


def test_a_likely_cve_with_no_cvss_at_all_is_still_promoted():
    """The forecast is the fact that decided the rank; the score only breaks ties."""
    unscored = epss("CVE-2026-30006", 0.42, cvss=None)
    ranked = priority(unscored)
    assert ranked.rank == RANK_EPSS
    assert ranked.score is None


def test_a_low_forecast_is_reported_even_though_it_changed_nothing():
    """What tells a reader a 9.8 can wait for the next patch window."""
    reason = priority(epss("CVE-2026-30007", 0.0004, cvss=9.8)).reason
    assert "EPSS" in reason
    assert "9.8" in reason


def test_the_reason_gives_the_forecast_as_a_percentage_with_its_percentile():
    reason = priority(epss("CVE-2026-30008", 0.4231, 0.9712)).reason
    assert "42.3%" in reason
    assert "p97" in reason


def test_a_near_certainty_is_not_reported_as_a_certainty():
    """Log4Shell's real reading, 0.99999, which `.1f` turns into "100.0%"."""
    reason = priority(epss("CVE-2021-44228", 0.99999, 0.99997)).reason
    assert ">99.9%" in reason
    assert "100.0%" not in reason
    # And a percentile is floored, because that is what a percentile means: the
    # top 1% is p99, and there is no p100 to be in.
    assert "p99" in reason
    assert "p100" not in reason


def test_an_actual_certainty_is_still_reported_as_one():
    """Only the rounding is refused, not the value: 1.0 is a real reading."""
    assert "100.0%" in priority(epss("CVE-2026-30014", 1.0, 1.0)).reason


def test_a_record_with_no_forecast_reads_exactly_as_it_did_before():
    """The sources that predate EPSS must not have their reasons rewritten."""
    assert priority(nvd("CVE-2026-30009", 8.8)).reason == "CVSS 8.8 (v3.1), not in CISA KEV"
    assert priority(nvd("CVE-2026-30010", None, "UNKNOWN")).reason == (
        "no score from any source, not in CISA KEV"
    )


@pytest.mark.parametrize("value", [
    "0.42",      # a string: epss.py converts before it writes, so this is not ours
    1.4,         # outside the scale — clamping it would promote the row
    -0.1,
    float("nan"),
    True,        # bool is an int, and True would read as certainty
    None,
    object(),
])
def test_an_unusable_forecast_field_is_ignored_rather_than_trusted(value):
    record = nvd("CVE-2026-30011", 5.0)
    record["epss_score"] = value
    ranked = priority(record)
    assert ranked.rank == RANK_SCORED
    assert "EPSS" not in ranked.reason


def test_a_forecast_without_its_percentile_still_ranks():
    """The percentile qualifies the number for a reader; it does not decide."""
    ranked = priority(epss("CVE-2026-30012", 0.42, percentile=None))
    assert ranked.rank == RANK_EPSS
    assert "42.0%" in ranked.reason


def test_a_label_exists_for_every_rank():
    """`cli.PRIORITY_STYLES` and `RANK_LABELS` are both keyed on the ranks: a
    rank added without them raises KeyError while printing a table."""
    import patchradar.cli as cli

    for rank in (RANK_UNSCORED, RANK_SCORED, RANK_EPSS, RANK_KEV, RANK_KEV_RANSOMWARE):
        assert cli.PRIORITY_STYLES[rank] is not None
    assert priority(epss("CVE-2026-30013", 0.42)).label == "likely"


# ── ordering ────────────────────────────────────────────────────────────────

def test_a_likely_cve_outranks_a_higher_scoring_unlikely_one():
    """The gap EPSS fills: a 9.8 nobody will touch, under an 5.0 about to go."""
    quiet = nvd("CVE-QUIET", 9.8, "CRITICAL")
    likely = epss("CVE-LIKELY", 0.42, cvss=5.0)
    assert [c["id"] for c in order_by_priority([quiet, likely])] == ["CVE-LIKELY", "CVE-QUIET"]


def test_within_the_forecast_rank_the_higher_score_comes_first():
    """One measure orders one band: the probability puts the rows in the band,
    the severity orders them inside it."""
    low = epss("CVE-LOW", 0.90, cvss=4.0)
    high = epss("CVE-HIGH", 0.11, cvss=9.1)
    assert [c["id"] for c in sort_by_priority([low, high])] == ["CVE-HIGH", "CVE-LOW"]


def test_sorting_without_merging_is_available_to_the_scan():
    """`_scan_target` merges, enriches, then sorts — the enrichment needs one row
    per CVE and the sort needs the enrichment to have happened."""
    rows = [nvd("CVE-A", 4.0), nvd("CVE-B", 9.0)]
    assert [c["id"] for c in sort_by_priority(rows)] == ["CVE-B", "CVE-A"]
    assert len(sort_by_priority(rows)) == 2


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
