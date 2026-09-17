"""
PatchRadar — Debian urgency mapping (L5)

The mapping table was keyed on Debian *BTS bug severities* (grave, serious,
important, moderate, critical) rather than Debian *security tracker urgencies*.
Sampling the live tracker shows the field only ever takes these six values:

    not yet assigned   62927
    unimportant        11869
    low                 4979
    medium              1205
    high                 313
    end-of-life           29

So `high` and `medium` — the two that actually matter — fell through to
UNKNOWN, which hid them from the CRITICAL/HIGH filters and from the severity
chart. None of the five keys the table did contain ever occur.
"""
import httpx
import pytest
import respx

from patchradar.collectors.debian import _urgency_to_severity, fetch_cves

DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"

# Every value the Debian security tracker emits, sampled from the live feed.
REAL_TRACKER_URGENCIES = {
    "not yet assigned",
    "unimportant",
    "low",
    "medium",
    "high",
    "end-of-life",
}

# Debian BTS bug severities — a different vocabulary entirely. The tracker's
# `urgency` field never contains these.
BTS_BUG_SEVERITIES = {"critical", "grave", "serious", "important", "normal", "minor", "wishlist"}


@pytest.mark.parametrize(
    "urgency, expected",
    [
        ("high", "HIGH"),
        ("medium", "MEDIUM"),
        ("low", "LOW"),
        ("unimportant", "LOW"),
        ("end-of-life", "LOW"),
        ("not yet assigned", "UNKNOWN"),
    ],
)
def test_real_urgencies_map_correctly(urgency, expected):
    assert _urgency_to_severity(urgency) == expected


def test_every_real_urgency_is_handled():
    """No value the tracker actually emits may fall through by accident."""
    unhandled = {
        u for u in REAL_TRACKER_URGENCIES - {"not yet assigned"}
        if _urgency_to_severity(u) == "UNKNOWN"
    }
    assert not unhandled, f"real tracker urgencies falling through to UNKNOWN: {sorted(unhandled)}"


@pytest.mark.parametrize("urgency", ["HIGH", "High", "MeDiUm"])
def test_mapping_is_case_insensitive(urgency):
    assert _urgency_to_severity(urgency) in {"HIGH", "MEDIUM"}


@pytest.mark.parametrize("urgency", [None, "", "  ", "banana"])
def test_unknown_or_missing_urgency_is_unknown(urgency):
    """Must degrade to UNKNOWN rather than raise — the feed is untrusted."""
    assert _urgency_to_severity(urgency) == "UNKNOWN"


def test_mapping_does_not_use_bts_bug_severities():
    """Guard against the original confusion creeping back in."""
    from patchradar.collectors import debian

    keys = set(debian.URGENCY_TO_SEVERITY)
    bogus = keys & BTS_BUG_SEVERITIES
    assert not bogus, (
        f"{sorted(bogus)} are Debian BTS bug severities, not tracker urgencies; "
        "they can never match and mislead the next reader"
    )
    assert keys <= REAL_TRACKER_URGENCIES, (
        f"unknown keys in the urgency table: {sorted(keys - REAL_TRACKER_URGENCIES)}"
    )


# ─── end to end through the collector ────────────────────────────────────────

def tracker_payload(urgency):
    return {
        "nginx": {
            "CVE-2026-0001": {
                "description": "test",
                "releases": {"trixie": {"status": "open", "urgency": urgency}},
            }
        }
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "urgency, expected",
    [("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW"), ("not yet assigned", "UNKNOWN")],
)
async def test_collector_reports_real_severity(urgency, expected):
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json=tracker_payload(urgency)))
        cves = await fetch_cves("nginx")
    assert len(cves) == 1
    assert cves[0]["severity"] == expected


@pytest.mark.asyncio
async def test_high_urgency_cve_is_visible_to_the_high_filter():
    """The user-visible consequence: a high-urgency CVE must reach the filter."""
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json=tracker_payload("high")))
        cves = await fetch_cves("nginx")
    high = [c for c in cves if c["severity"].upper() in {"CRITICAL", "HIGH"}]
    assert high, "a high-urgency Debian CVE is invisible to the HIGH severity filter"


@pytest.mark.asyncio
async def test_null_urgency_does_not_crash_the_collector():
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json=tracker_payload(None)))
        cves = await fetch_cves("nginx")
    assert cves[0]["severity"] == "UNKNOWN"
