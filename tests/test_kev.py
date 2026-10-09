"""
PatchRadar — CISA KEV collector

KEV answers a question none of the other sources answer: not "how bad would this
be" but "is it being exploited right now". The catalogue is small (1,726 entries
on 2026-09-25 against NVD's hundreds of thousands) precisely because it only
lists what has been observed in the wild.

Measured on a real machine on 2026-09-26: of 695 CVEs matched against installed
software, ordering by CVSS put five 10.0 entries on top, **none** of which were
exploited, while the four that were in KEV scored 9.8, 8.8, 8.6 and 7.8 — below
all five. That is what this collector is for.

The fixture is recorded from the live catalogue (version 2026.09.25), not
written by hand: a hand-made one collates the shape I imagine rather than the
shape CISA publishes.
"""
import json
import pathlib

import httpx
import pytest
import respx

from patchradar.collectors import kev
from patchradar.collectors.errors import CollectorError

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "kev_sample.json").read_text(encoding="utf-8")
)


@pytest.fixture(autouse=True)
def _reset_kev_cache(kev_offline_by_default):
    """Undo the suite-wide empty catalogue: this file is about fetching one.

    The dependency on `kev_offline_by_default` is what makes the order
    deterministic — both are autouse, and without it whichever ran last would
    decide whether the cache held an empty catalogue or nothing at all.
    """
    kev.clear_cache()
    yield
    kev.clear_cache()


def _mock(payload=FIXTURE, status=200):
    return respx.get(kev.KEV_URL).mock(return_value=httpx.Response(status, json=payload))


# ── selezione per parola chiave ──────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_keyword_matches_the_product():
    _mock()
    results = await kev.fetch_cves("acrobat")
    assert {r["id"] for r in results} == {"CVE-2021-21017", "CVE-2023-26369"}


@pytest.mark.asyncio
@respx.mock
async def test_keyword_matches_the_vendor_too():
    """`vendorProject` is where 'Oracle' lives; the product is 'Java SE'.

    A watchlist entry is as likely to name the vendor as the product, and
    searching only one of the two silently halves the catalogue.
    """
    _mock()
    results = await kev.fetch_cves("oracle")
    assert [r["id"] for r in results] == ["CVE-2015-2590"]


@pytest.mark.asyncio
@respx.mock
async def test_matching_ignores_case():
    _mock()
    assert await kev.fetch_cves("ADOBE") == await kev.fetch_cves("adobe")


@pytest.mark.asyncio
@respx.mock
async def test_no_match_is_an_empty_list():
    _mock()
    assert await kev.fetch_cves("nothing-called-this") == []


# ── what the collector must not invent ───────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_does_not_invent_a_severity():
    """KEV states no severity, so this collector must not supply one.

    Mapping "exploited" to CRITICAL is tempting and wrong: it manufactures a
    score CISA never gave, and it would then be indistinguishable from a CVSS
    that a scoring body actually assigned. The exploitation fact travels in
    `known_exploited`, where nothing can mistake it for a severity.
    """
    _mock()
    for r in await kev.fetch_cves("adobe"):
        assert r["cvss_score"] is None
        assert r["cvss_version"] is None
        assert r["severity"] == "UNKNOWN"


@pytest.mark.asyncio
@respx.mock
async def test_ransomware_unknown_is_not_true():
    """CISA writes the string "Unknown", which is truthy.

    `bool("Unknown")` is True, so a naive pass-through marks every entry as
    ransomware-linked — 1,610 of the 1,726 in the live catalogue.
    """
    _mock()
    entry = next(r for r in await kev.fetch_cves("acrobat") if r["id"] == "CVE-2021-21017")
    assert entry["kev_ransomware"] is False


@pytest.mark.asyncio
@respx.mock
async def test_ransomware_known_is_true():
    _mock()
    known = next(v for v in FIXTURE["vulnerabilities"]
                 if v["knownRansomwareCampaignUse"] == "Known")
    # Asked for by its vendor, as a watchlist would: "" used to stand for "every
    # entry" only because the match was a substring, and "" is a substring of
    # anything. A keyword is a word now, and no product is called nothing.
    entry = next(r for r in await kev.fetch_cves(known["vendorProject"]) if r["id"] == known["cveID"])
    assert entry["kev_ransomware"] is True


# ── an entry without a usable id ─────────────────────────────────────────────
# CISA has never published one, so the catalogue below is derived from the
# recording rather than recorded: `kev_sample_unusable_ids.json` is
# `kev_sample.json` with three `cveID`s spoiled, and its `_derived` key says
# which and how.

UNUSABLE_IDS = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "kev_sample_unusable_ids.json").read_text(encoding="utf-8")
)


def test_the_derived_catalogue_differs_from_the_recording_only_where_it_says():
    derived = json.loads(json.dumps(UNUSABLE_IDS))
    assert "CVE-2015-2590" in derived.pop("_derived")
    entries = {e["vendorProject"] + " " + e["product"] + " " + e["dateAdded"]: e
               for e in derived["vulnerabilities"]}
    entries["Oracle Java SE 2022-03-03"]["cveID"] = "CVE-2015-2590"
    entries["Adobe Acrobat and Reader 2021-11-03"]["cveID"] = "CVE-2021-21017"
    entries["Broadcom VMware vCenter 2026-08-18"]["cveID"] = "CVE-2026-59310"
    # The key order of the restored entry is not part of the comparison.
    assert derived == FIXTURE


def test_an_entry_without_a_cve_id_is_dropped():
    """An entry with no `cveID` became a record with id '' — the database's
    primary key, colliding with every other id-less record. NVD and MSRC drop
    theirs; KEV has to do the same."""
    assert kev.filter_catalogue(UNUSABLE_IDS, "oracle") == []


def test_an_entry_with_an_unusable_id_drops_itself_not_its_neighbours():
    """A blank id drops its own entry and leaves the other Adobe one in place;
    an id that is not a string at all goes the same way."""
    assert [r["id"] for r in kev.filter_catalogue(UNUSABLE_IDS, "adobe")] == ["CVE-2023-26369"]
    assert kev.filter_catalogue(UNUSABLE_IDS, "vcenter") == []


# ── the shape of a record, shared with the other collectors ──────────────────

@pytest.mark.asyncio
@respx.mock
async def test_record_shape_matches_the_other_collectors():
    """The API merges sources by key, so a missing key is a KeyError in prod."""
    _mock()
    common = {"id", "software", "description", "cvss_score", "cvss_version",
              "severity", "published_at", "source", "url"}
    for r in await kev.fetch_cves("adobe"):
        assert common <= set(r)
        assert r["source"] == kev.SOURCE
        assert r["id"] in r["url"]


@pytest.mark.asyncio
@respx.mock
async def test_carries_the_exploitation_facts():
    """The dates are the reason to act: `dueDate` is CISA's own deadline."""
    _mock()
    entry = next(r for r in await kev.fetch_cves("oracle"))
    assert entry["known_exploited"] is True
    assert entry["kev_date_added"] == "2022-03-03"
    assert entry["kev_due_date"] == "2022-03-24"


# ── direct lookup, to enrich CVEs that arrive from other sources ─────────────

@pytest.mark.asyncio
@respx.mock
async def test_known_exploited_reports_a_listed_cve():
    _mock()
    assert await kev.known_exploited("CVE-2015-2590") is not None


@pytest.mark.asyncio
@respx.mock
async def test_known_exploited_reports_none_for_an_unlisted_cve():
    """None means "not in the catalogue", which is a real answer here.

    The catalogue is a complete list of what CISA has observed, so absence is
    informative — unlike an empty answer from a source that may simply have
    failed. That distinction is why a download failure raises instead.
    """
    _mock()
    assert await kev.known_exploited("CVE-1999-0001") is None


# ── failures: an empty list must never mean "I could not ask" ────────────────

@pytest.mark.asyncio
@respx.mock
async def test_http_error_raises_instead_of_returning_empty():
    _mock(status=503)
    with pytest.raises(CollectorError):
        await kev.fetch_cves("adobe")


@pytest.mark.asyncio
@respx.mock
async def test_unparseable_payload_raises():
    respx.get(kev.KEV_URL).mock(return_value=httpx.Response(200, text="<html>nope</html>"))
    with pytest.raises(CollectorError):
        await kev.fetch_cves("adobe")


@pytest.mark.asyncio
@respx.mock
async def test_payload_of_the_wrong_shape_raises():
    _mock(payload=["not", "an", "object"])
    with pytest.raises(CollectorError):
        await kev.fetch_cves("adobe")


@pytest.mark.asyncio
@respx.mock
async def test_empty_catalogue_is_not_an_error():
    """Zero entries is a legitimate answer and must not look like a failure."""
    _mock(payload={"catalogVersion": "x", "count": 0, "vulnerabilities": []})
    assert await kev.fetch_cves("adobe") == []


# ── cache ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_catalogue_is_downloaded_once_per_ttl():
    route = _mock()
    await kev.fetch_cves("adobe")
    await kev.fetch_cves("oracle")
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_clear_cache_forces_a_new_download():
    route = _mock()
    await kev.fetch_cves("adobe")
    kev.clear_cache()
    await kev.fetch_cves("adobe")
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_a_failed_download_is_not_cached():
    """Otherwise one outage poisons the process for a whole TTL."""
    route = respx.get(kev.KEV_URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json=FIXTURE)]
    )
    with pytest.raises(CollectorError):
        await kev.fetch_cves("adobe")
    assert len(await kev.fetch_cves("adobe")) == 2
    assert route.call_count == 2
