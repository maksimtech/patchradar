"""
PatchRadar — EPSS enrichment (FIRST)

The module answers a different question from every collector, and the tests are
shaped by the two things that makes true.

First, it must not invent an absence of risk. FIRST scores about three quarters
of all published CVEs; the rest have no model output, and `epss_score: 0.0`
would say "the model puts this at virtually nil" about a CVE the model has never
seen. So the absence of the field is asserted as carefully as its presence.

Second, every number arrives as a string — `"0.00054"`, not `0.00054` — so the
conversion is real work with real failure modes, and a percentile of `"7.4"`
must be refused rather than clamped: clamped to 1.0 it would put the row at the
top of the scan on the strength of a parse error.
"""
import httpx
import pytest
import respx

from patchradar import epss
from patchradar.collectors.errors import BAD_PAYLOAD, NETWORK, RATE_LIMITED, CollectorError


@pytest.fixture(autouse=True)
def epss_offline_by_default():
    """Undo the suite-wide offline lookup: this file is about making the request.

    Overriding the fixture by name rather than clearing a cache, because what
    conftest installs is a monkeypatch over `_lookup` — and this file tests
    `_lookup`. The cache still has to be emptied around every test: it is
    process-wide, and a score left in it by one test answers the next one's
    request without a route ever being matched.
    """
    epss.clear_cache()
    yield
    epss.clear_cache()


def _payload(*entries):
    """A FIRST response body, with the numbers as strings as the API sends them."""
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "total": len(entries),
        "data": [
            {"cve": cve, "epss": score, "percentile": percentile, "date": "2026-09-30"}
            for cve, score, percentile in entries
        ],
    }


def _mock(payload, status=200):
    return respx.get(epss.EPSS_URL).mock(return_value=httpx.Response(status, json=payload))


def _record(cve_id, **extra):
    return {"id": cve_id, "software": "nginx", "description": "", "source": "NVD", **extra}


# ── what lands on a record ───────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_a_scored_cve_gets_both_numbers_as_floats():
    _mock(_payload(("CVE-2026-11111", "0.94260", "0.99930")))
    [row] = await epss.enrich([_record("CVE-2026-11111")])
    assert row["epss_score"] == pytest.approx(0.9426)
    assert row["epss_percentile"] == pytest.approx(0.9993)
    assert isinstance(row["epss_score"], float)


@pytest.mark.asyncio
@respx.mock
async def test_a_cve_first_does_not_score_keeps_neither_field():
    """The reason the module exists in this shape: 0.0 is a measurement.

    FIRST answers about the ids it scores and simply omits the others, so an
    unscored CVE has to leave here indistinguishable from one that was never
    asked about — absent, not zero.
    """
    _mock(_payload(("CVE-2026-11111", "0.01000", "0.50000")))
    rows = await epss.enrich([_record("CVE-2026-11111"), _record("CVE-2026-99999")])
    assert "epss_score" in rows[0]
    assert "epss_score" not in rows[1]
    assert "epss_percentile" not in rows[1]


@pytest.mark.asyncio
@respx.mock
async def test_enrichment_neither_drops_nor_reorders_nor_duplicates():
    """It is a pass over the records, not a filter: the scan's count is already
    printed from this list."""
    _mock(_payload(("CVE-B", "0.30000", "0.90000")))
    ids = ["CVE-A", "CVE-B", "CVE-C"]
    rows = await epss.enrich([_record(i) for i in ids])
    assert [r["id"] for r in rows] == ids


@pytest.mark.asyncio
@respx.mock
async def test_the_records_are_the_same_objects_mutated_in_place():
    """`_scan_target` prints and saves from the list it passed in."""
    _mock(_payload(("CVE-2026-11111", "0.30000", "0.90000")))
    original = _record("CVE-2026-11111")
    [row] = await epss.enrich([original])
    assert row is original


@pytest.mark.asyncio
@respx.mock
async def test_an_id_is_matched_case_insensitively():
    """Every source writes upper case today and nothing should depend on that."""
    _mock(_payload(("CVE-2026-11111", "0.30000", "0.90000")))
    [row] = await epss.enrich([_record("cve-2026-11111")])
    assert row["epss_score"] == pytest.approx(0.30)


@pytest.mark.asyncio
@respx.mock
async def test_no_request_is_made_when_there_is_nothing_to_ask_about():
    route = _mock(_payload())
    assert await epss.enrich([]) == []
    assert await epss.enrich([{"software": "nginx"}]) == [{"software": "nginx"}]
    assert not route.called


# ── payloads that are not what they should be ────────────────────────────────

@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("score,percentile", [
    ("7.4", "0.50000"),        # outside [0, 1] — a changed scale, not a score
    ("0.50000", "7.4"),
    ("-0.1", "0.50000"),
    ("nan", "0.50000"),
    ("", "0.50000"),
    ("high", "0.50000"),
    (None, "0.50000"),
    ("0.50000", None),         # half a reading cannot be ranked against the rest
])
async def test_an_unusable_number_leaves_the_record_untouched(score, percentile):
    _mock(_payload(("CVE-2026-11111", score, percentile)))
    [row] = await epss.enrich([_record("CVE-2026-11111")])
    assert "epss_score" not in row
    assert "epss_percentile" not in row


@pytest.mark.asyncio
@respx.mock
async def test_a_usable_entry_survives_an_unusable_one_beside_it():
    """One bad row in a batch of a hundred must not cost the other ninety-nine."""
    _mock(_payload(("CVE-GOOD", "0.20000", "0.80000"), ("CVE-BAD", "7.4", "0.80000")))
    good, bad = await epss.enrich([_record("CVE-GOOD"), _record("CVE-BAD")])
    assert good["epss_score"] == pytest.approx(0.20)
    assert "epss_score" not in bad


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("payload", [[], {"status": "OK"}, {"data": {"cve": "CVE-1"}}])
async def test_a_body_without_a_data_list_is_a_failure_not_an_empty_answer(payload):
    """An empty answer means "FIRST scores none of these", which is a finding.

    A body it could not read must not be able to say that — the scan would rank
    every CVE as unforecast and look like it had asked.
    """
    _mock(payload)
    with pytest.raises(CollectorError) as caught:
        await epss.enrich([_record("CVE-2026-11111")])
    assert caught.value.reason == BAD_PAYLOAD


@pytest.mark.asyncio
@respx.mock
async def test_a_non_json_body_is_a_failure():
    respx.get(epss.EPSS_URL).mock(
        return_value=httpx.Response(200, text="<html>captive portal</html>")
    )
    with pytest.raises(CollectorError) as caught:
        await epss.enrich([_record("CVE-2026-11111")])
    assert caught.value.reason == BAD_PAYLOAD


@pytest.mark.asyncio
@respx.mock
async def test_an_entry_that_is_not_an_object_is_skipped():
    _mock({"data": ["CVE-2026-11111", None, 7]})
    [row] = await epss.enrich([_record("CVE-2026-11111")])
    assert "epss_score" not in row


# ── failures ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_an_http_error_raises_with_the_reason_mapped():
    _mock(_payload(), status=429)
    with pytest.raises(CollectorError) as caught:
        await epss.enrich([_record("CVE-2026-11111")])
    assert caught.value.reason == RATE_LIMITED
    assert caught.value.source == epss.SOURCE
    assert caught.value.status == 429


@pytest.mark.asyncio
@respx.mock
async def test_a_network_failure_raises():
    respx.get(epss.EPSS_URL).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(CollectorError) as caught:
        await epss.enrich([_record("CVE-2026-11111")])
    assert caught.value.reason == NETWORK


@pytest.mark.asyncio
@respx.mock
async def test_a_failure_carries_no_partial_records():
    """CollectorError.partial exists so a caller can keep what was gathered.

    There is nothing to keep here: the caller's records are complete without
    EPSS, and handing them back as "partial" would invite a caller to use them
    twice.
    """
    _mock(_payload(), status=503)
    with pytest.raises(CollectorError) as caught:
        await epss.enrich([_record("CVE-2026-11111")])
    assert caught.value.partial == []


@pytest.mark.asyncio
@respx.mock
async def test_a_failed_lookup_is_not_cached():
    """One outage must not leave the scan unforecast for the whole TTL."""
    route = respx.get(epss.EPSS_URL)
    route.mock(return_value=httpx.Response(503))
    with pytest.raises(CollectorError):
        await epss.enrich([_record("CVE-2026-11111")])
    route.mock(return_value=httpx.Response(200, json=_payload(("CVE-2026-11111", "0.4", "0.9"))))
    [row] = await epss.enrich([_record("CVE-2026-11111")])
    assert row["epss_score"] == pytest.approx(0.4)


# ── request economy ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_the_whole_scan_costs_one_request():
    """A hundred CVEs, one call: the reason this is not a per-CVE lookup."""
    ids = [f"CVE-2026-{n:05d}" for n in range(epss.CHUNK_SIZE)]
    route = _mock(_payload(*[(i, "0.01", "0.5") for i in ids]))
    await epss.enrich([_record(i) for i in ids])
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_more_ids_than_a_page_are_split_rather_than_truncated():
    """FIRST pages at 100 and does not say it truncated.

    Sending 150 ids in one request yields 100 answers, and the 50 missing ones
    are indistinguishable from CVEs FIRST does not score — a silent wrong answer
    rather than a failure, which is why the chunk size and the `limit` sent are
    the same number.
    """
    ids = [f"CVE-2026-{n:05d}" for n in range(epss.CHUNK_SIZE + 50)]
    route = _mock(_payload(*[(i, "0.01", "0.5") for i in ids]))
    rows = await epss.enrich([_record(i) for i in ids])
    assert route.call_count == 2
    assert all("epss_score" in row for row in rows)
    asked = []
    for call in route.calls:
        asked += call.request.url.params["cve"].split(",")
    assert asked == ids


@pytest.mark.asyncio
@respx.mock
async def test_the_same_cve_is_asked_about_once_per_scan():
    """Sixteen targets, one shared cache: the per-target cost is the new ids only."""
    route = _mock(_payload(("CVE-2026-11111", "0.4", "0.9")))
    await epss.enrich([_record("CVE-2026-11111")])
    await epss.enrich([_record("CVE-2026-11111")])
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_an_unscored_cve_is_also_asked_about_only_once():
    """The absence is cached too, or every target re-asks for the same nothing."""
    route = _mock(_payload())
    await epss.enrich([_record("CVE-2026-99999")])
    [row] = await epss.enrich([_record("CVE-2026-99999")])
    assert route.call_count == 1
    assert "epss_score" not in row


@pytest.mark.asyncio
@respx.mock
async def test_a_duplicated_id_is_asked_about_once_and_lands_on_both_rows():
    route = _mock(_payload(("CVE-2026-11111", "0.4", "0.9")))
    rows = await epss.enrich([_record("CVE-2026-11111"), _record("cve-2026-11111")])
    assert route.call_count == 1
    assert [r["epss_score"] for r in rows] == [pytest.approx(0.4)] * 2
    assert route.calls[0].request.url.params["cve"] == "CVE-2026-11111"


@pytest.mark.asyncio
@respx.mock
async def test_a_stale_cache_is_refetched():
    import time as _time

    route = _mock(_payload(("CVE-2026-11111", "0.4", "0.9")))
    await epss.enrich([_record("CVE-2026-11111")])
    epss._cache_at = _time.monotonic() - epss.CACHE_TTL_SECONDS - 1
    route.mock(return_value=httpx.Response(200, json=_payload(("CVE-2026-11111", "0.8", "0.99"))))
    [row] = await epss.enrich([_record("CVE-2026-11111")])
    assert row["epss_score"] == pytest.approx(0.8)


# ── the scan still runs when FIRST does not ──────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_a_cli_scan_survives_an_epss_outage(monkeypatch, capsys):
    """The CVEs are complete without EPSS; only the ranking is poorer.

    Asserted through the CLI rather than the module because that is where the
    decision lives: a failure here is caught and reported, not propagated, and
    the scan prints its table and its total either way.
    """
    import patchradar.cli as cli

    _mock(_payload(), status=503)

    async def _one_cve(keyword, days_back=7):
        return [_record("CVE-2026-11111", cvss_score=9.8, cvss_version="3.1", severity="CRITICAL",
                        published_at="2026-09-20T00:00:00", url="")]

    async def _nothing(keyword, days_back=7):
        return []

    monkeypatch.setattr(cli, "fetch_cves", _one_cve)
    monkeypatch.setattr(cli, "msrc_fetch", _nothing)
    monkeypatch.setattr(cli, "kev_fetch", _nothing)

    assert await cli._scan_target("nginx", 7) == 1
    out = capsys.readouterr().out
    assert "CVE-2026-11111" in out
    assert epss.SOURCE in out
