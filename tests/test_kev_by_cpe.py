"""
PatchRadar — the exploited CVEs of a product with a CPE are found by its CPE

CISA names products its own way. On 2026-11-17 the catalogue held 72 exploited
Chrome CVEs, and the word "chrome" was in 6 of them: the rest are filed as
"Google / Chromium V8", "Chromium Mojo", "Chromium" and so on. A scan of
`chrome` therefore reported 6 known-exploited CVEs where CISA lists 72.

For an entry with a CPE the catalogue is now also read through NVD, which flags
each CVE in KEV (`hasKev`) and maps it to the products it affects
(`virtualMatchString`): asked for `cpe:2.3:a:google:chrome` it answered 78 — the
72, and six whose CISA entry names no browser at all (Adobe Flash Player,
WebRTC, Google Skia, Google Dawn). The keyword still applies, for entries
without a CPE and for CVEs NVD has not analysed yet.

Fixtures, both excerpts of real answers, with what was left out said in their
`_derived` key: `kev_chrome_excerpt.json` (eight entries of the 2026.11.17
catalogue: five Chrome CVEs under five CISA names, a Pixel, an Edge and a 7-Zip
one) and `nvd_chrome_has_kev_excerpt.json` (NVD's records of the five Chrome
CVEs, from its hasKev answer for google:chrome).
"""
from __future__ import annotations

import json
import pathlib

import httpx
import pytest
import respx
from typer.testing import CliRunner

from patchradar import cli
from patchradar.collectors import kev, msrc, nvd
from patchradar.collectors.errors import CollectorError

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
CATALOGUE = json.loads((FIXTURES / "kev_chrome_excerpt.json").read_text(encoding="utf-8"))
HAS_KEV = json.loads((FIXTURES / "nvd_chrome_has_kev_excerpt.json").read_text(encoding="utf-8"))
NO_RESULTS = json.loads((FIXTURES / "nvd_no_results.json").read_text(encoding="utf-8"))
CHROME = "cpe:2.3:a:google:chrome"

CHROME_CVES = {"CVE-2020-16017", "CVE-2026-125350", "CVE-2026-87491", "CVE-2025-2783", "CVE-2026-5281"}
NAMED_CHROME = {"CVE-2020-16017"}      # the one entry whose CISA product has the word


def _nvd(request: httpx.Request) -> httpx.Response:
    """NVD's hasKev answer for google:chrome; nothing for any other question."""
    params = request.url.params
    if "hasKev" in params and params.get("virtualMatchString") == CHROME:
        return httpx.Response(200, json=HAS_KEV)
    return httpx.Response(200, json=NO_RESULTS)


@pytest.fixture
def sources():
    kev.clear_cache()
    with respx.mock(assert_all_called=False) as router:
        router.get(kev.KEV_URL).mock(return_value=httpx.Response(200, json=CATALOGUE))
        router.get(url__startswith=nvd.NVD_API, name="nvd").mock(side_effect=_nvd)
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        yield router
    kev.clear_cache()


def test_the_excerpts_hold_what_the_tests_rely_on():
    products = {e["cveID"]: e["product"] for e in CATALOGUE["vulnerabilities"]}
    assert {cve for cve in CHROME_CVES if "chrome" in products[cve].lower()} == NAMED_CHROME
    assert {v["cve"]["id"] for v in HAS_KEV["vulnerabilities"]} == CHROME_CVES


async def test_the_keyword_alone_finds_only_the_entry_that_says_chrome(sources):
    """What a scan without a CPE still does, and the reason for the rest."""
    assert {r["id"] for r in await kev.fetch_cves("chrome")} == NAMED_CHROME


async def test_with_the_cpe_every_exploited_chrome_cve_is_found(sources):
    records = await kev.fetch_cves("chrome", cpe=CHROME)

    exploited = {r["id"] for r in records if r.get("known_exploited")}
    assert exploited == CHROME_CVES
    # Pixel, Edge and 7-Zip are in the catalogue and not Chrome's
    assert {r["id"] for r in records} == CHROME_CVES


async def test_nvd_is_asked_once_by_cpe_and_its_records_come_back(sources):
    """NVD's records travel with CISA's, configurations included, so the scan
    need not ask NVD about each of them again by id."""
    records = await kev.fetch_cves("chrome", cpe=CHROME)

    [call] = [c for c in sources.routes["nvd"].calls if "hasKev" in c.request.url.params]
    assert call.request.url.params["virtualMatchString"] == CHROME
    from_nvd = [r for r in records if r.get("source") == "NVD"]
    assert {r["id"] for r in from_nvd} == CHROME_CVES
    assert all("configurations" in r for r in from_nvd)


async def test_nvd_failing_leaves_the_keyword_matches_and_says_so():
    kev.clear_cache()
    with respx.mock(assert_all_called=False) as router:
        router.get(kev.KEV_URL).mock(return_value=httpx.Response(200, json=CATALOGUE))
        router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(503))
        with pytest.raises(CollectorError) as raised:
            await kev.fetch_cves("chrome", cpe=CHROME)
    kev.clear_cache()

    assert raised.value.source == nvd.SOURCE
    assert {r["id"] for r in raised.value.partial} == NAMED_CHROME


def test_a_scan_of_chrome_with_its_cpe_lists_every_exploited_cve(sources):
    runner = CliRunner()
    assert runner.invoke(cli.app, ["add", "chrome", "--cpe", CHROME]).exit_code == 0

    result = runner.invoke(cli.app, ["scan", "chrome", "--days", "7"], env={"COLUMNS": "250"})

    assert result.exit_code == 0, result.output
    assert all(cve in result.output for cve in CHROME_CVES), result.output
    assert "Total: 5 CVEs found" in " ".join(result.output.split())


async def test_a_scan_over_http_reads_kev_by_the_cpe_too(sources):
    """The API's scan, with Debian (which only it asks) refusing."""
    from httpx import ASGITransport, AsyncClient

    import patchradar.api.main as api

    sources.route().mock(return_value=httpx.Response(503))
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://localhost") as client:
        assert (await client.post("/api/watchlist/chrome", params={"cpe": CHROME})).status_code == 200
        body = (await client.post("/api/scan", params={"days": 7})).json()

    assert body["by_software"] == {"chrome": 5}
