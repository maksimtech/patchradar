"""
PatchRadar — a CVE from KEV or MSRC is judged through NVD's record of it (DESIGN §5.3)

CISA KEV and MSRC carry no `cpeMatch`, so for an entry with an installed version
a CVE that reached the scan only through them was "not evaluable": NVD's record
was not part of the scan. Those are the CVEs that matter most — KEV lists what
is being exploited — and the scan had the means to ask. For an entry it can
judge, it now asks NVD about each such CVE by id (`cveId=`) and merges the record
in, which brings NVD's configurations and its score with it. A CVE NVD cannot be
asked about stays not evaluable, and the scan says why.

NVD answers from recordings: `nvd_cve_2026_48092.json` (cveId=CVE-2026-48092,
7-Zip, 2026-10-07; affected 9.34 <= v < 26.01) and `nvd_no_results.json` for the
keyword search. The KEV catalogue is **derived**: CVE-2026-48092 is not in KEV,
so one entry is written in KEV's shape (the field names of
`tests/fixtures/kev_sample.json`) to stand for an exploited CVE that NVD's keyword
search did not return.
"""
from __future__ import annotations

import json
import pathlib
import time

import httpx
import pytest
import respx
from typer.testing import CliRunner

from patchradar import cli
from patchradar.api import main as api_main
from patchradar.collectors import kev, msrc, nvd
from patchradar.collectors.errors import CollectorError
from patchradar.db import database

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
CVE_48092 = json.loads((FIXTURES / "nvd_cve_2026_48092.json").read_text(encoding="utf-8"))
NVD_EMPTY = json.loads((FIXTURES / "nvd_no_results.json").read_text(encoding="utf-8"))
SEVEN_ZIP = "cpe:2.3:a:7-zip:7-zip"

KEV_DERIVED = {
    "catalogVersion": "derived", "count": 1,
    "vulnerabilities": [{
        "cveID": "CVE-2026-48092",
        "vendorProject": "7-Zip",
        "product": "7-Zip",
        "vulnerabilityName": "7-Zip Derived Entry For Tests",
        "dateAdded": "2026-06-10",
        "shortDescription": "Stands for an exploited 7-Zip CVE; not a real KEV entry.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2026-07-01",
        "knownRansomwareCampaignUse": "Unknown",
    }],
}


@pytest.fixture
def kev_lists_it():
    kev._snapshot = KEV_DERIVED
    kev._snapshot_at = time.monotonic()


@pytest.fixture
def nvd_router():
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API, params__contains={"keywordSearch": "7-zip"}).mock(
            return_value=httpx.Response(200, json=NVD_EMPTY))
        by_id = router.get(url__startswith=nvd.NVD_API, params__contains={"cveId": "CVE-2026-48092"}).mock(
            return_value=httpx.Response(200, json=CVE_48092))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        router.route().mock(return_value=httpx.Response(503))       # Debian, for the API
        yield by_id


# ─── nvd.records_for ─────────────────────────────────────────────────────────

async def test_nvd_is_asked_by_id_and_answers_with_the_configurations(nvd_router):
    [record] = await nvd.records_for(["CVE-2026-48092"], "7-zip")

    assert record["id"] == "CVE-2026-48092"
    assert record["software"] == "7-zip"
    assert record["configurations"]
    assert nvd_router.call_count == 1


async def test_an_id_nvd_does_not_know_gives_nothing():
    with respx.mock() as router:
        router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(200, json=NVD_EMPTY))
        assert await nvd.records_for(["CVE-2026-00001"], "7-zip") == []


async def test_nvd_refusing_is_a_collector_error_with_what_it_had():
    with respx.mock() as router:
        router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(503))
        with pytest.raises(CollectorError) as raised:
            await nvd.records_for(["CVE-2026-48092"], "7-zip")

    assert raised.value.partial == []


# ─── the CLI scan ────────────────────────────────────────────────────────────

def _scan(version="24.09", cpe=SEVEN_ZIP):
    runner = CliRunner()
    added = ["add", "7-zip"] + (["--version", version] if version else []) + (["--cpe", cpe] if cpe else [])
    assert runner.invoke(cli.app, added).exit_code == 0
    result = runner.invoke(cli.app, ["scan", "7-zip", "--days", "7", "--all"], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


def test_an_exploited_cve_from_kev_alone_is_judged_affected(kev_lists_it, nvd_router):
    out = _scan()

    assert "CVE-2026-48092" in out
    assert "affecting 24.09: 1; not evaluable: 0" in out
    assert "NVD states the fix is in 26.01" in out


def test_nvd_s_record_brings_its_score_to_the_kev_entry(kev_lists_it, nvd_router):
    """KEV states no severity; NVD's record, merged in, does."""
    out = _scan()

    assert "UNKNOWN" not in out


def test_the_fixed_version_is_not_affected(kev_lists_it, nvd_router):
    assert "affecting 26.01: 0; not evaluable: 0; not affecting it: 1" in _scan(version="26.01")


def test_an_entry_matched_by_name_does_not_cost_a_request(kev_lists_it, nvd_router):
    _scan(version=None, cpe=None)

    assert nvd_router.call_count == 0


def test_when_nvd_cannot_be_asked_the_cve_stays_not_evaluable_and_the_scan_says_so(kev_lists_it):
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API, params__contains={"keywordSearch": "7-zip"}).mock(
            return_value=httpx.Response(200, json=NVD_EMPTY))
        router.get(url__startswith=nvd.NVD_API, params__contains={"cveId": "CVE-2026-48092"}).mock(
            return_value=httpx.Response(503))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        out = _scan()

    assert "affecting 24.09: 0; not evaluable: 1" in out
    assert "NVD could not be asked about 1 CVE" in out


# ─── the API scan ────────────────────────────────────────────────────────────

async def test_the_api_judges_the_kev_entry_through_nvd_too(kev_lists_it, nvd_router):
    from patchradar.cpe import parse_cpe

    await database.add_to_watchlist("7-zip")
    await database.set_installed("7-zip", version="24.09", cpe=parse_cpe(SEVEN_ZIP))
    [entry] = await database.get_watch_entries()
    verdicts: dict = {}

    await api_main._scan_one("7-zip", 7, [], entry, verdicts)

    assert verdicts == {"7-zip": {"affected": 1, "not evaluable": 0, "not affected": 0}}


def test_a_cve_nvd_already_returned_is_not_asked_for_again(kev_lists_it):
    """NVD's keyword search found it too, configurations and all: the merged
    row has them, and a second request would cost a rate-limit slot for nothing."""
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API, params__contains={"keywordSearch": "7-zip"}).mock(
            return_value=httpx.Response(200, json=CVE_48092))
        by_id = router.get(url__startswith=nvd.NVD_API, params__contains={"cveId": "CVE-2026-48092"}).mock(
            return_value=httpx.Response(200, json=CVE_48092))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        out = _scan()

    assert by_id.call_count == 0
    assert "affecting 24.09: 1" in out


async def test_the_api_lists_nvd_refusing_the_lookup_among_its_errors(kev_lists_it):
    from patchradar.cpe import parse_cpe

    await database.add_to_watchlist("7-zip")
    await database.set_installed("7-zip", version="24.09", cpe=parse_cpe(SEVEN_ZIP))
    [entry] = await database.get_watch_entries()
    errors: list[dict] = []
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API, params__contains={"keywordSearch": "7-zip"}).mock(
            return_value=httpx.Response(200, json=NVD_EMPTY))
        router.get(url__startswith=nvd.NVD_API, params__contains={"cveId": "CVE-2026-48092"}).mock(
            return_value=httpx.Response(503))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        router.route().mock(return_value=httpx.Response(503))
        await api_main._scan_one("7-zip", 7, errors, entry, {})

    assert {"software": "7-zip", "source": "NVD", "reason": "server_error", "status": 503} in errors
