"""
PatchRadar — a verdict holds only when NVD's statement is about the version alone

NVD states which versions a CVE affects in `cpeMatch` entries, and an entry can
say more than a version:

- its other CPE fields: `7-zip:4.43:beta` is the 4.43 beta, not 4.43; Firefox's
  `sw_edition` is `esr` for the extended-support line and `-` for the release;
- the configuration around it: an AND of Chrome and `vulnerable: false` Android
  is Chrome *on Android*, and nothing about Chrome on Windows.

The verdict read the version and nothing else, so a Windows install of Chrome was
"affected" by a CVE NVD lists for Android only, and Firefox ESR 115.17.0 was
"affected, fix in 131.0.2" by a CVE whose ESR line was fixed in 115.16.1. The
watchlist knows the version and the CPE, not the operating system or (unless the
CPE names them) the update and edition: a match that holds only under such a
condition is "not evaluable", with the condition named, and never "affected".

The records are NVD's, recorded on 2026-11-17 (`nvd_cve_*_recorded.json`), and
the 7-Zip page recorded earlier (`nvd_7zip_page.json`).
"""
from __future__ import annotations

import json
import pathlib

import httpx
import pytest
import respx
from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

import patchradar.api.main as api
from patchradar import cli
from patchradar.affected import AFFECTED, NOT_AFFECTED, NOT_EVALUABLE, judge
from patchradar.collectors import msrc, nvd
from patchradar.collectors.nvd import _parse_item
from patchradar.cpe import parse_cpe

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def record(name: str, cve_id: str | None = None) -> dict:
    """The scan record NVD's answer in `name` gives for `cve_id` (or its only CVE)."""
    items = json.loads((FIXTURES / name).read_text(encoding="utf-8"))["vulnerabilities"]
    [item] = [i for i in items if cve_id in (None, i["cve"]["id"])]
    return _parse_item(item, "test")


ANDROID_ONLY = record("nvd_cve_2026_16424_recorded.json")    # Chrome < 150.0.7871.182 AND Android
MACOS_ONLY = record("nvd_cve_2026_17709_recorded.json")      # Chrome < 151.0.7922.72 AND macOS
FIREFOX_9680 = record("nvd_cve_2024_9680_recorded.json")     # ESR < 115.16.1, release < 131.0.2, ...
SEVEN_ZIP_BETAS = record("nvd_7zip_page.json", "CVE-2007-4725")   # <= 4.42, and 4.43 to 4.52 beta


def _judge(rec: dict, version: str, vendor: str, product: str, cpe: str | None):
    watched = {"watched": parse_cpe(cpe)} if cpe else {}
    return judge(rec, version=version, vendor=vendor, cpe_product=product, **watched)


def chrome(rec: dict, version: str):
    return _judge(rec, version, "google", "chrome", None)


def firefox(version: str, cpe: str | None = None):
    return _judge(FIREFOX_9680, version, "mozilla", "firefox", cpe)


def seven_zip(version: str, cpe: str | None = None):
    return _judge(SEVEN_ZIP_BETAS, version, "7-zip", "7-zip", cpe)


# ─── the platform an AND configuration requires ──────────────────────────────

def test_the_records_say_what_the_tests_rely_on():
    for rec, platform in ((ANDROID_ONLY, "android"), (MACOS_ONLY, "macos")):
        [configuration] = rec["configurations"]
        assert configuration["operator"] == "AND"
        [chrome_node, platform_node] = configuration["nodes"]
        assert [m["vulnerable"] for m in platform_node["cpeMatch"]] == [False]
        assert f":{platform}:" in platform_node["cpeMatch"][0]["criteria"]


def test_a_cve_listed_for_chrome_on_android_only_is_not_called_affected():
    verdict = chrome(ANDROID_ONLY, "150.0.7871.100")

    assert verdict.status == NOT_EVALUABLE, verdict
    assert "only on Android" in verdict.reason
    assert verdict.fixed_version is None


def test_a_cve_listed_for_chrome_on_macos_only_is_not_called_affected():
    verdict = chrome(MACOS_ONLY, "151.0.7922.10")

    assert verdict.status == NOT_EVALUABLE, verdict
    assert "only on macOS" in verdict.reason


def test_a_version_past_the_fix_is_not_affected_whatever_the_platform():
    """The condition only matters for a version inside the range."""
    assert chrome(ANDROID_ONLY, "151.0.7922.10").status == NOT_AFFECTED


# ─── the edition ─────────────────────────────────────────────────────────────

def test_firefox_esr_115_17_is_not_called_affected_with_the_release_fix():
    """The hunt's case: 115.17.0 is past the ESR fix (115.16.1) and inside the
    release range (< 131.0.2); the verdict was "affected, fix in 131.0.2"."""
    verdict = firefox("115.17.0")

    assert verdict.status == NOT_EVALUABLE, verdict
    assert "edition" in verdict.reason
    assert verdict.fixed_version is None


def test_a_cpe_that_names_the_esr_edition_is_judged_on_the_esr_ranges():
    assert firefox("115.17.0", "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*").status == NOT_AFFECTED
    verdict = firefox("115.16.0", "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*")
    assert (verdict.status, verdict.fixed_version) == (AFFECTED, "115.16.1")


def test_a_cpe_that_names_the_release_edition_is_judged_on_the_release_range():
    verdict = firefox("130.0", "cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*")
    assert (verdict.status, verdict.fixed_version) == (AFFECTED, "131.0.2")
    assert firefox("131.0.2", "cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*").status == NOT_AFFECTED


def test_a_version_outside_every_edition_s_range_is_not_affected():
    assert firefox("132.0").status == NOT_AFFECTED


def test_a_product_whose_entries_name_no_edition_is_judged_as_before():
    """Thunderbird in the same record: `sw_edition` is `*` throughout."""
    verdict = judge(FIREFOX_9680, version="115.15.0", vendor="mozilla", cpe_product="thunderbird")
    assert (verdict.status, verdict.fixed_version) == (AFFECTED, "115.16.0")


# ─── the update ──────────────────────────────────────────────────────────────

def test_the_4_43_beta_is_not_4_43():
    """`cpe:2.3:a:7-zip:7-zip:4.43:beta` was read as 4.43, so the final 4.43 was
    "affected" by a CVE NVD states for the betas."""
    verdict = seven_zip("4.43")

    assert verdict.status == NOT_EVALUABLE, verdict
    assert "update beta" in verdict.reason


def test_a_cpe_that_names_the_beta_is_affected():
    assert seven_zip("4.43", "cpe:2.3:a:7-zip:7-zip:*:beta").status == AFFECTED


def test_a_cpe_that_names_another_update_is_not_affected_by_the_betas():
    assert seven_zip("4.43", "cpe:2.3:a:7-zip:7-zip:*:-").status == NOT_AFFECTED


def test_a_range_with_no_update_still_decides_alone():
    """`versionEndIncluding: 4.42` with update `*`: no condition."""
    assert seven_zip("4.42").status == AFFECTED


def test_a_dash_no_other_entry_contradicts_is_no_condition():
    """`-` in a field that no entry of the product sets otherwise leaves nothing
    to choose between: VS Code's only entry has `target_sw: -`."""
    rec = record("nvd_cve_2026_81376_recorded.json")
    [configuration] = rec["configurations"]
    [entry] = configuration["nodes"][0]["cpeMatch"]
    assert entry["criteria"] == "cpe:2.3:a:microsoft:visual_studio_code:*:*:*:*:*:-:*:*"

    verdict = judge(rec, version="1.130.0", vendor="microsoft", cpe_product="visual_studio_code")

    assert (verdict.status, verdict.fixed_version) == (AFFECTED, "1.136.2")


# ─── through both scans ──────────────────────────────────────────────────────
# NVD answers with the recorded CVE-2024-9680, MSRC with no document, Debian
# (asked by the API only) with 503.

FIREFOX_ESR = "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*"


@pytest.fixture
def upstream_9680():
    payload = json.loads((FIXTURES / "nvd_cve_2024_9680_recorded.json").read_text(encoding="utf-8"))
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(200, json=payload))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        router.route().mock(return_value=httpx.Response(503))
        yield


def _cli_scan(cpe: str) -> str:
    runner = CliRunner()
    assert runner.invoke(cli.app, ["add", "firefox", "--version", "115.17.0", "--cpe", cpe]).exit_code == 0
    result = runner.invoke(cli.app, ["scan", "firefox", "--days", "7"], env={"COLUMNS": "250"})
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


def test_the_cli_scan_names_the_edition_it_could_not_check(upstream_9680):
    out = _cli_scan("cpe:2.3:a:mozilla:firefox")

    assert "affecting 115.17.0: 0; not evaluable: 1; not affecting it: 0" in out
    assert "standard edition" in out


def test_the_cli_scan_reads_the_edition_of_the_watched_cpe(upstream_9680):
    out = _cli_scan(FIREFOX_ESR)

    assert "affecting 115.17.0: 0; not evaluable: 0; not affecting it: 1" in out


async def test_the_api_scan_reads_the_edition_of_the_watched_cpe(upstream_9680):
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as client:
        added = await client.post("/api/watchlist/firefox", params={"version": "115.17.0", "cpe": FIREFOX_ESR})
        assert added.status_code == 200, added.text
        body = (await client.post("/api/scan", params={"days": 7})).json()

    assert body["verdicts"] == {"firefox": {"affected": 0, "not evaluable": 0, "not affected": 1}}
