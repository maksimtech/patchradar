"""
PatchRadar — a source nobody configured is not a source that failed

VulDB answers only with an API key, and most installations have none. Without
it the collector refused every target, and the scan reported each refusal as a
failure:

    ⚠️  VulDB no_api_key: set VULDB_API_KEY to use VulDB — results for 7-zip are incomplete
    … one line per target …
    ⚠️  VulDB answered for none of the 8 targets scanned — every CVE above comes from NVD, MSRC, CISA KEV.

and the line "no CVEs found", which needs every source to have answered, could
never be printed: `patchradar scan` of a product with no CVEs ended in a warning
instead of an all-clear (seen on 2026-10-17). The API listed the same refusal in
`errors`. A fixture in conftest.py made VulDB return nothing in every test, so
the suite never saw it.

VulDB is now queried only when its key is set, and a scan without it says so
once, as information about what was asked, not as a failure.

NVD answers from a recording (`nvd_no_results.json`, keywordSearch=patchradar,
2026-10-07), MSRC has no document for the months asked (404), and the KEV
catalogue is the empty one conftest.py caches.
"""
from __future__ import annotations

import asyncio
import json
import pathlib

import httpx
import pytest
import respx
from typer.testing import CliRunner

from patchradar import cli
from patchradar.api import main as api_main
from patchradar.collectors import msrc, nvd, vuldb
from patchradar.db import database

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NVD_EMPTY = json.loads((FIXTURES / "nvd_no_results.json").read_text(encoding="utf-8"))


@pytest.fixture
def nothing_anywhere():
    """Every source answers, with nothing; VulDB would be answered too, if asked."""
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(200, json=NVD_EMPTY))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        asked_vuldb = router.post(url__startswith=vuldb.VULDB_API).mock(return_value=httpx.Response(200, json={}))
        yield asked_vuldb


def test_a_scan_without_a_vuldb_key_can_still_give_an_all_clear(nothing_anywhere):
    result = CliRunner().invoke(cli.app, ["scan", "patchradar", "--days", "7"])

    assert result.exit_code == 0, result.output
    assert "no CVEs found" in result.output
    assert "incomplete" not in result.output


def test_vuldb_is_not_asked_without_its_key(nothing_anywhere):
    CliRunner().invoke(cli.app, ["scan", "patchradar", "--days", "7"])

    assert not nothing_anywhere.called


def test_the_scan_says_once_that_vuldb_was_not_asked(nothing_anywhere):
    """Information, not a warning: what was asked, and how to add VulDB."""
    result = CliRunner().invoke(cli.app, ["scan", "patchradar", "--days", "7"])

    assert result.output.count("VULDB_API_KEY") == 1


@pytest.mark.asyncio
async def test_the_api_lists_no_error_for_a_source_nobody_configured():
    """Over HTTP the scan's `errors` meant a source could not be queried; VulDB
    without its key was always there. Every upstream here refuses (503), so the
    other sources do appear in `errors` — VulDB must not."""
    errors: list[dict] = []
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(return_value=httpx.Response(503))
        await api_main._scan_one("patchradar", 7, errors)

    assert errors, "the other sources refused, and say so"
    assert not [e for e in errors if e["source"] == vuldb.SOURCE], errors


async def test_a_source_that_was_not_asked_is_not_named_as_one_that_answered():
    """With NVD refusing every target, the summary names the sources the CVEs
    came from. VulDB was not asked, so it is not one of them."""
    await database.add_to_watchlist("patchradar")
    await database.add_to_watchlist("zzqxnonexistentproduct")
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(503))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        result = await asyncio.to_thread(CliRunner().invoke, cli.app, ["scan", "--days", "7"])

    text = " ".join(result.output.split())   # Rich folds long lines at its own width
    assert "NVD answered for none of the 2 targets scanned" in text, result.output
    assert "every CVE above comes from MSRC, CISA KEV." in text
