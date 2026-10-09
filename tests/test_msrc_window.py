"""
PatchRadar — MSRC answers for the days asked, not for the whole months they touch

Seen on 2026-10-09 with `patchradar scan --days 30`: sixteen SharePoint CVEs
from MSRC, every one of them released on Patch Tuesday, 2026-09-08 — thirty-one
days earlier. The collector fetches the monthly CVRF documents that overlap the
window and keeps everything in them, so a 30-day scan on the 9th reported a
month and nine days, and `--days 7` on the same day would have reported the same
Patch Tuesday had October's document not existed yet. NVD was asked for the
same 30 days and answered one SharePoint CVE: the two sources disagreed about
what "30 days" meant, in the same table.

Every entry carries the date of its first revision, which is when MSRC published
it, so the window can be applied to the entries and not only to the documents.
An entry with no usable date is kept: the collector cannot tell when it was
published, and dropping it would hide a CVE on the strength of a formatting
oddity.

The fixture is the September 2026 document, recorded: six entries verbatim,
dated 2026-09-07 to 2026-09-09.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timedelta

import httpx
import pytest
import respx

from patchradar.collectors import msrc

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SEPTEMBER = json.loads((FIXTURES / "msrc_2026_sep_excerpt.json").read_text(encoding="utf-8"))
assert "verbatim" in SEPTEMBER.pop("_derived")

# The day of the recording, at noon.
RECORDED = datetime(2026, 10, 9, 12, 0)


def first_revision(cve_id: str) -> str:
    [vuln] = [v for v in SEPTEMBER["Vulnerability"] if v["CVE"] == cve_id]
    return vuln["RevisionHistory"][0]["Date"]


def test_the_recording_dates_the_tests_rely_on():
    assert first_revision("CVE-2026-69268") == "2026-09-08T07:00:00"   # Patch Tuesday
    assert first_revision("CVE-2026-85046") == "2026-09-09T15:09:50"   # the day after
    assert first_revision("CVE-2026-80803") == "2026-09-07T02:03:06"   # the day before


@pytest.fixture
def september_only():
    with respx.mock:
        respx.get(f"{msrc.MSRC_API}/cvrf/2026-Sep").mock(return_value=httpx.Response(200, json=SEPTEMBER))
        # Every other month asked for has no document yet, which MSRC says with 404.
        respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        yield


async def ids(keyword: str, days: int, now: datetime = RECORDED) -> list[str]:
    return [r["id"] for r in await msrc.fetch_cves(keyword, days_back=days, now=now)]


@pytest.mark.asyncio
async def test_thirty_days_on_the_ninth_do_not_reach_patch_tuesday_of_the_month_before(september_only):
    """2026-09-08 is 31 days before 2026-10-09: outside the window asked for,
    inside the document fetched."""
    assert await ids("sharepoint", 30) == []


@pytest.mark.asyncio
async def test_thirty_two_days_do(september_only):
    """Patch Tuesday is dated 07:00; the clock here says noon, so 31 days back
    lands five hours after it and 32 is the first window that holds it."""
    assert await ids("sharepoint", 31) == []
    assert await ids("sharepoint", 32) == ["CVE-2026-69268"]


@pytest.mark.asyncio
async def test_the_boundary_is_the_entry_date_and_not_the_document(september_only):
    """Three entries of one document, three dates, one cutoff between them."""
    assert await ids("chromium", 30) == ["CVE-2026-85046"]      # 09-09 15:09, inside
    assert await ids("digital", 30) == []                        # 09-07, outside
    assert await ids("digital", 33) == ["CVE-2026-80803"]


@pytest.mark.asyncio
async def test_the_whole_month_is_still_there_when_asked_for(september_only):
    assert await ids("sharepoint", 60) == ["CVE-2026-69268"]
    assert await ids("netlogon", 60) == ["CVE-2026-62759"]


@pytest.mark.asyncio
async def test_an_entry_without_a_usable_date_is_kept():
    """Nothing to compare: dropping it would hide a CVE for a formatting oddity."""
    undated = {"Vulnerability": [
        {"CVE": "CVE-2026-NODATE", "Title": {"Value": "nginx issue"}, "RevisionHistory": []},
        {"CVE": "CVE-2026-BADDATE", "Title": {"Value": "nginx issue"},
         "RevisionHistory": [{"Date": "last Tuesday"}]},
    ]}
    with respx.mock:
        respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(200, json=undated))
        found = await ids("nginx", 7)
    assert found == ["CVE-2026-NODATE", "CVE-2026-BADDATE"]


@pytest.mark.asyncio
async def test_an_entry_dated_in_the_future_is_kept():
    """The September document carries a revision dated 2026-10-13, the next
    Patch Tuesday, four days after it was recorded: MSRC pre-dates. A record
    newer than now is inside any window."""
    future = {"Vulnerability": [{"CVE": "CVE-2026-SOON", "Title": {"Value": "nginx issue"},
                                 "RevisionHistory": [{"Date": "2026-10-13T07:00:00"}]}]}
    with respx.mock:
        respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(200, json=future))
        assert await ids("nginx", 7) == ["CVE-2026-SOON"]


def test_the_default_clock_is_now():
    """`now` is a parameter for the tests; the scan passes nothing."""
    before = datetime.now() - timedelta(seconds=5)
    assert msrc._window_start(None, 7) >= before - timedelta(days=7)
