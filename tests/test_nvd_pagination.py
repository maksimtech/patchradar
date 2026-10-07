"""NVD answers in pages, and a window's answer is every page of it.

NVD returns at most `resultsPerPage` records per response and states the size of
the whole answer in `totalResults`; the rest is asked for with `startIndex`. The
collector asked for one page of 50 and ignored the total, so a keyword with more
CVEs than that in a window — "linux", "chrome", "windows" — came back cut at 50,
with a count that looked complete and nothing to say otherwise.

The fix follows the pages, at NVD's documented maximum of 2000 per page, and
treats each page like a window for the rate limit. A page that fails, or a page
that comes back empty before the stated total, makes the result incomplete — and
an incomplete result has to say so, carrying what the earlier pages found.
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import Callable

import httpx
import pytest
import respx

from patchradar.collectors import nvd
from patchradar.collectors.errors import CollectorError

# ─── what NVD sent ───────────────────────────────────────────────────────────
# An answer NVD really splits: keywordSearch=7-zip with pubStartDate=2024-11-01
# T00:00:00.000 and pubEndDate=2025-02-28T23:59:59.999 has three CVEs, and asked
# for with resultsPerPage=1 it sends them one per page, each page stating
# totalResults=3. The three pages, startIndex 0, 1 and 2, were recorded on
# 2026-10-07, without a key and seven seconds apart; each file's `timestamp`
# says when NVD answered.
#
# The collector asks for 2000 per page and for the window of its own clock, so
# the routes answer by keyword and by `startIndex`, the one parameter the
# collector works out from what the previous page held. That is the part of the
# request the paging decides; the page size and the dates are not.
#
# `nvd_no_results.json` is the answer to keywordSearch=patchradar over
# 2026-09-30..2026-10-07 with resultsPerPage=2000: no CVE carries the word.
# `nvd_error_window_too_wide.json` is the same query over 2026-01-01..2026-10-07,
# 280 days: NVD refuses it with a 404, an empty body and its reason in a
# `message` header, recorded the same day. It stands here for any page NVD
# refuses. `nvd_7zip_window_page_1_empty.json` is derived, and its `_derived`
# key says from what.

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
KEYWORD = "7-zip"
IDS = ["CVE-2024-11477", "CVE-2024-11612", "CVE-2025-0411"]


def recorded(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def page(index: int) -> httpx.Response:
    return httpx.Response(200, json=recorded(f"nvd_7zip_window_page_{index}.json"))


def empty_page() -> httpx.Response:
    derived = recorded("nvd_7zip_window_page_1_empty.json")
    del derived["_derived"]
    return httpx.Response(200, json=derived)


def refusal() -> httpx.Response:
    answer = recorded("nvd_error_window_too_wide.json")
    return httpx.Response(answer["status"], headers=answer["headers"], content=answer["body"].encode())


def nvd_answering(*answers: Callable[[], httpx.Response]) -> respx.Route:
    """NVD, as recorded: the n-th answer for startIndex n.

    A request without a `startIndex` is NVD's first page, which is how the
    collector asked before it followed pages at all.
    """
    def answer(request: httpx.Request) -> httpx.Response:
        assert request.url.params["keywordSearch"] == KEYWORD
        return answers[int(request.url.params.get("startIndex", "0"))]()
    return respx.get(nvd.NVD_API).mock(side_effect=answer)


def test_the_recorded_pages_are_one_answer_in_three_parts():
    pages = [recorded(f"nvd_7zip_window_page_{i}.json") for i in range(3)]
    assert [p["startIndex"] for p in pages] == [0, 1, 2]
    assert {p["totalResults"] for p in pages} == {3}
    assert [cve["cve"]["id"] for p in pages for cve in p["vulnerabilities"]] == IDS


def test_the_empty_page_differs_from_the_recording_only_where_it_says():
    recording = recorded("nvd_7zip_window_page_1.json")
    derived = recorded("nvd_7zip_window_page_1_empty.json")

    assert "CVE-2024-11612" in derived.pop("_derived")
    assert derived["vulnerabilities"] == [] and derived["resultsPerPage"] == 0
    derived["vulnerabilities"], derived["resultsPerPage"] = recording["vulnerabilities"], 1
    assert derived == recording


@pytest.mark.asyncio
@respx.mock
async def test_the_fetch_follows_the_pages_beyond_the_first():
    """Three CVEs stated, one per page: the second and third pages have to be
    asked for, rather than the answer being cut at the first without a word."""
    route = nvd_answering(lambda: page(0), lambda: page(1), lambda: page(2))
    results = await nvd.fetch_cves(KEYWORD, days_back=7)
    assert [r["id"] for r in results] == IDS
    assert [call.request.url.params["startIndex"] for call in route.calls] == ["0", "1", "2"]


@pytest.mark.asyncio
@respx.mock
async def test_the_largest_page_nvd_allows_is_asked_for():
    """2000 is NVD's documented maximum: fewer requests, less of the quota."""
    route = respx.get(nvd.NVD_API, params={"keywordSearch": "patchradar"}).mock(
        return_value=httpx.Response(200, json=recorded("nvd_no_results.json")))
    assert await nvd.fetch_cves("patchradar", days_back=7) == []
    assert route.calls[0].request.url.params["resultsPerPage"] == "2000"
    assert route.calls[0].request.url.params["startIndex"] == "0"


@pytest.mark.asyncio
@respx.mock
async def test_pages_are_paced_like_windows(monkeypatch):
    """Every request after the first — page or window — respects the rate
    limit: three pages, two waits."""
    waited: list[float] = []

    async def write_down(seconds: float) -> None:
        waited.append(seconds)

    monkeypatch.delenv(nvd.API_KEY_ENV, raising=False)
    nvd_answering(lambda: page(0), lambda: page(1), lambda: page(2))
    results = await nvd.fetch_cves(KEYWORD, days_back=7, wait=write_down)
    assert len(results) == 3
    assert waited == [nvd.KEYLESS_DELAY_SECONDS] * 2


@pytest.mark.asyncio
@respx.mock
async def test_a_later_page_that_fails_keeps_the_earlier_ones():
    """A refused page must not lose the ones already received: they travel as
    `partial`, which the API and the CLI already store."""
    nvd_answering(lambda: page(0), lambda: page(1), refusal)
    with pytest.raises(CollectorError) as caught:
        await nvd.fetch_cves(KEYWORD, days_back=7)
    assert caught.value.status == 404
    assert [r["id"] for r in caught.value.partial] == IDS[:2]


@pytest.mark.asyncio
@respx.mock
async def test_an_empty_page_before_the_total_is_not_a_complete_answer():
    """NVD states three results and stops sending them after one: that is an
    incomplete result and must be reported as one, not presented as the whole
    answer."""
    nvd_answering(lambda: page(0), empty_page, lambda: page(2))
    with pytest.raises(CollectorError) as caught:
        await nvd.fetch_cves(KEYWORD, days_back=7)
    assert [r["id"] for r in caught.value.partial] == IDS[:1]
