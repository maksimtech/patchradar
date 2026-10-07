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

import httpx
import pytest
import respx

from patchradar.collectors import nvd
from patchradar.collectors.errors import CollectorError

PAGE = 50


def nvd_item(cve_id: str, published: str = "2026-09-01T10:00:00.000") -> dict:
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "descriptions": [{"lang": "en", "value": f"desc {cve_id}"}],
            "metrics": {},
        }
    }


def paged_nvd(total: int, failing_start: int | None = None, empty_from: int | None = None):
    """A fake NVD that pages `total` CVEs in blocks of 50, as it would with a
    `resultsPerPage` smaller than the total."""
    def answer(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params.get("startIndex", "0"))
        if failing_start is not None and start >= failing_start:
            return httpx.Response(503)
        stop = start if empty_from is not None and start >= empty_from else min(start + PAGE, total)
        items = [nvd_item(f"CVE-2026-{i:05d}") for i in range(start, stop)]
        return httpx.Response(200, json={"resultsPerPage": len(items), "startIndex": start,
                                         "totalResults": total, "vulnerabilities": items})
    return answer


@pytest.mark.asyncio
@respx.mock
async def test_the_fetch_follows_the_pages_beyond_the_first():
    """60 CVEs stated, 50 per page: the second page has to be asked for, rather
    than the answer being cut at 50 without a word."""
    page1 = [nvd_item(f"CVE-2026-{i:05d}") for i in range(50)]
    page2 = [nvd_item(f"CVE-2026-{i:05d}") for i in range(50, 60)]

    def answer(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params.get("startIndex", "0"))
        items = page1 if start == 0 else page2 if start == 50 else []
        return httpx.Response(200, json={
            "resultsPerPage": len(items), "startIndex": start,
            "totalResults": 60, "vulnerabilities": items,
        })

    respx.get(nvd.NVD_API).mock(side_effect=answer)
    results = await nvd.fetch_cves("nginx", days_back=7)
    assert len({r["id"] for r in results}) == 60


@pytest.mark.asyncio
@respx.mock
async def test_the_largest_page_nvd_allows_is_asked_for():
    """2000 is NVD's documented maximum: fewer requests, less of the quota."""
    route = respx.get(nvd.NVD_API).mock(side_effect=paged_nvd(0))
    await nvd.fetch_cves("nginx", days_back=7)
    assert route.calls[0].request.url.params["resultsPerPage"] == "2000"
    assert route.calls[0].request.url.params["startIndex"] == "0"


@pytest.mark.asyncio
@respx.mock
async def test_pages_are_paced_like_windows(monkeypatch):
    """Every request after the first — page or window — respects the rate
    limit: three pages, two waits."""
    slept: list[float] = []

    async def record(seconds):
        slept.append(seconds)

    monkeypatch.setattr(nvd, "_pace", record)
    monkeypatch.delenv(nvd.API_KEY_ENV, raising=False)
    respx.get(nvd.NVD_API).mock(side_effect=paged_nvd(120))
    results = await nvd.fetch_cves("nginx", days_back=7)
    assert len(results) == 120
    assert slept == [nvd.KEYLESS_DELAY_SECONDS] * 2


@pytest.mark.asyncio
@respx.mock
async def test_a_later_page_that_fails_keeps_the_earlier_ones():
    """A failed page must not lose the ones already received: they travel as
    `partial`, which the API and the CLI already store."""
    respx.get(nvd.NVD_API).mock(side_effect=paged_nvd(120, failing_start=100))
    with pytest.raises(CollectorError) as caught:
        await nvd.fetch_cves("nginx", days_back=7)
    assert len(caught.value.partial) == 100


@pytest.mark.asyncio
@respx.mock
async def test_an_empty_page_before_the_total_is_not_a_complete_answer():
    """NVD states 120 results and stops sending them at 50: that is an incomplete
    result and must be reported as one, not presented as the whole answer."""
    respx.get(nvd.NVD_API).mock(side_effect=paged_nvd(120, empty_from=50))
    with pytest.raises(CollectorError) as caught:
        await nvd.fetch_cves("nginx", days_back=7)
    assert len(caught.value.partial) == 50
