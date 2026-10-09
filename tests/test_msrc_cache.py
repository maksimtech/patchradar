"""
PatchRadar — one download per MSRC month per scan, not one per watched product

Measured on 2026-10-09: the September 2026 CVRF document is 20,492,679 bytes,
and `patchradar scan --days 30` over a ten-entry watchlist fetched it ten
times, once per keyword, plus October's ten times — some 210 MB for two
documents that do not change between one keyword and the next. The Debian
tracker and the KEV catalogue are each downloaded once and filtered in memory
for the same reason; MSRC was the one source still paying per keyword.

A document is cached for an hour, like the other two. A month MSRC has no
document for yet (404) is not cached — the answer is small and the document may
appear within the hour — and a failed download is never cached, so one outage
does not poison the scan for every keyword after it.

The fixture is the September 2026 document, recorded: six entries verbatim.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime

import httpx
import pytest
import respx

from patchradar.collectors import msrc
from patchradar.collectors.errors import CollectorError

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SEPTEMBER = json.loads((FIXTURES / "msrc_2026_sep_excerpt.json").read_text(encoding="utf-8"))
assert "verbatim" in SEPTEMBER.pop("_derived")

RECORDED = datetime(2026, 10, 9, 12, 0)
SEP = f"{msrc.MSRC_API}/cvrf/2026-Sep"
OCT = f"{msrc.MSRC_API}/cvrf/2026-Oct"


async def fetch(keyword: str) -> list[str]:
    return [r["id"] for r in await msrc.fetch_cves(keyword, days_back=60, now=RECORDED)]


@pytest.mark.asyncio
@respx.mock
async def test_a_month_is_downloaded_once_for_the_whole_watchlist():
    september = respx.get(SEP).mock(return_value=httpx.Response(200, json=SEPTEMBER))
    respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))

    assert await fetch("sharepoint") == ["CVE-2026-69268"]
    assert await fetch("chromium") == ["CVE-2026-85046"]
    assert await fetch("netlogon") == ["CVE-2026-62759"]

    assert september.call_count == 1, f"September downloaded {september.call_count}x for three keywords"


@pytest.mark.asyncio
@respx.mock
async def test_a_month_with_no_document_yet_is_asked_again():
    """404 is "not published yet", and the document may appear within the hour."""
    respx.get(SEP).mock(return_value=httpx.Response(200, json=SEPTEMBER))
    october = respx.get(OCT).mock(return_value=httpx.Response(404))
    respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))

    await fetch("sharepoint")
    await fetch("chromium")

    assert october.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_a_failed_download_is_not_cached():
    september = respx.get(SEP).mock(side_effect=[httpx.Response(503),
                                                 httpx.Response(200, json=SEPTEMBER)])
    respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))

    with pytest.raises(CollectorError) as exc:
        await fetch("sharepoint")
    assert exc.value.reason == "server_error"

    assert await fetch("sharepoint") == ["CVE-2026-69268"]
    assert september.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_clear_cache_forces_a_new_download():
    september = respx.get(SEP).mock(return_value=httpx.Response(200, json=SEPTEMBER))
    respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))

    await fetch("sharepoint")
    msrc.clear_cache()
    await fetch("sharepoint")

    assert september.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_an_expired_document_is_downloaded_again(monkeypatch):
    september = respx.get(SEP).mock(return_value=httpx.Response(200, json=SEPTEMBER))
    respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))

    await fetch("sharepoint")
    monkeypatch.setattr(msrc, "CACHE_TTL_SECONDS", -1)
    await fetch("sharepoint")

    assert september.call_count == 2


def test_the_suite_starts_every_test_with_no_document_cached():
    """`conftest.reset_msrc_documents` — asserted, like the KEV guard is: a test
    that mocks one month's answer must not be fed another test's document."""
    assert msrc._documents == {}
