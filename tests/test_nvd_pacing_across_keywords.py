"""
PatchRadar — NVD's rate limit counts requests, not keywords

The collector paces the requests of one `fetch_cves` call: a two-year window
makes seven of them, six seconds apart without a key. A watchlist scan makes
one call per keyword, though, and between two calls nothing waited — each one
started with `sent = 0`, so ten keywords with a 30-day window sent ten requests
as fast as NVD answered them, against a limit of five per rolling thirty
seconds. README promises the opposite: "PatchRadar paces its requests to stay
under whichever limit applies, which makes a keyless scan slower rather than
incomplete."

Measured on 2026-10-09 the scan got away with it, at ten keywords in 100
seconds, because every keyword also downloaded 20 MB from MSRC in between. With
that download cached (see test_msrc_cache.py) the same scan reaches NVD five
times in well under thirty seconds, and the first 403 lands on the sixth
keyword — which is what the pacing was written to prevent.

So the moment of the last request is kept in the module, and a call that
starts less than one interval after it waits for the remainder before its first
request. A call that starts later waits for nothing, which keeps `--days 7`
on a single keyword exactly as fast as it was.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from patchradar.collectors import nvd
from patchradar.collectors.errors import CollectorError

EMPTY = {"vulnerabilities": []}


@pytest.fixture
def paced(monkeypatch):
    """A clock that stands still and a `wait` that writes down what it was
    asked, so the remainder is exact rather than "about six seconds"."""
    monkeypatch.delenv(nvd.API_KEY_ENV, raising=False)
    monkeypatch.setattr(nvd, "_monotonic", lambda: 1000.0)
    waited: list[float] = []

    async def write_down(seconds: float) -> None:
        waited.append(seconds)

    return waited, write_down


@pytest.mark.asyncio
@respx.mock
async def test_the_second_keyword_waits_for_the_interval(paced):
    waited, write_down = paced
    respx.get(nvd.NVD_API).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=7, wait=write_down)
    await nvd.fetch_cves("curl", days_back=7, wait=write_down)

    assert waited == [nvd.KEYLESS_DELAY_SECONDS]


@pytest.mark.asyncio
@respx.mock
async def test_only_the_remainder_is_waited(paced, monkeypatch):
    """Two seconds have passed since the last request: four are left to wait."""
    waited, write_down = paced
    respx.get(nvd.NVD_API).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=7, wait=write_down)
    monkeypatch.setattr(nvd, "_monotonic", lambda: 1002.0)
    await nvd.fetch_cves("curl", days_back=7, wait=write_down)

    assert waited == [pytest.approx(nvd.KEYLESS_DELAY_SECONDS - 2.0)]


@pytest.mark.asyncio
@respx.mock
async def test_a_keyword_scanned_after_the_interval_waits_for_nothing(paced, monkeypatch):
    waited, write_down = paced
    respx.get(nvd.NVD_API).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=7, wait=write_down)
    monkeypatch.setattr(nvd, "_monotonic", lambda: 1000.0 + nvd.KEYLESS_DELAY_SECONDS)
    await nvd.fetch_cves("curl", days_back=7, wait=write_down)

    assert waited == []


@pytest.mark.asyncio
@respx.mock
async def test_a_key_shortens_the_wait_between_keywords(paced, monkeypatch):
    waited, write_down = paced
    monkeypatch.setenv(nvd.API_KEY_ENV, "abcd-1234")
    respx.get(nvd.NVD_API).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=7, wait=write_down)
    await nvd.fetch_cves("curl", days_back=7, wait=write_down)

    assert waited == [nvd.KEYED_DELAY_SECONDS]


@pytest.mark.asyncio
@respx.mock
async def test_a_failed_request_still_counts_against_the_limit(paced):
    """NVD counted it — a 403 is the limit speaking — so the next keyword waits."""
    waited, write_down = paced
    respx.get(nvd.NVD_API).mock(side_effect=[httpx.Response(403), httpx.Response(200, json=EMPTY)])

    with pytest.raises(CollectorError):
        await nvd.fetch_cves("openssl", days_back=7, wait=write_down)
    await nvd.fetch_cves("curl", days_back=7, wait=write_down)

    assert waited == [nvd.KEYLESS_DELAY_SECONDS]


def test_the_suite_starts_every_test_with_no_request_on_record():
    """`conftest._no_rate_limit_pacing` resets it — asserted, so a test that
    counts waits is not handed the previous test's last request."""
    assert nvd._last_request_at is None
