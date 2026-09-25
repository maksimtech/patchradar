"""NVD rate-limits keyless clients, and splitting long windows multiplies requests.

Without an API key NVD allows 5 requests per rolling 30 seconds; with one, 50.
`patchradar scan --days 730` on a 16-entry watchlist now issues seven windowed
requests per keyword — 112 in all — where before the window fix it issued 16 and
got a 404 for each. Fixing the window therefore made the rate limit reachable in
ordinary use, and a keyless burst comes back 403 or 429, which the scan correctly
reports as incomplete results.

Two things follow, and neither is about parsing:

- an API key, if the user has one, has to be sent. It is `NVD_API_KEY` in the
  environment, the name NVD's own documentation uses, and it goes in the `apiKey`
  header — never in the query string, which ends up in logs.
- consecutive windows have to be paced. NVD's published guidance is roughly one
  request every six seconds without a key and 0.6 with, so that is the interval
  between windows of the same keyword. The single-window case — every ordinary
  `--days 7` scan — must not pay for it.

Measured on 2026-09-23 against the live API; the rate limit is documented at
https://nvd.nist.gov/developers/start-here.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx

from patchradar.collectors import nvd
from patchradar.collectors.errors import CollectorError

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EMPTY = {"vulnerabilities": []}


@pytest.fixture(autouse=True)
def no_key(monkeypatch):
    """Every test states its own key, so the developer's own must not leak in."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)


@pytest.fixture
def instant(monkeypatch):
    """Record the pacing instead of waiting for it."""
    slept: list[float] = []

    async def record(seconds):
        slept.append(seconds)

    # The collector's own seam. Patching asyncio.sleep would reach every
    # coroutine in the process, including other tests' simulated hangs.
    monkeypatch.setattr(nvd, "_pace", record)
    return slept


# ── the key ─────────────────────────────────────────────────────────────────


def test_no_key_configured_is_not_an_error(monkeypatch):
    assert nvd.api_key() is None


@pytest.mark.parametrize("value", ["", "   ", "\n"])
def test_a_blank_key_counts_as_none(monkeypatch, value):
    """An unset variable and an empty one mean the same thing to the user."""
    monkeypatch.setenv("NVD_API_KEY", value)

    assert nvd.api_key() is None


def test_the_key_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  abcd-1234  ")

    assert nvd.api_key() == "abcd-1234"


@pytest.mark.asyncio
@respx.mock
async def test_the_key_is_sent_as_a_header(monkeypatch, instant):
    monkeypatch.setenv("NVD_API_KEY", "abcd-1234")
    route = respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=7)

    assert route.calls[0].request.headers.get("apiKey") == "abcd-1234"


@pytest.mark.asyncio
@respx.mock
async def test_the_key_never_goes_in_the_query_string(monkeypatch, instant):
    """A URL with a secret in it is written to logs and proxy records."""
    monkeypatch.setenv("NVD_API_KEY", "abcd-1234")
    respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=7)

    assert "abcd-1234" not in str(respx.calls[0].request.url)


@pytest.mark.asyncio
@respx.mock
async def test_without_a_key_no_header_is_sent(instant):
    route = respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=7)

    assert "apiKey" not in route.calls[0].request.headers


# ── the pacing ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_one_window_waits_for_nothing(instant):
    """`--days 7` is the ordinary case and must stay as fast as it was."""
    respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=7)

    assert instant == []


@pytest.mark.asyncio
@respx.mock
async def test_consecutive_windows_are_paced(instant):
    """Three windows: two gaps, one before each request after the first."""
    respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=300)

    assert len(instant) == len(nvd.date_windows(300)) - 1
    assert all(seconds == nvd.KEYLESS_DELAY_SECONDS for seconds in instant)


@pytest.mark.asyncio
@respx.mock
async def test_a_key_buys_a_shorter_wait(monkeypatch, instant):
    monkeypatch.setenv("NVD_API_KEY", "abcd-1234")
    respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=EMPTY))

    await nvd.fetch_cves("openssl", days_back=300)

    assert instant, "a multi-window fetch with a key still needs pacing"
    assert all(seconds == nvd.KEYED_DELAY_SECONDS for seconds in instant)


def test_the_intervals_match_the_published_limits():
    """5 requests per 30 s keyless, 50 with a key.

    Compared exactly rather than approximately: each side is the same single
    division, so both are the same double by construction. No accumulation, no
    rounding to allow for.
    """
    assert nvd.KEYLESS_DELAY_SECONDS == 30 / 5
    assert nvd.KEYED_DELAY_SECONDS == 30 / 50


@pytest.mark.asyncio
@respx.mock
async def test_the_pacing_does_not_outlive_a_failure(instant):
    """A window that fails aborts the fetch; it does not sleep on the way out."""
    respx.get(NVD_URL).mock(return_value=httpx.Response(403, json={}))

    with pytest.raises(CollectorError):
        await nvd.fetch_cves("openssl", days_back=300)

    assert instant == []


# ── what the windows are, unchanged ─────────────────────────────────────────


def test_the_window_split_is_untouched_by_any_of_this():
    """The fix that made the requests numerous stays exactly as measured."""
    windows = nvd.date_windows(730, now=datetime(2026, 9, 23, 12, 0, tzinfo=UTC))

    assert len(windows) == 7
    assert all(
        (end - start).days <= nvd.NVD_MAX_WINDOW_DAYS for start, end in windows
    )
