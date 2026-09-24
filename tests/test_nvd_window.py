"""NVD refuses a date range longer than 120 days, so long windows are split.

Measured against the live API on 2026-09-23, keyword "openssl":

    days_back=119 -> HTTP 200
    days_back=120 -> HTTP 404
    days_back=121 -> HTTP 404

The cut is sharp and 404 is a confusing way to be told "your range is too
wide": it reads as "no such endpoint". `--days 180` simply returned nothing,
and the collector — which correctly refuses to turn a failure into an empty
list — reported the scan as incomplete.

A window is 120 days inclusive of both ends, so chunks are capped at 119 days
back from their own end: the same arithmetic that made 119 the last value to
work.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from patchradar.collectors import nvd


def windows(days: int) -> list[tuple[datetime, datetime]]:
    return nvd.date_windows(days, now=datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc))


def span_days(start: datetime, end: datetime) -> float:
    return (end - start).total_seconds() / 86400


# --------------------------------------------------------------------------
# splitting
# --------------------------------------------------------------------------


@pytest.mark.parametrize("days", [1, 7, 30, 90, 119])
def test_a_window_that_nvd_accepts_is_left_whole(days):
    """No pointless second request for the ordinary case."""
    assert len(windows(days)) == 1


@pytest.mark.parametrize("days", [120, 121, 200, 365, 1000])
def test_a_window_nvd_would_refuse_is_split(days):
    assert len(windows(days)) > 1


@pytest.mark.parametrize("days", [1, 119, 120, 121, 200, 365, 1000, 3650])
def test_no_chunk_is_ever_wide_enough_to_be_refused(days):
    """The property that matters: every request must be one NVD will answer."""
    for start, end in windows(days):
        assert span_days(start, end) <= 120.0, f"{days}: {start} to {end}"


@pytest.mark.parametrize("days", [1, 119, 120, 365, 1000])
def test_the_chunks_cover_the_whole_period_without_a_gap(days):
    """A gap would silently drop CVEs published inside it."""
    chunks = windows(days)
    now = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)

    assert chunks[0][0] <= now - timedelta(days=days)
    assert chunks[-1][1] >= now
    for (_, earlier_end), (later_start, _) in zip(chunks, chunks[1:]):
        assert later_start <= earlier_end, "gap between chunks"


@pytest.mark.parametrize("days", [120, 365, 1000])
def test_the_chunks_come_back_in_order(days):
    chunks = windows(days)
    assert chunks == sorted(chunks)


def test_the_boundary_that_was_measured():
    """119 whole, 120 split — the exact line the live API drew."""
    assert len(windows(119)) == 1
    assert len(windows(120)) == 2


@pytest.mark.parametrize("days", [0, -1, -400])
def test_a_window_of_nothing_is_refused_rather_than_guessed_at(days):
    with pytest.raises(ValueError):
        windows(days)


# --------------------------------------------------------------------------
# using it
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_long_window_makes_several_requests(monkeypatch):
    calls: list[dict] = []

    async def fake_get(self, url, params=None, **kwargs):
        calls.append(params)
        return _Response({"vulnerabilities": []})

    monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
    await nvd.fetch_cves("openssl", days_back=365)

    assert len(calls) >= 4
    for params in calls:
        start = datetime.strptime(params["pubStartDate"][:19], "%Y-%m-%dT%H:%M:%S")
        end = datetime.strptime(params["pubEndDate"][:19], "%Y-%m-%dT%H:%M:%S")
        assert (end - start).days <= 120


@pytest.mark.asyncio
async def test_the_results_of_every_chunk_are_kept(monkeypatch):
    """Splitting must not lose what the later requests found."""
    seen = {"n": 0}

    async def fake_get(self, url, params=None, **kwargs):
        seen["n"] += 1
        return _Response({"vulnerabilities": [
            {"cve": {"id": f"CVE-2026-{seen['n']:04d}",
                     "descriptions": [{"lang": "en", "value": "x"}],
                     "metrics": {}, "published": "2026-01-01T00:00:00.000"}}
        ]})

    monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
    found = await nvd.fetch_cves("openssl", days_back=365)

    ids = {cve.get("cve_id") or cve.get("id") for cve in found}
    assert len(ids) == seen["n"] >= 4


@pytest.mark.asyncio
async def test_a_short_window_still_makes_one_request(monkeypatch):
    calls = []

    async def fake_get(self, url, params=None, **kwargs):
        calls.append(params)
        return _Response({"vulnerabilities": []})

    monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
    await nvd.fetch_cves("openssl", days_back=7)

    assert len(calls) == 1


class _Response:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None
