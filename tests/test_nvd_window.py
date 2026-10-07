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

from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest
from typer.testing import CliRunner

import patchradar.cli as cli
from patchradar.collectors import nvd


def windows(days: int) -> list[tuple[datetime, datetime]]:
    return nvd.date_windows(days, now=datetime(2026, 9, 23, 12, 0, tzinfo=UTC))


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
    now = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)

    assert chunks[0][0] <= now - timedelta(days=days)
    assert chunks[-1][1] >= now
    for (_, earlier_end), (later_start, _) in pairwise(chunks):
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


def test_the_cli_refuses_a_window_of_nothing_without_a_traceback(monkeypatch):
    """`patchradar scan x --days 0` must end in a usage error, not a traceback:
    the ValueError above is not a CollectorError, and it went through the
    whole CLI."""
    async def nothing(*args, **kwargs):
        return []

    monkeypatch.setattr(cli, "msrc_fetch", nothing)
    monkeypatch.setattr(cli, "kev_fetch", nothing)
    result = CliRunner().invoke(cli.app, ["scan", "nginx", "--days", "0"])
    assert not isinstance(result.exception, ValueError), repr(result.exception)
    assert result.exit_code != 0


@pytest.mark.parametrize("days", ["0", "-1", "-400"])
def test_the_cli_refuses_a_window_of_nothing_as_a_usage_error(monkeypatch, days):
    """A usage error (exit 2, as for any invalid Typer option) before any
    request: no collector is asked anything."""
    async def must_not_run(*args, **kwargs):
        raise AssertionError("a collector ran for an invalid --days")

    for name in ("fetch_cves", "msrc_fetch", "kev_fetch"):
        monkeypatch.setattr(cli, name, must_not_run)
    result = CliRunner().invoke(cli.app, ["scan", "nginx", "--days", days])
    assert result.exit_code == 2, result.output


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


def _sent_windows(calls: list[dict]) -> list[tuple[datetime, datetime]]:
    return sorted((datetime.fromisoformat(params["pubStartDate"]),
                   datetime.fromisoformat(params["pubEndDate"])) for params in calls)


@pytest.mark.asyncio
async def test_the_windows_sent_to_nvd_do_not_overlap(monkeypatch):
    """Adjacent windows must not ask for the same day twice. The request covers
    whole days, so a window ending at 'D 23:59:59.999' followed by one starting
    at 'D 00:00:00.000' returned the CVEs published on D twice — and the API
    counted them twice."""
    calls: list[dict] = []

    async def fake_get(self, url, params=None, **kwargs):
        calls.append(params)
        return _Response({"totalResults": 0, "vulnerabilities": []})

    monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
    await nvd.fetch_cves("nginx", days_back=200)

    sent = _sent_windows(calls)
    assert len(sent) >= 2
    for (_, end_prev), (start_next, _) in pairwise(sent):
        assert end_prev < start_next, f"windows overlap: {end_prev} >= {start_next}"


@pytest.mark.asyncio
async def test_the_windows_sent_to_nvd_leave_no_gap(monkeypatch):
    """Removing the overlap must not open a hole: window N+1 starts on the
    millisecond after window N ends."""
    calls: list[dict] = []

    async def fake_get(self, url, params=None, **kwargs):
        calls.append(params)
        return _Response({"totalResults": 0, "vulnerabilities": []})

    monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
    await nvd.fetch_cves("nginx", days_back=365)

    sent = _sent_windows(calls)
    assert len(sent) >= 4
    for (_, end_prev), (start_next, _) in pairwise(sent):
        assert start_next - end_prev == timedelta(milliseconds=1)
    for start, end in sent:
        assert (end - start) < timedelta(days=120)


class _Response:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None
