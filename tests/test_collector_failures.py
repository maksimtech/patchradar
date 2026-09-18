"""
PatchRadar — upstream failures must not look like "no CVEs" (W10)

Every collector swallowed every failure and returned []:

    except Exception:
        return []

So an NVD 403/429 (NVD rate-limits keyless clients at 5 requests per 30 s), a
Debian 503, a DNS failure or a proxy answering with HTML all produced exactly
the output of a clean scan: "nginx — no CVEs found in last 7 days". In a
vulnerability monitor that is the worst possible failure mode — a false
all-clear.

Collectors now raise CollectorError(source, reason, status, partial). Callers
save whatever partial results exist and report each failed source.
"""
from io import StringIO

import httpx
import pytest
import respx
from httpx import ASGITransport, AsyncClient
from rich.console import Console

import patchradar.api.main as api
import patchradar.cli as cli
from patchradar.collectors import debian, msrc, nvd
from patchradar.collectors.errors import CollectorError
from patchradar.db.database import add_to_watchlist, get_cves

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"
MSRC_PREFIX = "https://api.msrc.microsoft.com"


def nvd_ok(cve_id="CVE-2026-0001"):
    return httpx.Response(200, json={"vulnerabilities": [{"cve": {
        "id": cve_id, "descriptions": [{"lang": "en", "value": "nginx bug"}],
        "metrics": {}, "published": "2026-09-01T00:00:00"}}]})


def msrc_doc(cve_id):
    return httpx.Response(200, json={"Vulnerability": [{
        "CVE": cve_id, "Title": {"Value": "nginx issue"},
        "Notes": [{"Type": 1, "Value": "nginx"}], "CVSSScoreSets": [{"BaseScore": 7.5}],
        "RevisionHistory": [{"Date": "2026-09-09"}]}]})


def by_call(first, second, rest):
    """MSRC side effect independent of today's date.

    How many months are queried depends on the calendar (days_back=60 spans
    three or four months), so a fixed-length iterator would run dry or never
    reach the failure. Call 0 -> first, call 1 -> second, then `rest`.
    """
    calls = []

    def handler(request):
        calls.append(request)
        n = len(calls) - 1
        return first if n == 0 else second if n == 1 else rest
    return handler


# ─── NVD ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("status, reason", [
    (429, "rate_limited"),
    (403, "forbidden"),       # NVD answers keyless over-quota clients with 403
    (500, "server_error"),
    (503, "server_error"),
    (400, "http_error"),
])
async def test_nvd_http_failures_raise(status, reason):
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(status))
        with pytest.raises(CollectorError) as exc:
            await nvd.fetch_cves("nginx")
    assert exc.value.source == "NVD"
    assert exc.value.reason == reason
    assert exc.value.status == status


@pytest.mark.asyncio
@pytest.mark.parametrize("side_effect", [
    httpx.ConnectError("dns"), httpx.ReadTimeout("slow"), httpx.ConnectTimeout("slow"),
])
async def test_nvd_network_failures_raise(side_effect):
    with respx.mock:
        respx.get(NVD_URL).mock(side_effect=side_effect)
        with pytest.raises(CollectorError) as exc:
            await nvd.fetch_cves("nginx")
    assert exc.value.reason == "network"
    assert exc.value.status is None


@pytest.mark.asyncio
async def test_nvd_non_json_body_raises():
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, text="<html>captive portal</html>"))
        with pytest.raises(CollectorError) as exc:
            await nvd.fetch_cves("nginx")
    assert exc.value.reason == "bad_payload"


@pytest.mark.asyncio
async def test_nvd_genuinely_empty_result_is_not_an_error():
    """The distinction W10 is about: a clean empty answer stays []."""
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
        assert await nvd.fetch_cves("nginx") == []


# ─── MSRC ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_msrc_unpublished_month_404_is_not_an_error():
    with respx.mock:
        respx.get(url__startswith=MSRC_PREFIX).mock(return_value=httpx.Response(404))
        assert await msrc.fetch_cves("nginx", days_back=60) == []


@pytest.mark.asyncio
async def test_msrc_partial_failure_keeps_the_months_that_worked():
    handler = by_call(msrc_doc("CVE-2026-GOOD"), httpx.Response(429), msrc_doc("CVE-2026-ALSO"))
    with respx.mock:
        respx.get(url__startswith=MSRC_PREFIX).mock(side_effect=handler)
        with pytest.raises(CollectorError) as exc:
            await msrc.fetch_cves("nginx", days_back=60)
    assert exc.value.source == "MSRC"
    assert exc.value.reason == "rate_limited"
    assert {c["id"] for c in exc.value.partial} == {"CVE-2026-GOOD", "CVE-2026-ALSO"}


@pytest.mark.asyncio
async def test_msrc_network_failure_raises():
    with respx.mock:
        respx.get(url__startswith=MSRC_PREFIX).mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(CollectorError) as exc:
            await msrc.fetch_cves("nginx", days_back=7)
    assert exc.value.reason == "network"


# ─── Debian ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("status, reason", [(429, "rate_limited"), (503, "server_error")])
async def test_debian_download_failure_raises(status, reason):
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(status))
        with pytest.raises(CollectorError) as exc:
            await debian.fetch_cves("nginx")
    assert exc.value.source == "Debian"
    assert exc.value.reason == reason


@pytest.mark.asyncio
async def test_debian_failure_is_not_cached():
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(503))
        with pytest.raises(CollectorError):
            await debian.fetch_cves("nginx")
    with respx.mock:
        route = respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json={}))
        assert await debian.fetch_cves("nginx") == []
    assert route.call_count == 1


def test_collector_error_is_readable():
    err = CollectorError("NVD", "rate_limited", status=429)
    assert "NVD" in str(err) and "429" in str(err)


# ─── API ─────────────────────────────────────────────────────────────────────

@pytest.fixture
async def client():
    await add_to_watchlist("nginx")
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://t") as ac:
        yield ac


@pytest.mark.asyncio
async def test_scan_reports_failed_sources(client):
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(429))
        respx.get(url__startswith=MSRC_PREFIX).mock(return_value=httpx.Response(404))
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json={}))
        body = (await client.post("/api/scan?days=7")).json()
    assert body["errors"] == [{"software": "nginx", "source": "NVD",
                               "reason": "rate_limited", "status": 429}]


@pytest.mark.asyncio
async def test_clean_scan_reports_no_errors(client):
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
        respx.get(url__startswith=MSRC_PREFIX).mock(return_value=httpx.Response(404))
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json={}))
        body = (await client.post("/api/scan?days=7")).json()
    assert body["errors"] == []
    assert body["total"] == 0


@pytest.mark.asyncio
async def test_one_failed_source_does_not_discard_the_others(client):
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=nvd_ok("CVE-2026-NVD1"))
        respx.get(url__startswith=MSRC_PREFIX).mock(side_effect=httpx.ConnectError("down"))
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(503))
        body = (await client.post("/api/scan?days=7")).json()
    assert body["total"] == 1
    assert {e["source"] for e in body["errors"]} == {"MSRC", "Debian"}
    assert [c["id"] for c in await get_cves(software="nginx")] == ["CVE-2026-NVD1"]


@pytest.mark.asyncio
async def test_partial_results_are_saved(client):
    # days=30 always spans at least two months, so the 500 is always reached
    handler = by_call(msrc_doc("CVE-2026-PART"), httpx.Response(500), httpx.Response(500))
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
        respx.get(url__startswith=MSRC_PREFIX).mock(side_effect=handler)
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json={}))
        body = (await client.post("/api/scan?days=30")).json()
    assert body["total"] == 1
    assert body["errors"][0]["source"] == "MSRC"
    assert [c["id"] for c in await get_cves(software="nginx")] == ["CVE-2026-PART"]


# ─── CLI ─────────────────────────────────────────────────────────────────────

def run_scan_target(monkeypatch, nvd_behaviour, msrc_behaviour):
    async def fake_nvd(target, days_back=7):
        if isinstance(nvd_behaviour, Exception):
            raise nvd_behaviour
        return nvd_behaviour

    async def fake_msrc(target, days_back=7):
        if isinstance(msrc_behaviour, Exception):
            raise msrc_behaviour
        return msrc_behaviour

    monkeypatch.setattr(cli, "fetch_cves", fake_nvd)
    monkeypatch.setattr(cli, "msrc_fetch", fake_msrc)
    buf = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=buf, width=300, force_terminal=False))
    count = cli.run(cli._scan_target("nginx", 7))
    return count, buf.getvalue()


def test_cli_does_not_claim_all_clear_when_a_source_failed(monkeypatch):
    count, out = run_scan_target(monkeypatch, CollectorError("NVD", "rate_limited", status=429), [])
    assert "no CVEs found" not in out, "a failed scan was reported as a clean one"
    assert "NVD" in out and "429" in out
    assert count == 0


def test_cli_still_reports_all_clear_when_every_source_answered(monkeypatch):
    _, out = run_scan_target(monkeypatch, [], [])
    assert "no CVEs found" in out


def test_cli_prints_partial_results_and_the_failure(monkeypatch):
    partial = [{"id": "CVE-2026-PART", "software": "nginx", "description": "d",
                "cvss_score": 7.5, "severity": "HIGH", "source": "MSRC"}]
    count, out = run_scan_target(monkeypatch, [],
                                 CollectorError("MSRC", "server_error", status=500, partial=partial))
    assert count == 1
    assert "CVE-2026-PART" in out
    assert "MSRC" in out and "500" in out


def test_cli_failure_message_is_escaped(monkeypatch):
    """The reason text reaches Rich markup; it must not be interpreted."""
    _, out = run_scan_target(monkeypatch, CollectorError("NVD", "network", detail="bad [/x] thing"), [])
    assert "bad [/x] thing" in out
