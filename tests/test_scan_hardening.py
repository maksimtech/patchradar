"""
PatchRadar — /api/scan hardening (G6)

Three separate defects on one endpoint:

* the Debian tracker (~75 MB) was re-downloaded once per watched package;
* the scan had no overall deadline, so one request could occupy a worker for
  hours (MSRC 4x30s + NVD 30s + Debian 60s, times an unbounded watchlist);
* the endpoint was unauthenticated while the Docker image binds 0.0.0.0.
"""
import asyncio

import httpx
import pytest
import respx
from httpx import ASGITransport, AsyncClient

import patchradar.api.main as api
import patchradar.collectors.debian as debian
from patchradar.db import database

DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

WATCHED = ["nginx", "apache", "redis", "postgresql", "openssl"]


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Never touch the real ~/.patchradar database from a test."""
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "patchradar.db")
    yield


@pytest.fixture(autouse=True)
def clear_debian_cache():
    debian.clear_cache()
    yield
    debian.clear_cache()


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    """Default to the unauthenticated posture; auth tests opt in."""
    monkeypatch.delenv(api.API_KEY_ENV, raising=False)
    yield


@pytest.fixture
async def client(tmp_path):
    await database.init_db()
    for sw in WATCHED:
        await database.add_to_watchlist(sw)
    async with AsyncClient(
        transport=ASGITransport(app=api.app), base_url="http://test", timeout=60
    ) as ac:
        yield ac


def mock_collectors():
    """Route every collector to an in-process mock and count Debian hits."""
    counter = {"debian": 0, "nvd": 0, "msrc": 0}

    def debian_handler(request):
        counter["debian"] += 1
        return httpx.Response(200, json={})

    def nvd_handler(request):
        counter["nvd"] += 1
        return httpx.Response(200, json={"vulnerabilities": []})

    def msrc_handler(request):
        counter["msrc"] += 1
        return httpx.Response(404)

    respx.get(DEBIAN_URL).mock(side_effect=debian_handler)
    respx.get(NVD_URL).mock(side_effect=nvd_handler)
    respx.get(url__startswith="https://api.msrc.microsoft.com").mock(side_effect=msrc_handler)
    return counter


# ─── Debian snapshot cache ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_downloads_debian_tracker_once(client):
    """One /api/scan must download the 75 MB tracker exactly once, not once
    per watched package."""
    with respx.mock:
        counter = mock_collectors()
        r = await client.post("/api/scan?days=7")
    assert r.status_code == 200
    assert counter["debian"] == 1, (
        f"tracker downloaded {counter['debian']}x for {len(WATCHED)} packages "
        f"(~{counter['debian'] * 75} MB)"
    )
    # the per-package collectors are still called once each
    assert counter["nvd"] == len(WATCHED)


@pytest.mark.asyncio
async def test_repeated_fetch_cves_reuses_snapshot():
    with respx.mock:
        counter = mock_collectors()
        for sw in WATCHED:
            await debian.fetch_cves(sw)
    assert counter["debian"] == 1


@pytest.mark.asyncio
async def test_clear_cache_forces_refetch():
    with respx.mock:
        counter = mock_collectors()
        await debian.fetch_cves("nginx")
        debian.clear_cache()
        await debian.fetch_cves("nginx")
    assert counter["debian"] == 2


@pytest.mark.asyncio
async def test_expired_snapshot_is_refetched(monkeypatch):
    with respx.mock:
        counter = mock_collectors()
        await debian.fetch_cves("nginx")
        monkeypatch.setattr(debian, "CACHE_TTL_SECONDS", -1)
        await debian.fetch_cves("nginx")
    assert counter["debian"] == 2


@pytest.mark.asyncio
async def test_concurrent_fetches_share_one_download():
    """A stampede of concurrent scans must not each start a 75 MB download."""
    with respx.mock:
        counter = mock_collectors()
        await asyncio.gather(*(debian.fetch_cves(sw) for sw in WATCHED))
    assert counter["debian"] == 1


@pytest.mark.asyncio
async def test_failed_download_is_not_cached():
    """An error response must not poison the cache with an empty snapshot."""
    from patchradar.collectors.errors import CollectorError
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(500))
        # raises since W10; used to return [] indistinguishable from "no CVEs"
        with pytest.raises(CollectorError):
            await debian.fetch_cves("nginx")
    with respx.mock:
        counter = mock_collectors()
        await debian.fetch_cves("nginx")
    assert counter["debian"] == 1, "a failed fetch was cached as a valid snapshot"


@pytest.mark.asyncio
async def test_cached_snapshot_still_filters_per_keyword():
    payload = {
        "nginx": {"CVE-2026-1": {"description": "n", "releases": {"trixie": {"status": "open", "urgency": "high"}}}},
        "redis": {"CVE-2026-2": {"description": "r", "releases": {"trixie": {"status": "open", "urgency": "high"}}}},
    }
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json=payload))
        nginx = await debian.fetch_cves("nginx")
        redis = await debian.fetch_cves("redis")
    assert [c["id"] for c in nginx] == ["CVE-2026-1"]
    assert [c["id"] for c in redis] == ["CVE-2026-2"]


# ─── Scan deadline ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_respects_deadline(client, monkeypatch):
    """A hanging upstream must not hold the worker past the budget."""
    monkeypatch.setattr(api, "SCAN_TIMEOUT_SECONDS", 0.5)

    async def hang(*args, **kwargs):
        await asyncio.sleep(30)
        return []

    monkeypatch.setattr(api, "nvd_fetch", hang)
    monkeypatch.setattr(api, "msrc_fetch", hang)
    monkeypatch.setattr(api, "debian_fetch", hang)

    loop = asyncio.get_running_loop()
    started = loop.time()
    r = await client.post("/api/scan?days=7")
    elapsed = loop.time() - started

    assert r.status_code == 200
    assert elapsed < 10, f"scan ran {elapsed:.1f}s, deadline was 0.5s"
    body = r.json()
    assert body["timed_out"] is True, "a truncated scan must say so, not look complete"
    assert body["scanned"] < len(WATCHED)


@pytest.mark.asyncio
async def test_completed_scan_is_not_flagged_timed_out(client):
    with respx.mock:
        mock_collectors()
        r = await client.post("/api/scan?days=7")
    body = r.json()
    assert body["timed_out"] is False
    assert body["scanned"] == len(WATCHED)


# ─── API key ─────────────────────────────────────────────────────────────────

PROTECTED = [
    ("POST", "/api/scan"),
    ("POST", "/api/watchlist/somepkg"),
    ("POST", "/api/watchlist/import"),
    ("DELETE", "/api/watchlist/somepkg"),
]

PUBLIC = [
    ("GET", "/"),
    ("GET", "/api/watchlist"),
    ("GET", "/api/cves"),
    ("GET", "/api/stats"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path", PROTECTED)
async def test_protected_endpoints_reject_missing_key(client, monkeypatch, method, path):
    monkeypatch.setenv(api.API_KEY_ENV, "s3cret")
    r = await client.request(method, path, json={"software": []})
    assert r.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path", PROTECTED)
async def test_protected_endpoints_reject_wrong_key(client, monkeypatch, method, path):
    monkeypatch.setenv(api.API_KEY_ENV, "s3cret")
    r = await client.request(method, path, json={"software": []}, headers={"X-API-Key": "nope"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_correct_key_is_accepted(client, monkeypatch):
    monkeypatch.setenv(api.API_KEY_ENV, "s3cret")
    with respx.mock:
        mock_collectors()
        r = await client.post("/api/scan", headers={"X-API-Key": "s3cret"})
    assert r.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path", PUBLIC)
async def test_read_endpoints_stay_public(client, monkeypatch, method, path):
    """The bundled UI must still load and render without a key."""
    monkeypatch.setenv(api.API_KEY_ENV, "s3cret")
    r = await client.request(method, path)
    assert r.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path", PROTECTED)
async def test_no_key_configured_keeps_endpoints_open(client, method, path):
    """Backwards compatible: an unset key means local use is unchanged."""
    with respx.mock:
        mock_collectors()
        r = await client.request(method, path, json={"software": []})
    assert r.status_code != 401


@pytest.mark.asyncio
async def test_empty_key_env_var_does_not_enable_auth(client, monkeypatch):
    """PATCHRADAR_API_KEY='' must not mean 'the empty string is the key'."""
    monkeypatch.setenv(api.API_KEY_ENV, "")
    with respx.mock:
        mock_collectors()
        r = await client.post("/api/scan")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_key_comparison_is_constant_time(monkeypatch):
    """Guard against a plain == creeping back in."""
    import inspect

    src = inspect.getsource(api.require_api_key)
    assert "compare_digest" in src
