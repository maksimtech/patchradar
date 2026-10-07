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
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
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
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
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
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
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
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
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


@pytest.mark.parametrize("raw, expected", [
    (None, api.DEFAULT_SCAN_TIMEOUT),
    ("", api.DEFAULT_SCAN_TIMEOUT),
    ("120", 120.0),
    ("2.5", 2.5),
    ("ten minutes", api.DEFAULT_SCAN_TIMEOUT),   # was a ValueError at import: no server
    ("0", api.DEFAULT_SCAN_TIMEOUT),             # was every scan timed out at once
    ("-5", api.DEFAULT_SCAN_TIMEOUT),
    ("nan", api.DEFAULT_SCAN_TIMEOUT),
    ("inf", api.DEFAULT_SCAN_TIMEOUT),
])
def test_the_deadline_setting_falls_back_on_values_that_are_not_a_deadline(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv(api.SCAN_TIMEOUT_ENV, raising=False)
    else:
        monkeypatch.setenv(api.SCAN_TIMEOUT_ENV, raw)
    assert api.scan_timeout_from_env() == expected


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


@pytest.mark.asyncio
async def test_a_non_ascii_key_header_is_a_401_not_a_500(monkeypatch):
    """`hmac.compare_digest` on two `str` raises TypeError when either holds a
    non-ASCII character: one latin-1 byte in X-API-Key (an 'é') was an HTTP 500
    instead of a 401."""
    monkeypatch.setenv(api.API_KEY_ENV, "secret")
    transport = ASGITransport(app=api.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/watchlist/x", headers={"X-API-Key": "s\xe9cret".encode("latin-1")})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_a_non_ascii_configured_key_does_not_turn_a_wrong_header_into_a_500(monkeypatch):
    """The configured side can hold non-ASCII characters too: a wrong header
    stays a 401."""
    monkeypatch.setenv(api.API_KEY_ENV, "chiavé")
    transport = ASGITransport(app=api.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/watchlist/x", headers={"X-API-Key": "chiave"})
    assert r.status_code == 401


# ─── Cross-site writes ───────────────────────────────────────────────────────
# With no key configured — the default — any page the user visits could send a
# "simple" POST (no body, so no CORS preflight) to localhost:8000 and the write
# happened; the browser only hid the answer.

@pytest.fixture
async def empty_database():
    await database.init_db()


async def _write(method: str, path: str, headers: dict, monkeypatch) -> httpx.Response:
    async def nothing(sw, *args, **kwargs):
        return []

    for name in ("nvd_fetch", "kev_fetch", "msrc_fetch", "debian_fetch"):
        monkeypatch.setattr(api, name, nothing)
    async with AsyncClient(transport=ASGITransport(app=api.app),
                           base_url="http://localhost:8000") as ac:
        return await ac.request(method, path, headers=headers)


@pytest.mark.asyncio
async def test_a_cross_origin_post_cannot_modify_the_watchlist_when_no_key_is_set(empty_database):
    async with AsyncClient(transport=ASGITransport(app=api.app),
                           base_url="http://localhost:8000") as ac:
        r = await ac.post("/api/watchlist/evilsoftware",
                          headers={"Origin": "https://evil.example"})
    assert r.status_code in (401, 403)
    assert "evilsoftware" not in await database.get_watchlist()


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path", [
    ("POST", "/api/scan"),
    ("POST", "/api/watchlist/evilsoftware"),
    ("DELETE", "/api/watchlist/nginx"),
])
async def test_a_browser_write_from_another_site_is_refused(empty_database, monkeypatch, method, path):
    """Fetch Metadata: a modern browser states where the request comes from."""
    await database.add_to_watchlist("nginx")
    r = await _write(method, path, {"Origin": "https://evil.example",
                                    "Sec-Fetch-Site": "cross-site"}, monkeypatch)
    assert r.status_code == 403
    assert sorted(await database.get_watchlist()) == ["nginx"]


@pytest.mark.asyncio
async def test_the_bundled_ui_can_still_write(empty_database, monkeypatch):
    """The UI PatchRadar serves itself: same-origin, with Origin equal to the host."""
    r = await _write("POST", "/api/watchlist/nginx", {
        "Origin": "http://localhost:8000", "Sec-Fetch-Site": "same-origin",
        "Content-Type": "application/json"}, monkeypatch)
    assert r.status_code == 200
    assert await database.get_watchlist() == ["nginx"]


@pytest.mark.asyncio
async def test_a_browser_without_fetch_metadata_is_judged_by_its_origin(empty_database, monkeypatch):
    r = await _write("POST", "/api/watchlist/nginx", {"Origin": "http://localhost:8000"}, monkeypatch)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_a_client_that_is_not_a_browser_is_unaffected(empty_database, monkeypatch):
    """curl, scripts, the CLI: no Origin and no Sec-Fetch-Site, so no CSRF is possible."""
    r = await _write("POST", "/api/scan", {}, monkeypatch)
    assert r.status_code == 200


def test_every_write_route_carries_the_origin_guard():
    """A write endpoint added tomorrow without the guard would be CSRF again."""
    from fastapi.routing import APIRoute

    for route in api.app.routes:
        if isinstance(route, APIRoute) and route.methods - {"GET", "HEAD", "OPTIONS"}:
            calls = {dep.call for dep in route.dependant.dependencies}
            assert api.require_same_origin in calls, route.path


# ─── Counting ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_scan_counts_each_cve_once_across_sources(empty_database, monkeypatch):
    """A CVE that NVD and CISA KEV both report is one CVE, as `patchradar scan`
    counts it with merge_by_cve; `_scan_one` added up every source and said 2."""
    def record(cve_id, software, source):
        return {"id": cve_id, "software": software, "description": "d", "cvss_score": 7.5,
                "cvss_version": "3.1", "severity": "HIGH", "published_at": "2026-09-01T00:00:00",
                "source": source, "url": "https://example.invalid"}

    async def nvd_fake(sw, days_back=7):
        return [record("CVE-2026-3333", sw, "NVD")]

    async def kev_fake(sw, days_back=30):
        return [record("CVE-2026-3333", sw, "CISA KEV")]

    async def nothing(sw, *args, **kwargs):
        return []

    monkeypatch.setattr(api, "nvd_fetch", nvd_fake)
    monkeypatch.setattr(api, "kev_fetch", kev_fake)
    monkeypatch.setattr(api, "msrc_fetch", nothing)
    monkeypatch.setattr(api, "debian_fetch", nothing)
    await database.add_to_watchlist("foo")

    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as ac:
        r = await ac.post("/api/scan?days=7")
    assert r.status_code == 200
    assert r.json()["by_software"]["foo"] == 1
    assert r.json()["total"] == 1
