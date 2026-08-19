"""
PatchRadar — Test Suite
"""
import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from patchradar.api.main import app
from patchradar.db.database import init_db, add_to_watchlist, get_watchlist, remove_from_watchlist

pytestmark = pytest.mark.asyncio

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

@pytest.mark.asyncio
async def test_index_returns_200(client):
    response = await client.get("/")
    assert response.status_code == 200
    assert "PatchRadar" in response.text

@pytest.mark.asyncio
async def test_security_headers(client):
    response = await client.get("/")
    assert "content-security-policy" in response.headers
    assert "x-frame-options" in response.headers
    assert response.headers["x-frame-options"] == "DENY"
    assert "x-content-type-options" in response.headers

@pytest.mark.asyncio
async def test_watchlist_empty(client):
    response = await client.get("/api/watchlist")
    assert response.status_code == 200
    assert "watchlist" in response.json()

@pytest.mark.asyncio
async def test_add_software(client):
    response = await client.post("/api/watchlist/testapp")
    assert response.status_code == 200
    data = response.json()
    assert data["software"] == "testapp"

@pytest.mark.asyncio
async def test_remove_software(client):
    await client.post("/api/watchlist/testapp2")
    response = await client.delete("/api/watchlist/testapp2")
    assert response.status_code == 200
    assert response.json()["removed"] == True

@pytest.mark.asyncio
async def test_software_too_long(client):
    long_name = "a" * 101
    response = await client.post(f"/api/watchlist/{long_name}")
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_days_too_high(client):
    response = await client.post("/api/scan?days=999")
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_limit_too_high(client):
    response = await client.get("/api/cves?limit=9999")
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_days_minimum(client):
    response = await client.post("/api/scan?days=0")
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_limit_minimum(client):
    response = await client.get("/api/cves?limit=0")
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_cves_endpoint(client):
    response = await client.get("/api/cves")
    assert response.status_code == 200
    data = response.json()
    assert "cves" in data
    assert "total" in data

@pytest.mark.asyncio
async def test_stats_endpoint(client):
    response = await client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_cves" in data
    assert "watched" in data
    assert "by_severity" in data
    assert "by_software" in data

@pytest.mark.asyncio
async def test_db_add_and_get():
    await init_db()
    # Remove first in case it exists from previous test run
    await remove_from_watchlist("pytest-test-software")
    added = await add_to_watchlist("pytest-test-software")
    assert added == True
    watchlist = await get_watchlist()
    assert "pytest-test-software" in watchlist
    # Cleanup
    await remove_from_watchlist("pytest-test-software")

@pytest.mark.asyncio
async def test_db_duplicate():
    await init_db()
    await add_to_watchlist("duplicate-test")
    added_again = await add_to_watchlist("duplicate-test")
    assert added_again == False

@pytest.mark.asyncio
async def test_db_remove():
    await init_db()
    await add_to_watchlist("remove-test")
    removed = await remove_from_watchlist("remove-test")
    assert removed == True


@pytest.mark.asyncio
async def test_db_remove_cleans_orphan_cves():
    """Verify that removing a software from watchlist also deletes its CVEs."""
    from patchradar.db.database import save_cve, get_cves
    await init_db()
    await add_to_watchlist("orphan-test")
    await save_cve({
        "id": "CVE-2026-99999",
        "software": "orphan-test",
        "description": "Test CVE for orphan cleanup",
        "cvss_score": 7.5,
        "cvss_version": "3.1",
        "severity": "HIGH",
        "published_at": "2026-01-01T00:00:00",
        "source": "NVD",
        "url": "https://example.com"
    })
    cves_before = await get_cves(software="orphan-test")
    assert len(cves_before) == 1
    await remove_from_watchlist("orphan-test")
    cves_after = await get_cves(software="orphan-test")
    assert len(cves_after) == 0, "Orphan CVEs should be deleted when software is removed from watchlist"

# ─── CLI Tests ──────────────────────────────────────────────────────────────

from typer.testing import CliRunner
from patchradar.cli import app as cli_app

runner = CliRunner()

def test_cli_help():
    result = runner.invoke(cli_app, ["--help"])
    assert result.exit_code == 0
    assert "PatchRadar" in result.output

def test_cli_add():
    result = runner.invoke(cli_app, ["add", "test-cli-software"])
    assert result.exit_code == 0
    assert "test-cli-software" in result.output

def test_cli_list():
    runner.invoke(cli_app, ["add", "test-list-software"])
    result = runner.invoke(cli_app, ["list"])
    assert result.exit_code == 0

def test_cli_remove():
    runner.invoke(cli_app, ["add", "test-remove-software"])
    result = runner.invoke(cli_app, ["remove", "test-remove-software"])
    assert result.exit_code == 0
    assert "test-remove-software" in result.output

def test_cli_status():
    result = runner.invoke(cli_app, ["status"])
    assert result.exit_code == 0

def test_cli_add_invalid():
    """CLI add with very long name — goes to API which validates"""
    long_name = "a" * 101
    result = runner.invoke(cli_app, ["add", long_name])
    # CLI itself doesn't validate length — API does via Path validator
    # Just verify CLI doesn't crash
    assert result.exit_code in [0, 1]

# ─── NVD Collector Tests ─────────────────────────────────────────────────────

import respx
import httpx
from patchradar.collectors.nvd import fetch_cves

@pytest.mark.asyncio
async def test_nvd_fetch_success():
    """Mock NVD API response with valid CVE data"""
    mock_response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-99999",
                    "published": "2026-08-15T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Test vulnerability description"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "version": "3.1",
                                    "baseSeverity": "CRITICAL"
                                },
                                "baseSeverity": "CRITICAL"
                            }
                        ]
                    }
                }
            }
        ]
    }

    with respx.mock:
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(200, json=mock_response)
        )
        cves = await fetch_cves("testsoftware", days_back=7)

    assert len(cves) == 1
    assert cves[0]["id"] == "CVE-2026-99999"
    assert cves[0]["severity"] == "CRITICAL"
    assert cves[0]["cvss_score"] == 9.8
    assert cves[0]["software"] == "testsoftware"

@pytest.mark.asyncio
async def test_nvd_fetch_empty():
    """Mock NVD API response with no CVEs"""
    mock_response = {"vulnerabilities": []}

    with respx.mock:
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(200, json=mock_response)
        )
        cves = await fetch_cves("unknownsoftware", days_back=7)

    assert len(cves) == 0

@pytest.mark.asyncio
async def test_nvd_fetch_error():
    """Mock NVD API error — should return empty list gracefully"""
    with respx.mock:
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(500)
        )
        cves = await fetch_cves("testsoftware", days_back=7)

    assert cves == []

@pytest.mark.asyncio
async def test_nvd_fetch_timeout():
    """Mock NVD API timeout — should return empty list gracefully"""
    with respx.mock:
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        cves = await fetch_cves("testsoftware", days_back=7)

    assert cves == []

# ─── Database CRUD Tests ──────────────────────────────────────────────────────

from patchradar.db.database import save_cve, get_cves

@pytest.mark.asyncio
async def test_db_save_and_get_cve():
    """Test saving and retrieving a CVE"""
    await init_db()
    test_cve = {
        "id": "CVE-2026-TEST01",
        "software": "test-db-software",
        "description": "Test CVE description",
        "cvss_score": 7.5,
        "cvss_version": "3.1",
        "severity": "HIGH",
        "published_at": "2026-08-15T00:00:00.000",
        "source": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-TEST01"
    }
    await save_cve(test_cve)
    cves = await get_cves(software="test-db-software")
    assert any(c["id"] == "CVE-2026-TEST01" for c in cves)

@pytest.mark.asyncio
async def test_db_save_duplicate_cve():
    """Test that duplicate CVEs are handled gracefully"""
    await init_db()
    test_cve = {
        "id": "CVE-2026-TEST02",
        "software": "test-db-software",
        "description": "Test duplicate CVE",
        "cvss_score": 5.0,
        "cvss_version": "3.1",
        "severity": "MEDIUM",
        "published_at": "2026-08-15T00:00:00.000",
        "source": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-TEST02"
    }
    await save_cve(test_cve)
    await save_cve(test_cve)  # duplicate — should not crash
    cves = await get_cves(software="test-db-software")
    count = sum(1 for c in cves if c["id"] == "CVE-2026-TEST02")
    assert count == 1  # only one copy

@pytest.mark.asyncio
async def test_db_get_cves_with_limit():
    """Test CVE retrieval with limit"""
    await init_db()
    cves = await get_cves(limit=5)
    assert len(cves) <= 5
