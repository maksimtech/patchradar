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
