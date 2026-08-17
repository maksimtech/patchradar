"""Benchmarks for the FastAPI application.

Requests go through the real ASGI stack (routing, validation, the security
headers middleware and JSON serialization) via ``httpx.ASGITransport``.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from patchradar.api.main import app, sanitize_cve


@pytest.fixture
def client(loop, seeded_db):
    transport = ASGITransport(app=app)
    http_client = AsyncClient(transport=transport, base_url="http://bench")
    yield http_client
    loop.run_until_complete(http_client.aclose())


def _get(loop, client, url: str):
    response = loop.run_until_complete(client.get(url))
    assert response.status_code == 200
    return response


def test_api_cves(benchmark, loop, client):
    """List endpoint: SQLite query plus sanitization of 50 CVEs."""
    response = benchmark(lambda: _get(loop, client, "/api/cves?limit=50"))

    assert response.json()["total"] == 50


def test_api_cves_filtered(benchmark, loop, client):
    """List endpoint filtered on a single watched software."""
    response = benchmark(
        lambda: _get(loop, client, "/api/cves?software=proxmox&limit=100")
    )

    assert response.json()["cves"]


def test_api_cve_detail(benchmark, loop, client):
    """Single CVE lookup by primary key."""
    response = benchmark(lambda: _get(loop, client, "/api/cves/CVE-2026-00042"))

    assert response.json()["id"] == "CVE-2026-00042"


def test_api_stats(benchmark, loop, client):
    """Dashboard aggregation queries (counts grouped by severity and software)."""
    response = benchmark(lambda: _get(loop, client, "/api/stats"))

    assert response.json()["total_cves"] > 0


def test_api_watchlist(benchmark, loop, client):
    """Smallest endpoint of the API, dominated by framework overhead."""
    response = benchmark(lambda: _get(loop, client, "/api/watchlist"))

    assert response.json()["watchlist"]


def test_api_index(benchmark, loop, client):
    """Dashboard rendering: template read and version substitution."""
    response = benchmark(lambda: _get(loop, client, "/"))

    assert "PatchRadar" in response.text


def test_sanitize_cve_batch(benchmark, cve_records):
    """Sanitization of a full page of CVEs, on the hot path of every response."""

    def run():
        return [sanitize_cve(cve) for cve in cve_records]

    result = benchmark(run)

    assert len(result) == len(cve_records)
