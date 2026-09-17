"""
PatchRadar — /health endpoint (G1)

The Dockerfile HEALTHCHECK and docker-compose both probe
``http://localhost:8000/health``, which did not exist: the container reported
unhealthy forever, causing restart loops under `restart: unless-stopped` and
blocking any `depends_on: condition: service_healthy`.
"""
import asyncio
import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

import patchradar.api.main as api
from patchradar.db import database

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "patchradar.db")
    yield


@pytest.fixture
async def client():
    await database.init_db()
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_returns_200(client):
    r = await client.get("/health")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_health_reports_status_and_version(client):
    body = (await client.get("/health")).json()
    assert body["status"] == "ok"
    assert body["version"]


@pytest.mark.asyncio
async def test_health_needs_no_api_key(client, monkeypatch):
    """A healthcheck must not have to hold a credential."""
    monkeypatch.setenv(api.API_KEY_ENV, "s3cret")
    assert (await client.get("/health")).status_code == 200


@pytest.mark.asyncio
async def test_health_reports_database_reachability(client):
    body = (await client.get("/health")).json()
    assert body["database"] == "ok"


@pytest.mark.asyncio
async def test_health_degrades_when_database_unreachable(client, monkeypatch, tmp_path):
    """An unwritable DB must not read as healthy."""
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "nonexistent-dir" / "x.db")
    r = await client.get("/health")
    assert r.status_code == 503
    assert r.json()["database"] == "error"


def test_dockerfile_healthcheck_targets_an_existing_route():
    """Pin the contract: the probed path must be a registered route."""
    dockerfile = (REPO_ROOT / "Dockerfile").read_text()
    probed = set(re.findall(r"localhost:8000(/[\w/\-]*)", dockerfile))
    assert probed, "no healthcheck URL found in Dockerfile"
    routes = {r.path for r in api.app.routes}
    assert probed <= routes, f"Dockerfile probes {probed - routes}, which is not a route"


def test_compose_healthcheck_targets_an_existing_route():
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    probed = set(re.findall(r"localhost:8000(/[\w/\-]*)", compose))
    assert probed, "no healthcheck URL found in docker-compose.yml"
    routes = {r.path for r in api.app.routes}
    assert probed <= routes, f"compose probes {probed - routes}, which is not a route"
