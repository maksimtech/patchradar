"""
PatchRadar — the API knows what is installed, and judges as the CLI does (DESIGN §5.5)

A scan over HTTP and a scan from the command line that give different answers
for the same machine are the failure `tests/test_collector_wiring.py` exists
for. PR-01a taught only the CLI to judge CVEs against the installed version;
the API now records the version and CPE, judges with the same function, and
returns what it stored.

NVD answers from the recording `nvd_notepadpp_configurations.json`; MSRC has no
document (404); Debian refuses (503), so the API lists that one source in
`errors`; KEV is the empty catalogue conftest.py caches.
"""
from __future__ import annotations

import json
import pathlib

import httpx
import pytest
import respx
from httpx import ASGITransport, AsyncClient

import patchradar.api.main as api
from patchradar.collectors import msrc, nvd
from patchradar.db import database

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "nvd_notepadpp_configurations.json"
PAYLOAD = json.loads(FIXTURE.read_text(encoding="utf-8"))
NOTEPADPP = "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as ac:
        yield ac


async def _add(client, **params):
    return await client.post("/api/watchlist/notepad", params=params)


async def test_the_version_and_cpe_are_recorded_over_http(client):
    response = await _add(client, version="8.5.0", cpe=NOTEPADPP)

    assert response.status_code == 200, response.text
    assert response.json()["installed_version"] == "8.5.0"
    [entry] = await database.get_watch_entries()
    assert entry.installed() == ("8.5.0", "notepad-plus-plus", "notepad\\+\\+")


async def test_a_cpe_nvd_would_match_nothing_with_is_refused_with_its_form(client):
    response = await _add(client, version="8.5.0", cpe="cpe:2.3:a:notepad-plus-plus:notepad++")

    assert response.status_code == 422
    assert "notepad\\+\\+" in response.json()["detail"]
    assert await database.get_watchlist() == []


async def test_a_version_the_scan_cannot_order_is_refused(client):
    response = await _add(client, version="8.x-beta", cpe=NOTEPADPP)

    assert response.status_code == 422
    assert await database.get_watchlist() == []


async def test_adding_again_with_a_version_updates_it(client):
    await _add(client)
    response = await _add(client, version="8.9.6.4")

    assert response.json()["added"] is False
    assert response.json()["installed_version"] == "8.9.6.4"


async def test_the_watchlist_lists_what_is_installed_beside_the_names(client):
    await _add(client, version="8.5.0", cpe=NOTEPADPP)

    body = (await client.get("/api/watchlist")).json()

    assert body["watchlist"] == ["notepad"]
    assert body["entries"] == [{"name": "notepad", "installed_version": "8.5.0", "cpe": NOTEPADPP}]


@pytest.fixture
def upstream():
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(200, json=PAYLOAD))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        router.route().mock(return_value=httpx.Response(503))     # Debian
        yield


async def test_a_scan_over_http_gives_the_split_the_cli_gives(client, upstream):
    await _add(client, version="8.5.0", cpe=NOTEPADPP)

    body = (await client.post("/api/scan", params={"days": 7})).json()

    assert body["by_software"] == {"notepad": 21}
    assert body["verdicts"] == {"notepad": {"affected": 10, "not evaluable": 0, "not affected": 11}}


async def test_the_cves_read_back_over_http_carry_their_verdict(client, upstream):
    await _add(client, version="8.5.0", cpe=NOTEPADPP)
    await client.post("/api/scan", params={"days": 7})

    rows = (await client.get("/api/cves", params={"software": "notepad"})).json()["cves"]

    assert len(rows) == 21
    verdicts = [row["verdict"] for row in rows]
    assert (verdicts.count("affected"), verdicts.count("not affected")) == (10, 11)
    assert all(row["verdict_reason"] for row in rows)


async def test_an_entry_without_a_version_has_no_verdicts_over_http(client, upstream):
    await _add(client)

    body = (await client.post("/api/scan", params={"days": 7})).json()

    assert body["by_software"] == {"notepad": 21}
    assert body["verdicts"] == {}
    rows = (await client.get("/api/cves", params={"software": "notepad"})).json()["cves"]
    assert {row["verdict"] for row in rows} == {None}
