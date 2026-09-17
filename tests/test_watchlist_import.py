"""
PatchRadar — watchlist import validation (L7, L8)

POST /api/watchlist/{software} enforces `^[\\w\\s\\-\\.]+$` and max_length=100.
POST /api/watchlist/import enforced nothing: it did `sw.strip().lower()[:100]`
and stored the result.

* L7 — anything the path endpoint rejected could be smuggled in through the
  import endpoint. `evil<script>alert(1)</script>` and `evil[bold]x` both
  reached the database that way; the latter then rendered as `evilx` in
  `patchradar list`, which is how the CLI markup injection was demonstrated.
* L8 — `sw.strip()` assumed a string, so `{"software": [123]}` raised
  AttributeError and returned HTTP 500 instead of a validation error.

Over-long names were silently truncated to 100 characters, quietly watching
something other than what was asked for; they are now rejected, matching the
path endpoint's 422.
"""
import re

import pytest
from httpx import ASGITransport, AsyncClient

import patchradar.api.main as api
from patchradar.api.main import (
    SOFTWARE_NAME_MAX_LENGTH,
    SOFTWARE_NAME_PATTERN,
    normalise_software_name,
)
from patchradar.db.database import get_watchlist, init_db


@pytest.fixture(autouse=True)
async def fresh_db():
    await init_db()
    yield


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as ac:
        yield ac


ACCEPTED = ["nginx", "NGINX", "nginx 1.2", "my-app", "app.name", "under_score", "django3"]

REJECTED = [
    "evil[bold]x",
    "evil<script>alert(1)</script>",
    "a;rm -rf /",
    "a|b",
    "a$(id)b",
    "a`id`b",
    "a&b",
    "a/b",
    "a\\b",
    "a\nb",
    "a\x00b",
    "a'b",
    'a"b',
    "",
    "   ",
    "a" * (SOFTWARE_NAME_MAX_LENGTH + 1),
]


# ─── L7: the two endpoints must agree ────────────────────────────────────────

@pytest.mark.parametrize("name", ACCEPTED)
def test_valid_names_are_normalised(name):
    result = normalise_software_name(name)
    assert result == name.strip().lower()


@pytest.mark.parametrize("name", REJECTED)
def test_invalid_names_are_rejected(name):
    assert normalise_software_name(name) is None


@pytest.mark.parametrize("name", ACCEPTED + REJECTED)
def test_validator_agrees_with_the_path_endpoint_pattern(name):
    """Parity: the helper accepts exactly what the shared pattern allows.

    Compared against the *normalised* form, because the helper strips and
    lowercases before validating — so "   " is rejected even though the bare
    regex would match three spaces.
    """
    normalised = name.strip().lower()
    pattern_ok = (
        bool(normalised)
        and len(normalised) <= SOFTWARE_NAME_MAX_LENGTH
        and bool(re.match(SOFTWARE_NAME_PATTERN, normalised))
    )
    assert (normalise_software_name(name) is not None) == pattern_ok, (
        f"{name!r}: helper and shared pattern disagree"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("name", REJECTED)
async def test_rejected_names_never_reach_the_database(client, name):
    r = await client.post("/api/watchlist/import", json={"software": [name]})
    assert r.status_code == 200
    assert name.strip().lower() not in await get_watchlist()
    assert name.strip().lower()[:SOFTWARE_NAME_MAX_LENGTH] not in await get_watchlist()


@pytest.mark.asyncio
async def test_markup_payload_cannot_be_smuggled_in(client):
    """The exact payload used to demonstrate the CLI markup injection."""
    r = await client.post("/api/watchlist/import", json={"software": ["evil[bold]x"]})
    assert r.json()["added"] == []
    assert "evil[bold]x" in r.json()["rejected"]
    assert await get_watchlist() == []


@pytest.mark.asyncio
async def test_over_long_name_is_rejected_not_truncated(client):
    long_name = "a" * 150
    r = await client.post("/api/watchlist/import", json={"software": [long_name]})
    assert r.json()["added"] == []
    assert await get_watchlist() == [], "an over-long name was silently truncated and stored"


@pytest.mark.asyncio
async def test_valid_names_are_still_imported(client):
    r = await client.post("/api/watchlist/import", json={"software": ["Nginx", " redis "]})
    body = r.json()
    assert set(body["added"]) == {"nginx", "redis"}
    assert set(await get_watchlist()) == {"nginx", "redis"}


@pytest.mark.asyncio
async def test_already_present_names_are_skipped_not_rejected(client):
    await client.post("/api/watchlist/import", json={"software": ["nginx"]})
    body = (await client.post("/api/watchlist/import", json={"software": ["nginx"]})).json()
    assert body["skipped"] == ["nginx"]
    assert body["added"] == []
    assert body["rejected"] == []


# ─── L8: non-string items must not 500 ───────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("item", [123, None, True, 4.5, {"a": 1}, ["nested"], []])
async def test_non_string_items_do_not_crash(client, item):
    r = await client.post("/api/watchlist/import", json={"software": [item]})
    assert r.status_code == 200, f"{item!r} produced {r.status_code}"
    assert r.json()["added"] == []


@pytest.mark.asyncio
async def test_mixed_payload_imports_the_valid_entries(client):
    r = await client.post("/api/watchlist/import", json={
        "software": ["nginx", 123, "evil[bold]x", None, "redis", {"x": 1}]
    })
    body = r.json()
    assert set(body["added"]) == {"nginx", "redis"}
    assert body["total"] == 2
    assert len(body["rejected"]) == 4
    assert set(await get_watchlist()) == {"nginx", "redis"}


@pytest.mark.asyncio
async def test_rejected_entries_are_reported_as_strings(client):
    """The response must be JSON-serialisable whatever was sent."""
    r = await client.post("/api/watchlist/import", json={"software": [123, None, {"a": 1}]})
    assert all(isinstance(x, str) for x in r.json()["rejected"])


# ─── payload shape ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{"software": "nginx"}, {"software": 42}, {"software": None}])
async def test_non_list_software_is_a_client_error(client, payload):
    assert (await client.post("/api/watchlist/import", json=payload)).status_code == 400


@pytest.mark.asyncio
async def test_missing_software_key_yields_empty_result(client):
    body = (await client.post("/api/watchlist/import", json={})).json()
    assert body["added"] == [] and body["total"] == 0


@pytest.mark.asyncio
async def test_response_always_carries_every_bucket(client):
    body = (await client.post("/api/watchlist/import", json={"software": []})).json()
    assert set(body) == {"added", "skipped", "rejected", "total"}


# ─── the path endpoint keeps its own behaviour ───────────────────────────────

@pytest.mark.asyncio
async def test_path_endpoint_still_rejects_invalid_names(client):
    assert (await client.post("/api/watchlist/evil[bold]x")).status_code == 422


@pytest.mark.asyncio
async def test_path_endpoint_normalises_like_import(client):
    """Both routes must land the same canonical value in the database."""
    await client.post("/api/watchlist/NGINX")
    assert await get_watchlist() == ["nginx"]


@pytest.mark.asyncio
async def test_path_endpoint_rejects_whitespace_only_name(client):
    """Matches the bare regex but normalises to nothing — must not be stored."""
    r = await client.post("/api/watchlist/%20%20%20")
    assert r.status_code == 422
    assert await get_watchlist() == []


@pytest.mark.asyncio
async def test_newline_is_not_a_valid_name_on_either_route(client):
    r = await client.post("/api/watchlist/import", json={"software": ["a\nb"]})
    assert r.json()["added"] == []
    assert await get_watchlist() == []
