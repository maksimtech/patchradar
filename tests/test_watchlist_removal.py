"""
PatchRadar — watchlist removal scope (L9)

`remove_from_watchlist` issued the CVE delete unconditionally:

    cursor = await db.execute("DELETE FROM watchlist WHERE name = ?", ...)
    await db.execute("DELETE FROM cves WHERE software = ?", ...)   # always
    return cursor.rowcount > 0

So it reported False for a name that was never watched while still wiping every
CVE stored under that name. DELETE /api/watchlist/<anything> was therefore a
data-destruction primitive that worked on software the caller had never added.
"""
import pytest
from httpx import ASGITransport, AsyncClient

import patchradar.api.main as api
from patchradar.db.database import (
    add_to_watchlist,
    get_cves,
    get_watchlist,
    init_db,
    remove_from_watchlist,
    save_cve,
)


def cve_for(software, cve_id):
    return {
        "id": cve_id,
        "software": software,
        "description": "test",
        "cvss_score": 7.5,
        "cvss_version": "3.1",
        "severity": "HIGH",
        "published_at": "2026-01-01T00:00:00",
        "source": "NVD",
        "url": "https://example.invalid",
    }


@pytest.fixture(autouse=True)
async def fresh_db():
    await init_db()
    yield


# ─── the defect ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_removing_unwatched_software_does_not_delete_its_cves():
    """The headline: nothing was watched, so nothing should be destroyed."""
    await save_cve(cve_for("never-watched", "CVE-2026-L9-01"))
    assert len(await get_cves(software="never-watched")) == 1

    removed = await remove_from_watchlist("never-watched")

    assert removed is False
    assert len(await get_cves(software="never-watched")) == 1, (
        "CVEs were deleted for software that was never in the watchlist"
    )


@pytest.mark.asyncio
async def test_removing_watched_software_still_deletes_its_cves():
    """The intended behaviour must survive the fix."""
    await add_to_watchlist("watched-pkg")
    await save_cve(cve_for("watched-pkg", "CVE-2026-L9-02"))

    removed = await remove_from_watchlist("watched-pkg")

    assert removed is True
    assert "watched-pkg" not in await get_watchlist()
    assert await get_cves(software="watched-pkg") == []


@pytest.mark.asyncio
async def test_removal_does_not_touch_other_software():
    await add_to_watchlist("pkg-a")
    await add_to_watchlist("pkg-b")
    await save_cve(cve_for("pkg-a", "CVE-2026-L9-03"))
    await save_cve(cve_for("pkg-b", "CVE-2026-L9-04"))

    await remove_from_watchlist("pkg-a")

    assert await get_cves(software="pkg-a") == []
    assert len(await get_cves(software="pkg-b")) == 1
    assert "pkg-b" in await get_watchlist()


@pytest.mark.asyncio
async def test_repeated_removal_is_idempotent_and_harmless():
    await add_to_watchlist("pkg-c")
    await save_cve(cve_for("pkg-c", "CVE-2026-L9-05"))
    assert await remove_from_watchlist("pkg-c") is True

    # re-adding after removal must not have its history wiped by a stale call
    await add_to_watchlist("pkg-c")
    await save_cve(cve_for("pkg-c", "CVE-2026-L9-06"))
    assert await remove_from_watchlist("nonexistent") is False
    assert len(await get_cves(software="pkg-c")) == 1


@pytest.mark.asyncio
async def test_removal_is_case_insensitive():
    await add_to_watchlist("MixedCase")
    await save_cve(cve_for("mixedcase", "CVE-2026-L9-07"))
    assert await remove_from_watchlist("MIXEDCASE") is True
    assert await get_cves(software="mixedcase") == []


# ─── through the API ─────────────────────────────────────────────────────────

@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_api_delete_of_unwatched_software_preserves_cves(client):
    await save_cve(cve_for("api-unwatched", "CVE-2026-L9-08"))

    r = await client.delete("/api/watchlist/api-unwatched")

    assert r.status_code == 200
    assert r.json()["removed"] is False
    assert len(await get_cves(software="api-unwatched")) == 1


@pytest.mark.asyncio
async def test_api_delete_of_watched_software_clears_cves(client):
    await add_to_watchlist("api-watched")
    await save_cve(cve_for("api-watched", "CVE-2026-L9-09"))

    r = await client.delete("/api/watchlist/api-watched")

    assert r.json()["removed"] is True
    assert await get_cves(software="api-watched") == []


# ─── a CVE that two watched products share ───────────────────────────────────
# `cves.id` was the only key, so the second product to find a CVE was ignored:
# the CVE was missing from its listing, and removing the first product deleted
# it although the second was still watched.

@pytest.mark.asyncio
async def test_a_cve_affecting_two_watched_products_is_listed_for_both():
    await add_to_watchlist("openssl")
    await add_to_watchlist("nginx")
    await save_cve(cve_for("openssl", "CVE-2026-1111"))
    await save_cve(cve_for("nginx", "CVE-2026-1111"))

    assert "CVE-2026-1111" in [c["id"] for c in await get_cves(software="nginx")]


@pytest.mark.asyncio
async def test_removing_one_product_keeps_the_cves_another_still_needs():
    await add_to_watchlist("openssl")
    await add_to_watchlist("nginx")
    await save_cve(cve_for("openssl", "CVE-2026-2222"))
    await save_cve(cve_for("nginx", "CVE-2026-2222"))

    await remove_from_watchlist("openssl")

    assert "CVE-2026-2222" in [c["id"] for c in await get_cves()]


@pytest.mark.asyncio
async def test_removing_the_last_product_of_a_cve_still_deletes_it():
    await add_to_watchlist("openssl")
    await add_to_watchlist("nginx")
    await save_cve(cve_for("openssl", "CVE-2026-7778"))
    await save_cve(cve_for("nginx", "CVE-2026-7778"))

    await remove_from_watchlist("openssl")
    await remove_from_watchlist("nginx")

    assert await get_cves() == []


@pytest.mark.asyncio
async def test_a_cve_listed_for_a_product_names_that_product():
    """Filtered by 'nginx', the row says 'nginx', not the first product that
    happened to find it."""
    await save_cve(cve_for("openssl", "CVE-2026-7779"))
    await save_cve(cve_for("nginx", "CVE-2026-7779"))

    [row] = await get_cves(software="nginx")

    assert row["software"] == "nginx"


@pytest.mark.asyncio
async def test_stats_count_a_shared_cve_for_every_product(client):
    await add_to_watchlist("openssl")
    await save_cve(cve_for("openssl", "CVE-2026-7780"))
    await save_cve(cve_for("nginx", "CVE-2026-7780"))

    stats = (await client.get("/api/stats")).json()

    assert stats["total_cves"] == 1
    assert stats["by_software"] == {"nginx": 1, "openssl": 1}


@pytest.mark.asyncio
async def test_api_delete_strips_the_name_like_the_add_does(client, monkeypatch):
    """Adding " nginx " stored "nginx", and removing " nginx " looked for a name
    that was never there."""
    monkeypatch.delenv(api.API_KEY_ENV, raising=False)
    await add_to_watchlist("nginx")

    r = await client.delete("/api/watchlist/%20nginx%20")

    assert r.json() == {"removed": True, "software": "nginx"}
    assert await get_watchlist() == []
