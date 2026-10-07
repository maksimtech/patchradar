"""
PatchRadar — a column added to `cves` has to reach the databases that exist

`init_db` creates the table with `CREATE TABLE IF NOT EXISTS`, which means it
does nothing whatsoever to a database that already has one. A column added to
that statement therefore reaches new installations only, and every existing
install keeps the old shape — while `save_cve` starts naming the new column and
fails, silently, because it swallows its exceptions and returns False.

So the migration is the feature, not a detail of it: the EPSS pair is worth
nothing to anybody who has been running PatchRadar since 2026.40 unless their
database grows the columns too. These tests run against a database built with
the pre-EPSS schema, by hand, rather than against a fresh one.
"""
from __future__ import annotations

import asyncio

import aiosqlite
import pytest

from patchradar.db import database

# The `cves` table as it shipped before the EPSS columns existed, written out
# rather than generated: a migration test that builds its "old" database from
# today's code tests nothing at all.
OLD_SCHEMA = """
    CREATE TABLE cves (
        id TEXT PRIMARY KEY,
        software TEXT NOT NULL,
        description TEXT,
        cvss_score REAL,
        cvss_version TEXT,
        severity TEXT,
        published_at TIMESTAMP,
        source TEXT,
        url TEXT,
        seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""

OLD_ROW = ("CVE-2026-40001", "nginx", "stored before EPSS existed", 9.8, "3.1",
           "CRITICAL", "2026-08-01T00:00:00Z", "NVD", "https://nvd.nist.gov/x")


@pytest.fixture
def old_database(tmp_path, monkeypatch):
    """A database with the pre-EPSS schema and one row already in it."""
    path = tmp_path / "old.db"

    async def _build():
        async with aiosqlite.connect(path) as db:
            await db.execute(OLD_SCHEMA)
            await db.execute("""
                CREATE TABLE watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("INSERT INTO watchlist (name) VALUES ('nginx')")
            await db.execute("""
                INSERT INTO cves
                (id, software, description, cvss_score, cvss_version, severity,
                 published_at, source, url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, OLD_ROW)
            await db.commit()

    asyncio.run(_build())
    monkeypatch.setattr(database, "DB_PATH", path)
    return path


async def _columns(path) -> set[str]:
    async with aiosqlite.connect(path) as db, db.execute("PRAGMA table_info(cves)") as cursor:
        return {row[1] for row in await cursor.fetchall()}


@pytest.mark.asyncio
async def test_the_columns_are_added_to_an_existing_table(old_database):
    assert "epss_score" not in await _columns(old_database)
    await database.init_db()
    assert {"epss_score", "epss_percentile"} <= await _columns(old_database)


@pytest.mark.asyncio
async def test_the_rows_that_were_there_survive_with_no_forecast(old_database):
    """NULL and not 0.0: the CVE was stored before anybody asked FIRST about it,
    which is not the same as FIRST putting it at nil."""
    await database.init_db()
    [row] = await database.get_cves()
    assert row["id"] == "CVE-2026-40001"
    assert row["cvss_score"] == 9.8
    assert row["epss_score"] is None
    assert row["epss_percentile"] is None


@pytest.mark.asyncio
async def test_migrating_twice_is_not_an_error(old_database):
    """`init_db` runs on every CLI invocation and every API startup."""
    await database.init_db()
    await database.init_db()
    assert {"epss_score", "epss_percentile"} <= await _columns(old_database)


@pytest.mark.asyncio
async def test_a_forecast_can_be_stored_once_the_migration_has_run(old_database):
    await database.init_db()
    assert await database.save_cve({
        "id": "CVE-2026-40002", "software": "nginx", "description": "new",
        "cvss_score": 5.0, "severity": "MEDIUM", "published_at": "2026-09-30T00:00:00Z",
        "source": "NVD", "url": "", "epss_score": 0.42, "epss_percentile": 0.97,
    })
    [stored] = [r for r in await database.get_cves() if r["id"] == "CVE-2026-40002"]
    assert stored["epss_score"] == pytest.approx(0.42)


@pytest.mark.asyncio
async def test_a_second_scan_refreshes_the_forecast_and_nothing_else(old_database):
    """FIRST re-runs the model daily, so the reading has to be allowed to move.

    Everything else about a stored row stays as the first writer left it — the
    description below is deliberately different and deliberately ignored.
    """
    await database.init_db()
    first = {
        "id": "CVE-2026-40003", "software": "nginx", "description": "as first seen",
        "cvss_score": 5.0, "severity": "MEDIUM", "published_at": "2026-09-30T00:00:00Z",
        "source": "NVD", "url": "", "epss_score": 0.11, "epss_percentile": 0.90,
    }
    await database.save_cve(first)
    await database.save_cve({**first, "description": "rewritten", "epss_score": 0.44,
                             "epss_percentile": 0.98})

    [stored] = [r for r in await database.get_cves() if r["id"] == "CVE-2026-40003"]
    assert stored["epss_score"] == pytest.approx(0.44)
    assert stored["epss_percentile"] == pytest.approx(0.98)
    assert stored["description"] == "as first seen"


@pytest.mark.asyncio
async def test_a_scan_that_could_not_reach_first_does_not_erase_the_last_reading(old_database):
    """The `COALESCE`: an outage must cost the refresh, not the value."""
    await database.init_db()
    row = {
        "id": "CVE-2026-40004", "software": "nginx", "description": "x",
        "cvss_score": 5.0, "severity": "MEDIUM", "published_at": "2026-09-30T00:00:00Z",
        "source": "NVD", "url": "", "epss_score": 0.33, "epss_percentile": 0.95,
    }
    await database.save_cve(row)
    await database.save_cve({**row, "epss_score": None, "epss_percentile": None})

    [stored] = [r for r in await database.get_cves() if r["id"] == "CVE-2026-40004"]
    assert stored["epss_score"] == pytest.approx(0.33)
    assert stored["epss_percentile"] == pytest.approx(0.95)


# ─── the links between CVEs and products ─────────────────────────────────────
# Until 2026.44 `cves.id` was the only key, and the row's `software` column was
# the only record of which product a CVE concerned: a CVE shared by openssl and
# nginx belonged to whichever was scanned first. The links now live in
# `cve_software`, and `init_db` fills it from the rows that are already there.

# The tables as they shipped in 2026.44, written out by hand like OLD_SCHEMA
# above: a migration tested on a database built by today's code proves nothing.
PRE_LINK_SCHEMA = [
    """CREATE TABLE watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE cves (
        id TEXT PRIMARY KEY,
        software TEXT NOT NULL,
        description TEXT,
        cvss_score REAL,
        cvss_version TEXT,
        severity TEXT,
        published_at TIMESTAMP,
        source TEXT,
        url TEXT,
        epss_score REAL,
        epss_percentile REAL,
        seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
]


def linked_row(cve_id: str, software: str) -> dict:
    return {
        "id": cve_id, "software": software, "description": "d", "cvss_score": 7.5,
        "cvss_version": "3.1", "severity": "HIGH", "published_at": "2026-09-01T00:00:00",
        "source": "NVD", "url": "https://example.invalid",
    }


@pytest.fixture
def pre_link_database(tmp_path, monkeypatch):
    """A 2026.44 database with two products and one CVE already stored."""
    path = tmp_path / "old.db"

    async def _build():
        async with aiosqlite.connect(path) as db:
            for statement in PRE_LINK_SCHEMA:
                await db.execute(statement)
            await db.execute("INSERT INTO watchlist (name) VALUES ('openssl'), ('nginx')")
            await db.execute(
                "INSERT INTO cves (id, software, description, cvss_score, severity, published_at,"
                " source, url, epss_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("CVE-2026-7777", "openssl", "stored by 2026.44", 9.8, "CRITICAL",
                 "2026-08-01T00:00:00Z", "NVD", "https://nvd.nist.gov/x", 0.5),
            )
            await db.commit()

    asyncio.run(_build())
    monkeypatch.setattr(database, "DB_PATH", path)
    return path


@pytest.mark.asyncio
async def test_the_migration_keeps_existing_rows_and_their_product(pre_link_database):
    await database.init_db()
    [row] = await database.get_cves(software="openssl")
    assert row["id"] == "CVE-2026-7777"
    assert row["description"] == "stored by 2026.44"
    assert row["epss_score"] == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_after_the_migration_a_cve_can_belong_to_a_second_product(pre_link_database):
    await database.init_db()
    await database.save_cve(linked_row("CVE-2026-7777", "nginx"))
    assert [c["id"] for c in await database.get_cves(software="nginx")] == ["CVE-2026-7777"]
    assert [c["id"] for c in await database.get_cves(software="openssl")] == ["CVE-2026-7777"]
    # Still one row per CVE in the unfiltered listing, as before.
    assert [c["id"] for c in await database.get_cves()] == ["CVE-2026-7777"]


@pytest.mark.asyncio
async def test_after_the_migration_removal_keeps_a_cve_another_product_still_needs(pre_link_database):
    await database.init_db()
    await database.save_cve(linked_row("CVE-2026-7777", "nginx"))
    assert await database.remove_from_watchlist("openssl")
    assert [c["id"] for c in await database.get_cves(software="nginx")] == ["CVE-2026-7777"]
    assert await database.get_cves(software="openssl") == []
    # A restart (init_db runs on every CLI and API start) must not bring back
    # the link that was just removed.
    await database.init_db()
    assert await database.get_cves(software="openssl") == []


# ─── a row that cannot be stored ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_cve_that_cannot_be_stored_is_logged_not_swallowed(caplog):
    """`save_cve` returns False and no caller reads it: without a log line the
    lost record (a locked database, a malformed record) leaves no trace — the
    silence this file's docstring describes."""
    import logging

    with caplog.at_level(logging.WARNING, logger="patchradar.db.database"):
        assert await database.save_cve({"id": "CVE-2026-0001", "software": "x"}) is False
    assert "CVE-2026-0001" in caplog.text
