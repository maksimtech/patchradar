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
