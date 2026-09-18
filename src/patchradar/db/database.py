import logging
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

# The production location. Kept separate from DB_PATH so the running value can
# be redirected (the test suite does) without losing the real default.
DEFAULT_DB_PATH = Path.home() / ".patchradar" / "patchradar.db"

DB_PATH = DEFAULT_DB_PATH

# One fixed-width UTC form for published_at. The column is TEXT and is sorted
# as text, so every source must be stored in the same shape: NVD sends naive
# UTC with milliseconds, Debian "+00:00" with microseconds, MSRC naive, "Z" or
# an offset — mixed, `ORDER BY published_at` was not chronological.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def normalize_timestamp(value) -> str | None:
    """Return `value` as YYYY-MM-DDTHH:MM:SSZ in UTC, or None if unparseable.

    Naive values are taken as UTC, which is what NVD and MSRC publish.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        logger.debug("unparseable timestamp %r stored as NULL", value)
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


async def _normalize_stored_timestamps(db) -> None:
    """Rewrite published_at values saved before normalisation existed."""
    async with db.execute(
        "SELECT id, published_at FROM cves WHERE published_at IS NOT NULL"
    ) as cursor:
        rows = await cursor.fetchall()
    updates = []
    for cve_id, raw in rows:
        canonical = normalize_timestamp(raw)
        if canonical != raw:
            updates.append((canonical, cve_id))
    if updates:
        await db.executemany("UPDATE cves SET published_at = ? WHERE id = ?", updates)


async def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS cves (
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
        """)
        await _normalize_stored_timestamps(db)
        await db.commit()

async def add_to_watchlist(name: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT INTO watchlist (name) VALUES (?)", (name.lower(),)
            )
            await db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

async def get_watchlist() -> list[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT name FROM watchlist ORDER BY name") as cursor:
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

async def remove_from_watchlist(name: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "DELETE FROM watchlist WHERE name = ?", (name.lower(),)
        )
        removed = cursor.rowcount > 0
        # Only cascade when something was actually being watched: an
        # unconditional delete let a caller wipe the CVE history of software
        # that was never on the list.
        if removed:
            await db.execute(
                "DELETE FROM cves WHERE software = ?", (name.lower(),)
            )
        await db.commit()
        return removed

async def save_cve(cve: dict) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            cursor = await db.execute("""
                INSERT OR IGNORE INTO cves 
                (id, software, description, cvss_score, cvss_version, 
                 severity, published_at, source, url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve["id"], cve["software"], cve["description"],
                cve.get("cvss_score"), cve.get("cvss_version"),
                cve.get("severity"), normalize_timestamp(cve.get("published_at")),
                cve.get("source"), cve.get("url")
            ))
            await db.commit()
            return cursor.rowcount > 0
        except Exception:
            return False

async def get_cves(software: str = None, limit: int = 50) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if software:
            async with db.execute(
                "SELECT * FROM cves WHERE software = ? ORDER BY published_at DESC LIMIT ?",
                (software.lower(), limit)
            ) as cursor:
                rows = await cursor.fetchall()
        else:
            async with db.execute(
                "SELECT * FROM cves ORDER BY published_at DESC LIMIT ?",
                (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
        return [dict(row) for row in rows]
