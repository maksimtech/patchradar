import logging
from datetime import UTC, datetime
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
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime(TIMESTAMP_FORMAT)


# Columns added to `cves` after it first shipped. The CREATE TABLE above is
# IF NOT EXISTS, so it does nothing at all to a database that already exists —
# a column added to it reaches new installations only. SQLite has no
# "ADD COLUMN IF NOT EXISTS" either, hence the PRAGMA below rather than a try.
#
# Every entry must stay nullable and without a default: a column back-filled
# with 0.0 would tell every CVE stored before EPSS existed that FIRST scores it
# at zero, which is a measurement and not an absence.
_ADDED_COLUMNS = {
    "epss_score": "REAL",
    "epss_percentile": "REAL",
}


async def _add_missing_columns(db) -> None:
    """Bring an existing `cves` table up to the current schema."""
    async with db.execute("PRAGMA table_info(cves)") as cursor:
        existing = {row[1] for row in await cursor.fetchall()}
    for column, kind in _ADDED_COLUMNS.items():
        if column in existing:
            continue
        # Interpolated, because SQLite takes no parameters in DDL. The names and
        # types come from the module constant above and never from input.
        await db.execute(f"ALTER TABLE cves ADD COLUMN {column} {kind}")
        logger.info("added column %s to the cves table", column)


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


async def _link_stored_cves(db) -> None:
    """Give every stored CVE a link to the product its row names.

    `cves.id` is the primary key, so a CVE is one row however many watched
    products it concerns; which products those are lives in `cve_software`.
    Until 2026.44 only the row's own `software` column said it, and a CVE
    shared by openssl and nginx belonged to whichever was scanned first:
    invisible under the other, and deleted with the first one's removal.

    Run on every start, not once: `INSERT OR IGNORE` makes it idempotent, and
    it links rows written since by anything that does not know the table.
    `remove_from_watchlist` keeps the column pointing at a product still
    linked, so this never brings back a link that was taken away.
    """
    await db.execute(
        "INSERT OR IGNORE INTO cve_software (cve_id, software) SELECT id, software FROM cves"
    )


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
                epss_score REAL,
                epss_percentile REAL,
                seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS cve_software (
                cve_id TEXT NOT NULL,
                software TEXT NOT NULL,
                PRIMARY KEY (cve_id, software)
            )
        """)
        await _add_missing_columns(db)
        await _normalize_stored_timestamps(db)
        await _link_stored_cves(db)
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
    async with aiosqlite.connect(DB_PATH) as db, db.execute("SELECT name FROM watchlist ORDER BY name") as cursor:
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
                "DELETE FROM cve_software WHERE software = ?", (name.lower(),)
            )
            # A CVE another product is still linked to stays, and is handed to
            # that product so the row never names one it no longer belongs to.
            await db.execute("""
                UPDATE cves SET software = (
                    SELECT MIN(software) FROM cve_software WHERE cve_id = cves.id
                ) WHERE software = ? AND id IN (SELECT cve_id FROM cve_software)
            """, (name.lower(),))
            await db.execute(
                "DELETE FROM cves WHERE software = ?", (name.lower(),)
            )
        await db.commit()
        return removed

async def save_cve(cve: dict) -> bool:
    """Store a CVE, refreshing its EPSS forecast if it is already stored.

    Everything else about a stored row is left alone — first writer wins, as it
    has since the table existed. The exception is the EPSS pair, and it is not a
    special case so much as the nature of the field: FIRST re-runs the model
    daily, so a probability is a reading taken on a date rather than a fact about
    the CVE, and a row that kept its first one would go quietly stale while
    looking exactly like a fresh one. `COALESCE` on the excluded value keeps a
    scan that could not reach FIRST from erasing yesterday's reading with NULL.

    The CVE is also linked to `software`, so one already stored for another
    product is listed for this one too.

    True means a row was written — inserted, or its forecast updated.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT OR IGNORE INTO cve_software (cve_id, software) VALUES (?, ?)",
                (cve["id"], cve["software"]),
            )
            cursor = await db.execute("""
                INSERT INTO cves
                (id, software, description, cvss_score, cvss_version,
                 severity, published_at, source, url, epss_score, epss_percentile)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    epss_score = COALESCE(excluded.epss_score, cves.epss_score),
                    epss_percentile = COALESCE(excluded.epss_percentile, cves.epss_percentile)
            """, (
                cve["id"], cve["software"], cve["description"],
                cve.get("cvss_score"), cve.get("cvss_version"),
                cve.get("severity"), normalize_timestamp(cve.get("published_at")),
                cve.get("source"), cve.get("url"),
                cve.get("epss_score"), cve.get("epss_percentile")
            ))
            await db.commit()
            return cursor.rowcount > 0
        except Exception as exc:
            # Still False rather than a raise, so one bad record cannot end a
            # scan — but said: no caller reads the return value, and a CVE lost
            # to "database is locked" or a malformed record left no trace.
            logger.warning("could not store %s: %s", cve.get("id", "<no id>"), exc)
            logger.debug("save_cve failure", exc_info=True)
            return False

async def get_cves(software: str | None = None, limit: int = 50) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if software:
            # The column as well as the links, so a row written without a link
            # (by hand, or by an older release after the migration) still shows.
            async with db.execute("""
                SELECT * FROM cves
                WHERE software = ? OR id IN (SELECT cve_id FROM cve_software WHERE software = ?)
                ORDER BY published_at DESC LIMIT ?
            """, (software.lower(), software.lower(), limit)) as cursor:
                rows = await cursor.fetchall()
            # Named after the product asked about, not the first one to find it.
            return [{**dict(row), "software": software.lower()} for row in rows]
        else:
            async with db.execute(
                "SELECT * FROM cves ORDER BY published_at DESC LIMIT ?",
                (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
        return [dict(row) for row in rows]
