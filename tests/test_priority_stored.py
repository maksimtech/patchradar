"""
PatchRadar — what decides a rank is stored, and the stored listings are ranked (DESIGN §5.5)

`known_exploited`, `kev_ransomware`, the KEV dates and the provider's CVSS v4.0
exploit maturity travelled in the scan's records and were not columns, so the
fact that CISA has seen a CVE exploited existed for the length of one scan.
`patchradar status` and `/api/cves` listed by publication date, and an exploited
CVE from 2023 sat under every new 5.3. `tests/test_priority_wiring.py` held that
boundary on purpose, to say "now rank the database paths too" the day the
columns arrived; this is that day.

The order is computed by SQLite, so a listing of 50 is still a query for 50 —
and it is built from the constants `priority()` uses, so the two cannot
drift: the test below runs one set of rows through both and asks for the same
order.
"""
from __future__ import annotations

import asyncio

import aiosqlite
import pytest
from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

import patchradar.api.main as api
from patchradar import cli
from patchradar.db import database
from patchradar.priority import sort_by_priority

PRIORITY_COLUMNS = {"known_exploited", "kev_ransomware", "kev_date_added", "kev_due_date",
                    "cvss_exploit_maturity"}


def _row(cve_id, published, score=None, **facts):
    return {"id": cve_id, "software": "nginx", "description": cve_id, "cvss_score": score,
            "cvss_version": "3.1" if score is not None else None,
            "severity": "HIGH" if score is not None else "UNKNOWN",
            "published_at": published, "source": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", **facts}


# One row per rank, and the edges between them: ties on score, no score,
# EPSS exactly at the threshold, an EPSS outside [0, 1] that must not promote,
# ransomware "Unknown" (CISA's word for no), and v4.0 maturity both ways.
ROWS = [
    _row("CVE-2026-0001", "2026-10-01T00:00:00Z", 5.3),
    _row("CVE-2026-0002", "2026-09-30T00:00:00Z", 9.8),
    _row("CVE-2026-0003", "2026-09-29T00:00:00Z", None),
    _row("CVE-2026-0004", "2026-09-28T00:00:00Z", 6.1, epss_score=0.1, epss_percentile=0.95),
    _row("CVE-2026-0005", "2026-09-27T00:00:00Z", 9.1, epss_score=0.0999, epss_percentile=0.9),
    _row("CVE-2026-0006", "2026-09-26T00:00:00Z", 7.5, epss_score=1.5),
    _row("CVE-2026-0007", "2026-09-25T00:00:00Z", 4.3, cvss_exploit_maturity="PROOF_OF_CONCEPT"),
    _row("CVE-2026-0008", "2026-09-24T00:00:00Z", 8.8, cvss_exploit_maturity="UNREPORTED"),
    _row("CVE-2023-0009", "2023-03-01T00:00:00Z", 7.8, known_exploited=True,
         kev_date_added="2024-01-10", kev_due_date="2024-01-31", kev_ransomware=False),
    _row("CVE-2022-0010", "2022-05-01T00:00:00Z", 6.5, known_exploited=True,
         kev_date_added="2023-02-01", kev_ransomware=True),
    _row("CVE-2021-0011", "2021-06-01T00:00:00Z", None, known_exploited=True,
         kev_date_added="2022-03-03", kev_ransomware="Unknown"),
    _row("CVE-2026-0012", "2026-09-23T00:00:00Z", 9.8),
    # CVSS 0.0 is a measurement — no impact — and sorts above no score at all,
    # in the same rank: the sentinel for "no score" must sit below every real one.
    _row("CVE-2020-0014", "2020-01-01T00:00:00Z", 0.0, known_exploited=True,
         kev_date_added="2021-11-03"),
]


async def _store(rows):
    await database.add_to_watchlist("nginx")
    for row in rows:
        assert await database.save_cve(dict(row)), row["id"]


def _expected(rows):
    """`priority()`'s order, from rows in the order the database breaks ties."""
    by_date = sorted(rows, key=lambda r: (r["published_at"], r["id"]), reverse=True)
    return [r["id"] for r in sort_by_priority(by_date)]


# ─── the columns ─────────────────────────────────────────────────────────────

@pytest.fixture
def old_cves(tmp_path, monkeypatch):
    path = tmp_path / "old.db"

    async def _build():
        async with aiosqlite.connect(path) as db:
            await db.execute("""
                CREATE TABLE cves (
                    id TEXT PRIMARY KEY, software TEXT NOT NULL, description TEXT,
                    cvss_score REAL, cvss_version TEXT, severity TEXT, published_at TIMESTAMP,
                    source TEXT, url TEXT, epss_score REAL, epss_percentile REAL,
                    seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.commit()

    asyncio.run(_build())
    monkeypatch.setattr(database, "DB_PATH", path)
    return path


@pytest.mark.asyncio
async def test_an_existing_cves_table_gains_the_columns_a_rank_needs(old_cves):
    await database.init_db()

    async with aiosqlite.connect(old_cves) as db, db.execute("PRAGMA table_info(cves)") as cursor:
        assert {row[1] for row in await cursor.fetchall()} >= PRIORITY_COLUMNS


@pytest.mark.asyncio
async def test_the_exploitation_fact_is_read_back():
    await _store([ROWS[8]])

    [row] = await database.get_cves()

    assert row["known_exploited"] is True
    assert row["kev_ransomware"] is False
    assert (row["kev_date_added"], row["kev_due_date"]) == ("2024-01-10", "2024-01-31")


@pytest.mark.asyncio
async def test_cisas_unknown_is_stored_as_no_ransomware():
    await _store([ROWS[10]])

    [row] = await database.get_cves()

    assert row["kev_ransomware"] is False


@pytest.mark.asyncio
async def test_a_cve_stored_before_kev_listed_it_learns_it_on_the_next_scan():
    """First writer wins for the description; it cannot for this. NVD stored the
    row on Monday, CISA added it on Tuesday, Wednesday's scan must say so."""
    await _store([_row("CVE-2026-0013", "2026-09-01T00:00:00Z", 7.2)])
    await database.save_cve(_row("CVE-2026-0013", "2026-09-01T00:00:00Z", None, known_exploited=True,
                                 kev_date_added="2026-10-15", kev_ransomware=True))

    [row] = await database.get_cves()

    assert row["known_exploited"] is True
    assert row["kev_ransomware"] is True
    assert row["cvss_score"] == 7.2


@pytest.mark.asyncio
async def test_a_scan_without_the_kev_record_does_not_forget_it():
    await _store([ROWS[8]])
    await database.save_cve(_row("CVE-2023-0009", "2023-03-01T00:00:00Z", 7.8))

    [row] = await database.get_cves()

    assert row["known_exploited"] is True


# ─── the order ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_stored_listing_is_in_the_order_priority_gives():
    await _store(ROWS)

    assert [r["id"] for r in await database.get_cves(limit=100)] == _expected(ROWS)


@pytest.mark.asyncio
async def test_the_listing_for_one_product_is_in_the_same_order():
    await _store(ROWS)

    assert [r["id"] for r in await database.get_cves(software="nginx", limit=100)] == _expected(ROWS)


@pytest.mark.asyncio
async def test_a_short_listing_is_the_most_urgent_not_the_newest():
    await _store(ROWS)

    assert [r["id"] for r in await database.get_cves(limit=3)] == _expected(ROWS)[:3]
    assert (await database.get_cves(limit=1))[0]["id"] == "CVE-2022-0010"


# ─── what reads it ───────────────────────────────────────────────────────────

async def test_the_api_listing_says_why_each_row_ranks_where_it_does():
    await _store(ROWS)
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as client:
        rows = (await client.get("/api/cves", params={"limit": 100})).json()["cves"]

    assert [r["id"] for r in rows] == _expected(ROWS)
    assert rows[0]["priority"] == "ransomware"
    assert "in CISA KEV since 2023-02-01" in rows[0]["priority_reason"]
    assert rows[0]["known_exploited"] is True


def test_status_lists_the_exploited_cve_above_the_newest():
    asyncio.run(_store([ROWS[0], ROWS[8]]))

    result = CliRunner().invoke(cli.app, ["status"], env={"COLUMNS": "200"})

    out = result.output
    assert out.index("CVE-2023-0009") < out.index("CVE-2026-0001")
    assert "exploited" in out
