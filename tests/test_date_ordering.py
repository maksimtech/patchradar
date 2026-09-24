"""
PatchRadar — published_at normalisation (W8)

Each collector stored its source's own timestamp format:

  NVD     2026-08-15T00:00:00.000          (no zone; NVD times are UTC)
  Debian  2026-08-15T00:00:00.123456+00:00
  MSRC    2026-08-12T07:00:00, ...Z, or with an offset such as -07:00

The column is TEXT, so `ORDER BY published_at DESC` compared them as strings:
"…T20:00:00-07:00" (03:00 UTC the next day) sorted before "…T23:00:00+00:00",
and with LIMIT the newest CVEs could fall off the page entirely.

The fix normalises every timestamp to one fixed-width UTC form,
YYYY-MM-DDTHH:MM:SSZ, when it is saved — and rewrites rows saved before.
"""
import time

import aiosqlite
import pytest

from patchradar.db import database

# (raw value as a collector produced it, canonical UTC value)
FORMATS = [
    pytest.param("2026-08-15T00:00:00.000", "2026-08-15T00:00:00Z", id="nvd"),
    pytest.param("2026-08-15T12:34:56.789", "2026-08-15T12:34:56Z", id="nvd-millis"),
    pytest.param("2026-08-15T00:00:00+00:00", "2026-08-15T00:00:00Z", id="debian"),
    pytest.param("2026-08-15T09:10:11.123456+00:00", "2026-08-15T09:10:11Z", id="debian-micros"),
    pytest.param("2026-08-12T07:00:00", "2026-08-12T07:00:00Z", id="msrc-naive"),
    pytest.param("2026-08-12T07:00:00Z", "2026-08-12T07:00:00Z", id="msrc-z"),
    pytest.param("2026-08-12T00:00:00-07:00", "2026-08-12T07:00:00Z", id="msrc-offset"),
    pytest.param("2026-08-16T01:00:00+02:00", "2026-08-15T23:00:00Z", id="offset-crosses-day"),
    pytest.param("2026-12-31T23:30:00-01:00", "2027-01-01T00:30:00Z", id="offset-crosses-year"),
    pytest.param("2026-08-12", "2026-08-12T00:00:00Z", id="date-only"),
    pytest.param("  2026-08-12T07:00:00Z ", "2026-08-12T07:00:00Z", id="whitespace"),
]

UNPARSEABLE = [None, "", "   ", "not a date", "2026-13-45", "N/A", 12345, 3.5, True, ["2026-08-12"]]


# ─── the normaliser ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw, expected", FORMATS)
def test_normalises_every_source_format_to_utc(raw, expected):
    assert database.normalize_timestamp(raw) == expected


@pytest.mark.parametrize("raw, expected", FORMATS)
def test_normalisation_is_idempotent(raw, expected):
    assert database.normalize_timestamp(database.normalize_timestamp(raw)) == expected


@pytest.mark.parametrize("raw", UNPARSEABLE, ids=repr)
def test_unparseable_becomes_null(raw):
    assert database.normalize_timestamp(raw) is None


@pytest.mark.parametrize("raw, expected", FORMATS)
def test_canonical_form_is_fixed_width(raw, expected):
    """Fixed width + one zone is what makes string order equal time order."""
    assert len(database.normalize_timestamp(raw)) == len("2026-08-15T00:00:00Z")


# ─── what gets stored and how it sorts ───────────────────────────────────────

def cve(cid, published_at, source="NVD", software="nginx"):
    return {"id": cid, "software": software, "description": "d", "cvss_score": None,
            "cvss_version": None, "severity": "LOW", "published_at": published_at,
            "source": source, "url": "u"}


# Chronological order (newest first): B, A, D, C.
# The raw strings, sorted as text, give A, D, C, B — B, the newest, comes last.
MIXED = [
    cve("CVE-A", "2026-08-16T00:00:00.000", "NVD"),               # 16th 00:00Z
    cve("CVE-B", "2026-08-15T20:00:00-07:00", "MSRC"),            # 16th 03:00Z
    cve("CVE-C", "2026-08-15T23:00:00.000000+00:00", "Debian"),   # 15th 23:00Z
    cve("CVE-D", "2026-08-15T23:30:00Z", "MSRC"),                 # 15th 23:30Z
]


@pytest.mark.asyncio
async def test_mixed_sources_sort_chronologically():
    for c in MIXED:
        assert await database.save_cve(c)
    assert [r["id"] for r in await database.get_cves()] == ["CVE-B", "CVE-A", "CVE-D", "CVE-C"]


@pytest.mark.asyncio
async def test_mixed_sources_sort_chronologically_per_software():
    for c in MIXED:
        await database.save_cve(c)
    assert [r["id"] for r in await database.get_cves("nginx")] == ["CVE-B", "CVE-A", "CVE-D", "CVE-C"]


@pytest.mark.asyncio
async def test_limit_keeps_the_newest():
    for c in MIXED:
        await database.save_cve(c)
    assert [r["id"] for r in await database.get_cves(limit=1)] == ["CVE-B"]


@pytest.mark.asyncio
async def test_stored_value_is_canonical():
    await database.save_cve(MIXED[1])
    (row,) = await database.get_cves()
    assert row["published_at"] == "2026-08-16T03:00:00Z"


@pytest.mark.asyncio
async def test_save_does_not_mutate_the_callers_dict():
    record = cve("CVE-X", "2026-08-15T00:00:00.000")
    await database.save_cve(record)
    assert record["published_at"] == "2026-08-15T00:00:00.000"


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", ["", "garbage", None])
async def test_unknown_date_is_stored_as_null_and_sorts_last(raw):
    await database.save_cve(cve("CVE-OLD", "2020-01-01T00:00:00.000"))
    await database.save_cve(cve("CVE-NODATE", raw))
    rows = await database.get_cves()
    assert [r["id"] for r in rows] == ["CVE-OLD", "CVE-NODATE"]
    assert rows[1]["published_at"] is None


# ─── rows saved before the fix ───────────────────────────────────────────────

async def insert_raw(rows):
    async with aiosqlite.connect(database.DB_PATH) as db:
        for c in rows:
            await db.execute(
                "INSERT INTO cves (id, software, description, severity, published_at, source, url)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (c["id"], c["software"], c["description"], c["severity"],
                 c["published_at"], c["source"], c["url"]))
        await db.commit()


@pytest.mark.asyncio
async def test_init_db_migrates_legacy_rows():
    await insert_raw(MIXED + [cve("CVE-BAD", "garbage")])
    await database.init_db()
    rows = await database.get_cves()
    assert [r["id"] for r in rows] == ["CVE-B", "CVE-A", "CVE-D", "CVE-C", "CVE-BAD"]
    assert rows[0]["published_at"] == "2026-08-16T03:00:00Z"
    assert rows[-1]["published_at"] is None


@pytest.mark.asyncio
async def test_migration_is_idempotent_and_keeps_other_columns():
    await insert_raw(MIXED)
    await database.init_db()
    first = await database.get_cves()
    await database.init_db()
    assert await database.get_cves() == first
    assert {r["source"] for r in first} == {"NVD", "MSRC", "Debian"}


def _assert_naive_values_are_utc():
    assert database.normalize_timestamp("2026-08-15T00:00:00.000") == "2026-08-15T00:00:00Z"
    assert database.normalize_timestamp("2026-08-12") == "2026-08-12T00:00:00Z"


def test_naive_values_are_read_as_utc():
    """NVD and MSRC send UTC without a zone, and it must be read as UTC.

    Split out from the host-zone case below so that the assertion itself runs
    everywhere: time.tzset() exists only on POSIX, and on Windows the whole
    case used to fail with AttributeError — which also took down the Sonar
    contract test, since that one runs this file in a subprocess.
    """
    _assert_naive_values_are_utc()


@pytest.mark.skipif(
    not hasattr(time, "tzset"),
    reason="time.tzset() is POSIX only; the assertion itself runs in the case above",
)
@pytest.mark.parametrize("zone", ["Asia/Tokyo", "America/Los_Angeles"])
def test_naive_values_are_utc_whatever_the_host_zone(monkeypatch, zone):
    """The stronger form: reading them as local time is invisible on a UTC
    server and shifts every date on anyone else's machine."""
    monkeypatch.setenv("TZ", zone)
    time.tzset()
    try:
        _assert_naive_values_are_utc()
    finally:
        monkeypatch.undo()
        time.tzset()
