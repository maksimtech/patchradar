"""
PatchRadar — the verdict outlives the scan (docs/DESIGN.md §5.5)

PR-01a judged each CVE against the installed version in memory, and the next
`patchradar status`, `/api/cves` and the web UI went back to CVEs by name. The
verdict is now kept beside the link between a CVE and a product, in
`cve_software`, because that is where it belongs: one CVE stored once can be
"affected" for one watched product and "not affected" for another.

It is kept with the version it was given for. A verdict about 8.5.0 is not a
verdict about 8.9.6.4: after `add notepad --version 8.9.6.4`, the stored one is
not shown until a scan judges the new version — a stale "affected" would send
someone to patch what is already patched, and a stale "not affected" is worse.
"""
from __future__ import annotations

import asyncio
import json
import pathlib

import aiosqlite
import httpx
import pytest
import respx
from typer.testing import CliRunner

from patchradar import cli
from patchradar.collectors import msrc, nvd
from patchradar.cpe import parse_cpe
from patchradar.db import database

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "nvd_notepadpp_configurations.json"
PAYLOAD = json.loads(FIXTURE.read_text(encoding="utf-8"))
NOTEPADPP = "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"
VERDICT_COLUMNS = {"verdict", "verdict_reason", "verdict_fixed_version", "judged_version"}


def _record(cve_id="CVE-2023-40031", software="notepad", **verdict):
    return {"id": cve_id, "software": software, "description": "x", "cvss_score": 7.8,
            "cvss_version": "3.1", "severity": "HIGH", "published_at": "2023-08-25T00:00:00Z",
            "source": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", **verdict}


AFFECTED_850 = {"verdict": "affected", "verdict_reason": "last affected version 8.5.6; NVD does "
                "not state which release fixed it", "verdict_fixed_version": None,
                "judged_version": "8.5.0"}


async def _watch(version="8.5.0"):
    await database.add_to_watchlist("notepad")
    await database.set_installed("notepad", version=version, cpe=parse_cpe(NOTEPADPP))


# ─── the migration ───────────────────────────────────────────────────────────

@pytest.fixture
def old_links(tmp_path, monkeypatch):
    """`cve_software` as it shipped in 2026.44, written out by hand."""
    path = tmp_path / "old.db"

    async def _build():
        async with aiosqlite.connect(path) as db:
            await db.execute("""
                CREATE TABLE cve_software (
                    cve_id TEXT NOT NULL,
                    software TEXT NOT NULL,
                    PRIMARY KEY (cve_id, software)
                )
            """)
            await db.execute("INSERT INTO cve_software VALUES ('CVE-2023-40031', 'notepad')")
            await db.commit()

    asyncio.run(_build())
    monkeypatch.setattr(database, "DB_PATH", path)
    return path


@pytest.mark.asyncio
async def test_an_existing_link_table_gains_the_verdict_columns(old_links):
    await database.init_db()

    async with aiosqlite.connect(old_links) as db, db.execute("PRAGMA table_info(cve_software)") as cursor:
        columns = {row[1] for row in await cursor.fetchall()}
    assert columns >= VERDICT_COLUMNS


# ─── storing and reading it ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_judged_cve_is_read_back_with_its_verdict():
    await _watch()
    await database.save_cve(_record(**AFFECTED_850))

    [row] = await database.get_cves(software="notepad")

    assert row["verdict"] == "affected"
    assert row["verdict_reason"].startswith("last affected version 8.5.6")
    assert row["judged_version"] == "8.5.0"


@pytest.mark.asyncio
async def test_the_listing_of_every_product_carries_the_verdict_too():
    await _watch()
    await database.save_cve(_record(**AFFECTED_850))

    [row] = await database.get_cves()

    assert row["verdict"] == "affected"


@pytest.mark.asyncio
async def test_a_verdict_for_another_version_is_not_shown():
    await _watch()
    await database.save_cve(_record(**AFFECTED_850))
    await database.set_installed("notepad", version="8.9.6.4", cpe=None)

    [row] = await database.get_cves(software="notepad")

    assert row["verdict"] is None
    assert row["verdict_reason"] is None


@pytest.mark.asyncio
async def test_a_cve_has_its_own_verdict_for_each_product():
    """Stored once, linked twice: judged for notepad, matched by name for the other."""
    await _watch()
    await database.add_to_watchlist("scintilla")
    await database.save_cve(_record(**AFFECTED_850))
    await database.save_cve(_record(software="scintilla"))

    [for_notepad] = await database.get_cves(software="notepad")
    [for_scintilla] = await database.get_cves(software="scintilla")

    assert for_notepad["verdict"] == "affected"
    assert for_scintilla["verdict"] is None


@pytest.mark.asyncio
async def test_the_latest_scan_decides_the_verdict():
    """A second scan that judges differently — NVD analysed the CVE since —
    replaces the first verdict rather than being ignored like the first writer
    of a description."""
    await _watch()
    await database.save_cve(_record(verdict="not evaluable", verdict_reason="NVD has not yet stated "
                                    "which products it affects", judged_version="8.5.0"))
    await database.save_cve(_record(**AFFECTED_850))

    [row] = await database.get_cves(software="notepad")

    assert row["verdict"] == "affected"


# ─── patchradar status ───────────────────────────────────────────────────────

def test_status_shows_the_verdict_the_scan_gave():
    runner = CliRunner()
    runner.invoke(cli.app, ["add", "notepad", "--version", "8.5.0", "--cpe", NOTEPADPP])
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(200, json=PAYLOAD))
        router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        runner.invoke(cli.app, ["scan", "notepad", "--days", "7"])

    result = runner.invoke(cli.app, ["status"], env={"COLUMNS": "200"})

    out = " ".join(result.output.split())
    assert "Verdict" in out
    assert "affected" in out
    assert "not affected" in out


@pytest.mark.asyncio
async def test_the_listing_of_every_product_hides_a_stale_verdict_too():
    await _watch()
    await database.save_cve(_record(**AFFECTED_850))
    await database.set_installed("notepad", version="8.9.6.4", cpe=None)

    [row] = await database.get_cves()

    assert row["verdict"] is None
