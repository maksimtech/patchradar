"""
PatchRadar — the watchlist learns what is installed (DESIGN §5.1, §5.2)

Five columns, nullable and without a default: `cpe`, `vendor`, `product_id`,
`installed_version`, `channel` — the names `inventory.py` has been waiting for.
A missing version is an absence; a default would be a claim.

The migration is half the feature, as it was for EPSS: `CREATE TABLE IF NOT
EXISTS` does nothing to a database that already has a watchlist, so the old
database below is written out by hand, in the shape it shipped in.
"""
from __future__ import annotations

import asyncio

import aiosqlite
import pytest
from typer.testing import CliRunner

from patchradar import cli
from patchradar.cpe import parse_cpe
from patchradar.db import database

NOTEPADPP = "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"
FIVE = {"cpe", "vendor", "product_id", "installed_version", "channel"}

# The watchlist as it shipped until 2026-10-17, written out rather than
# generated: a migration test whose "old" database comes from today's code
# tests nothing.
OLD_WATCHLIST = """
    CREATE TABLE watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""


@pytest.fixture
def old_database(tmp_path, monkeypatch):
    path = tmp_path / "old.db"

    async def _build():
        async with aiosqlite.connect(path) as db:
            await db.execute(OLD_WATCHLIST)
            await db.execute("INSERT INTO watchlist (name) VALUES ('notepad')")
            await db.commit()

    asyncio.run(_build())
    monkeypatch.setattr(database, "DB_PATH", path)
    return path


async def _watchlist_columns(path) -> set[str]:
    async with aiosqlite.connect(path) as db, db.execute("PRAGMA table_info(watchlist)") as cursor:
        return {row[1] for row in await cursor.fetchall()}


def _out(result) -> str:
    """Rich wraps long lines to the runner's width; the words are what count."""
    return " ".join(result.output.split())


# ─── the migration ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_existing_watchlist_gains_the_five_columns(old_database):
    assert not FIVE & await _watchlist_columns(old_database)

    await database.init_db()

    assert await _watchlist_columns(old_database) >= FIVE


@pytest.mark.asyncio
async def test_an_entry_from_before_keeps_its_name_and_knows_no_version(old_database):
    await database.init_db()

    [entry] = await database.get_watch_entries()
    assert entry.name == "notepad"
    assert entry.installed_version is None
    assert entry.cpe is None
    assert not entry.judgeable


@pytest.mark.asyncio
async def test_migrating_twice_is_not_an_error(old_database):
    await database.init_db()
    await database.init_db()

    assert await _watchlist_columns(old_database) >= FIVE


# ─── storing what is installed ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_version_and_cpe_are_stored_with_vendor_and_product():
    await database.add_to_watchlist("notepad")

    assert await database.set_installed("notepad", version="8.5.0", cpe=parse_cpe(NOTEPADPP))

    [entry] = await database.get_watch_entries()
    assert entry.installed_version == "8.5.0"
    assert entry.cpe == NOTEPADPP
    assert entry.vendor == "notepad-plus-plus"
    assert entry.product_id == "notepad\\+\\+"
    assert entry.channel is None
    assert entry.judgeable


@pytest.mark.asyncio
async def test_a_version_without_a_cpe_is_kept_and_cannot_be_judged():
    """The version alone says nothing NVD can be asked about: the vendor and
    product are what `cpeMatch` is read by."""
    await database.add_to_watchlist("notepad")
    await database.set_installed("notepad", version="8.5.0", cpe=None)

    [entry] = await database.get_watch_entries()
    assert entry.installed_version == "8.5.0"
    assert not entry.judgeable


@pytest.mark.asyncio
async def test_setting_one_field_leaves_the_other_alone():
    await database.add_to_watchlist("notepad")
    await database.set_installed("notepad", version="8.5.0", cpe=parse_cpe(NOTEPADPP))

    await database.set_installed("notepad", version="8.9.6.4", cpe=None)

    [entry] = await database.get_watch_entries()
    assert entry.installed_version == "8.9.6.4"
    assert entry.cpe == NOTEPADPP


@pytest.mark.asyncio
async def test_a_name_not_on_the_watchlist_is_not_added_by_the_back_door():
    assert not await database.set_installed("notepad", version="8.5.0", cpe=None)
    assert await database.get_watchlist() == []


@pytest.mark.asyncio
async def test_get_watchlist_still_answers_names():
    """The API and the scan read names from it; their shape does not change."""
    await database.add_to_watchlist("notepad")
    await database.set_installed("notepad", version="8.5.0", cpe=parse_cpe(NOTEPADPP))

    assert await database.get_watchlist() == ["notepad"]


# ─── patchradar add / list ───────────────────────────────────────────────────

def test_add_with_version_and_cpe_says_what_it_stored():
    result = CliRunner().invoke(cli.app, ["add", "notepad", "--version", "8.5.0", "--cpe", NOTEPADPP])

    assert result.exit_code == 0, result.output
    assert "Added" in result.output
    assert "8.5.0" in _out(result)
    [entry] = asyncio.run(database.get_watch_entries())
    assert (entry.installed_version, entry.cpe) == ("8.5.0", NOTEPADPP)


def test_add_on_an_existing_entry_updates_what_is_installed():
    runner = CliRunner()
    runner.invoke(cli.app, ["add", "notepad"])

    result = runner.invoke(cli.app, ["add", "notepad", "--version", "8.9.6.4", "--cpe", NOTEPADPP])

    assert result.exit_code == 0, result.output
    assert "Updated" in result.output
    assert "already in your watchlist" not in result.output
    [entry] = asyncio.run(database.get_watch_entries())
    assert entry.installed_version == "8.9.6.4"


def test_add_without_options_on_an_existing_entry_is_unchanged():
    runner = CliRunner()
    runner.invoke(cli.app, ["add", "notepad", "--version", "8.5.0"])

    result = runner.invoke(cli.app, ["add", "notepad"])

    assert "already in your watchlist" in result.output
    [entry] = asyncio.run(database.get_watch_entries())
    assert entry.installed_version == "8.5.0"


def test_a_version_the_scan_cannot_order_is_refused_at_add():
    """Refused once, here, rather than "not evaluable" on every CVE of every scan."""
    result = CliRunner().invoke(cli.app, ["add", "notepad", "--version", "8.x-beta", "--cpe", NOTEPADPP])

    assert result.exit_code == 1
    assert "8.x-beta" in result.output
    assert asyncio.run(database.get_watchlist()) == []


def test_a_cpe_with_an_unescaped_plus_is_refused_with_the_form_nvd_wants():
    result = CliRunner().invoke(cli.app, ["add", "notepad", "--version", "8.5.0",
                                          "--cpe", "cpe:2.3:a:notepad-plus-plus:notepad++"])

    assert result.exit_code == 1
    assert "notepad\\+\\+" in result.output
    assert asyncio.run(database.get_watchlist()) == []


def test_list_shows_the_version_and_the_cpe():
    runner = CliRunner()
    runner.invoke(cli.app, ["add", "notepad", "--version", "8.5.0", "--cpe", NOTEPADPP])
    runner.invoke(cli.app, ["add", "nginx"])

    result = runner.invoke(cli.app, ["list"])

    out = _out(result)
    assert "8.5.0" in out
    assert "notepad-plus-plus" in out
    assert "nginx" in out


@pytest.mark.asyncio
async def test_setting_nothing_changes_nothing():
    await database.add_to_watchlist("notepad")
    await database.set_installed("notepad", version="8.5.0", cpe=parse_cpe(NOTEPADPP))

    assert await database.set_installed("notepad", version=None, cpe=None)

    [entry] = await database.get_watch_entries()
    assert (entry.installed_version, entry.cpe) == ("8.5.0", NOTEPADPP)
