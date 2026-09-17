"""
PatchRadar — test database isolation (L10)

The suite ran against `Path.home()/".patchradar"/"patchradar.db"` — the real
user database. Running `pytest` polluted it with fixtures (`testapp`,
`duplicate-test`, a 101-character name, and at one point an injected
`evil<script>alert(1)</script>`), and `test_db_remove_cleans_orphan_cves`
deleted rows from it.

The session fixture in conftest.py now redirects DB_PATH at a temporary
directory. These tests are the guard that it stays redirected.
"""
import sqlite3
import uuid
from pathlib import Path

import pytest

from patchradar.db import database


def test_default_path_still_points_at_the_user_home():
    """The production default must be unchanged — only tests get redirected."""
    assert database.DEFAULT_DB_PATH == Path.home() / ".patchradar" / "patchradar.db"


def test_db_path_is_redirected_during_tests():
    assert database.DB_PATH != database.DEFAULT_DB_PATH, (
        "the suite is pointed at the real user database"
    )


def test_db_path_is_outside_the_user_data_directory():
    real_dir = database.DEFAULT_DB_PATH.parent
    assert real_dir not in database.DB_PATH.parents, (
        f"{database.DB_PATH} lives inside the real {real_dir}"
    )


@pytest.mark.asyncio
async def test_writes_do_not_reach_the_production_database():
    """Decisive check: write a canary and prove it never lands in the real file.

    The canary name is unique per run. A fixed name would make this test fail
    forever once a single leaking run had written it — which is exactly what
    happened while mutation-testing this fix.
    """
    canary = f"l10-canary-{uuid.uuid4().hex[:12]}"
    real = database.DEFAULT_DB_PATH
    before = real.stat().st_mtime_ns if real.exists() else None

    await database.init_db()
    await database.add_to_watchlist(canary)

    assert canary in await database.get_watchlist()  # it did get written somewhere

    if real.exists():
        assert real.stat().st_mtime_ns == before, "the real database file was modified"
        with sqlite3.connect(f"file:{real}?mode=ro", uri=True) as con:
            names = {row[0] for row in con.execute("SELECT name FROM watchlist")}
        assert canary not in names, "the canary reached the real database"


@pytest.mark.asyncio
async def test_the_temporary_database_is_a_real_working_database():
    """Isolation must not be achieved by breaking persistence."""
    await database.init_db()
    await database.add_to_watchlist("roundtrip-check")
    assert "roundtrip-check" in await database.get_watchlist()
    assert database.DB_PATH.exists()
    await database.remove_from_watchlist("roundtrip-check")
