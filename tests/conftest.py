"""Shared test fixtures."""
import asyncio

import aiosqlite
import pytest

from patchradar.collectors import debian
from patchradar.db import database


@pytest.fixture(scope="session", autouse=True)
def isolated_database(tmp_path_factory):
    """Point the whole suite at a throwaway database.

    Without this the tests ran against Path.home()/".patchradar", i.e. the
    user's real data: fixtures were left behind in it and
    test_db_remove_cleans_orphan_cves deleted rows from it.

    This also creates the schema once per session. httpx's ASGITransport does
    not run the app's lifespan handler, so the `init_db()` call in
    patchradar.api.main.lifespan never fires under test; without it the API
    tests only passed when some earlier test happened to create the database.
    """
    db_path = tmp_path_factory.mktemp("patchradar") / "patchradar.db"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(database, "DB_PATH", db_path)
        asyncio.run(database.init_db())
        yield db_path


@pytest.fixture(autouse=True)
async def clean_tables(isolated_database):
    """Give every test an empty database.

    The temporary database is shared for the whole session, so without this
    tests observe each other's rows and assertions like
    `get_watchlist() == ["nginx"]` depend on execution order.
    """
    async with aiosqlite.connect(database.DB_PATH) as db:
        await db.execute("DELETE FROM watchlist")
        await db.execute("DELETE FROM cves")
        await db.commit()
    yield


@pytest.fixture(autouse=True)
def reset_debian_snapshot():
    """Isolate the process-wide Debian tracker cache between tests.

    The collector caches the ~75 MB tracker dump for an hour, which is what we
    want in production and never what we want across tests.
    """
    debian.clear_cache()
    yield
    debian.clear_cache()


@pytest.fixture(autouse=True)
def _isolate_law_checker(tmp_path, monkeypatch):
    """No test may reach EUR-Lex or write to ~/.patchradar: the law cache goes
    to a temporary folder and every download fails."""
    from patchradar import law_fetcher

    monkeypatch.setenv("PATCHRADAR_HOME", str(tmp_path / "patchradar-home"))

    def no_network(*args, **kwargs):
        raise law_fetcher.LawFetchError("network disabled in tests")

    monkeypatch.setattr(law_fetcher, "fetch_html", no_network)
