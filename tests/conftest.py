"""Shared test fixtures."""
import asyncio
import time

import aiosqlite
import pytest

from patchradar import epss
from patchradar.collectors import debian, kev
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
def kev_offline_by_default():
    """Give every test an empty KEV catalogue, already cached.

    Isolation is only half the reason. The other half is that the collector
    downloads the catalogue the first time it is asked, and a scan reaches it
    through the CLI and the API alike — so a test that exercises a scan without
    mocking cisa.gov makes a live request. That is exactly what happened when
    KEV joined the fan-out: `tests/test_scan_source_outage.py` fetched the real
    catalogue and a test asserting on a zero total found one CVE, while four
    other files did the same more quietly, leaving only a thread exception
    about a closed event loop behind them.

    Seeding an empty catalogue closes that off for every test that does not ask
    for one, and for every source added after this one. A test that wants a
    real catalogue clears the cache itself — see `tests/test_kev.py`.
    """
    kev.clear_cache()
    kev._snapshot = {"catalogVersion": "test", "count": 0, "vulnerabilities": []}
    kev._snapshot_at = time.monotonic()
    yield
    kev.clear_cache()


@pytest.fixture(autouse=True)
def epss_offline_by_default(monkeypatch):
    """Give every test an EPSS lookup that scores nothing, without a request.

    The same reasoning as `kev_offline_by_default`, one step further along the
    scan: FIRST is asked about every CVE a scan finds, from the CLI and the API
    alike, so any test that exercises a scan would otherwise reach
    api.first.org — and unlike the collectors there is no keyword to make the
    request narrow, so it would be a request about whatever CVEs the test's own
    fixtures invented.

    This patches the one networked function rather than `enrich`, which leaves
    the enrichment itself running: records still pass through it and still come
    out with no EPSS fields, which is exactly what a CVE FIRST does not score
    looks like. `tests/test_epss.py` overrides this fixture to get the real
    function back.
    """
    async def _scores_nothing(cve_ids):
        return {}

    epss.clear_cache()
    monkeypatch.setattr(epss, "_lookup", _scores_nothing)
    yield
    epss.clear_cache()


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
def _no_rate_limit_pacing(monkeypatch):
    """Do not wait for NVD's rate limit in the suite.

    The collector paces consecutive windowed requests — six seconds apart
    without an API key — so a 365-day fetch, which two tests make, would hold
    the suite for eighteen seconds each while asserting nothing about waiting.

    A test that is about the pacing replaces this with a recorder of its own and
    asserts on what would have been slept.

    `nvd._pace`, not `asyncio.sleep`: `nvd.asyncio` is the asyncio module, so
    patching its sleep replaces it for the whole interpreter — which broke the
    API deadline test, where `asyncio.sleep(30)` is how a hanging upstream is
    simulated.
    """
    from patchradar.collectors import nvd

    async def no_wait(seconds):
        return None

    monkeypatch.setattr(nvd, "_pace", no_wait)


@pytest.fixture(autouse=True)
def _isolate_law_checker(tmp_path, monkeypatch):
    """No test may reach EUR-Lex or write to ~/.patchradar: the law cache goes
    to a temporary folder and every download fails."""
    from patchradar import law_fetcher

    monkeypatch.setenv("PATCHRADAR_HOME", str(tmp_path / "patchradar-home"))

    def no_network(*args, **kwargs):
        raise law_fetcher.LawFetchError("network disabled in tests")

    monkeypatch.setattr(law_fetcher, "fetch_html", no_network)
