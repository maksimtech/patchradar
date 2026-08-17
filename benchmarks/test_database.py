"""Benchmarks for the SQLite persistence layer."""

import itertools

from patchradar.db import database


def test_get_watchlist(benchmark, loop, seeded_db):
    """Watchlist read, executed on every CLI invocation and API request."""
    result = benchmark(lambda: loop.run_until_complete(database.get_watchlist()))

    assert result


def test_add_to_watchlist(benchmark, loop, seeded_db):
    """Insert path, including the duplicate detection round trip."""
    counter = itertools.count()

    def run():
        name = f"bench-software-{next(counter)}"
        return loop.run_until_complete(database.add_to_watchlist(name))

    assert benchmark(run) is True


def test_get_cves(benchmark, loop, seeded_db):
    """Paginated CVE read with row-to-dict conversion."""
    result = benchmark(lambda: loop.run_until_complete(database.get_cves(limit=50)))

    assert len(result) == 50


def test_get_cves_by_software(benchmark, loop, seeded_db):
    """CVE read filtered by software, the query used by the dashboard filters."""
    result = benchmark(
        lambda: loop.run_until_complete(
            database.get_cves(software="proxmox", limit=100)
        )
    )

    assert result


def test_init_db(benchmark, loop, seeded_db):
    """Schema initialization, run at every startup."""
    benchmark(lambda: loop.run_until_complete(database.init_db()))
