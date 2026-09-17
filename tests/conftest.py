"""Shared test fixtures."""
import asyncio

import pytest

from patchradar.collectors import debian
from patchradar.db.database import init_db


@pytest.fixture(scope="session", autouse=True)
def initialise_database():
    """Create the schema once per session.

    httpx's ASGITransport does not run the app's lifespan handler, so the
    `init_db()` call in patchradar.api.main.lifespan never fires under test.
    Without this, the API tests only pass when some earlier test happens to
    have created the database first.
    """
    asyncio.run(init_db())


@pytest.fixture(autouse=True)
def reset_debian_snapshot():
    """Isolate the process-wide Debian tracker cache between tests.

    The collector caches the ~75 MB tracker dump for an hour, which is what we
    want in production and never what we want across tests.
    """
    debian.clear_cache()
    yield
    debian.clear_cache()
