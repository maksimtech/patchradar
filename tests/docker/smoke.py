"""
Docker smoke test: the container user must be able to create the database
where the volume actually is.

This is the G5 bug turned into a live check. docker-compose mounted the named
volume at /root/.patchradar while the image runs as the unprivileged
`patchradar` user, so the application wrote to /home/patchradar/.patchradar
instead: the volume stayed empty and the watchlist plus the whole CVE history
disappeared on every container recreation — silently, because the database was
still being created, just inside the container's own filesystem.

tests/test_docker_contract.py pins the three declarations against each other by
reading files. This runs inside the built image, where the answer is no longer a
declaration: the directory is either writable by this user or it is not.

If EXPECTED_VERSION is set, the installed patchradar must match it (the version
in pyproject.toml, for a local-source build).
"""
import asyncio
import os
from importlib.metadata import version
from pathlib import Path

from patchradar.db.database import DB_PATH, init_db

# What the Dockerfile declares as VOLUME. Hardcoded on purpose: the container
# cannot read the Dockerfile, and a value passed in from the workflow would be
# the same claim made twice rather than a second witness.
DECLARED_VOLUME = Path("/home/patchradar/.patchradar")


def _normalize(v: str) -> str:
    # PEP 440 drops leading zeros: 2026.09.4 → 2026.9.4
    return ".".join(str(int(p)) if p.isdigit() else p for p in v.lstrip("v").split("."))


async def main():
    expected = os.environ.get("EXPECTED_VERSION")
    installed = version("patchradar")
    if expected:
        assert _normalize(installed) == _normalize(expected), f"installed {installed}, expected {expected}"
    print(f"smoke: patchradar {installed} OK")

    assert DB_PATH.parent == DECLARED_VOLUME, (
        f"the database goes to {DB_PATH.parent}, the image declares {DECLARED_VOLUME} "
        "as its volume: whatever is written here does not survive the container"
    )

    await init_db()
    assert DB_PATH.is_file(), f"init_db() left no database at {DB_PATH}"

    # mkdir(exist_ok=True) is happy with a directory it cannot write to, so the
    # file existing is the part that proves the chown is still in place.
    assert os.access(DB_PATH, os.W_OK), f"{DB_PATH} is not writable by this user"
    print(f"smoke: database at {DB_PATH} OK")


asyncio.run(main())
