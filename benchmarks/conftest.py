"""Shared fixtures and synthetic datasets for the PatchRadar benchmarks.

The benchmarks never touch the network or the real user database: HTTP calls are
served by an in-process ``httpx.MockTransport`` and the SQLite database points to
a temporary file seeded with realistic CVE data.
"""

import asyncio
import random
from pathlib import Path

import aiosqlite
import pytest

from patchradar.db import database

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SOFTWARE = ["proxmox", "bitwarden", "windows 10", "nginx", "postgresql"]

DESCRIPTION = (
    "A flaw was found in the request handling code of the affected component. "
    "An unauthenticated remote attacker can send a specially crafted payload "
    "that triggers an out-of-bounds write, leading to memory corruption and "
    "potentially arbitrary code execution in the context of the service user. "
)


def _description(seed: int) -> str:
    """Build a description long enough to exercise the truncation paths."""
    return f"CVE-{seed} " + DESCRIPTION * (2 + seed % 4)


def make_cve(index: int) -> dict:
    """Build a single CVE record in the shape used across the codebase."""
    score = round((index % 100) / 10, 1)
    return {
        "id": f"CVE-2026-{index:05d}",
        "software": SOFTWARE[index % len(SOFTWARE)],
        "description": _description(index),
        "cvss_score": score,
        "cvss_version": "3.1",
        "severity": SEVERITIES[index % len(SEVERITIES)],
        "published_at": f"2026-08-{(index % 28) + 1:02d}T12:00:00.000",
        "source": "NVD" if index % 2 else "MSRC",
        "url": f"https://nvd.nist.gov/vuln/detail/CVE-2026-{index:05d}",
    }


@pytest.fixture(scope="session")
def cve_records() -> list[dict]:
    """A page-sized batch of CVEs, as returned by the collectors."""
    return [make_cve(i) for i in range(100)]


@pytest.fixture(scope="session")
def loop():
    """A single event loop reused by every benchmark iteration."""
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    yield event_loop
    event_loop.close()


@pytest.fixture(scope="session")
def db_path(tmp_path_factory) -> Path:
    """Redirect the module level ``DB_PATH`` to a throwaway database."""
    path = tmp_path_factory.mktemp("patchradar-bench") / "patchradar.db"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(database, "DB_PATH", path)
        yield path


@pytest.fixture(scope="session")
def seeded_db(loop, db_path) -> Path:
    """A database pre-populated with a realistic amount of CVEs."""

    async def _seed():
        await database.init_db()
        async with aiosqlite.connect(db_path) as db:
            await db.executemany(
                "INSERT OR IGNORE INTO watchlist (name) VALUES (?)",
                [(name,) for name in SOFTWARE],
            )
            await db.executemany(
                """
                INSERT OR IGNORE INTO cves
                (id, software, description, cvss_score, cvss_version,
                 severity, published_at, source, url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        cve["id"],
                        cve["software"],
                        cve["description"],
                        cve["cvss_score"],
                        cve["cvss_version"],
                        cve["severity"],
                        cve["published_at"],
                        cve["source"],
                        cve["url"],
                    )
                    for cve in (make_cve(i) for i in range(500))
                ],
            )
            await db.commit()

    loop.run_until_complete(_seed())
    return db_path


@pytest.fixture(scope="session")
def nvd_payload() -> dict:
    """An NVD API response with a full page of vulnerabilities."""
    rng = random.Random(0)
    vulnerabilities = []
    for index in range(50):
        metric_key = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"][
            index % 4
        ]
        vulnerabilities.append(
            {
                "cve": {
                    "id": f"CVE-2026-{index:05d}",
                    "published": f"2026-08-{(index % 28) + 1:02d}T12:00:00.000",
                    "descriptions": [
                        {"lang": "es", "value": _description(index)},
                        {"lang": "en", "value": _description(index)},
                    ],
                    "metrics": {
                        metric_key: [
                            {
                                "baseSeverity": SEVERITIES[index % 4],
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": round(rng.uniform(0, 10), 1),
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                            }
                        ]
                    },
                    "references": [
                        {"url": f"https://example.com/advisory/{index}/{i}"}
                        for i in range(5)
                    ],
                }
            }
        )
    return {"totalResults": len(vulnerabilities), "vulnerabilities": vulnerabilities}


@pytest.fixture(scope="session")
def msrc_payload() -> dict:
    """An MSRC CVRF response mixing matching and non-matching vulnerabilities."""
    vulnerabilities = []
    for index in range(200):
        product = "Windows 10" if index % 3 == 0 else "Azure DevOps"
        vulnerabilities.append(
            {
                "CVE": f"CVE-2026-{index:05d}",
                "Title": {"Value": f"{product} Remote Code Execution Vulnerability"},
                "Notes": [
                    {"Type": 1, "Value": _description(index)},
                    {"Type": 7, "Value": f"{product} advisory note"},
                ],
                "CVSSScoreSets": [{"BaseScore": round((index % 100) / 10, 1)}],
                "RevisionHistory": [{"Date": "2026-08-12T00:00:00"}],
            }
        )
    return {"Vulnerability": vulnerabilities}
