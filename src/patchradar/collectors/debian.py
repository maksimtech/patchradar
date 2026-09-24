import asyncio
import logging
import time
from datetime import UTC, datetime

import httpx

from patchradar.collectors.errors import BAD_PAYLOAD, CollectorError, from_http_error

logger = logging.getLogger(__name__)

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_RELEASE = "trixie"  # default: Debian 13
SOURCE = "Debian"

# The tracker emits exactly three status values: resolved, open, undetermined.
# "undetermined" means the release may be affected, so it is reported.
UNRESOLVED_STATUSES = frozenset({"open", "undetermined"})

# The tracker dump is a single ~75 MB JSON document covering every package, so
# it is fetched once and filtered in memory rather than re-downloaded per
# keyword. A scan over N packages used to cost N * 75 MB.
CACHE_TTL_SECONDS = 3600

_snapshot: dict | None = None
_snapshot_at: float = 0.0
_lock = asyncio.Lock()


def clear_cache() -> None:
    """Drop the cached tracker snapshot (used by tests and manual refreshes)."""
    global _snapshot, _snapshot_at
    _snapshot = None
    _snapshot_at = 0.0


def _fresh_snapshot() -> dict | None:
    """The cached dump while it is still within the TTL, else None.

    This returns the value rather than a boolean so that "fresh" and "present"
    cannot drift apart: a caller cannot act on one without holding the other.
    """
    if _snapshot is None or (time.monotonic() - _snapshot_at) >= CACHE_TTL_SECONDS:
        return None
    return _snapshot


async def _download_tracker() -> dict:
    """Fetch the tracker dump, raising CollectorError on any failure."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.get(DEBIAN_TRACKER_URL)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise from_http_error(SOURCE, exc) from exc
    try:
        data = response.json()
    except ValueError as exc:
        raise CollectorError(SOURCE, BAD_PAYLOAD, status=response.status_code) from exc
    if not isinstance(data, dict):
        raise CollectorError(SOURCE, BAD_PAYLOAD, status=response.status_code,
                             detail=f"expected an object, got {type(data).__name__}")
    return data


async def get_tracker_snapshot() -> dict:
    """Return the cached tracker dump, downloading it at most once per TTL.

    The lock collapses a stampede of concurrent scans into a single download;
    a failed download raises and is never cached, so the next call retries.
    """
    global _snapshot, _snapshot_at
    cached = _fresh_snapshot()
    if cached is not None:
        return cached
    async with _lock:
        # Re-check: another coroutine may have populated it while we waited.
        cached = _fresh_snapshot()
        if cached is not None:
            return cached
        data = await _download_tracker()
        _snapshot = data
        _snapshot_at = time.monotonic()
        return _snapshot


# The tracker's `urgency` field only ever takes these six values. The table
# used to be keyed on Debian BTS *bug severities* (grave, serious, important,
# moderate, critical), which the security tracker never emits — so `high` and
# `medium` fell through to UNKNOWN and vanished from the severity filters.
URGENCY_TO_SEVERITY = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "unimportant": "LOW",
    "end-of-life": "LOW",
    # "not yet assigned" is the most common value by far (~77% of entries);
    # reporting it as LOW would be a false reassurance, so it stays UNKNOWN.
    "not yet assigned": "UNKNOWN",
}


def _urgency_to_severity(urgency: str | None) -> str:
    if not urgency:
        return "UNKNOWN"
    return URGENCY_TO_SEVERITY.get(str(urgency).strip().lower(), "UNKNOWN")


def filter_tracker(data: dict, keyword: str, release: str = DEBIAN_RELEASE) -> list[dict]:
    """Select the open CVEs matching `keyword` from a tracker snapshot."""
    results = []
    keyword_lower = keyword.lower()

    for package_name, cves in data.items():
        if keyword_lower not in package_name.lower():
            continue

        for cve_id, cve_data in cves.items():
            if not cve_id.startswith("CVE-"):
                continue

            releases = cve_data.get("releases")
            if not isinstance(releases, dict):
                continue
            release_data = releases.get(release)
            # No entry for this release means the tracker says nothing about
            # it — the package is not in that release, or the CVE does not
            # apply. Treating that silence as "open" produced 7,924 phantom
            # vulnerabilities tracker-wide (100% of postgresql's, 47% of
            # python's), so such CVEs are now out of scope.
            if not isinstance(release_data, dict):
                continue

            # Whitelist rather than "anything that is not resolved": an empty
            # or unrecognised status is exactly what caused the false positives.
            status = release_data.get("status")
            if status not in UNRESOLVED_STATUSES:
                if status != "resolved":
                    logger.debug(
                        "skipping %s/%s: unrecognised status %r", package_name, cve_id, status
                    )
                continue

            urgency = release_data.get("urgency", "unimportant")
            severity = _urgency_to_severity(urgency)

            results.append({
                "id": cve_id,
                "software": keyword_lower,
                "description": cve_data.get("description", ""),
                "cvss_score": None,
                "cvss_version": None,
                "severity": severity,
                "published_at": datetime.now(UTC).isoformat(),
                "source": "Debian",
                "url": f"https://security-tracker.debian.org/tracker/{cve_id}",
            })

    return results


async def fetch_cves(keyword: str, days_back: int = 30, release: str = DEBIAN_RELEASE) -> list[dict]:
    """Fetch CVEs from Debian Security Tracker for a given package keyword."""
    return filter_tracker(await get_tracker_snapshot(), keyword, release)
