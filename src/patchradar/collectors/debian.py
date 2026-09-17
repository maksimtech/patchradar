import asyncio
import time
import httpx
from datetime import datetime, timezone

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_RELEASE = "trixie"  # default: Debian 13

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


def _is_fresh() -> bool:
    return _snapshot is not None and (time.monotonic() - _snapshot_at) < CACHE_TTL_SECONDS


async def _download_tracker() -> dict | None:
    """Fetch the tracker dump. Returns None on any failure — never a partial."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.get(DEBIAN_TRACKER_URL)
            response.raise_for_status()
            data = response.json()
        except Exception:
            return None
    return data if isinstance(data, dict) else None


async def get_tracker_snapshot() -> dict | None:
    """Return the cached tracker dump, downloading it at most once per TTL.

    The lock collapses a stampede of concurrent scans into a single download;
    a failed download is never cached, so the next call retries.
    """
    global _snapshot, _snapshot_at
    if _is_fresh():
        return _snapshot
    async with _lock:
        # Re-check: another coroutine may have populated it while we waited.
        if _is_fresh():
            return _snapshot
        data = await _download_tracker()
        if data is None:
            return None
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

            releases = cve_data.get("releases", {})
            release_data = releases.get(release, {})

            # Solo CVE aperte (non risolte)
            status = release_data.get("status", "")
            if status == "resolved":
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
                "published_at": datetime.now(timezone.utc).isoformat(),
                "source": "Debian",
                "url": f"https://security-tracker.debian.org/tracker/{cve_id}",
            })

    return results


async def fetch_cves(keyword: str, days_back: int = 30, release: str = DEBIAN_RELEASE) -> list[dict]:
    """Fetch CVEs from Debian Security Tracker for a given package keyword."""
    data = await get_tracker_snapshot()
    if data is None:
        return []
    return filter_tracker(data, keyword, release)
