import asyncio
import logging
import time

import httpx

from patchradar.collectors.errors import BAD_PAYLOAD, CollectorError, from_http_error

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE = "CISA KEV"

# The catalogue is published roughly daily and is small — 1,726 entries on
# 2026-09-25, against NVD's hundreds of thousands. Like the Debian tracker it is
# one document covering everything, so it is fetched once and filtered in
# memory rather than re-downloaded per keyword.
CACHE_TTL_SECONDS = 3600

_snapshot: dict | None = None
_snapshot_at: float = 0.0
_lock = asyncio.Lock()


def clear_cache() -> None:
    """Drop the cached catalogue (used by tests and manual refreshes)."""
    global _snapshot, _snapshot_at
    _snapshot = None
    _snapshot_at = 0.0


def _fresh_snapshot() -> dict | None:
    """The cached catalogue while it is still within the TTL, else None."""
    if _snapshot is None or (time.monotonic() - _snapshot_at) >= CACHE_TTL_SECONDS:
        return None
    return _snapshot


async def _download_catalogue() -> dict:
    """Fetch the KEV catalogue, raising CollectorError on any failure.

    Never returns an empty catalogue in place of an error: for this source an
    empty answer is meaningful — CISA lists everything it has observed being
    exploited, so "not in the catalogue" is a finding. Letting a failed
    download look like that would turn an outage into a clean bill of health.
    """
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.get(KEV_URL)
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
    if not isinstance(data.get("vulnerabilities"), list):
        raise CollectorError(SOURCE, BAD_PAYLOAD, status=response.status_code,
                             detail="no 'vulnerabilities' list in the catalogue")
    return data


async def get_catalogue() -> dict:
    """Return the cached catalogue, downloading it at most once per TTL.

    The lock collapses concurrent scans into a single download; a failed
    download raises and is never cached, so one outage does not poison the
    process for a whole hour.
    """
    global _snapshot, _snapshot_at
    cached = _fresh_snapshot()
    if cached is not None:
        return cached
    async with _lock:
        cached = _fresh_snapshot()
        if cached is not None:
            return cached
        data = await _download_catalogue()
        _snapshot = data
        _snapshot_at = time.monotonic()
        return _snapshot


def _ransomware(value: object) -> bool:
    """CISA writes the strings "Known" and "Unknown" — never a boolean.

    `bool("Unknown")` is True, so passing the field through unconverted marks
    every entry as ransomware-linked: 1,610 of the 1,726 in the live catalogue
    say "Unknown".
    """
    return str(value).strip().lower() == "known"


def _to_record(entry: dict, keyword: str) -> dict:
    cve_id = entry.get("cveID", "")
    return {
        "id": cve_id,
        "software": keyword.lower(),
        "description": entry.get("shortDescription", ""),
        # KEV states no severity, and this collector must not supply one.
        # Mapping "exploited" to CRITICAL would manufacture a score CISA never
        # gave, and it would then be indistinguishable from one a scoring body
        # actually assigned. The exploitation fact travels in `known_exploited`,
        # where nothing can mistake it for a severity — and where it is worth
        # more than a severity anyway: measured on a real machine on
        # 2026-09-26, ordering 695 matched CVEs by CVSS put five 10.0 entries
        # on top, none of them exploited, while the four that were in KEV
        # scored 9.8, 8.8, 8.6 and 7.8 — below all five.
        "cvss_score": None,
        "cvss_version": None,
        "severity": "UNKNOWN",
        # The date the entry was added, not `now()`: this source carries no
        # publication date, and a clock reading would make the same CVE differ
        # between two fetches and defeat de-duplication downstream.
        "published_at": entry.get("dateAdded", ""),
        "source": SOURCE,
        "url": ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                f"?search_api_fulltext={cve_id}"),
        "known_exploited": True,
        "kev_date_added": entry.get("dateAdded"),
        # CISA's own remediation deadline. For a federal agency it is binding;
        # for everyone else it is the most concrete due date any source gives.
        "kev_due_date": entry.get("dueDate"),
        "kev_ransomware": _ransomware(entry.get("knownRansomwareCampaignUse")),
        "kev_required_action": entry.get("requiredAction"),
        "kev_vulnerability_name": entry.get("vulnerabilityName"),
    }


def filter_catalogue(data: dict, keyword: str) -> list[dict]:
    """Select the catalogue entries matching `keyword`.

    Both `vendorProject` and `product` are searched: a watchlist entry is as
    likely to name one as the other — "Oracle" against a product called
    "Java SE" — and searching only one of the two silently halves the
    catalogue.
    """
    needle = keyword.lower()
    results = []
    for entry in data.get("vulnerabilities", []):
        if not isinstance(entry, dict):
            continue
        haystack = f"{entry.get('vendorProject', '')} {entry.get('product', '')}".lower()
        if needle in haystack:
            results.append(_to_record(entry, keyword))
    return results


async def fetch_cves(keyword: str, days_back: int = 30) -> list[dict]:
    """Fetch known-exploited CVEs for a given vendor or product keyword.

    `days_back` is accepted for signature compatibility with the other
    collectors and deliberately ignored: the catalogue is a standing list of
    what is being exploited, not a feed of recent publications, and dropping
    older entries would hide the ones that have been exploited the longest.
    """
    return filter_catalogue(await get_catalogue(), keyword)


async def known_exploited(cve_id: str) -> dict | None:
    """The catalogue entry for `cve_id`, or None if it is not listed.

    None is a real answer here rather than an absence of one: CISA lists what
    it has observed, so "not in the catalogue" means "not known to be
    exploited". It is distinguishable from a failure because a failure raises.
    """
    data = await get_catalogue()
    wanted = cve_id.strip().upper()
    for entry in data.get("vulnerabilities", []):
        if isinstance(entry, dict) and str(entry.get("cveID", "")).upper() == wanted:
            return _to_record(entry, "")
    return None
