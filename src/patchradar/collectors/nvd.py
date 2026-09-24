import logging
from datetime import UTC, datetime, timedelta

import httpx

from patchradar.collectors.errors import BAD_PAYLOAD, CollectorError, from_http_error

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE = "NVD"

# Preferred first: newer CVSS revisions carry the more accurate score.
CVSS_METRIC_KEYS = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]


def _extract_description(cve: dict) -> str:
    """The English description, or "" when the feed does not supply a usable one.

    Entries are indexed defensively: a single record missing `lang` or `value`
    used to raise KeyError and abort the entire scan.
    """
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for d in descriptions:
        if isinstance(d, dict) and d.get("lang") == "en":
            return d.get("value") or ""
    return ""


def _extract_metrics(cve: dict) -> tuple[float | None, str | None, str]:
    """(score, cvss_version, severity), degrading to UNKNOWN on any oddity."""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None, None, "UNKNOWN"

    for key in CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        entry = entries[0]
        if not isinstance(entry, dict):
            continue
        cvss_data = entry.get("cvssData")
        if not isinstance(cvss_data, dict):
            cvss_data = {}
        severity = entry.get("baseSeverity") or cvss_data.get("baseSeverity") or "UNKNOWN"
        return cvss_data.get("baseScore"), cvss_data.get("version"), severity

    return None, None, "UNKNOWN"


# NVD tags references only once it has analysed a CVE
ANALYSED_STATUSES = {"Analyzed", "Modified"}

# CVSS v2 says COMPLETE/PARTIAL where v3 and v4 say HIGH/LOW
CONFIDENTIALITY_LEVELS = {"HIGH": "HIGH", "LOW": "LOW", "NONE": "NONE", "COMPLETE": "HIGH", "PARTIAL": "LOW"}


def _extract_patch_available(cve: dict) -> bool | None:
    """True if a reference is tagged "Patch", False if NVD analysed the CVE
    and tagged none, None while it is not analysed: no tags yet says nothing."""
    references = cve.get("references")
    tags: set[str] = set()
    if isinstance(references, list):
        for reference in references:
            if isinstance(reference, dict) and isinstance(reference.get("tags"), list):
                tags.update(tag for tag in reference["tags"] if isinstance(tag, str))
    if "Patch" in tags:
        return True
    return False if cve.get("vulnStatus") in ANALYSED_STATUSES else None


def _extract_confidentiality(cve: dict) -> str | None:
    """CVSS confidentiality impact (HIGH/LOW/NONE) of the metric the score comes from."""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    for key in CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
            continue
        cvss_data = entries[0].get("cvssData")
        if not isinstance(cvss_data, dict):
            return None
        value = cvss_data.get("confidentialityImpact") or cvss_data.get("vulnConfidentialityImpact")
        return CONFIDENTIALITY_LEVELS.get(value) if isinstance(value, str) else None
    return None


def _parse_item(item: dict, keyword: str) -> dict | None:
    """Turn one `vulnerabilities[]` entry into a CVE dict, or None if unusable."""
    if not isinstance(item, dict):
        return None
    cve = item.get("cve")
    if not isinstance(cve, dict):
        return None
    # The id is the database primary key — a blank one would collide with any
    # other id-less record, so such an entry is dropped rather than stored.
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not cve_id:
        return None

    cvss_score, cvss_version, severity = _extract_metrics(cve)
    return {
        "id": cve_id,
        "software": keyword.lower(),
        "description": _extract_description(cve),
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "severity": severity,
        "published_at": cve.get("published"),
        "source": "NVD",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "patch_available": _extract_patch_available(cve),
        "confidentiality_impact": _extract_confidentiality(cve),
    }


# NVD answers HTTP 404 — not 400 — when pubStartDate and pubEndDate are more
# than 120 days apart, which reads as "no such endpoint" rather than "your
# range is too wide". Measured against the live API on 2026-09-23: 119 days
# back returned 200, 120 returned 404. A chunk therefore spans at most 119 days
# back from its own end, leaving the inclusive window at 120.
NVD_MAX_WINDOW_DAYS = 119

# NVD's own maximum for a single page.
RESULTS_PER_PAGE = 50


def date_windows(
    days_back: int, now: datetime | None = None
) -> list[tuple[datetime, datetime]]:
    """`days_back` split into ranges NVD will accept, oldest first.

    Adjacent chunks touch rather than leave a gap: a CVE published in a gap
    would simply be missing from the scan, and nothing would say so.
    """
    if days_back < 1:
        raise ValueError(f"days_back must be at least 1, got {days_back}")

    now = now or datetime.now(UTC)
    oldest = now - timedelta(days=days_back)

    windows: list[tuple[datetime, datetime]] = []
    end = now
    while end > oldest:
        start = max(oldest, end - timedelta(days=NVD_MAX_WINDOW_DAYS))
        windows.append((start, end))
        if start <= oldest:
            break
        end = start
    return sorted(windows)


async def _fetch_window(
    client: httpx.AsyncClient, keyword: str, start: datetime, end: datetime
) -> list[dict]:
    params = {
        "keywordSearch": keyword,
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        # A string, because httpx's params type does not accept an int: it
        # stringifies one anyway, so this changes the annotation, not the request.
        "resultsPerPage": str(RESULTS_PER_PAGE),
    }

    # Failures raise instead of returning []: an empty list must only ever
    # mean "NVD answered and had nothing", never "NVD could not be reached".
    try:
        response = await client.get(NVD_API, params=params)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise from_http_error(SOURCE, exc) from exc
    try:
        data = response.json()
    except ValueError as exc:
        raise CollectorError(SOURCE, BAD_PAYLOAD, status=response.status_code) from exc

    if not isinstance(data, dict):
        logger.warning("NVD returned %s, expected an object", type(data).__name__)
        return []
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []

    results = []
    for item in vulnerabilities:
        # A malformed record may drop itself, never its neighbours.
        try:
            parsed = _parse_item(item, keyword)
        except Exception:
            logger.debug("skipping unparseable NVD record", exc_info=True)
            continue
        if parsed:
            results.append(parsed)

    return results


async def fetch_cves(keyword: str, days_back: int = 7) -> list[dict]:
    """Fetch CVEs from NVD for a given keyword.

    A window wider than NVD accepts is split into several requests; a short one
    still costs exactly one, which is every ordinary use of this function.
    """
    results: list[dict] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for start, end in date_windows(days_back):
            results.extend(await _fetch_window(client, keyword, start, end))
    return results
