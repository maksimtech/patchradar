import logging
import httpx
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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
    }


async def fetch_cves(keyword: str, days_back: int = 7) -> list[dict]:
    """Fetch CVEs from NVD for a given keyword."""
    start = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
        "%Y-%m-%dT00:00:00.000"
    )
    end = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999")

    params = {
        "keywordSearch": keyword,
        "pubStartDate": start,
        "pubEndDate": end,
        "resultsPerPage": 50,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(NVD_API, params=params)
            response.raise_for_status()
            data = response.json()
        except Exception:
            return []

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
