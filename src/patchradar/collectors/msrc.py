import logging
import httpx
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

MSRC_API = "https://api.msrc.microsoft.com/cvrf/v3.0"
HEADERS = {"Accept": "application/json"}


def _notes(vuln: dict) -> list[dict]:
    notes = vuln.get("Notes")
    return [n for n in notes if isinstance(n, dict)] if isinstance(notes, list) else []


def _title(vuln: dict) -> str:
    title = vuln.get("Title")
    if not isinstance(title, dict):
        return ""
    return title.get("Value") or ""


def _extract_description(vuln: dict) -> str:
    """Extract description from MSRC vulnerability notes."""
    for note in _notes(vuln):
        if note.get("Type") == 1:
            return note.get("Value") or ""
    return ""


def _published_at(vuln: dict) -> str:
    """First revision date, or "" — the list can be present but empty."""
    history = vuln.get("RevisionHistory")
    if not isinstance(history, list) or not history:
        return ""
    first = history[0]
    return (first.get("Date") or "") if isinstance(first, dict) else ""


def _base_score(vuln: dict) -> float | None:
    score_sets = vuln.get("CVSSScoreSets")
    if not isinstance(score_sets, list) or not score_sets:
        return None
    first = score_sets[0]
    if not isinstance(first, dict):
        return None
    score = first.get("BaseScore")
    return score if isinstance(score, (int, float)) else None


def _matches_keyword(vuln: dict, keyword: str) -> bool:
    """Check if vulnerability matches keyword in title or notes."""
    notes = " ".join([n.get("Value") or "" for n in _notes(vuln)])
    kw = keyword.lower()
    return kw in _title(vuln).lower() or kw in notes.lower()


def _parse_vuln(vuln: dict, keyword: str) -> dict | None:
    """Parse a single MSRC vulnerability into a CVE dict."""
    if not isinstance(vuln, dict):
        return None
    if not _matches_keyword(vuln, keyword):
        return None
    cve_id = vuln.get("CVE")
    if not isinstance(cve_id, str) or not cve_id:
        return None
    cvss_score = _base_score(vuln)
    severity = _score_to_severity(cvss_score)
    description = _extract_description(vuln)
    return {
        "id": cve_id,
        "software": keyword.lower(),
        "description": description[:2000] if description else _title(vuln),
        "cvss_score": cvss_score,
        "cvss_version": "3.1",
        "severity": severity,
        "published_at": _published_at(vuln),
        "source": "MSRC",
        "url": f"https://msrc.microsoft.com/update-guide/en-US/vulnerability/{cve_id}",
    }


async def fetch_cves(keyword: str, days_back: int = 30) -> list[dict]:
    """Fetch CVEs from Microsoft MSRC for a given keyword."""
    results = []

    # Determina i mesi da controllare
    now = datetime.now()
    months_to_check = set()

    safe_days_back = min(max(int(days_back), 1), 90)  # clamp to safe range
    for days in range(0, safe_days_back + 30, 30):
        check_date = now - timedelta(days=days)
        months_to_check.add(f"{check_date.year}-{check_date.strftime('%b')}")

    async with httpx.AsyncClient(timeout=30.0, headers=HEADERS) as client:
        for month in months_to_check:
            try:
                response = await client.get(f"{MSRC_API}/cvrf/{month}")
                if response.status_code != 200:
                    continue
                data = response.json()
            except Exception:
                logger.debug("MSRC request failed for %s", month, exc_info=True)
                continue

            if not isinstance(data, dict):
                continue
            vulnerabilities = data.get("Vulnerability")
            if not isinstance(vulnerabilities, list):
                continue

            for vuln in vulnerabilities:
                # Per-record, not per-month: a single malformed entry used to
                # discard every remaining CVE of the month silently.
                try:
                    parsed = _parse_vuln(vuln, keyword)
                except Exception:
                    logger.debug("skipping unparseable MSRC record", exc_info=True)
                    continue
                if parsed:
                    results.append(parsed)

    return results


def _score_to_severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"
