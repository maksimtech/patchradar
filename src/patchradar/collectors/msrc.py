import httpx
from datetime import datetime, timedelta

MSRC_API = "https://api.msrc.microsoft.com/cvrf/v3.0"
HEADERS = {"Accept": "application/json"}

def _extract_description(vuln: dict) -> str:
    """Extract description from MSRC vulnerability notes."""
    for note in vuln.get("Notes", []):
        if note.get("Type") == 1:
            return note.get("Value", "")
    return ""


def _matches_keyword(vuln: dict, keyword: str) -> bool:
    """Check if vulnerability matches keyword in title or notes."""
    title = vuln.get("Title", {}).get("Value", "")
    notes = " ".join([n.get("Value", "") for n in vuln.get("Notes", [])])
    kw = keyword.lower()
    return kw in title.lower() or kw in notes.lower()


def _parse_vuln(vuln: dict, keyword: str) -> dict | None:
    """Parse a single MSRC vulnerability into a CVE dict."""
    if not _matches_keyword(vuln, keyword):
        return None
    cve_id = vuln.get("CVE", "")
    cvss_score = None
    severity = "UNKNOWN"
    cvss_sets = vuln.get("CVSSScoreSets", [])
    if cvss_sets:
        cvss_score = cvss_sets[0].get("BaseScore")
        severity = _score_to_severity(cvss_score)
    description = _extract_description(vuln)
    title = vuln.get("Title", {}).get("Value", "")
    return {
        "id": cve_id,
        "software": keyword.lower(),
        "description": description[:2000] if description else title,
        "cvss_score": cvss_score,
        "cvss_version": "3.1",
        "severity": severity,
        "published_at": vuln.get("RevisionHistory", [{}])[0].get("Date", ""),
        "source": "MSRC",
        "url": f"https://msrc.microsoft.com/update-guide/en-US/vulnerability/{cve_id}",
    }


async def fetch_cves(keyword: str, days_back: int = 30) -> list[dict]:
    """Fetch CVEs from Microsoft MSRC for a given keyword."""
    results = []
    
    # Determina i mesi da controllare
    now = datetime.now()
    months_to_check = set()
    
    for days in range(0, days_back + 30, 30):
        check_date = now - timedelta(days=days)
        months_to_check.add(f"{check_date.year}-{check_date.strftime('%b')}")
    
    async with httpx.AsyncClient(timeout=30.0, headers=HEADERS) as client:
        for month in months_to_check:
            try:
                response = await client.get(f"{MSRC_API}/cvrf/{month}")
                if response.status_code != 200:
                    continue
                    
                data = response.json()
                vulnerabilities = data.get("Vulnerability", [])
                for vuln in vulnerabilities:
                    parsed = _parse_vuln(vuln, keyword)
                    if parsed:
                        results.append(parsed)
            except Exception:
                continue
    
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
