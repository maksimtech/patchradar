import httpx
from datetime import datetime, timezone

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_RELEASE = "trixie"  # default: Debian 13

def _urgency_to_severity(urgency: str) -> str:
    mapping = {
        "critical": "CRITICAL",
        "grave": "HIGH",
        "serious": "HIGH",
        "important": "MEDIUM",
        "moderate": "MEDIUM",
        "low": "LOW",
        "unimportant": "LOW",
        "end-of-life": "LOW",
    }
    return mapping.get(urgency.lower(), "UNKNOWN")

async def fetch_cves(keyword: str, days_back: int = 30, release: str = DEBIAN_RELEASE) -> list[dict]:
    """Fetch CVEs from Debian Security Tracker for a given package keyword."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.get(DEBIAN_TRACKER_URL)
            response.raise_for_status()
            data = response.json()
        except Exception:
            return []

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
