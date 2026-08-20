import httpx
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Descrizione inglese
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"), ""
        )

        # CVSS score
        cvss_score = None
        cvss_version = None
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})

        for version in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                m = metrics[version][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_version = cvss_data.get("version")
                severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                break

        results.append({
            "id": cve_id,
            "software": keyword.lower(),
            "description": description,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "severity": severity,
            "published_at": cve.get("published"),
            "source": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return results
