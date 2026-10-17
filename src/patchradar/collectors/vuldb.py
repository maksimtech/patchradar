"""VulDB vulnerability database collector.

VulDB (https://vuldb.com) is an independent vulnerability database with exploit
pricing intelligence, threat actor attribution, and faster indexing than NVD for
some entries. The API is a single POST endpoint at https://vuldb.com/api.

Authentication is via an API key sent in the ``X-VulDB-ApiKey`` header. The key
is read from the ``VULDB_API_KEY`` environment variable; without it the collector
raises ``CollectorError`` rather than making an unauthenticated request that would
fail anyway.

API credits are consumed per request; the ``response_remaining`` field in every
response reports the balance. The collector logs a warning when credits drop
below a threshold so a scan does not silently exhaust the quota.
"""
import logging
import os
from urllib.parse import urlencode

import httpx

from patchradar.collectors.errors import BAD_PAYLOAD, CollectorError, from_http_error
from patchradar.cvss import severity_for
from patchradar.names import keyword_pattern

logger = logging.getLogger(__name__)

VULDB_API = "https://vuldb.com/api"
SOURCE = "VulDB"

API_KEY_ENV = "VULDB_API_KEY"

# Warn when the remaining credits drop below this threshold. A keyword search
# costs one credit; a scan of ten keywords with details costs more. The
# threshold is deliberately conservative so the operator sees it before the
# quota runs out, not after.
CREDITS_WARNING_THRESHOLD = 10


def api_key() -> str | None:
    """The configured VulDB API key, or None if there is none."""
    key = (os.environ.get(API_KEY_ENV) or "").strip()
    return key or None


def _parse_entry(entry: dict, keyword: str) -> dict | None:
    """Turn one VulDB result entry into a PatchRadar CVE dict, or None."""
    if not isinstance(entry, dict):
        return None

    source_data = entry.get("source") or {}
    advisory = entry.get("advisory") or {}
    vulnerability = entry.get("vulnerability") or {}
    cvss = entry.get("cvss3") or entry.get("cvss2") or {}

    cve_id = source_data.get("cve") or advisory.get("id")
    if not cve_id:
        return None
    # VulDB IDs are numeric; CVE IDs are strings like "CVE-2024-1234".
    # When no CVE is assigned, VulDB uses its own numeric ID — prefix it.
    cve_id = str(cve_id)
    if not cve_id.startswith("CVE-"):
        cve_id = f"VDB-{cve_id}"

    score = cvss.get("base_score") if isinstance(cvss, dict) else None
    if isinstance(score, str):
        try:
            score = float(score)
        except (ValueError, TypeError):
            score = None
    elif not isinstance(score, (int, float)):
        score = None

    cvss_version = None
    if entry.get("cvss3"):
        cvss_version = "3.1"
    elif entry.get("cvss2"):
        cvss_version = "2.0"

    return {
        "id": cve_id,
        "software": keyword.lower(),
        "description": vulnerability.get("title") or advisory.get("title") or "",
        "cvss_score": score,
        "cvss_version": cvss_version,
        "severity": severity_for(score, cvss_version),
        "published_at": advisory.get("date") or "",
        "source": SOURCE,
        "url": f"https://vuldb.com/?id.{advisory.get('id', '')}",
    }


def _matches_keyword(entry: dict, keyword: str) -> bool:
    """Whether the entry is relevant to `keyword`.

    VulDB's search is broad and may return entries only tangentially related.
    This post-filters the same way the other collectors do: whole-word match
    in the title.
    """
    vulnerability = entry.get("vulnerability") or {}
    advisory = entry.get("advisory") or {}
    title = f"{vulnerability.get('title', '')} {advisory.get('title', '')}".lower()
    return keyword.lower() in title and keyword_pattern(keyword).search(title) is not None


def request_body(keyword: str) -> str:
    """The form body of a search. Encoded, so that a software name with `&`, `=`
    or a space arrives as one value and cannot add parameters to the request."""
    return urlencode({"search": keyword, "details": 1})


async def fetch_cves(keyword: str, days_back: int = 30) -> list[dict]:
    """Fetch vulnerabilities from VulDB for a given keyword.

    `days_back` is accepted for signature compatibility with the other
    collectors. VulDB's search endpoint does not take a date range; the results
    are the most recent entries matching the keyword, and the API returns at
    most 10 per request on the free tier.

    Raises ``CollectorError`` when the API key is missing, when the request
    fails, or when the response is not parseable.
    """
    key = api_key()
    if key is None:
        raise CollectorError(SOURCE, "no_api_key",
                             detail=f"set {API_KEY_ENV} to use VulDB")

    headers = {
        "X-VulDB-ApiKey": key,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = request_body(keyword)

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(VULDB_API, headers=headers, content=body)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise from_http_error(SOURCE, exc) from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise CollectorError(SOURCE, BAD_PAYLOAD,
                             status=response.status_code) from exc

    if not isinstance(data, dict):
        raise CollectorError(SOURCE, BAD_PAYLOAD, status=response.status_code,
                             detail=f"expected an object, got {type(data).__name__}")

    # Log remaining credits so operators know before they run out.
    resp_meta = data.get("response") or {}
    remaining = resp_meta.get("remaining")
    if isinstance(remaining, (int, float)) and remaining < CREDITS_WARNING_THRESHOLD:
        logger.warning("VulDB API credits low: %s remaining", remaining)

    result = data.get("result")
    if not isinstance(result, list):
        # An empty result set is a valid answer (no matching entries).
        return []

    records: list[dict] = []
    for entry in result:
        if not isinstance(entry, dict):
            continue
        parsed = _parse_entry(entry, keyword)
        if parsed is not None:
            records.append(parsed)

    return records
