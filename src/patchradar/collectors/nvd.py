import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import httpx

from patchradar.collectors.errors import BAD_PAYLOAD, CollectorError, from_http_error
from patchradar.cvss import exploit_maturity

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


def scoring_entry(entries: object) -> dict | None:
    """The metric a score is read from: NVD's own when there is one.

    A CVE can carry the same CVSS version twice, NVD's assessment ("type":
    "Primary") and the CNA's ("Secondary"), and the API does not promise their
    order — taking the first made the score depend on it. NVD's is preferred
    because it is the one assessed for every CVE by the same body; the CNA's is
    used when NVD has not scored it, which is the common case for new CVEs.
    """
    if not isinstance(entries, list):
        return None
    usable = [entry for entry in entries if isinstance(entry, dict)]
    return next((entry for entry in usable if entry.get("type") == "Primary"),
                usable[0] if usable else None)


def _extract_metrics(cve: dict) -> tuple[float | None, str | None, str]:
    """(score, cvss_version, severity), degrading to UNKNOWN on any oddity."""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None, None, "UNKNOWN"

    for key in CVSS_METRIC_KEYS:
        entry = scoring_entry(metrics.get(key))
        if entry is None:
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
        entry = scoring_entry(metrics.get(key))
        if entry is None:
            continue
        cvss_data = entry.get("cvssData")
        if not isinstance(cvss_data, dict):
            return None
        value = cvss_data.get("confidentialityImpact") or cvss_data.get("vulnConfidentialityImpact")
        return CONFIDENTIALITY_LEVELS.get(value) if isinstance(value, str) else None
    return None


def _extract_exploit_maturity(cve: dict) -> str | None:
    """What the v4.0 vector says about exploitation, or None.

    Only the v4.0 block: v3.1 has an `E:` of its own with the values U/P/F/H, and
    reading those as v4's A/P/U would translate a claim the provider never made.
    `cvss.exploit_maturity` checks the vector's own prefix, so this hands it the
    string and does not interpret it here.

    None covers "no v4.0 block", "no vector", "no E: metric" and `E:X` alike —
    none of which is a statement — and the caller leaves the field off the record
    entirely, because a field holding "X" or "" would read like a verdict.
    """
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    entries = metrics.get("cvssMetricV40")
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        data = entry.get("cvssData")
        if not isinstance(data, dict):
            continue
        found = exploit_maturity(data.get("vectorString"))
        if found is not None:
            return found
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
    # Left off the record entirely when the provider defined no threat metric:
    # the absence is the fact, and a key holding "X" would read as a verdict.
    maturity = _extract_exploit_maturity(cve)
    return {
        **({"cvss_exploit_maturity": maturity} if maturity else {}),
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


def _parse_page(vulnerabilities: list, keyword: str) -> list[dict]:
    """The usable records of one page's `vulnerabilities[]`, in NVD's order.

    A malformed record may drop itself, never its neighbours. Its own function,
    apart from the request loop, so that a page NVD actually sent can be run
    through it without standing up a server.
    """
    records: list[dict] = []
    for item in vulnerabilities:
        try:
            parsed = _parse_item(item, keyword)
        except Exception:
            logger.debug("skipping unparseable NVD record", exc_info=True)
            continue
        if parsed:
            records.append(parsed)
    return records


# NVD answers HTTP 404 — not 400 — when pubStartDate and pubEndDate are more
# than 120 days apart, which reads as "no such endpoint" rather than "your
# range is too wide". Measured against the live API on 2026-09-23: 119 days
# back returned 200, 120 returned 404. A chunk therefore spans at most 119 days
# back from its own end, leaving the inclusive window at 120.
NVD_MAX_WINDOW_DAYS = 119

# NVD's own maximum for a single page. It was 50 until 2026-10, with no request
# for the next page, so a keyword with more CVEs than that in a window — "linux",
# "chrome", "windows" — came back cut at 50 and looked complete. The pages are
# followed now; the size only decides how many requests that costs.
RESULTS_PER_PAGE = 2000

# The name NVD's own documentation uses for it.
API_KEY_ENV = "NVD_API_KEY"

# Published limits: 5 requests per rolling 30 seconds without a key, 50 with one
# (https://nvd.nist.gov/developers/start-here). Expressed as the interval between
# requests rather than as a quota, because that is what this code can honour.
KEYLESS_DELAY_SECONDS = 30 / 5
KEYED_DELAY_SECONDS = 30 / 50


async def _pace(seconds: float) -> None:
    """Wait between two requests to the same source.

    Its own function so that tests can replace it. Replacing `asyncio.sleep`
    instead would silence every wait in the process — including the ones other
    tests use to simulate a hanging upstream.
    """
    await asyncio.sleep(seconds)


def api_key() -> str | None:
    """The configured NVD API key, or None if there is none to send.

    Unset and set-to-blank are the same thing to whoever configured it, so both
    give None rather than an empty header.
    """
    key = (os.environ.get(API_KEY_ENV) or "").strip()
    return key or None


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
    client: httpx.AsyncClient, keyword: str, start: datetime, end: datetime,
    pace: Callable[[], Awaitable[None]], results: list[dict],
) -> None:
    """Every page of one window, appended to `results` as it arrives.

    NVD answers at most `resultsPerPage` records and states the size of the
    whole answer in `totalResults`; the rest is asked for with `startIndex`.
    `pace` is awaited before each request, so pages count against the rate
    limit exactly as windows do.

    `results` is the caller's list rather than a return value so that a page
    that fails can hand back, as `partial`, every record the earlier ones found.
    """
    params = {
        "keywordSearch": keyword,
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        # A string, because httpx's params type does not accept an int: it
        # stringifies one anyway, so this changes the annotation, not the request.
        "resultsPerPage": str(RESULTS_PER_PAGE),
    }

    start_index = 0
    while True:
        await pace()
        # Failures raise instead of returning []: an empty list must only ever
        # mean "NVD answered and had nothing", never "NVD could not be reached".
        try:
            response = await client.get(NVD_API, params={**params, "startIndex": str(start_index)})
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise from_http_error(SOURCE, exc, partial=results) from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise CollectorError(SOURCE, BAD_PAYLOAD, status=response.status_code, partial=results) from exc

        if not isinstance(data, dict):
            logger.warning("NVD returned %s, expected an object", type(data).__name__)
            return
        vulnerabilities = data.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            return

        results.extend(_parse_page(vulnerabilities, keyword))

        total = data.get("totalResults")
        start_index += len(vulnerabilities)
        if not isinstance(total, int) or start_index >= total:
            return
        if not vulnerabilities:
            # NVD promised more and sent nothing: stopping here quietly would
            # present the records so far as the whole answer.
            raise CollectorError(SOURCE, BAD_PAYLOAD, status=response.status_code, partial=results,
                                 detail=f"empty page at {start_index} of {total}")


async def fetch_cves(keyword: str, days_back: int = 7) -> list[dict]:
    """Fetch CVEs from NVD for a given keyword.

    A window wider than NVD accepts is split into several requests, and an
    answer larger than one page is followed page by page; a short window with
    a modest answer still costs exactly one request, which is every ordinary
    use of this function.

    Those requests are paced. Splitting a two-year window makes seven of them
    per keyword, and a keyless client is allowed five per thirty seconds — so
    the fix for the window created a way to trip the rate limit. The wait is
    between requests only: a single-request fetch waits for nothing.

    The key, when set, travels in a header. In the query string it would be
    written to every log and proxy record that sees the URL.
    """
    key = api_key()
    headers = {"apiKey": key} if key else {}
    delay = KEYED_DELAY_SECONDS if key else KEYLESS_DELAY_SECONDS
    sent = 0

    async def pace() -> None:
        nonlocal sent
        if sent:
            await _pace(delay)
        sent += 1

    results: list[dict] = []
    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        for index, (start, end) in enumerate(date_windows(days_back)):
            if index:
                # The windows touch, and a request covers whole days: the one
                # before ran to 23:59:59.999 of the day this one starts on.
                # Asking for that day again returned its CVEs twice.
                start += timedelta(days=1)
            await _fetch_window(client, keyword, start, end, pace, results)
    return results
