import asyncio
import logging
import re
import time
from datetime import datetime, timedelta

import httpx

from patchradar.collectors.errors import (
    BAD_PAYLOAD,
    NETWORK,
    CollectorError,
    reason_for_status,
)
from patchradar.cvss import severity_for
from patchradar.names import keyword_pattern

logger = logging.getLogger(__name__)

MSRC_API = "https://api.msrc.microsoft.com/cvrf/v3.0"
HEADERS = {"Accept": "application/json"}
SOURCE = "MSRC"

# MSRC addresses its monthly CVRF documents as e.g. "2026-Sep", always in
# English. strftime("%b") follows LC_TIME, so on a non-English machine every
# request would 404 and the collector would silently return nothing.
MONTH_ABBR = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

MAX_DAYS_BACK = 90

# A monthly document is one download for every keyword of a scan: September 2026
# measured 20,492,679 bytes, and a ten-entry watchlist fetched it ten times. The
# Debian tracker and the KEV catalogue are each downloaded once and filtered in
# memory; this is the same arrangement, per month. A document MSRC has not
# published yet (404) is not cached — the answer is small, and the document may
# appear within the hour — and a failed download is never cached.
CACHE_TTL_SECONDS = 3600

_documents: dict[str, dict] = {}
_documents_at: dict[str, float] = {}
_lock = asyncio.Lock()


def clear_cache() -> None:
    """Drop the cached documents (used by tests and manual refreshes)."""
    _documents.clear()
    _documents_at.clear()


def _fresh_document(month: str) -> dict | None:
    """The cached document for `month` while it is within the TTL, else None."""
    cached = _documents.get(month)
    if cached is None or (time.monotonic() - _documents_at.get(month, 0.0)) >= CACHE_TTL_SECONDS:
        return None
    return cached


class _MonthFailure(Exception):
    """One month that could not be read: the reason and the status, for the
    caller to fold into the CollectorError it raises after the loop."""

    def __init__(self, reason: str, status: int | None):
        super().__init__(reason)
        self.reason = reason
        self.status = status


async def _month_document(client: httpx.AsyncClient, month: str) -> dict | None:
    """The CVRF document for `month`, from the cache or from MSRC.

    None means MSRC has no document for that month (404), which is not a
    failure: the current month has none until Patch Tuesday. Anything else that
    is not a usable document raises `_MonthFailure`.
    """
    cached = _fresh_document(month)
    if cached is not None:
        return cached
    async with _lock:
        cached = _fresh_document(month)
        if cached is not None:
            return cached
        try:
            response = await client.get(f"{MSRC_API}/cvrf/{month}")
        except httpx.HTTPError as exc:
            logger.debug("MSRC request failed for %s", month, exc_info=True)
            raise _MonthFailure(NETWORK, None) from exc
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise _MonthFailure(reason_for_status(response.status_code), response.status_code)
        try:
            data = response.json()
        except ValueError as exc:
            raise _MonthFailure(BAD_PAYLOAD, response.status_code) from exc
        if not isinstance(data, dict):
            # Not a document, but MSRC answered: there is nothing to retry and
            # nothing to read, and the shape is remembered like a document is.
            data = {}
        _documents[month] = data
        _documents_at[month] = time.monotonic()
        return data


def _months_in_range(now: datetime, days_back: int) -> list[str]:
    """Every calendar month overlapping [now - days_back, now], oldest first.

    Walks months directly instead of stepping by 30 days: a fixed stride skips
    short months outright (from 2026-03-31 over 90 days it produced Dec, Jan,
    Mar — February, and its Patch Tuesday, never fetched).
    """
    days = min(max(int(days_back), 1), MAX_DAYS_BACK)
    start = now - timedelta(days=days)

    months = []
    year, month = start.year, start.month
    while (year, month) <= (now.year, now.month):
        months.append(f"{year}-{MONTH_ABBR[month - 1]}")
        if month == 12:
            year, month = year + 1, 1
        else:
            month += 1
    return months


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


# CVRF remediation type of a security update
VENDOR_FIX = 2
_CONFIDENTIALITY = re.compile(r"(?:^|/)C:([HLN])(?:/|$)")
_CONFIDENTIALITY_LEVELS = {"H": "HIGH", "L": "LOW", "N": "NONE"}


def _patch_available(vuln: dict) -> bool | None:
    """True when MSRC lists a security update, else None: third-party CVEs
    listed for information carry no remediation at all, so a missing one
    does not mean there is no patch."""
    remediations = vuln.get("Remediations")
    if isinstance(remediations, list) and any(
        isinstance(r, dict) and r.get("Type") == VENDOR_FIX for r in remediations
    ):
        return True
    return None


def _confidentiality(vuln: dict) -> str | None:
    """HIGH/LOW/NONE from the C: metric of the CVSS vector."""
    score_sets = vuln.get("CVSSScoreSets")
    if not isinstance(score_sets, list) or not score_sets or not isinstance(score_sets[0], dict):
        return None
    vector = score_sets[0].get("Vector")
    match = _CONFIDENTIALITY.search(vector) if isinstance(vector, str) else None
    return _CONFIDENTIALITY_LEVELS[match.group(1)] if match else None


def _window_start(now: datetime | None, days_back: int) -> datetime:
    """The oldest publication date the scan asked for.

    Capped like the months are: MSRC keeps three months of documents, so the
    window cannot open earlier than that, and the CLI says so after the total.
    """
    now = now or datetime.now()
    return now - timedelta(days=min(max(int(days_back), 1), MAX_DAYS_BACK))


def _published_inside(published_at: str, start: datetime) -> bool:
    """Whether the entry's first revision falls inside the window — or cannot be
    placed at all, which keeps it: dropping a CVE for a formatting oddity would
    hide it, and the record still says when it thinks it was published."""
    try:
        published = datetime.fromisoformat(published_at)
    except (TypeError, ValueError):
        return True
    if published.tzinfo is not None:
        # The documents date in naive UTC; `start` is naive too. An offset, if
        # one ever appears, is honoured and then dropped for the comparison.
        published = (published - published.utcoffset()).replace(tzinfo=None)  # type: ignore[operator]
    return published >= start


def _matches_keyword(vuln: dict, keyword: str) -> bool:
    """Whether the keyword is a word of the title or of a note.

    The notes stay in: curl's and OpenSSL's advisories carry their own titles
    ("OpenLDAP SASL authentication bypass") and name the product only in a note.
    A whole word, though, and not a substring: "git" matched 109 entries of the
    September 2026 document — "GitHub", "legitimate", "digital", "10-digit" —
    and not one of them was Git's.
    """
    notes = " ".join([n.get("Value") or "" for n in _notes(vuln)])
    matches = keyword_pattern(keyword).search
    return bool(matches(_title(vuln).lower()) or matches(notes.lower()))


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
        "patch_available": _patch_available(vuln),
        "confidentiality_impact": _confidentiality(vuln),
    }


async def fetch_cves(keyword: str, days_back: int = 30, *, now: datetime | None = None) -> list[dict]:
    """Fetch CVEs from Microsoft MSRC for a given keyword.

    The documents are monthly and the window is in days, so the months that
    overlap it are fetched and then each entry is held to the window by the date
    of its first revision. Until 2026-10-09 the documents were the window: a
    30-day scan on the 9th reported the Patch Tuesday of the 8th of the month
    before, 31 days back — sixteen SharePoint CVEs, while NVD, asked for the same
    30 days, answered one. `now` is for the tests; a scan passes nothing.
    """
    results = []
    failures: list[tuple[str, str, int | None]] = []   # (month, reason, status)
    now = now or datetime.now()
    months_to_check = _months_in_range(now, days_back)
    window_start = _window_start(now, days_back)

    async with httpx.AsyncClient(timeout=30.0, headers=HEADERS) as client:
        for month in months_to_check:
            try:
                data = await _month_document(client, month)
            except _MonthFailure as failure:
                failures.append((month, failure.reason, failure.status))
                continue
            if data is None:
                continue   # no CVRF document for that month yet — not a failure

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
                if parsed and _published_inside(parsed["published_at"], window_start):
                    results.append(parsed)

    if failures:
        # Months that did answer are kept in `partial`; the caller decides.
        _, reason, status = failures[0]
        raise CollectorError(SOURCE, reason, status=status, partial=results,
                             detail="failed months: " + ", ".join(m for m, _, _ in failures))
    return results


def _score_to_severity(score: float | None) -> str:
    """The qualitative step of the score, on the v3 scale.

    Delegates to `patchradar.cvss`, which keeps the thresholds FIRST publishes in
    a single place. The table written by hand here returned LOW for 0.0, while on
    v3 zero is NONE and Low starts at 0.1 — and no test pinned it.

    The version is "3.1" because that is the one MSRC publishes, and it is the
    same one that ends up in the `cvss_version` field of the record below: if
    MSRC ever changed scale, the two lines would have to change together.
    """
    return severity_for(score, "3.1")
