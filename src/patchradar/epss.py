"""EPSS, from FIRST: how likely a CVE is to be exploited in the next 30 days.

Not a collector, and the distinction is the whole design. The four sources under
`collectors/` answer "which CVEs affect this software"; EPSS answers nothing of
the kind — asked about a CVE it already knows, it returns a probability. Wiring
it as a fifth collector would have meant inventing a keyword search it does not
have, and every CVE it returned would have been one another source had already
reported. So it runs after the fan-out, over the CVEs the scan actually found,
and adds two fields to them.

It sits between CVSS and KEV, which is the gap the scan had. CVSS says how bad
exploitation would be if it happened; KEV says it is happening. Between the two
is the question a patch window is actually scheduled against — how likely is
this to be used against me — and until now the scan ranked a 9.8 that nobody has
ever exploited above an 8.1 that is about to be. `priority.RANK_EPSS` reads the
fields this module writes.

A CVE FIRST does not score keeps no EPSS field at all. The absence is the point:
`epss_score: 0.0` is a real measurement — the floor of the scale, where tens of
thousands of CVEs sit — and would be indistinguishable from a CVE published
yesterday that the model has not scored yet.
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from patchradar.collectors.errors import BAD_PAYLOAD, CollectorError, from_http_error

logger = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
SOURCE = "FIRST EPSS"

# The model is re-run once a day, so a cache inside one scan is free accuracy and
# a cache across a day is a stale percentile. An hour splits the difference the
# way `collectors.kev` does, and for the same reason: a watchlist scan asks about
# the same CVEs several times over.
CACHE_TTL_SECONDS = 3600

# CVEs per request. FIRST accepts a comma-separated list and its default page
# size is 100, so asking about more than 100 ids truncates the answer at 100
# rather than failing — which would read here as "FIRST does not score the
# rest". The chunk size and the `limit` sent below are the same number for that
# reason, and must stay so.
CHUNK_SIZE = 100

# None as a value means "FIRST answered and does not score this CVE", which is a
# different fact from "not asked yet" and worth keeping: a scan of sixteen
# targets would otherwise ask about the same unscored CVE sixteen times.
_cache: dict[str, tuple[float, float] | None] = {}
_cache_at: float = 0.0
_lock = asyncio.Lock()


def clear_cache() -> None:
    """Drop the cached scores (used by tests and manual refreshes)."""
    global _cache_at
    _cache.clear()
    _cache_at = 0.0


def _expire_if_stale() -> None:
    """Empty the cache once it is past the TTL.

    One timestamp for the whole cache rather than one per entry: the entries all
    come from the same daily model run, so they go stale together.
    """
    global _cache_at
    if _cache and (time.monotonic() - _cache_at) >= CACHE_TTL_SECONDS:
        _cache.clear()
        _cache_at = 0.0


def _as_probability(value: object) -> float | None:
    """A float in [0, 1] from the strings FIRST sends, or None.

    The API returns `"0.00054"`, not `0.00054` — both fields are strings in the
    JSON — so this is a conversion, not a type check. Anything outside the unit
    interval is refused rather than clamped: a percentile of 7.4 is a payload
    that changed shape, and clamping it to 1.0 would put a CVE at the top of the
    scan on the strength of a parse error.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    if number != number or not 0.0 <= number <= 1.0:   # NaN fails both halves
        return None
    return number


def _parse(payload: object, status: int) -> dict[str, tuple[float, float]]:
    """{CVE id: (score, percentile)} from one response body.

    An entry missing or mangling either number is skipped rather than
    half-recorded: a score without its percentile cannot be read against the
    rest of the scan, and a percentile without a score has nothing to qualify.
    """
    if not isinstance(payload, dict):
        raise CollectorError(SOURCE, BAD_PAYLOAD, status=status,
                             detail=f"expected an object, got {type(payload).__name__}")
    data = payload.get("data")
    if not isinstance(data, list):
        raise CollectorError(SOURCE, BAD_PAYLOAD, status=status,
                             detail="no 'data' list in the response")
    found: dict[str, tuple[float, float]] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        cve_id = str(entry.get("cve") or "").strip().upper()
        score = _as_probability(entry.get("epss"))
        percentile = _as_probability(entry.get("percentile"))
        if not cve_id or score is None or percentile is None:
            logger.debug("skipping unusable EPSS entry %r", entry)
            continue
        found[cve_id] = (score, percentile)
    return found


def _chunks(ids: list[str]) -> list[list[str]]:
    return [ids[i:i + CHUNK_SIZE] for i in range(0, len(ids), CHUNK_SIZE)]


async def _lookup(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Ask FIRST about `cve_ids`, in chunks. The only networked function here.

    Raises CollectorError on any failure, carrying nothing in `partial`: the
    caller's records are already complete without EPSS, so there is no
    half-built result to hand back — only scores it did not get.
    """
    found: dict[str, tuple[float, float]] = {}
    async with httpx.AsyncClient(timeout=30.0) as client:
        for chunk in _chunks(cve_ids):
            params = {"cve": ",".join(chunk), "limit": str(CHUNK_SIZE)}
            try:
                response = await client.get(EPSS_URL, params=params)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise from_http_error(SOURCE, exc) from exc
            try:
                payload = response.json()
            except ValueError as exc:
                raise CollectorError(SOURCE, BAD_PAYLOAD, status=response.status_code) from exc
            found.update(_parse(payload, response.status_code))
    return found


async def scores_for(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """{CVE id: (score, percentile)} for the ids FIRST scores, from cache or live.

    Ids absent from the return value are ones FIRST does not score. A failure
    raises instead, so the two are never confused.
    """
    global _cache_at
    _expire_if_stale()
    wanted: list[str] = []
    seen: set[str] = set()
    for raw in cve_ids:
        cve_id = str(raw or "").strip().upper()
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            wanted.append(cve_id)

    # The lock collapses concurrent scans into one request per missing id, the
    # way `collectors.kev` collapses them into one download.
    async with _lock:
        _expire_if_stale()
        missing = [cve_id for cve_id in wanted if cve_id not in _cache]
        if missing:
            fetched = await _lookup(missing)
            # Every id asked about is recorded, including the ones FIRST had
            # nothing for: without the None entry the next target re-asks.
            for cve_id in missing:
                _cache[cve_id] = fetched.get(cve_id)
            if not _cache_at:
                _cache_at = time.monotonic()

    return {cve_id: pair for cve_id in wanted if (pair := _cache.get(cve_id)) is not None}


async def enrich(records: list[dict]) -> list[dict]:
    """Add `epss_score` and `epss_percentile` to the records FIRST scores.

    The records are returned mutated in place, in the order they came in: this is
    an enrichment pass and not a filter, so it must not drop, reorder or
    duplicate anything the collectors found. Call it on merged records — one row
    per CVE — so the ranking that follows reads one set of numbers per CVE.

    A record FIRST does not score is left exactly as it was, with neither key.
    """
    ids = [str(record.get("id") or "") for record in records]
    if not any(ids):
        return records
    found = await scores_for(ids)
    for record in records:
        cve_id = str(record.get("id") or "").strip().upper()
        pair = found.get(cve_id)
        if pair is None:
            continue
        record["epss_score"], record["epss_percentile"] = pair
    return records
