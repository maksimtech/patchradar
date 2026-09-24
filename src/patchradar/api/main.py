import asyncio
import hmac
import logging
import os
import re
from contextlib import asynccontextmanager
from importlib.metadata import version as pkg_version
from pathlib import Path as FilePath

import aiosqlite
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles

from patchradar.collectors.debian import fetch_cves as debian_fetch
from patchradar.collectors.errors import CollectorError
from patchradar.collectors.msrc import fetch_cves as msrc_fetch
from patchradar.collectors.nvd import fetch_cves as nvd_fetch
from patchradar.db.database import add_to_watchlist, get_cves, get_watchlist, init_db, remove_from_watchlist

logger = logging.getLogger("patchradar")

API_KEY_ENV = "PATCHRADAR_API_KEY"
API_KEY_HEADER = "X-API-Key"
SCAN_TIMEOUT_ENV = "PATCHRADAR_SCAN_TIMEOUT"
DEFAULT_SCAN_TIMEOUT = 600.0
SCAN_TIMEOUT_SECONDS = float(os.environ.get(SCAN_TIMEOUT_ENV) or DEFAULT_SCAN_TIMEOUT)

_api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


def configured_api_key() -> str | None:
    """The API key, or None when auth is disabled.

    Read per-request rather than at import time so the key can be rotated
    without rebuilding the image. An empty value means "unset", never "the
    empty string is the key".
    """
    return os.environ.get(API_KEY_ENV) or None


async def require_api_key(provided: str | None = Depends(_api_key_header)) -> None:
    """Guard state-changing and network-expensive endpoints.

    When no key is configured the endpoints stay open, so local use is
    unchanged; the startup warning covers the exposed-port case.
    """
    expected = configured_api_key()
    if expected is None:
        return
    if provided is None or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=401,
            detail=f"Missing or invalid {API_KEY_HEADER} header",
            headers={"WWW-Authenticate": API_KEY_HEADER},
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — replaces deprecated @app.on_event"""
    await init_db()
    if configured_api_key() is None:
        logger.warning(
            "%s is not set: /api/scan and the watchlist write endpoints are "
            "unauthenticated. Set it before exposing PatchRadar beyond localhost.",
            API_KEY_ENV,
        )
    yield

app = FastAPI(title="PatchRadar", version=pkg_version("patchradar"), lifespan=lifespan)
app.mount("/static", StaticFiles(directory=FilePath(__file__).parent / "static"), name="static")

@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    """Add security headers to all responses — defense in depth against XSS and clickjacking."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        # No 'unsafe-inline' for scripts: the page script lives in
        # /static/app.js and binds its handlers with addEventListener, so an
        # injected on*= attribute or <script> block is refused by the browser.
        "script-src 'self'; "
        # Styles still need it (style= attributes); CSS cannot run script.
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# Single source of truth for what a watchlist name may be. The import endpoint
# used to enforce none of this, so anything the path endpoint rejected could be
# smuggled in through it and then rendered by the CLI.
# A literal space rather than \s: \s also matches newlines and tabs, so the
# original pattern admitted multi-line names, which break the CLI table layout
# and open the door to log injection. Only a space is ever meant ("windows 10").
SOFTWARE_NAME_PATTERN = r"^[\w \-\.]+$"
SOFTWARE_NAME_MAX_LENGTH = 100
_SOFTWARE_NAME_RE = re.compile(SOFTWARE_NAME_PATTERN)


def normalise_software_name(value) -> str | None:
    """Canonical watchlist name, or None when the value is not acceptable.

    Accepts only strings: an import payload is arbitrary JSON, and calling
    .strip() on an int used to surface as HTTP 500. Over-long names are
    rejected rather than truncated — silently watching a different name than
    the caller asked for is worse than refusing.
    """
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    if not name or len(name) > SOFTWARE_NAME_MAX_LENGTH:
        return None
    if not _SOFTWARE_NAME_RE.match(name):
        return None
    return name


# C0 controls except tab and newline, DEL, and the C1 block (which includes
# \x9b, the single-byte CSI). Carriage returns are normalised to \n first.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _strip_control_chars(value: str) -> str:
    """Remove terminal control characters, keeping ordinary line structure.

    Only \x00 used to be removed, so ESC/BEL/BS reached the API response and,
    through the same stored rows, the CLI's terminal output.
    """
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL_CHARS_RE.sub("", value)


def sanitize_cve(cve: dict) -> dict:
    """Sanitize CVE data before returning to frontend — removes control characters and truncates long strings."""
    safe = {}
    str_fields = ["id", "software", "description", "severity", "source", "url", "published_at", "cvss_version"]
    for field in str_fields:
        val = cve.get(field)
        if isinstance(val, str):
            val = _strip_control_chars(val).strip()
            # Truncate excessively long strings
            if field == "description" and len(val) > 2000:
                val = val[:2000] + "..."
            elif field not in ["description", "url"] and len(val) > 200:
                val = val[:200]
        safe[field] = val
    # Numeric fields
    safe["cvss_score"] = cve.get("cvss_score")
    return safe

@app.get("/api/watchlist")
async def api_watchlist():
    items = await get_watchlist()
    return {"watchlist": items}

@app.post(
    "/api/watchlist/import",
    dependencies=[Depends(require_api_key)],
    responses={
        400: {"description": "Invalid payload — expected a list of software names"},
        401: {"description": "Missing or invalid API key"},
    },
)
async def api_watchlist_import(payload: dict):
    """Import a list of software names into the watchlist."""
    software_list = payload.get("software", [])
    if not isinstance(software_list, list):
        raise HTTPException(status_code=400, detail="Expected {'software': [...list of names...]}")
    added = []
    skipped = []
    rejected = []
    for raw in software_list:
        name = normalise_software_name(raw)
        if name is None:
            # Reported rather than dropped silently: an import file usually
            # contains some junk lines and the caller should see which.
            rejected.append(str(raw)[:SOFTWARE_NAME_MAX_LENGTH])
            continue
        if await add_to_watchlist(name):
            added.append(name)
        else:
            skipped.append(name)
    return {"added": added, "skipped": skipped, "rejected": rejected, "total": len(added)}

@app.post(
    "/api/watchlist/{software}",
    dependencies=[Depends(require_api_key)],
    responses={401: {"description": "Missing or invalid API key"}},
)
async def api_add(
    software: str = Path(
        ..., min_length=1, max_length=SOFTWARE_NAME_MAX_LENGTH, pattern=SOFTWARE_NAME_PATTERN
    )
):
    # Normalise here too, so both routes store the same canonical value.
    name = normalise_software_name(software)
    if name is None:
        raise HTTPException(status_code=422, detail="Invalid software name")
    added = await add_to_watchlist(name)
    return {"added": added, "software": name}


@app.delete(
    "/api/watchlist/{software}",
    dependencies=[Depends(require_api_key)],
    responses={401: {"description": "Missing or invalid API key"}},
)
async def api_remove(software: str = Path(..., min_length=1, max_length=200)):
    removed = await remove_from_watchlist(software)
    return {"removed": removed, "software": software}

@app.get("/api/cves")
async def api_cves(software: str = Query(None, min_length=1, max_length=100), limit: int = Query(50, ge=1, le=200)):
    cves = await get_cves(software=software, limit=limit)
    sanitized = [sanitize_cve(c) for c in cves]
    return {"cves": sanitized, "total": len(sanitized)}

async def _scan_one(sw: str, days: int, errors: list[dict]) -> int:
    """Collect and persist every source for a single package.

    A source that fails is recorded in `errors` rather than silently counted
    as zero, and whatever it managed to return before failing is still saved.
    """
    from patchradar.db.database import save_cve
    count = 0
    # Debian is served from a process-wide snapshot, so this costs one
    # download per scan rather than one per package.
    fetches = (
        lambda: nvd_fetch(sw, days_back=days),
        lambda: msrc_fetch(sw, days_back=days),
        lambda: debian_fetch(sw),
    )
    for fetch in fetches:
        try:
            cves = await fetch()
        except CollectorError as exc:
            logger.warning("scan of %r incomplete: %s", sw, exc)
            errors.append({"software": sw, "source": exc.source,
                           "reason": exc.reason, "status": exc.status})
            cves = exc.partial
        for cve in cves:
            await save_cve(cve)
        count += len(cves)
    return count


@app.post(
    "/api/scan",
    dependencies=[Depends(require_api_key)],
    responses={401: {"description": "Missing or invalid API key"}},
)
async def api_scan(days: int = Query(7, ge=1, le=90)):
    watchlist = await get_watchlist()
    total = 0
    results = {}
    errors: list[dict] = []
    timed_out = False
    try:
        # A whole-scan deadline: upstream feeds are slow and unbounded, and a
        # scan that never returns pins a worker indefinitely.
        async with asyncio.timeout(SCAN_TIMEOUT_SECONDS):
            for sw in watchlist:
                count = await _scan_one(sw, days, errors)
                results[sw] = count
                total += count
    except TimeoutError:
        # Partial results are already persisted; report the truncation instead
        # of letting an incomplete scan look like a clean bill of health.
        timed_out = True
        logger.warning(
            "scan exceeded %ss budget after %d/%d packages",
            SCAN_TIMEOUT_SECONDS, len(results), len(watchlist),
        )
    return {
        "total": total,
        "by_software": results,
        "timed_out": timed_out,
        "scanned": len(results),
        "watched": len(watchlist),
        # Non-empty means some counts above are lower bounds, not answers.
        "errors": errors,
    }

@app.get("/api/stats")
async def api_stats():
    from patchradar.db.database import DB_PATH
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM cves") as cur:
            total = (await cur.fetchone())[0]
        async with db.execute(
            "SELECT severity, COUNT(*) FROM cves GROUP BY severity"
        ) as cur:
            by_severity = dict(await cur.fetchall())
        async with db.execute(
            "SELECT software, COUNT(*) FROM cves GROUP BY software ORDER BY COUNT(*) DESC"
        ) as cur:
            by_software = dict(await cur.fetchall())
    watchlist = await get_watchlist()
    return {
        "total_cves": total,
        "watched": len(watchlist),
        "by_severity": by_severity,
        "by_software": by_software,
    }


@app.get("/api/cves/{cve_id}", responses={404: {"description": "CVE not found"}})
async def api_cve_detail(cve_id: str = Path(..., min_length=1, max_length=50)):
    """Get a single CVE by ID."""
    from patchradar.db.database import DB_PATH
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM cves WHERE id = ?", (cve_id,)
        ) as cursor:
            row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="CVE not found")
    return sanitize_cve(dict(row))

@app.get(
    "/health",
    responses={503: {"description": "A dependency is unhealthy"}},
)
async def health():
    """Liveness/readiness probe for Docker and orchestrators.

    Deliberately unauthenticated: a healthcheck should not need a credential.
    It touches the database, so an unwritable volume reports unhealthy rather
    than passing on a process that cannot serve a single real request.
    """
    from patchradar.db.database import DB_PATH
    db_status = "ok"
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("SELECT 1")
    except Exception:
        db_status = "error"
    body = {
        "status": "ok" if db_status == "ok" else "degraded",
        "version": pkg_version("patchradar"),
        "database": db_status,
    }
    return JSONResponse(content=body, status_code=200 if db_status == "ok" else 503)


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = FilePath(__file__).parent / "templates" / "index.html"
    html = html_path.read_text(encoding='utf-8')
    html = html.replace('__VERSION__', pkg_version('patchradar'))
    return HTMLResponse(content=html)
