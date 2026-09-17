import asyncio
import hmac
import logging
import os
from fastapi import Depends, FastAPI, HTTPException, Request, Query, Path
from fastapi.security import APIKeyHeader
from contextlib import asynccontextmanager
from fastapi.responses import Response, HTMLResponse, JSONResponse
from pathlib import Path as FilePath
from importlib.metadata import version as pkg_version
from patchradar.db.database import (
    init_db, get_watchlist, add_to_watchlist,
    remove_from_watchlist, get_cves
)
from patchradar.collectors.nvd import fetch_cves as nvd_fetch
from patchradar.collectors.msrc import fetch_cves as msrc_fetch
from patchradar.collectors.debian import fetch_cves as debian_fetch
import aiosqlite

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

@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    """Add security headers to all responses — defense in depth against XSS and clickjacking."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


def sanitize_cve(cve: dict) -> dict:
    """Sanitize CVE data before returning to frontend — removes null bytes and truncates long strings."""
    safe = {}
    str_fields = ["id", "software", "description", "severity", "source", "url", "published_at", "cvss_version"]
    for field in str_fields:
        val = cve.get(field)
        if isinstance(val, str):
            # Remove null bytes and control characters
            val = val.replace("\x00", "").strip()
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
    for sw in software_list:
        sw = sw.strip().lower()[:100]
        if not sw:
            continue
        result = await add_to_watchlist(sw)
        if result:
            added.append(sw)
        else:
            skipped.append(sw)
    return {"added": added, "skipped": skipped, "total": len(added)}

@app.post(
    "/api/watchlist/{software}",
    dependencies=[Depends(require_api_key)],
    responses={401: {"description": "Missing or invalid API key"}},
)
async def api_add(software: str = Path(..., min_length=1, max_length=100, pattern=r"^[\w\s\-\.]+$")):
    added = await add_to_watchlist(software)
    return {"added": added, "software": software}


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

async def _scan_one(sw: str, days: int) -> int:
    """Collect and persist every source for a single package."""
    from patchradar.db.database import save_cve
    count = 0
    # Debian is served from a process-wide snapshot, so this costs one
    # download per scan rather than one per package.
    for cves in (
        await nvd_fetch(sw, days_back=days),
        await msrc_fetch(sw, days_back=days),
        await debian_fetch(sw),
    ):
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
    timed_out = False
    try:
        # A whole-scan deadline: upstream feeds are slow and unbounded, and a
        # scan that never returns pins a worker indefinitely.
        async with asyncio.timeout(SCAN_TIMEOUT_SECONDS):
            for sw in watchlist:
                count = await _scan_one(sw, days)
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
