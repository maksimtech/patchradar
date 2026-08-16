from fastapi import FastAPI, Request, Query, Path
from contextlib import asynccontextmanager
from fastapi.responses import Response
from fastapi.responses import HTMLResponse
from pathlib import Path as FilePath
from importlib.metadata import version as pkg_version
from patchradar.db.database import (
    init_db, get_watchlist, add_to_watchlist,
    remove_from_watchlist, get_cves
)
from patchradar.collectors.nvd import fetch_cves as nvd_fetch
from patchradar.collectors.msrc import fetch_cves as msrc_fetch
import aiosqlite

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — replaces deprecated @app.on_event"""
    await init_db()
    yield

app = FastAPI(title="PatchRadar", version="2026.8.7", lifespan=lifespan)

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

@app.post("/api/watchlist/{software}")
async def api_add(software: str = Path(..., min_length=1, max_length=100, pattern=r"^[\w\s\-\.]+$")):
    added = await add_to_watchlist(software)
    return {"added": added, "software": software}

@app.delete("/api/watchlist/{software}")
async def api_remove(software: str = Path(..., min_length=1, max_length=100, pattern=r"^[\w\s\-\.]+$")):
    removed = await remove_from_watchlist(software)
    return {"removed": removed, "software": software}

@app.get("/api/cves")
async def api_cves(software: str = Query(None, min_length=1, max_length=100), limit: int = Query(50, ge=1, le=200)):
    cves = await get_cves(software=software, limit=limit)
    sanitized = [sanitize_cve(c) for c in cves]
    return {"cves": sanitized, "total": len(sanitized)}

@app.post("/api/scan")
async def api_scan(days: int = Query(7, ge=1, le=90)):
    from patchradar.db.database import save_cve
    watchlist = await get_watchlist()
    total = 0
    results = {}
    for sw in watchlist:
        # NVD
        cves = await nvd_fetch(sw, days_back=days)
        for cve in cves:
            await save_cve(cve)
        # MSRC
        msrc_cves = await msrc_fetch(sw, days_back=days)
        for cve in msrc_cves:
            await save_cve(cve)
        count = len(cves) + len(msrc_cves)
        results[sw] = count
        total += count
    return {"total": total, "by_software": results}

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

@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = FilePath(__file__).parent / "templates" / "index.html"
    html = html_path.read_text(encoding='utf-8')
    html = html.replace('__VERSION__', pkg_version('patchradar'))
    return HTMLResponse(content=html)
