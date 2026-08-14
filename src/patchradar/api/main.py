from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pathlib import Path
from patchradar.db.database import (
    init_db, get_watchlist, add_to_watchlist,
    remove_from_watchlist, get_cves
)
from patchradar.collectors.nvd import fetch_cves as nvd_fetch
import asyncio

app = FastAPI(title="PatchRadar", version="2026.8.1")

@app.on_event("startup")
async def startup():
    await init_db()

@app.get("/api/watchlist")
async def api_watchlist():
    items = await get_watchlist()
    return {"watchlist": items}

@app.post("/api/watchlist/{software}")
async def api_add(software: str):
    added = await add_to_watchlist(software)
    return {"added": added, "software": software}

@app.delete("/api/watchlist/{software}")
async def api_remove(software: str):
    removed = await remove_from_watchlist(software)
    return {"removed": removed, "software": software}

@app.get("/api/cves")
async def api_cves(software: str = None, limit: int = 50):
    cves = await get_cves(software=software, limit=limit)
    return {"cves": cves, "total": len(cves)}

@app.post("/api/scan")
async def api_scan(days: int = 7):
    from patchradar.db.database import save_cve
    watchlist = await get_watchlist()
    total = 0
    results = {}
    for sw in watchlist:
        cves = await nvd_fetch(sw, days_back=days)
        for cve in cves:
            await save_cve(cve)
        results[sw] = len(cves)
        total += len(cves)
    return {"total": total, "by_software": results}

@app.get("/api/stats")
async def api_stats():
    from patchradar.db.database import DB_PATH
    import aiosqlite
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
    html_path = Path(__file__).parent / "templates" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding='utf-8'))
