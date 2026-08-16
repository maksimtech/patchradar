import typer
import asyncio
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
from patchradar.db.database import (
    init_db, add_to_watchlist, get_watchlist,
    remove_from_watchlist, get_cves, save_cve
)
from patchradar.collectors.nvd import fetch_cves
from patchradar.collectors.msrc import fetch_cves as msrc_fetch

app = typer.Typer(
    name="patchradar",
    help="Realtime CVE intelligence for your software stack 🛡️",
    add_completion=False,
)
console = Console()

def run(coro):
    return asyncio.run(coro)

@app.callback()
def startup():
    run(init_db())

@app.command()
def add(software: str = typer.Argument(..., help="Software to monitor")):
    """Add software to your watchlist."""
    added = run(add_to_watchlist(software))
    if added:
        console.print(f"✅ [green]Added[/green] [bold]{software}[/bold] to watchlist")
    else:
        console.print(f"⚠️  [yellow]{software}[/yellow] is already in your watchlist")

@app.command()
def remove(software: str = typer.Argument(..., help="Software to remove")):
    """Remove software from your watchlist."""
    removed = run(remove_from_watchlist(software))
    if removed:
        console.print(f"🗑️  [red]Removed[/red] [bold]{software}[/bold] from watchlist")
    else:
        console.print(f"❌ [red]{software}[/red] not found in watchlist")

@app.command(name="list")
def list_watchlist():
    """Show your current watchlist."""
    items = run(get_watchlist())
    if not items:
        console.print("📭 Your watchlist is empty. Use [bold]patchradar add <software>[/bold]")
        return
    table = Table(title="🛡️ PatchRadar Watchlist", box=box.ROUNDED)
    table.add_column("Software", style="cyan bold")
    for item in items:
        table.add_row(item)
    console.print(table)

@app.command()
def scan(
    software: str = typer.Argument(None, help="Software to scan (or all watchlist)"),
    days: int = typer.Option(7, "--days", "-d", help="Days back to search"),
):
    """Scan for CVEs affecting your software."""
    async def _scan():
        targets = [software] if software else await get_watchlist()
        if not targets:
            console.print("📭 Nothing to scan. Add software with [bold]patchradar add[/bold]")
            return

        total = 0
        for target in targets:
            with console.status(f"[cyan]Scanning {target}...[/cyan]"):
                cves = await fetch_cves(target, days_back=days)
            msrc_cves = await msrc_fetch(target, days_back=days)
            all_cves = cves + msrc_cves

            for cve in all_cves:
                await save_cve(cve)

            total += len(all_cves)
            cves = all_cves
            if cves:
                _print_cves(target, cves)
            else:
                console.print(f"✅ [green]{target}[/green] — no CVEs found in last {days} days")

        console.print(f"\n📊 Total: [bold]{total}[/bold] CVEs found")

    run(_scan())

@app.command()
def status():
    """Show latest CVEs from your watchlist."""
    async def _status():
        cves = await get_cves(limit=20)
        if not cves:
            console.print("📭 No CVEs in database yet. Run [bold]patchradar scan[/bold]")
            return
        _print_cves_table(cves)
    run(_status())

def _print_cves(software: str, cves: list):
    table = Table(
        title=f"🚨 CVEs for [bold]{software}[/bold]",
        box=box.ROUNDED,
        show_lines=True
    )
    table.add_column("CVE ID", style="bold cyan", no_wrap=True)
    table.add_column("Score", justify="center", width=6)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Description", max_width=60)

    for cve in cves:
        score = cve.get("cvss_score")
        severity = cve.get("severity", "UNKNOWN")
        score_str = f"{score:.1f}" if score else "N/A"
        severity_color = {
            "CRITICAL": "red bold",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(severity.upper(), "white")

        table.add_row(
            cve["id"],
            score_str,
            Text(severity, style=severity_color),
            cve.get("description", "")[:120] + "..." if len(cve.get("description", "")) > 120 else cve.get("description", ""),
        )
    console.print(table)

def _print_cves_table(cves: list):
    table = Table(title="🛡️ PatchRadar — Latest CVEs", box=box.ROUNDED, show_lines=True)
    table.add_column("CVE ID", style="bold cyan", no_wrap=True)
    table.add_column("Software", style="blue")
    table.add_column("Score", justify="center", width=6)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Source", width=6)

    for cve in cves:
        score = cve.get("cvss_score")
        severity = cve.get("severity", "UNKNOWN")
        score_str = f"{score:.1f}" if score else "N/A"
        severity_color = {
            "CRITICAL": "red bold",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(severity.upper(), "white")

        table.add_row(
            cve["id"],
            cve.get("software", ""),
            score_str,
            Text(severity, style=severity_color),
            cve.get("source", ""),
        )
    console.print(table)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(8000, "--port", "-p"),
):
    """Launch the PatchRadar web UI."""
    import uvicorn
    console.print(f"🛡️  [bold]PatchRadar[/bold] UI → [cyan]http://{host}:{port}[/cyan]")
    uvicorn.run("patchradar.api.main:app", host=host, port=port, reload=False)


def main():
    app()

if __name__ == "__main__":
    main()
