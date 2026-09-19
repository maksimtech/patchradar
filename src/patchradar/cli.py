import typer
import asyncio
import patchradar
from rich.console import Console
from rich.table import Table
from rich import box
from rich.markup import escape
from rich.text import Text
from patchradar.db.database import (
    init_db, add_to_watchlist, get_watchlist,
    remove_from_watchlist, get_cves, save_cve
)
from patchradar.collectors.nvd import fetch_cves
from patchradar.collectors.msrc import fetch_cves as msrc_fetch
from patchradar.collectors.errors import CollectorError

app = typer.Typer(
    name="patchradar",
    help="Realtime CVE intelligence for your software stack 🛡️",
    add_completion=False,
)
console = Console()

def run(coro):
    return asyncio.run(coro)

SEVERITY_STYLES = {
    "CRITICAL": "red bold",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _normalise_severity(value) -> str:
    """Upper-cased severity, or UNKNOWN for anything that is not a usable string.

    `cve.get("severity", "UNKNOWN")` only falls back when the key is absent; the
    column is nullable, and .upper() on None crashed `patchradar status`.
    """
    if not isinstance(value, str) or not value.strip():
        return "UNKNOWN"
    return value.strip().upper()


def _format_score(value) -> str:
    """One-decimal CVSS score, or N/A when there is no usable number.

    Tests `is None`/type rather than truthiness: 0.0 is a real score and used
    to be shown as N/A.
    """
    if isinstance(value, bool):
        return "N/A"
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return "N/A"
    if not isinstance(value, (int, float)) or value != value:  # NaN
        return "N/A"
    return f"{value:.1f}"

def _truncate(text, limit: int) -> str:
    """Coerce to str and cap at `limit`, appending an ellipsis when cut.

    Collectors may yield None for a field (the Debian tracker does for
    `description`), so this must never assume a string.
    """
    if not text:
        return ""
    text = str(text)
    return text if len(text) <= limit else text[:limit] + "..."

def _print_version(value: bool) -> None:
    # Looked up at call time so it always reflects patchradar.__version__.
    if value:
        typer.echo(f"PatchRadar {patchradar.__version__}")
        raise typer.Exit()

@app.callback()
def startup(
    version: bool = typer.Option(
        False, "--version", callback=_print_version, is_eager=True,
        help="Show the PatchRadar version and exit.",
    ),
):
    run(init_db())


def _law_check(subject, out=None, **context):
    """Run the law check; any failure is reported and never fails the command."""
    from patchradar import law_checker

    try:
        return law_checker.check(subject, **context)
    except Exception as e:
        (out or console).print(f"[yellow]⚠️  Verifica delle norme non riuscita: {escape(str(e))}[/yellow]\n")
        return None


def _print_law_check(law, out=None) -> None:
    """Cite the provisions applied to the findings, with their SHA-256."""
    from patchradar.law_checker import FINDING_TITLES, format_citation

    out = out or console
    if law is None or not (law.citations or law.notes):
        return

    out.print("[bold]⚖️  Norme applicate[/bold]")
    for status in law.acts:
        act = status.act
        name, source = escape(act.name), escape(act.source)
        if status.source == "verified":
            out.print(f"[dim]{name}: verificato su {source} ({act.id_label} {escape(act.celex)})[/dim]")
        elif status.source == "cache":
            out.print(f"[yellow]{name}: {source} non raggiungibile, testo dalla copia in cache non riverificato[/yellow]")
        else:
            out.print(f"[yellow]{name}: {source} non raggiungibile e nessuna copia in cache, testo non verificabile[/yellow]")
        if act.note:
            out.print(f"[dim]  {escape(act.note)}[/dim]")
        if status.error:
            out.print(f"[dim]  {escape(status.error)}[/dim]")
    for provision, previous in law.changed.items():
        out.print(f"[yellow]⚠️  Il testo di {escape(provision)} è cambiato dall'ultimo audit[/yellow]")
        out.print(f"[dim]   precedente: {previous}[/dim]")
    for note in law.notes:
        out.print(f"[yellow]⚠️  {escape(note)}[/yellow]")

    out.print()
    finding = None
    for citation in law.citations:
        if citation.finding != finding:
            finding = citation.finding
            out.print(f"[bold]{escape(FINDING_TITLES[finding])}[/bold]")
            if law.evidence.get(finding):
                out.print(f"[dim]{escape(', '.join(law.evidence[finding]))}[/dim]")
        out.print(format_citation(citation), markup=False, highlight=False)
        out.print()


@app.command()
def add(software: str = typer.Argument(..., help="Software to monitor")):
    """Add software to your watchlist."""
    added = run(add_to_watchlist(software))
    safe = escape(software)
    if added:
        console.print(f"✅ [green]Added[/green] [bold]{safe}[/bold] to watchlist")
    else:
        console.print(f"⚠️  [yellow]{safe}[/yellow] is already in your watchlist")

@app.command()
def remove(software: str = typer.Argument(..., help="Software to remove")):
    """Remove software from your watchlist."""
    removed = run(remove_from_watchlist(software))
    safe = escape(software)
    if removed:
        console.print(f"🗑️  [red]Removed[/red] [bold]{safe}[/bold] from watchlist")
    else:
        console.print(f"❌ [red]{safe}[/red] not found in watchlist")

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
        table.add_row(Text(str(item)))
    console.print(table)

async def _scan_target(target: str, days: int, collected: list | None = None) -> int:
    """Scan a single target for CVEs and return count.

    The CVEs found are also appended to `collected`, when given, for the law
    check at the end of the scan.
    """
    safe_target = escape(target)
    all_cves: list[dict] = []
    failures: list[CollectorError] = []
    with console.status(f"[cyan]Scanning {safe_target}...[/cyan]"):
        for fetch in (fetch_cves, msrc_fetch):
            try:
                all_cves += await fetch(target, days_back=days)
            except CollectorError as exc:
                failures.append(exc)
                all_cves += exc.partial
    for cve in all_cves:
        await save_cve(cve)
    if collected is not None:
        collected.extend(all_cves)
    if all_cves:
        _print_cves(target, all_cves)
    for exc in failures:
        console.print(
            f"⚠️  [yellow]{escape(str(exc))}[/yellow] — "
            f"results for [bold]{safe_target}[/bold] are incomplete"
        )
    # Only an answer from every source may be reported as an all-clear.
    if not all_cves and not failures:
        console.print(f"[green]{safe_target}[/green] — no CVEs found in last {days} days")
    return len(all_cves)


@app.command()
def scan(
    software: str = typer.Argument(None, help="Software to scan (or all watchlist)"),
    days: int = typer.Option(7, "--days", "-d", help="Days back to search"),
):
    """Scan for CVEs affecting your software."""
    async def _scan():
        targets = [software] if software else await get_watchlist()
        if not targets:
            console.print("Nothing to scan. Add software with [bold]patchradar add[/bold]")
            return
        cves: list[dict] = []
        total = sum([await _scan_target(t, days, cves) for t in targets])
        console.print(f"\n Total: [bold]{total}[/bold] CVEs found\n")
        _print_law_check(_law_check(cves))
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
        title=f"🚨 CVEs for [bold]{escape(software)}[/bold]",
        box=box.ROUNDED,
        show_lines=True
    )
    table.add_column("CVE ID", style="bold cyan", no_wrap=True)
    table.add_column("Score", justify="center", width=6)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Description", max_width=60)

    for cve in cves:
        score_str = _format_score(cve.get("cvss_score"))
        severity = _normalise_severity(cve.get("severity"))
        severity_color = SEVERITY_STYLES.get(severity, "white")

        # Text() renders verbatim — CVE data is untrusted and must never be
        # parsed as Rich markup (forged styles, OSC-8 links, MarkupError).
        table.add_row(
            Text(str(cve.get("id", ""))),
            score_str,
            Text(severity, style=severity_color),
            Text(_truncate(cve.get("description"), 120)),
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
        score_str = _format_score(cve.get("cvss_score"))
        severity = _normalise_severity(cve.get("severity"))
        severity_color = SEVERITY_STYLES.get(severity, "white")

        table.add_row(
            Text(str(cve.get("id", ""))),
            Text(str(cve.get("software") or "")),
            score_str,
            Text(severity, style=severity_color),
            Text(str(cve.get("source") or "")),
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
