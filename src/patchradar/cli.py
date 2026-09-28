import asyncio
import contextlib
import pathlib
import sys
from collections import Counter

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

import patchradar
from patchradar.collectors.errors import CollectorError
from patchradar.collectors.kev import SOURCE as kev_source
from patchradar.collectors.kev import fetch_cves as kev_fetch
from patchradar.collectors.msrc import fetch_cves as msrc_fetch
from patchradar.collectors.nvd import api_key as nvd_api_key
from patchradar.collectors.nvd import fetch_cves
from patchradar.db.database import add_to_watchlist, get_cves, get_watchlist, init_db, remove_from_watchlist, save_cve
from patchradar.priority import (
    RANK_KEV,
    RANK_KEV_RANSOMWARE,
    RANK_SCORED,
    RANK_UNSCORED,
    order_by_priority,
    priority,
)


def enable_utf8_output() -> None:
    """Make stdout and stderr accept characters the console cannot encode.

    On Windows the console code page is cp1252, and Python encodes output with
    it: the first emoji — the one in this CLI's own help text — ended the
    program with UnicodeEncodeError before any command had run. It was never
    the command failing, only the printing of its output.

    errors="replace" rather than "strict": a glyph the terminal cannot show
    should come out as a question mark, never as a traceback.

    Streams that cannot be reconfigured are left alone. pytest's capture and
    anything wrapping a pipe are not TextIOWrapper, and replacing them would
    break whatever is reading them; a cosmetic setting is not worth raising
    over, so this gives up quietly.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding == "utf8":
            continue
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")

enable_utf8_output()


app = typer.Typer(
    name="patchradar",
    help="Realtime CVE intelligence for your software stack 🛡️",
    add_completion=False,
)
console = Console()


@contextlib.contextmanager
def _status(message: str):
    """console.status(), svuotando i flussi prima che lo spinner si fermi.

    Mentre lo spinner gira, Rich sostituisce sys.stdout e sys.stderr con un
    FileProxy che trattiene il testo finche' non incontra un newline, e `Live`
    ripristina i flussi originali senza svuotarlo. Una riga parziale scritta da
    una libreria resta nel buffer e viene stampata soltanto quando l'interprete
    finalizza il proxy, quando importare non e' piu' possibile:

        Exception ignored while finalizing file <rich.file_proxy.FileProxy ...>
        ImportError: sys.meta_path is None, Python is likely shutting down

    Una scansione riuscita finisce cosi' con un traceback, e chi guarda non ha
    modo di sapere che il risultato era valido. Solo su terminale: in pipe Rich
    non installa il proxy e il difetto non si vede. Osservato su APKRadar con
    rich 15.0.0 e Python 3.14.7; qui lo spinner avvolge i tre collector, che
    parlano in rete e scrivono sui flussi.

    Lo `finally` copre anche il caso con eccezione: e' quello in cui il messaggio
    parziale della libreria serve di piu'.
    """
    with console.status(message):
        try:
            yield
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
    console.file.flush()


def run(coro):
    return asyncio.run(coro)

SEVERITY_STYLES = {
    "CRITICAL": "red bold",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    # 0.0 nella scala v3: un difetto senza impatto. Smorzato perche' non e'
    # niente, ed e' l'unico gradino che lo sia davvero.
    "NONE": "dim",
    # Non smorzato, di proposito. UNKNOWN vuol dire che nessuna fonte ha dato un
    # punteggio a questa voce, e una riga grigia si legge come "trascurabile"
    # mentre la cosa vera e' "non misurata". Le due si assomigliano ed e'
    # esattamente per questo che va vista.
    "UNKNOWN": "magenta",
}

# The priority column, styled by what decides it and not by how bad it would be.
# "scored" is left plain on purpose: the Severity column beside it already
# carries that colour, and repeating it would read as a second measurement.
# "unscored" is magenta for the same reason UNKNOWN severity is — nothing gave
# this row a score, and a dim row reads as "negligible" instead of "not
# measured".
PRIORITY_STYLES = {
    RANK_KEV_RANSOMWARE: "red bold",
    RANK_KEV: "red",
    RANK_SCORED: "",
    RANK_UNSCORED: "magenta",
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
        (out or console).print(f"[yellow]⚠️  Law check failed: {escape(str(e))}[/yellow]\n")
        return None


def _print_law_check(law, out=None) -> None:
    """Cite the provisions applied to the findings, with their SHA-256."""
    from patchradar.law_checker import FINDING_TITLES, format_citation

    out = out or console
    if law is None or not (law.citations or law.notes):
        return

    out.print("[bold]⚖️  Provisions applied[/bold]")
    for status in law.acts:
        act = status.act
        name, source = escape(act.name), escape(act.source)
        if status.source == "verified":
            out.print(f"[dim]{name}: verified against {source} ({act.id_label} {escape(act.celex)})[/dim]")
        elif status.source == "cache":
            out.print(
                f"[yellow]{name}: {source} unreachable, "
                "text from the cached copy, not re-verified[/yellow]"
            )
        else:
            # The missing SHA-256 below is the consequence of this line, and
            # the two used to sit apart: a reader who saw the gap went looking
            # for a bug in the hashing. There is no verified text to hash, and
            # printing one anyway would assert a verification never made.
            out.print(
                f"[yellow]{name}: {source} unreachable and nothing cached, "
                "text not verifiable: the citations below have no SHA-256[/yellow]"
            )
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

async def _scan_target(
    target: str,
    days: int,
    collected: list | None = None,
    failed: list | None = None,
) -> int:
    """Scan a single target for CVEs and return count.

    The CVEs found are also appended to `collected`, when given, for the law
    check at the end of the scan, and the failures to `failed`: one source
    refusing every target in a watchlist is a different event from one hiccup,
    and only the whole scan can tell them apart.
    """
    safe_target = escape(target)
    all_cves: list[dict] = []
    failures: list[CollectorError] = []
    with _status(f"[cyan]Scanning {safe_target}...[/cyan]"):
        # Kept in step with `_scan_one` in the API: a scan from the command
        # line and a scan over HTTP that consult different sources print
        # different totals for the same machine, and neither says which.
        # `tests/test_collector_wiring.py` holds the two lists together.
        for fetch in (fetch_cves, msrc_fetch, kev_fetch):
            try:
                all_cves += await fetch(target, days_back=days)
            except CollectorError as exc:
                failures.append(exc)
                if failed is not None:
                    failed.append(exc)
                all_cves += exc.partial
    # One row per CVE, most urgent first, before anything counts or prints it.
    # The three collectors are concatenated and de-duplicate nothing, so a CVE
    # that NVD scored and CISA lists arrived twice: once scored, once exploited
    # with `severity: "UNKNOWN"`. The count therefore also changes meaning, from
    # records returned to CVEs found — which is what the line claims to say.
    all_cves = order_by_priority(all_cves)
    for cve in all_cves:
        await save_cve(cve)
    if collected is not None:
        collected.extend(all_cves)
    if all_cves:
        _print_cves(target, all_cves)
    for failure in failures:
        console.print(
            f"⚠️  [yellow]{escape(str(failure))}[/yellow] — "
            f"results for [bold]{safe_target}[/bold] are incomplete"
        )
    # Only an answer from every source may be reported as an all-clear.
    if not all_cves and not failures:
        console.print(f"[green]{safe_target}[/green] — no CVEs found in last {days} days")
    return len(all_cves)


# Every source `scan` queries. Named here so the summary can say which ones
# answered, without inferring it from the CVEs — a source that answered and had
# nothing would otherwise look like one that did not answer.
#
# It has to list *all* of them: while it still said ("NVD", "MSRC") after KEV
# joined the fan-out, a scan whose only result came from KEV printed "every CVE
# above comes from MSRC". `tests/test_collector_wiring.py` now holds this tuple
# and the fan-out together.
SCAN_SOURCES = ("NVD", "MSRC", kev_source)

# NVD answers a keyless client over quota with 403, and a key holder going too
# fast with 429. Both are worth a word about the key; a timeout is not.
QUOTA_REASONS = {"rate_limited", "forbidden"}


def _report_silent_sources(failures: list[CollectorError], targets: list[str]) -> None:
    """Say which sources answered for no target at all.

    The per-target warnings stay: which target failed is what a reader acts on.
    What they cannot show is that one source was silent throughout — sixteen
    identical lines read as an intermittent problem, and the total underneath
    them reads as a result.
    """
    if len(targets) < 2:
        # Nothing to generalise from; the per-target line has said it already.
        return

    # One failure per source per target at most, since each is queried once per
    # target — so a count equal to the number of targets means it failed on all
    # of them.
    failures_per_source = Counter(f.source for f in failures)
    silent = [s for s in SCAN_SOURCES if failures_per_source[s] >= len(targets)]
    if not silent:
        return

    answered = [source for source in SCAN_SOURCES if source not in silent]
    for source in silent:
        where = (
            f"every CVE above comes from {', '.join(answered)}"
            if answered else "no source answered at all"
        )
        console.print(
            f"⚠️  [yellow]{escape(source)} answered for none of the "
            f"{len(targets)} targets scanned[/yellow] — {where}."
        )

    if "NVD" in silent and not nvd_api_key() and any(
        f.source == "NVD" and f.reason in QUOTA_REASONS for f in failures
    ):
        console.print(
            "   [dim]NVD limits clients without an API key to 5 requests per "
            "30 seconds. Set [bold]NVD_API_KEY[/bold] to raise it to 50.[/dim]"
        )


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
        failures: list[CollectorError] = []
        total = sum([await _scan_target(t, days, cves, failures) for t in targets])
        console.print(f"\n Total: [bold]{total}[/bold] CVEs found\n")
        # After the total, because it is the total it qualifies.
        _report_silent_sources(failures, list(targets))
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
    # Why this row is where it is. A rank on its own is a number to be taken on
    # trust, so the reason travels with it: which catalogue, since when, and the
    # remediation date when CISA states one.
    table.add_column("Priority", max_width=34)
    table.add_column("Description", max_width=52)

    for cve in cves:
        score_str = _format_score(cve.get("cvss_score"))
        severity = _normalise_severity(cve.get("severity"))
        severity_color = SEVERITY_STYLES.get(severity, "white")
        rank = priority(cve)

        # Text() renders verbatim — CVE data is untrusted and must never be
        # parsed as Rich markup (forged styles, OSC-8 links, MarkupError).
        why = Text(rank.label, style=PRIORITY_STYLES[rank.rank])
        why.append("\n" + rank.reason, style="dim")

        table.add_row(
            Text(str(cve.get("id", ""))),
            score_str,
            Text(severity, style=severity_color),
            why,
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


@app.command(name="import")
def import_inventory(
    path: str = typer.Argument(..., help="Inventory snapshot written by inventory.ps1"),
    show: int = typer.Option(12, "--show", "-n",
                             help="How many entries to list per group; 0 for all"),
):
    """Read a machine's inventory and report what could be watched by version.

    Writes nothing, asks nothing of the network, decides nothing. The mapping
    from what the registry writes to what a vendor API wants cannot be deduced
    from a name — measured on a real machine, 30% mapped by themselves and a
    guess produced `MX5` → a Juniper router — so this proposes and a person
    confirms. Storing a confirmed mapping needs the watchlist columns that do
    not exist yet.
    """
    from patchradar.inventory import CERTAIN, PROPOSED, read_snapshot, survey

    try:
        snapshot = read_snapshot(path)
    except FileNotFoundError:
        console.print(f"[red]no such file: {escape(path)}[/red]")
        raise typer.Exit(2) from None
    except (ValueError, UnicodeDecodeError) as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(2) from None

    found = survey(snapshot)
    taken = found.taken_at[:16].replace("T", " ") or "an unstated moment"
    # Rows and products are different numbers and the difference is large: on the
    # machine this was written against, 147 rows are 89 products, because the
    # registry lists the features of an install and not the install.
    console.print(f"\n📋 [bold]{escape(pathlib.Path(path).name)}[/bold] — "
                  f"{found.total} products in {found.rows} registry entries, "
                  f"taken {escape(taken)}\n")

    by_source = found.proposals_by_source
    certain_sources = Counter(f.best.source for f in found.families
                              if f.confidence is CERTAIN)
    summary = Table(box=box.SIMPLE, show_header=False)
    summary.add_column("", style="bold", width=24)
    summary.add_column("", justify="right", width=5)
    summary.add_column("", style="dim")
    summary.add_row("watchable by version", str(found.certain),
                    ", ".join(f"{name} {n}" for name, n in sorted(certain_sources.items())))
    summary.add_row("to confirm", str(found.proposed),
                    ", ".join(f"{name} {len(rows)}" for name, rows in sorted(by_source.items())))
    summary.add_row("components", str(found.components),
                    "updated by whatever installed them")
    summary.add_row("no source by version", str(found.uncovered),
                    "keyword or CPE search only")
    # Separate from the categories: a program can have a source and still be
    # unanswerable, because there is no build to compare a fix against.
    summary.add_row("— of which no version", str(found.without_version),
                    "the registry holds none")
    console.print(summary)

    biggest = [f for f in found.largest_families(4) if f.rows > 1]
    if biggest:
        # Named, so a product that arrived as twenty-five rows cannot hide inside
        # a total: whoever reads this has to be able to disagree with the grouping.
        console.print("\n[bold]Grouped[/bold] [dim]— one product, several entries[/dim]")
        for family in biggest:
            console.print(f"  {Text(family.name)} [dim]— {family.rows} entries, "
                          f"counted once ({family.confidence})[/dim]")

    limit = None if show == 0 else show
    for title, rows in (("Watchable by version",
                         [f.best for f in found.families if f.confidence is CERTAIN]),
                        ("To confirm, by hand, once per product",
                         [f.best for f in found.families if f.confidence is PROPOSED])):
        if not rows:
            continue
        console.print(f"\n[bold]{title}[/bold]")
        for candidate in rows[:limit]:
            version = candidate.installed_version or "— no version —"
            source = candidate.source or "?"
            console.print(f"  {Text(candidate.name)} [dim]{escape(version)}[/dim] "
                          f"→ [cyan]{escape(source)}[/cyan]")
            console.print(f"      [dim]{escape(candidate.reason)}[/dim]")
        if limit is not None and len(rows) > limit:
            console.print(f"  [dim]…and {len(rows) - limit} more[/dim]")

    console.print("\n[dim]Nothing was written. A confirmed mapping needs the watchlist "
                  "columns (vendor, product_id, installed_version, channel, cpe), "
                  "which this release does not have.[/dim]")


def main():
    app()

if __name__ == "__main__":
    main()
