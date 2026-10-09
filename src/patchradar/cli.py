import asyncio
import contextlib
import json
import math
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
from patchradar.collectors.debian import DEBIAN_RELEASE as debian_release
from patchradar.collectors.debian import get_tracker_snapshot
from patchradar.collectors.errors import CollectorError
from patchradar.collectors.kev import SOURCE as kev_source
from patchradar.collectors.kev import fetch_cves as kev_fetch
from patchradar.collectors.msrc import MAX_DAYS_BACK as msrc_max_days
from patchradar.collectors.msrc import fetch_cves as msrc_fetch
from patchradar.collectors.nvd import api_key as nvd_api_key
from patchradar.collectors.nvd import fetch_cves
from patchradar.db.database import add_to_watchlist, get_cves, get_watchlist, init_db, remove_from_watchlist, save_cve
from patchradar.epss import enrich as epss_enrich
from patchradar.names import SOFTWARE_NAME_MAX_LENGTH, normalise_software_name
from patchradar.priority import (
    RANK_EPSS,
    RANK_KEV,
    RANK_KEV_RANSOMWARE,
    RANK_REPORTED,
    RANK_SCORED,
    RANK_UNSCORED,
    merge_by_cve,
    priority,
    sort_by_priority,
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
    help="CVE intelligence for your software stack 🛡️",
    add_completion=False,
)
console = Console()


@contextlib.contextmanager
def _status(message: str):
    """console.status(), flushing the streams before the spinner stops.

    While the spinner runs, Rich replaces sys.stdout and sys.stderr with a
    FileProxy that holds text until it meets a newline, and `Live` puts the
    original streams back without flushing it. A partial line written by a library
    stays in that buffer and is printed only when the interpreter finalises the
    proxy, at a point where importing is no longer possible:

        Exception ignored while finalizing file <rich.file_proxy.FileProxy ...>
        ImportError: sys.meta_path is None, Python is likely shutting down

    A successful scan therefore ends in a traceback, and whoever is watching has
    no way of knowing the result was valid. Only on a terminal: through a pipe
    Rich does not install the proxy and the defect cannot be seen. Observed on
    APKRadar with rich 15.0.0 and Python 3.14.7; here the spinner wraps the three
    collectors, which speak over the network and write to the streams.

    The exception path is covered too, and it is the one where the library's
    partial message matters most — see the comment below for how it was not, until
    2026-09-29.
    """
    # Both flushes in a `finally`, including the outer one. It sat after the
    # `with` block until 2026-09-29, where an exception leaving the body skipped
    # it — the path where a library's partial line matters most, because it is the
    # run about to print a traceback. SonarCloud's python:S9152 found it; no test
    # did, because every test exercised the success path.
    try:
        with console.status(message):
            try:
                yield
            finally:
                sys.stdout.flush()
                sys.stderr.flush()
    finally:
        console.file.flush()


def run(coro):
    return asyncio.run(coro)

SEVERITY_STYLES = {
    "CRITICAL": "red bold",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    # 0.0 on the v3 scale: a defect with no impact. Dimmed because it really is
    # nothing, and it is the only step that is.
    "NONE": "dim",
    # Not dimmed, deliberately. UNKNOWN means no source gave this entry a score,
    # and a grey row reads as "negligible" while the true statement is "not
    # measured". The two resemble each other, and that is exactly why this one
    # has to be seen.
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
    # Yellow rather than red: a forecast, not an observation. The colour is the
    # one piece of the row a reader takes in before any of the words, so it has
    # to carry that difference by itself.
    RANK_EPSS: "yellow",
    # Cyan rather than another shade of yellow: this row is here because somebody
    # said so, not because anything was observed or modelled, and the colour is
    # where that difference has to survive being skimmed.
    RANK_REPORTED: "cyan",
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
    if not isinstance(value, (int, float)) or math.isnan(value):
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
    # The same rule and the same canonical form as the API: "  Proxmox  " was
    # stored as is, beside the "proxmox" the API stores, and a multi-line name
    # reached the watchlist that every other way in refuses.
    name = normalise_software_name(software)
    if name is None:
        console.print(
            f"❌ [red]{escape(software)}[/red] is not a valid software name — letters, digits, "
            f"spaces, '-', '_' and '.', up to {SOFTWARE_NAME_MAX_LENGTH} characters"
        )
        raise typer.Exit(1)
    added = run(add_to_watchlist(name))
    safe = escape(name)
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
    # One row per CVE, before anything counts, enriches or prints it. The three
    # collectors are concatenated and de-duplicate nothing, so a CVE that NVD
    # scored and CISA lists arrived twice: once scored, once exploited with
    # `severity: "UNKNOWN"`. The count therefore also changes meaning, from
    # records returned to CVEs found — which is what the line claims to say.
    all_cves = merge_by_cve(all_cves)
    # FIRST is asked about the CVEs the scan found, in one request, after the
    # merge and before the sort: `priority` ranks on the EPSS fields, so
    # enriching after the sort would order the report on the facts it had a
    # moment earlier. A failure here leaves the scan complete and the ranking
    # poorer, which is why it does not join `failures` — the warning below says
    # exactly that, and `_report_silent_sources` speaks only about the sources
    # that decide whether a CVE appears at all.
    epss_failure: CollectorError | None = None
    with _status(f"[cyan]Scoring {safe_target} with EPSS...[/cyan]"):
        try:
            all_cves = await epss_enrich(all_cves)
        except CollectorError as exc:
            epss_failure = exc
    all_cves = sort_by_priority(all_cves)
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
    if epss_failure is not None:
        console.print(
            f"⚠️  [yellow]{escape(str(epss_failure))}[/yellow] — "
            f"CVEs for [bold]{safe_target}[/bold] are complete but ranked "
            f"without an exploitation forecast"
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
    # min=1: a window of no days is a usage error, refused here; it used to
    # reach the NVD collector and end the command in a ValueError traceback.
    days: int = typer.Option(7, "--days", "-d", min=1, help="Days back to search"),
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
        if days > msrc_max_days:
            # The collector caps its window without a word, so `--days 365`
            # looked like a year of Patch Tuesdays and was three months of them.
            console.print(f"ℹ️  MSRC covers the last {msrc_max_days} days only, not {days}.")
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


@app.command()
def collector(
    output: str = typer.Option("inventory.ps1", "--output", "-o",
                               help="Where to write the collector"),
    to_stdout: bool = typer.Option(False, "--stdout",
                                   help="Print it instead, for a shell whose > is UTF-8"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file"),
) -> None:
    """Write out the PowerShell collector that produces a snapshot.

    The machine worth surveying is the one without a checkout: no git, no
    development folder, often no Python until you put it there. The collector used
    to live in `tools/` and shipped in the sdist and not in the wheel, so
    `pip install patchradar` gave you the half that reads a snapshot and not the
    half that takes one. It travels with the package now, and this hands it over.

    A file by default, and not stdout: Windows PowerShell 5.1 writes UTF-16LE for
    `>`, so `patchradar collector > inventory.ps1` would produce a file PowerShell
    itself cannot parse — on the one platform the script exists for. `--stdout` is
    for a shell that does not do that.
    """
    import importlib.resources
    from pathlib import Path

    script = importlib.resources.files("patchradar") / "data" / "inventory.ps1"
    body = script.read_bytes()

    if to_stdout:
        # Written to the buffer, not printed: `print` would translate the line
        # endings and rich would be tempted to wrap it.
        sys.stdout.buffer.write(body)
        return

    target = Path(output)
    if target.exists() and not force:
        console.print(
            f"[red]{target} exists already.[/red] Pass [bold]--force[/bold] to "
            f"replace it — this is the file you are about to run elevated on a "
            f"machine under diagnosis, so it is not replaced quietly."
        )
        raise typer.Exit(1)

    target.write_bytes(body)

    console.print(f"🛡️  [bold]{target}[/bold] — {len(body):,} bytes\n")
    console.print("Three things a clean machine needs, and none of them is the script:")
    console.print(f"  [cyan]Unblock-File .\\{target.name}[/cyan]"
                  "                    the download mark, or PowerShell refuses it")
    console.print(f"  [cyan]powershell -ExecutionPolicy Bypass -File .\\{target.name}[/cyan]")
    console.print("  …and run it [bold]as administrator[/bold]: without that the driver "
                  "store and the event log come back empty, which are the two sources "
                  "that resolved both real cases.")
    console.print("\nThen, here or anywhere: [cyan]patchradar import <snapshot>.json[/cyan]")


@app.command(name="import")
def import_inventory(
    path: str = typer.Argument(..., help="Inventory snapshot written by `patchradar collector`"),
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


POSITION_STYLES = {
    "resolved": "green",
    "not-affected": "green",
    "fix-elsewhere": "yellow",
    "point-release": "cyan",
    "no-dsa": "magenta",
    "open": "red",
    "undetermined": "blue",
    "untracked": "dim",
}


@app.command()
def debian(
    cves: list[str] = typer.Argument(..., help="CVE ids, as a scanner reported them"),
    release: str = typer.Option(debian_release, "--release", "-r",
                                help="Debian suite the image is built on"),
    package: str = typer.Option(None, "--package", "-p",
                                help="Narrow to one source package"),
    file: str = typer.Option(None, "--file", "-f",
                             help="Read a saved tracker snapshot instead of downloading"),
):
    """What Debian says about these CVEs, and what can be done about each one.

    A container scanner reports "no fix available" for anything it cannot see a
    fixed version for, and that single line covers situations with nothing in
    common. Of our own five Debian findings, two are unfixed everywhere and three
    are already fixed in unstable and scheduled for a trixie point release. The
    first two cannot be waited out; the last three only need a rebuild after a
    dated event.

    The tracker is ~75 MB. `--file` reads a snapshot saved earlier, which is how
    the tests ask this question without the network.
    """
    from patchradar.debian_status import standings

    if file:
        try:
            data = json.loads(pathlib.Path(file).read_text(encoding="utf-8"))
        except FileNotFoundError:
            console.print(f"[red]no such file: {escape(file)}[/red]")
            raise typer.Exit(2) from None
        except (ValueError, UnicodeDecodeError) as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(2) from None
        if not isinstance(data, dict):
            console.print(f"[red]{escape(file)} is not a Debian tracker snapshot: "
                          f"expected an object keyed by source package[/red]")
            raise typer.Exit(2)
        origin = pathlib.Path(file).name
    else:
        try:
            with _status("[cyan]Reading the Debian security tracker...[/cyan]"):
                data = run(get_tracker_snapshot())
        except CollectorError as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(2) from None
        origin = "security-tracker.debian.org"

    console.print(f"\n🐧 [bold]Debian {escape(release)}[/bold] — "
                  f"{len(data)} source packages, from {escape(origin)}\n")

    for cve in cves:
        for standing in standings(data, cve, release=release, package=package):
            style = POSITION_STYLES.get(standing.position.value, "white")
            where = standing.package or "—"
            console.print(f"[bold]{escape(cve)}[/bold]  {Text(where)}  "
                          f"[{style}]{standing.position.value}[/{style}]")
            if standing.in_release:
                console.print(f"  [dim]in {escape(release)}:[/dim] "
                              f"{escape(standing.in_release)}"
                              f"   [dim]urgency:[/dim] {escape(standing.urgency or '—')}")
            if standing.fixed_here:
                console.print(f"  [dim]fixed here:[/dim] {escape(standing.fixed_here)}")
            for suite, version in standing.fixed_elsewhere.items():
                console.print(f"  [dim]fixed in {escape(suite)}:[/dim] {escape(version)}")
            # The action, not the status: a status can be read off the tracker
            # page, and the reason this command exists is that reading it off the
            # page is exactly what nobody does before deciding to wait.
            console.print(f"  [bold]→[/bold] {escape(standing.action())}\n")


def main():
    app()

if __name__ == "__main__":
    main()
