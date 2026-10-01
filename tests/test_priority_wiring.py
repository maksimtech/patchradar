"""
PatchRadar — the ranking must be in the scan, and the scan must not claim more
than the database can hold.

Two structural facts, in the spirit of `test_collector_wiring.py`: a module is
dead weight until something calls it, and a report that ranks while the API does
not is a drift nobody notices until two people compare their screens.

The second half pins the boundary deliberately. `known_exploited`,
`kev_ransomware` and `kev_due_date` travel in the records the collectors return
and are **not** columns in `cves`, so the exploitation fact exists in memory
during a scan and is gone by the next `patchradar status`. Until the migration of
DESIGN §5 lands, only the in-memory path can rank — and the day someone adds the
column, this test is what says "now wire the API too".

The EPSS pair *is* stored, which narrows that gap without closing it: a ranking
computed from the database would know the forecast and still not know what CISA
has observed, and a rank that silently omits the top two tiers is worse than no
rank at all. So the boundary below stays where it is, and stays about KEV.
"""
from __future__ import annotations

import ast
import pathlib

import patchradar.api.main as api_main
import patchradar.cli as cli_module
import patchradar.db.database as database

CLI_SOURCE = pathlib.Path(cli_module.__file__).read_text(encoding="utf-8")
DB_SOURCE = pathlib.Path(database.__file__).read_text(encoding="utf-8")
API_SOURCE = pathlib.Path(api_main.__file__).read_text(encoding="utf-8")

# The fields the KEV collector attaches to a record, which decide a rank.
KEV_FACTS = ("known_exploited", "kev_ransomware", "kev_date_added", "kev_due_date")


def _function_source(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(source, node) or ""
    raise AssertionError(f"{name} not found")


def test_the_scan_orders_before_it_counts_or_prints():
    """Ordering inside `_print_cves` alone would leave the count, the saved rows
    and the law check reading the unmerged list — five records for four CVEs."""
    body = _function_source(CLI_SOURCE, "_scan_target")
    assert "merge_by_cve(" in body
    assert "sort_by_priority(" in body


def test_the_scan_merges_then_enriches_then_sorts():
    """The order of the three steps, which is not a matter of taste.

    EPSS has to be asked after the merge, or FIRST is asked twice about a CVE two
    sources reported; and the sort has to come after the enrichment, or the
    report is ordered on the facts it held a moment earlier — the EPSS rank would
    exist in the table's reasons while playing no part in its order, which is the
    one failure mode a reader cannot see.
    """
    body = _function_source(CLI_SOURCE, "_scan_target")
    assert body.index("merge_by_cve(") < body.index("epss_enrich(") < body.index("sort_by_priority(")


def test_the_report_shows_why_a_row_ranks_where_it_does():
    body = _function_source(CLI_SOURCE, "_print_cves")
    assert "priority(" in body
    assert "reason" in body, "a rank without its reason is a number taken on trust"


def test_the_database_does_not_store_the_exploitation_fact_yet():
    """The boundary, asserted so it cannot move silently.

    If this fails because a column was added, the ranking is no longer confined
    to a single scan: `/cves` and `patchradar status` read from the database and
    must order by priority too, or the same machine gets two different answers.
    """
    schema = _function_source(DB_SOURCE, "init_db")
    stored = [fact for fact in KEV_FACTS if fact in schema]
    assert not stored, (
        "the schema now holds " + ", ".join(stored)
        + " — rank the database-backed paths as well (API /cves, status)"
    )


def test_the_api_listing_is_still_ordered_by_date():
    """Named here so the two paths are compared in one place rather than
    discovered to differ. `get_cves` orders by publication date, which is the
    only order the stored columns support."""
    assert "ORDER BY published_at DESC" in DB_SOURCE
    assert "order_by_priority" not in API_SOURCE
