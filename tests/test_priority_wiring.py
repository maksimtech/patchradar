"""
PatchRadar — the ranking must be in the scan, and the scan must not claim more
than the database can hold.

Two structural facts, in the spirit of `test_collector_wiring.py`: a module is
dead weight until something calls it, and a report that ranks while the API does
not is a drift nobody notices until two people compare their screens.

The second half pinned a boundary deliberately: `known_exploited`,
`kev_ransomware` and the KEV dates travelled in the scan's records and were not
columns in `cves`, so the exploitation fact was gone by the next `patchradar
status`, and the day someone added the columns this file was to say "now wire
the API too". They arrived with docs/DESIGN.md §5.5, and the tests below now
hold the other side: the facts are stored, and the stored listings are ranked
by the same rules (`priority.sql_order`), not by date.

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


def test_the_database_stores_every_fact_a_rank_is_decided_by():
    schema = _function_source(DB_SOURCE, "init_db")
    missing = [fact for fact in KEV_FACTS if fact not in schema]
    assert not missing, "a rank decided by an unstored fact cannot be repeated by status or /cves"


def test_the_stored_listings_are_ordered_by_priority_not_by_date():
    """Named here so the two paths are compared in one place rather than
    discovered to differ: `get_cves`, which `status` and `/api/cves` read, orders
    by the expression `priority.sql_order` builds from the scan's own rules —
    written out in the statement, and held to that text by
    tests/test_sql_is_not_formatted.py."""
    body = _function_source(DB_SOURCE, "get_cves")
    assert body.count("ORDER BY CASE") == 2
    assert "ORDER BY published_at DESC" not in body
