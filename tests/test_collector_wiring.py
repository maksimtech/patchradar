"""
PatchRadar — every collector that exists must actually be called

A collector module is dead weight until something invokes it, and nothing in
the test suite noticed the difference: `debian.py` was complete, tested and
imported, and the README still advertised it as "Coming soon" — the reverse
mistake, but the same blind spot. A module can equally well be written, tested
and never wired into the scan, and every one of its own tests would still pass.

This asserts the structural fact instead: for each module under
`patchradar/collectors/`, `_scan_one` in the API must call it. It is a contract
test rather than a behaviour test on purpose — it costs no mocks and it holds
for collectors that do not exist yet.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

import patchradar.api.main as api_main
import patchradar.cli as cli_module
from patchradar import collectors

COLLECTORS_DIR = pathlib.Path(collectors.__file__).parent
API_SOURCE = pathlib.Path(api_main.__file__).read_text(encoding="utf-8")
API_TREE = ast.parse(API_SOURCE)
CLI_SOURCE = pathlib.Path(cli_module.__file__).read_text(encoding="utf-8")
CLI_TREE = ast.parse(CLI_SOURCE)

# Modules that are not sources: `errors` defines the exception type the
# collectors raise, and has nothing to fetch.
NOT_A_SOURCE = {"__init__", "errors"}


def _defines_fetch_cves(path: pathlib.Path) -> bool:
    """Whether the module defines `fetch_cves`.

    The test keys on this rather than on the file existing, because
    `collectors/snyk.py` is an empty file: importing it succeeds and yields a
    module with nothing in it, which is a placeholder rather than a collector.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(isinstance(n, ast.AsyncFunctionDef | ast.FunctionDef) and n.name == "fetch_cves"
               for n in ast.walk(tree))


_CANDIDATES = [p for p in COLLECTORS_DIR.glob("*.py") if p.stem not in NOT_A_SOURCE]
COLLECTOR_MODULES = sorted(p.stem for p in _CANDIDATES if _defines_fetch_cves(p))
PLACEHOLDER_MODULES = sorted(p.stem for p in _CANDIDATES if not _defines_fetch_cves(p))


def _import_aliases(tree: ast.AST = API_TREE) -> dict[str, str]:
    """{module name: the name `fetch_cves` was imported as} in a module."""
    aliases = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if not node.module.startswith("patchradar.collectors."):
            continue
        module = node.module.rsplit(".", 1)[-1]
        for alias in node.names:
            if alias.name == "fetch_cves":
                aliases[module] = alias.asname or alias.name
    return aliases


def _scan_one_source() -> str:
    for node in ast.walk(API_TREE):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_scan_one":
            return ast.get_source_segment(API_SOURCE, node) or ""
    raise AssertionError("_scan_one not found in patchradar.api.main")


def test_there_is_at_least_one_collector():
    """Guard the guard: an empty list would make every test below vacuous."""
    assert COLLECTOR_MODULES


# `collectors/snyk.py` has been a zero-byte file for the whole life of the
# package. Listing it here rather than deleting it keeps the debt visible and
# keeps `from patchradar.collectors import snyk` — which succeeds and returns
# nothing — from ever quietly becoming a half-written source.
KNOWN_PLACEHOLDERS = {"snyk"}


def test_placeholders_are_still_placeholders():
    """A placeholder that grows code must be wired, not left half-connected.

    The moment one of these defines `fetch_cves` it leaves this set and joins
    the parametrised tests above, which will then demand that the API import
    and call it.
    """
    assert set(PLACEHOLDER_MODULES) == KNOWN_PLACEHOLDERS, (
        f"placeholder collectors changed: {sorted(PLACEHOLDER_MODULES)}. "
        f"Fill one in and wire it into _scan_one, or delete the file."
    )


# The CLI scans two ways and they must agree about what a scan is. They do not
# agree about Debian, and that is deliberate rather than forgotten: the tracker
# dump is a single ~75 MB download, which the long-running API amortises over a
# process-wide snapshot and a one-shot `patchradar scan` would pay in full every
# time. Recorded here so the gap is a decision with a reason, not a drift.
CLI_MINUS_API: set[str] = set()
API_MINUS_CLI = {"debian"}


def _sources_in(tree, source, function):
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == function:
            body = ast.get_source_segment(source, node) or ""
            return {m for m, a in _import_aliases(tree).items() if a in body}
    raise AssertionError(f"{function} not found")


def test_cli_and_api_scan_the_same_sources():
    """Two totals for the same machine, from two entry points, must mean the
    same thing - or the difference must be written down."""
    api = _sources_in(API_TREE, API_SOURCE, "_scan_one")
    cli = _sources_in(CLI_TREE, CLI_SOURCE, "_scan_target")
    assert api - cli == API_MINUS_CLI, f"API scans {sorted(api - cli)} and the CLI does not"
    assert cli - api == CLI_MINUS_API, f"the CLI scans {sorted(cli - api)} and the API does not"


@pytest.mark.asyncio
async def test_a_scan_source_cannot_reach_the_network_by_default():
    """No respx here, and no request either: the catalogue is already cached.

    This is the guard from `conftest.kev_offline_by_default`, asserted rather
    than assumed. If the seeding stops working, this fails here instead of
    turning into a live request buried inside some unrelated scan test — which
    is how the problem announced itself the first time: as a thread exception
    about a closed event loop, three files away from its cause.
    """
    from patchradar.collectors import kev

    assert await kev.fetch_cves("anything") == []


def test_scan_sources_lists_every_source_the_cli_queries():
    """`SCAN_SOURCES` names the sources for the end-of-scan summary.

    It drifted once already: it still said ("NVD", "MSRC") after KEV joined the
    fan-out, so a scan whose only result came from KEV announced that "every
    CVE above comes from MSRC". The summary is the one line a reader takes away,
    and it was naming the wrong source.
    """
    import importlib

    declared = set(cli_module.SCAN_SOURCES)
    queried = {
        importlib.import_module(f"patchradar.collectors.{m}").SOURCE
        for m in _sources_in(CLI_TREE, CLI_SOURCE, "_scan_target")
    }
    assert declared == queried, (
        f"SCAN_SOURCES says {sorted(declared)} but the scan queries {sorted(queried)}"
    )


@pytest.mark.parametrize("module", sorted(KNOWN_PLACEHOLDERS))
def test_placeholder_is_empty_rather_than_broken(module):
    """An empty file is a stub; a file with code that defines no entry point
    is a mistake, and the two look identical from the outside.

    Skipped inside mutmut's working copy, and the reason is not a technicality:
    mutmut rewrites every file under `source_paths` and gives each one its own
    preamble, so an empty placeholder is not empty there. The claim is about this
    repository, and in that tree it is not the repository being read. On 2026-10-03
    this failed the whole mutation run in the stats phase, before a single mutant
    was tried, because mutmut's `-x` stops at the first failure.
    """
    if "mutants" in COLLECTORS_DIR.parts:
        pytest.skip("mutmut's copy carries its own preamble in every source file")

    path = COLLECTORS_DIR / f"{module}.py"
    assert path.read_text(encoding="utf-8").strip() == "", (
        f"{module}.py has content but defines no fetch_cves"
    )


@pytest.mark.parametrize("module", COLLECTOR_MODULES)
def test_collector_is_imported_by_the_api(module):
    assert module in _import_aliases(), (
        f"collectors/{module}.py exists but patchradar.api.main never imports its "
        f"fetch_cves — it can never run"
    )


@pytest.mark.parametrize("module", COLLECTOR_MODULES)
def test_collector_is_called_during_a_scan(module):
    alias = _import_aliases().get(module)
    assert alias, f"collectors/{module}.py is not imported by the API"
    assert alias in _scan_one_source(), (
        f"{alias} is imported but never called in _scan_one: a scan would "
        f"silently skip {module}"
    )


@pytest.mark.parametrize("module", COLLECTOR_MODULES)
def test_collector_is_listed_in_the_readme(module):
    """The README's source table is public documentation of what runs.

    It said "Coming soon" for Debian long after the collector shipped, and left
    Snyk out altogether. A table that understates the product is a smaller
    problem than one that overstates it, but both mislead whoever reads it to
    decide whether to trust a scan.
    """
    readme = (pathlib.Path(api_main.__file__).parents[3] / "README.md")
    if not readme.exists():          # installed without the source tree
        pytest.skip("README.md not present next to the package")
    text = readme.read_text(encoding="utf-8").lower()
    assert module.lower() in text, f"collectors/{module}.py is not mentioned in README.md"
