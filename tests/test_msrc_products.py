"""
PatchRadar — MSRC entries are found by the products they affect, not only by their titles

Seen on 2026-10-17: `patchradar scan "windows 11"` found nothing in MSRC, while
the October 2026 document lists 1,057 entries whose affected products include a
Windows 11 one, and KB5127648 — October's cumulative update for Windows 11 — was
installed on the machine that ran the scan. MSRC titles its entries by component
("Windows Kernel Information Disclosure Vulnerability") and names the operating
system only in the document's ProductTree, which each entry points into through
its ProductStatuses. The keyword was matched against the title and the notes
alone, and the September fixture these tests used had no ProductTree at all.

An entry is now kept when the keyword names one of the products it lists as
Known Affected (ProductStatuses Type 3), by the same whole-word rule as titles.

The fixture is the October 2026 document, recorded: three entries verbatim and
the ProductTree names they point to.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime

import httpx
import pytest
import respx

from patchradar.collectors import msrc

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
OCTOBER = json.loads((FIXTURES / "msrc_2026_oct_excerpt_recorded.json").read_text(encoding="utf-8"))
assert "verbatim" in OCTOBER.pop("_recorded")

KERNEL = "CVE-2026-102187"     # Windows Kernel Information Disclosure, Windows 11 26H2 among 32 products
CLUSTER = "CVE-2026-102192"    # Windows Failover Cluster, Windows Server only
EXCEL = "CVE-2026-100209"      # Microsoft Office Excel

# The day of the recording, at noon.
RECORDED = datetime(2026, 10, 17, 12, 0)


def products_of(cve_id: str) -> set[str]:
    names = {p["ProductID"]: p["Value"] for p in OCTOBER["ProductTree"]["FullProductName"]}
    [vuln] = [v for v in OCTOBER["Vulnerability"] if v["CVE"] == cve_id]
    return {names[pid] for s in vuln["ProductStatuses"] if s["Type"] == 3 for pid in s["ProductID"]}


def test_the_recording_says_what_the_tests_rely_on():
    assert "Windows 11 Version 26H2 for x64-based Systems" in products_of(KERNEL)
    assert all("Windows Server" in name for name in products_of(CLUSTER))
    assert not any("Windows" in name for name in products_of(EXCEL))
    assert all("Windows 11" not in v["Title"]["Value"] for v in OCTOBER["Vulnerability"])


@pytest.fixture
def october_only():
    msrc.clear_cache()
    with respx.mock:
        respx.get(f"{msrc.MSRC_API}/cvrf/2026-Oct").mock(return_value=httpx.Response(200, json=OCTOBER))
        respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        yield
    msrc.clear_cache()


async def ids(keyword: str) -> list[str]:
    return [c["id"] for c in await msrc.fetch_cves(keyword, days_back=30, now=RECORDED)]


async def test_windows_11_finds_the_entries_that_affect_it(october_only):
    assert await ids("windows 11") == [KERNEL]


async def test_windows_server_finds_its_own_and_not_excel(october_only):
    found = await ids("windows server")

    assert CLUSTER in found
    assert EXCEL not in found


async def test_a_title_still_finds_its_entry(october_only):
    """What matched before still matches: Excel is in the title."""
    assert await ids("excel") == [EXCEL]


async def test_a_product_name_is_matched_as_a_word_as_titles_are(october_only):
    """"win" is in every Windows product name as part of a word, and finds none
    of them — the rule titles follow, and the reason it exists ("git" once found
    "GitHub", "legitimate" and "digital")."""
    assert await ids("win") == []


async def test_only_a_known_affected_status_counts():
    """The October document holds ProductStatuses of Type 3, Known Affected, and
    nothing else (2,133 of them). CVRF has other statuses — not affected, fixed —
    and a product under one of those is not one the entry affects. Derived: the
    recorded kernel entry with its status Type changed from 3."""
    derived = json.loads(json.dumps(OCTOBER))
    [kernel] = [v for v in derived["Vulnerability"] if v["CVE"] == KERNEL]
    for status in kernel["ProductStatuses"]:
        status["Type"] = 2
    msrc.clear_cache()
    with respx.mock:
        respx.get(f"{msrc.MSRC_API}/cvrf/2026-Oct").mock(return_value=httpx.Response(200, json=derived))
        respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        found = await ids("windows 11")
    msrc.clear_cache()

    assert found == []


async def test_a_malformed_product_entry_does_not_hide_the_others():
    """One product that is not an object is skipped, as one malformed entry of
    Vulnerability is: it used to cost the month. Derived: the recorded excerpt
    with a string inserted at the head of FullProductName."""
    derived = json.loads(json.dumps(OCTOBER))
    derived["ProductTree"]["FullProductName"].insert(0, "not a product")
    msrc.clear_cache()
    with respx.mock:
        respx.get(f"{msrc.MSRC_API}/cvrf/2026-Oct").mock(return_value=httpx.Response(200, json=derived))
        respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        found = await ids("windows 11")
    msrc.clear_cache()

    assert found == [KERNEL]
