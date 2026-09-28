"""
PatchRadar — the same reading, against what NVD actually sent.

`test_affected.py` builds each shape by hand: it proves the rules and it agrees
with itself. This one runs the whole module over a real payload — the 21 CVEs NVD
returns for `cpe:2.3:a:notepad-plus-plus:notepad\\+\\+` — and pins the three
answers the versionradar design measured on 2026-09-28.

It earned its place immediately. The first run of this module against this file
returned **zero hits for all three versions**, because the tests spelled the
product field `notepad++` the way a person writes it while NVD writes
`notepad\\+\\+`: CPE 2.3 requires the escape, and the same trap gives HTTP 404
on the API. Every hand-built test still passed.

The fixture is trimmed to the nodes under test — id, published, one metric,
`configurations` — 20 KB instead of 95. A shape change should produce a diff
someone can read.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from patchradar.affected import summarise

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "nvd_notepadpp_configurations.json"
VENDOR = "notepad-plus-plus"
PRODUCT = "notepad\\+\\+"


@pytest.fixture(scope="module")
def payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def summary(payload: dict, version: str):
    return summarise(payload, version=version, vendor=VENDOR, cpe_product=PRODUCT)


def test_the_payload_is_the_one_this_test_describes(payload):
    assert len(payload["vulnerabilities"]) == 21


def test_8_9_5_has_five_and_one_update_closes_all_five(payload):
    found = summary(payload, "8.9.5")

    assert found.total == 5
    assert found.worst == 7.8
    assert found.target == "8.9.6.4"
    assert found.closed_by_target == 5
    assert found.unresolved == 0


def test_8_5_0_has_ten_and_the_update_closes_six(payload):
    """The four that stay open are open because NVD does not state where they
    were fixed — `versionEndIncluding` names the last affected release and not
    the first sound one — not because 8.9.6.4 is insufficient."""
    found = summary(payload, "8.5.0")

    assert found.total == 10
    assert found.target == "8.9.6.4"
    assert found.closed_by_target == 6
    assert found.unresolved == 4

    unstated = [hit for hit in found.hits if hit.fixed_version is None]
    assert len(unstated) == 4
    assert all("does not state" in hit.note for hit in unstated)


def test_8_9_8_has_none_and_that_is_not_an_all_clear(payload):
    """Zero CVEs in NVD, and five vulnerabilities the author declared in the
    8.9.8.1 release notes with no identifier assigned — a UAC operation
    performed without verifying the caller among them."""
    found = summary(payload, "8.9.8")

    assert found.total == 0
    assert found.target is None
    assert found.caveat, "a count of zero must carry the reason it is not an absolution"
    assert "identifier" in found.caveat


def test_the_non_vulnerable_node_is_not_counted(payload):
    """CVE-2017-8803 carries a Notepad++ node with `vulnerable: false`: it
    describes the context in which another component is vulnerable. Version
    7.3.3 is inside the range it names, so counting the node would report it."""
    found = summary(payload, "7.3.3")
    assert "CVE-2017-8803" not in {hit.cve for hit in found.hits}


def test_the_other_products_in_the_same_cves_are_not_this_one(payload):
    """The payload also carries `scintilla:scintilla` and `mh-nexus:hex_editor`
    nodes. A vendor filter that let them through would attribute another
    project's vulnerability to this one."""
    found = summarise(payload, version="8.9.5", vendor="scintilla", cpe_product="scintilla")
    assert {hit.cve for hit in found.hits}.isdisjoint(
        {hit.cve for hit in summary(payload, "8.9.5").hits}
    )
