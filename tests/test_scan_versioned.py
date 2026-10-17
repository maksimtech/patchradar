"""
PatchRadar — `scan` judges what it finds against the installed version (DESIGN §5.4)

Until now a scan found the CVEs that **name** the software and could not say
which of them affect what is installed: for Notepad++ 8.5.0 the recorded NVD
answer holds 21 CVEs, and 11 of them concern other versions or another product.
The table printed all 21, ranked, as if each were a job.

For an entry added with `--version` and `--cpe` the scan now judges each CVE:
the table lists the ones that affect the version or could not be evaluated, the
others are counted and listed only with `--all`, one line gives the split, one
says what an update closes, and the caveat that a count from NVD is a count of
identifiers is always there. An entry without them is scanned by name as before,
and the scan says so.

NVD answers from the recording `nvd_notepadpp_configurations.json` (21 CVEs,
trimmed to the fields under test); MSRC has no document for the months asked
(404); the KEV catalogue is the empty one conftest.py caches.
"""
from __future__ import annotations

import copy
import json
import pathlib

import httpx
import pytest
import respx
from typer.testing import CliRunner

from patchradar import cli
from patchradar.affected import summarise
from patchradar.collectors import msrc, nvd

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "nvd_notepadpp_configurations.json"
PAYLOAD = json.loads(FIXTURE.read_text(encoding="utf-8"))
NOTEPADPP = "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"

AFFECTING_850 = {hit.cve for hit in summarise(PAYLOAD, version="8.5.0", vendor="notepad-plus-plus",
                                              cpe_product="notepad\\+\\+").hits}
NOT_AFFECTING_850 = {item["cve"]["id"] for item in PAYLOAD["vulnerabilities"]} - AFFECTING_850


def _nvd_answers(payload):
    router = respx.mock(assert_all_called=False)
    router.get(url__startswith=nvd.NVD_API).mock(return_value=httpx.Response(200, json=payload))
    router.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
    return router


@pytest.fixture
def nvd_answers_notepadpp():
    with _nvd_answers(PAYLOAD):
        yield


def _scan(*args, version="8.5.0"):
    runner = CliRunner()
    added = ["add", "notepad", "--cpe", NOTEPADPP] + (["--version", version] if version else [])
    assert runner.invoke(cli.app, added).exit_code == 0
    result = runner.invoke(cli.app, ["scan", "notepad", "--days", "7", *args], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    return result.output


def _words(output: str) -> str:
    return " ".join(output.split())


def test_the_payload_splits_ten_and_eleven():
    assert (len(AFFECTING_850), len(NOT_AFFECTING_850)) == (10, 11)


def test_the_split_is_said_in_one_line(nvd_answers_notepadpp):
    out = _words(_scan())

    assert "found by name: 21; affecting 8.5.0: 10; not evaluable: 0; not affecting it: 11" in out


def test_the_table_lists_what_affects_the_version_and_not_the_rest(nvd_answers_notepadpp):
    out = _scan()

    assert all(cve in out for cve in AFFECTING_850)
    assert not any(cve in out for cve in NOT_AFFECTING_850)


def test_each_listed_cve_carries_its_verdict(nvd_answers_notepadpp):
    out = _words(_scan())

    assert out.count("affected") >= 10
    assert "NVD states the fix is in 8.9.6.4" in out


def test_all_lists_the_ones_that_do_not_affect_it_with_their_verdict(nvd_answers_notepadpp):
    out = _scan("--all")

    assert all(cve in out for cve in AFFECTING_850 | NOT_AFFECTING_850)
    assert "not affected" in out


def test_without_all_the_scan_says_how_to_see_the_rest(nvd_answers_notepadpp):
    assert "--all" in _scan()


def test_what_one_update_closes_and_why_the_rest_stay_open(nvd_answers_notepadpp):
    out = _words(_scan())

    assert "Updating to 8.9.6.4 closes 6 of 10" in out
    assert "NVD does not state where they were fixed" in out


def test_the_caveat_is_always_there(nvd_answers_notepadpp):
    assert "Counted in NVD only" in _words(_scan())


def test_a_version_none_of_them_affects_lists_none_and_keeps_the_caveat(nvd_answers_notepadpp):
    out = _words(_scan(version="8.9.8"))

    assert "found by name: 21; affecting 8.9.8: 0; not evaluable: 0; not affecting it: 21" in out
    assert not any(cve in out for cve in AFFECTING_850 | NOT_AFFECTING_850)
    assert "Counted in NVD only" in out
    assert "no CVEs found" not in out


def test_the_total_keeps_counting_what_was_found_by_name(nvd_answers_notepadpp):
    assert "Total: 21 CVEs found" in _words(_scan())


def test_a_cve_nvd_has_not_analysed_is_listed_as_not_evaluable():
    """Derived: the payload above with the `configurations` of CVE-2026-52885
    removed, the state of a CVE in NVD's backlog."""
    payload = copy.deepcopy(PAYLOAD)
    for item in payload["vulnerabilities"]:
        if item["cve"]["id"] == "CVE-2026-52885":
            del item["cve"]["configurations"]

    with _nvd_answers(payload):
        out = _words(_scan(version="8.9.8"))

    assert "CVE-2026-52885" in out
    assert "not evaluable" in out
    assert "affecting 8.9.8: 0; not evaluable: 1; not affecting it: 20" in out


# ─── entries without a version ───────────────────────────────────────────────

def test_an_entry_without_a_version_is_scanned_by_name_and_said_to_be(nvd_answers_notepadpp):
    out = _words(_scan(version=None))

    assert all(cve in out for cve in AFFECTING_850 | NOT_AFFECTING_850)
    assert "Matched by name only, version not checked: notepad" in out
    assert "found by name:" not in out


def test_a_versioned_entry_is_not_among_those_matched_by_name_only(nvd_answers_notepadpp):
    assert "Matched by name only" not in _scan()


def test_an_update_that_closes_all_says_nothing_about_a_rest(nvd_answers_notepadpp):
    """8.9.5: five affect it, every fix stated, the highest is 8.9.6.4."""
    out = _words(_scan(version="8.9.5"))

    assert "Updating to 8.9.6.4 closes 5 of 5." in out
    assert "The rest stay open" not in out


def test_when_nothing_is_left_out_the_scan_does_not_point_at_all():
    """Derived: the payload above reduced to the ten CVEs that affect 8.5.0."""
    payload = {**PAYLOAD, "vulnerabilities": [item for item in PAYLOAD["vulnerabilities"]
                                              if item["cve"]["id"] in AFFECTING_850]}

    with _nvd_answers(payload):
        out = _words(_scan())

    assert "not affecting it: 0" in out
    assert "--all" not in out


def test_the_caveat_stays_when_nvd_finds_nothing():
    """NVD's recorded answer for a keyword with no CVEs: no CVE in NVD is the
    case the caveat exists for."""
    empty = json.loads((FIXTURE.parent / "nvd_no_results.json").read_text(encoding="utf-8"))

    with _nvd_answers(empty):
        out = _words(_scan())

    assert "no CVEs found" in out
    assert "Counted in NVD only" in out
