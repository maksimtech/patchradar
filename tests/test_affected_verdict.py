"""
PatchRadar — every CVE found by name gets one of three verdicts (DESIGN §5.3)

`affects()` answers "which of these affect the version", and is silent about the
rest; a scan needs to say what it is silent about. So each record is judged:

- affected: a vulnerable `cpeMatch` for the vendor and product contains it;
- not affected: NVD lists the affected products and versions, and this version
  of this product is not among them;
- not evaluable: anything that cannot be decided — NVD has not yet said which
  products the CVE affects, NVD's record was not part of the scan, or NVD's
  versions belong to another scheme than the installed one.

"Not evaluable" never becomes "not affected": an answer a security tool cannot
give is not an absolution.

The payload is the recorded NVD answer for Notepad++ that
`test_affected_real_payload.py` already pins; `judge` reads it as the scan does,
one record at a time, through `nvd._parse_item`.
"""
from __future__ import annotations

import copy
import json
import pathlib

import pytest

from patchradar.affected import (
    AFFECTED,
    NOT_AFFECTED,
    NOT_EVALUABLE,
    closed_by,
    judge,
    summarise,
)
from patchradar.collectors.nvd import _parse_item

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "nvd_notepadpp_configurations.json"
VENDOR = "notepad-plus-plus"
PRODUCT = "notepad\\+\\+"


@pytest.fixture(scope="module")
def payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def records(payload) -> list[dict]:
    return [_parse_item(item, "notepad") for item in payload["vulnerabilities"]]


def verdicts(records, version):
    return {r["id"]: judge(r, version=version, vendor=VENDOR, cpe_product=PRODUCT) for r in records}


# ─── what NVD's record carries ───────────────────────────────────────────────

def test_an_nvd_record_keeps_its_configurations(records):
    assert all(isinstance(r["configurations"], list) for r in records)
    assert any(r["configurations"] for r in records)


def test_an_nvd_record_without_configurations_says_so_with_an_empty_list():
    """Present and empty: NVD's record was read, and NVD has not analysed it
    yet. Absent means something else — the record did not come from NVD."""
    record = _parse_item({"cve": {"id": "CVE-2026-99999", "published": "2026-10-16T10:00:00.000"}}, "notepad")

    assert record["configurations"] == []


# ─── the three verdicts on the real payload ──────────────────────────────────

def test_the_affected_ones_are_exactly_those_affects_finds(payload, records):
    """Two readings of one payload must agree: `summarise` through `affects`,
    and `judge` record by record."""
    expected = {hit.cve for hit in summarise(payload, version="8.5.0", vendor=VENDOR,
                                             cpe_product=PRODUCT).hits}

    found = {cve for cve, v in verdicts(records, "8.5.0").items() if v.status == AFFECTED}

    assert found == expected
    assert len(found) == 10


def test_every_other_record_of_the_payload_is_not_affected(records):
    """Every CVE here has its products analysed and every version compares,
    so nothing is left undecided."""
    statuses = [v.status for v in verdicts(records, "8.5.0").values()]

    assert statuses.count(NOT_AFFECTED) == 11
    assert NOT_EVALUABLE not in statuses


def test_a_newer_version_is_affected_by_none(records):
    assert all(v.status == NOT_AFFECTED for v in verdicts(records, "8.9.8").values())


def test_a_product_named_only_as_context_is_not_affected(records):
    """CVE-2017-8803: the Notepad++ node is `vulnerable: false`, the context of
    a plugin's flaw, and 7.3.3 sits inside the range it names."""
    verdict = verdicts(records, "7.3.3")["CVE-2017-8803"]

    assert verdict.status == NOT_AFFECTED
    assert "not among them" in verdict.reason


def test_an_affected_verdict_says_where_nvd_states_the_fix(records):
    """8.9.5: five, fixed in 8.9.6 (CVE-2026-46710), 8.9.6.1 (three) and
    8.9.6.4 (CVE-2026-52885) — each as its `versionEndExcluding` says."""
    found = verdicts(records, "8.9.5")
    fixed = {cve: v.fixed_version for cve, v in found.items() if v.status == AFFECTED}

    assert fixed == {
        "CVE-2026-46710": "8.9.6",
        "CVE-2026-48770": "8.9.6.1",
        "CVE-2026-48778": "8.9.6.1",
        "CVE-2026-48800": "8.9.6.1",
        "CVE-2026-52885": "8.9.6.4",
    }
    assert all(found[cve].fixed_version in found[cve].reason for cve in fixed)


def test_a_last_affected_version_is_not_turned_into_a_fix(records):
    """`versionEndIncluding: X` names the last affected release; the next one
    is not a number any source stated."""
    open_ones = [v for v in verdicts(records, "8.5.0").values()
                 if v.status == AFFECTED and v.fixed_version is None]

    assert len(open_ones) == 4
    assert all("does not state" in v.reason for v in open_ones)


# ─── what cannot be decided ──────────────────────────────────────────────────

def test_a_record_from_another_source_is_not_evaluable():
    """MSRC, KEV and VulDB carry no `cpeMatch`; without NVD's record of the same
    CVE there is nothing to judge the version with."""
    verdict = judge({"id": "CVE-2026-12345", "source": "CISA KEV"},
                    version="8.5.0", vendor=VENDOR, cpe_product=PRODUCT)

    assert verdict.status == NOT_EVALUABLE
    assert "not part of this scan" in verdict.reason


def test_a_record_nvd_has_not_analysed_is_not_evaluable():
    verdict = judge({"id": "CVE-2026-99999", "source": "NVD", "configurations": []},
                    version="8.5.0", vendor=VENDOR, cpe_product=PRODUCT)

    assert verdict.status == NOT_EVALUABLE
    assert "not yet" in verdict.reason


def test_versions_of_another_scheme_are_not_evaluable_rather_than_not_affected(records):
    """Derived from CVE-2023-40031 of the payload, its range moved to an Office
    build number: `2.07` against `16.0.14334.20918` is a comparison with no
    meaning, and "not affected" would be a verdict on it."""
    record = copy.deepcopy(next(r for r in records if r["id"] == "CVE-2023-40031"))
    for configuration in record["configurations"]:
        for node in configuration["nodes"]:
            for entry in node["cpeMatch"]:
                entry.pop("versionEndIncluding", None)
                entry.pop("versionStartIncluding", None)
                entry["versionEndExcluding"] = "16.0.14334.20918"

    verdict = judge(record, version="2.07", vendor=VENDOR, cpe_product=PRODUCT)

    assert verdict.status == NOT_EVALUABLE
    assert "cannot be compared" in verdict.reason


def test_a_version_that_is_not_a_version_is_not_evaluable_wherever_the_product_is_listed(records):
    """"latest" orders against nothing. Where NVD lists Notepad++ as affected,
    the answer is "cannot tell", never "not affected" — and never "affected"."""
    at_850 = verdicts(records, "8.5.0")
    latest = verdicts(records, "latest")

    assert AFFECTED not in {v.status for v in latest.values()}
    assert all(latest[cve].status == NOT_EVALUABLE
               for cve, v in at_850.items() if v.status == AFFECTED)


# ─── what one update closes ──────────────────────────────────────────────────

def test_closed_by_agrees_with_summarise(payload, records):
    summary = summarise(payload, version="8.5.0", vendor=VENDOR, cpe_product=PRODUCT)
    fixes = [v.fixed_version for v in verdicts(records, "8.5.0").values() if v.status == AFFECTED]

    assert closed_by(fixes) == (summary.target, summary.closed_by_target) == ("8.9.6.4", 6)


def test_closed_by_names_no_target_when_nobody_states_a_fix():
    assert closed_by([None, None]) == (None, 0)


def test_every_version_is_comparable_with_every_version():
    """A `*` in NVD's criteria: unbounded contains any version, so `judge` never
    asks — but `comparable` must not be the one to say otherwise."""
    from patchradar.affected import Range

    assert Range(unbounded=True).comparable("8.5.0")
    assert not Range(unbounded=True).comparable("latest")
