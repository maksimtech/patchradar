"""
PatchRadar — `import --accept` writes what a person confirmed, and only that (DESIGN §5.6)

`import` proposes and a person confirms, and what gets remembered is the
confirmation (`inventory.py`). Until the watchlist had the columns, the
confirmation had nowhere to go and the command wrote nothing. Now
`--accept "<name>"`, once per product, writes a product the survey identified
completely — the vendor source and the product it needs — with the version the
registry holds, into the watchlist and its `vendor`, `product_id` and
`installed_version` columns.

What the survey did not identify is not written however it is asked: a source
without its product, a component, a program no source answers for. Writing
those would be the silent guess the command exists to avoid.
"""
from __future__ import annotations

import asyncio
import json

from typer.testing import CliRunner

from patchradar.cli import app
from patchradar.db import database

runner = CliRunner()


def snapshot_file(tmp_path, *programs) -> str:
    path = tmp_path / "cavia.json"
    path.write_text(json.dumps({
        "schema": "radar.inventory/1",
        "takenAt": "2026-09-27T21:15:42.0000000+02:00",
        "installedSoftware": list(programs),
    }), encoding="utf-8")
    return str(path)


def entry(name: str, version: str | None = "1.0", publisher: str = "") -> dict:
    return {"name": name, "version": version, "publisher": publisher, "hive": "HKLM"}


CHROME = entry("Google Chrome", "154.0.8037.58", "Google LLC")
EDGE = entry("Microsoft Edge", "154.0.3912.60", "Microsoft Corporation")
OFFICE = entry("Microsoft Office LTSC Professional Plus 2021", "16.0.14332.21037", "Microsoft Corporation")
WAVEPAD = entry("WavePad Sound Editor", "5.99", "NCH Software")


def _import(tmp_path, *accepted, programs=(CHROME, EDGE, OFFICE, WAVEPAD)):
    args = ["import", snapshot_file(tmp_path, *programs)]
    for name in accepted:
        args += ["--accept", name]
    result = runner.invoke(app, args)
    return result, " ".join(result.output.split())


def _entries():
    return {e.name: e for e in asyncio.run(database.get_watch_entries())}


def test_an_accepted_product_is_watched_with_its_version_and_source(tmp_path):
    result, out = _import(tmp_path, "Google Chrome")

    assert result.exit_code == 0, result.output
    chrome = _entries()["google chrome"]
    assert (chrome.installed_version, chrome.vendor, chrome.product_id) == ("154.0.8037.58", "chrome", "chrome")
    assert "google chrome" in out and "154.0.8037.58" in out


def test_the_name_is_matched_however_it_is_capitalised(tmp_path):
    _import(tmp_path, "microsoft edge")

    edge = _entries()["microsoft edge"]
    assert (edge.vendor, edge.product_id) == ("edge", "Edge")


def test_only_what_was_accepted_is_written(tmp_path):
    _import(tmp_path, "Google Chrome")

    assert list(_entries()) == ["google chrome"]


def test_without_accept_nothing_is_written_and_the_way_to_accept_is_said(tmp_path):
    result, out = _import(tmp_path)

    assert result.exit_code == 0
    assert _entries() == {}
    assert "Nothing was written" in out
    assert "--accept" in out
    assert "which this release does not have" not in out


def test_a_source_without_its_product_is_not_written(tmp_path):
    """MSRC answers for Office, and lists 13 products for one advisory: which
    one this install is has not been stated, so there is nothing to confirm."""
    result, out = _import(tmp_path, "Microsoft Office LTSC Professional Plus 2021")

    assert result.exit_code == 1
    assert _entries() == {}
    assert "not written" in out
    assert "msrc" in out


def test_a_program_no_source_answers_for_is_not_written(tmp_path):
    result, out = _import(tmp_path, "WavePad Sound Editor")

    assert result.exit_code == 1
    assert _entries() == {}
    assert "no source that answers by version" in out


def test_a_name_not_in_the_inventory_is_said_to_be_missing(tmp_path):
    result, out = _import(tmp_path, "Firefox")

    assert result.exit_code == 1
    assert "Firefox" in out and "not in this inventory" in out


def test_one_refusal_does_not_cancel_what_was_confirmed(tmp_path):
    result, out = _import(tmp_path, "Google Chrome", "WavePad Sound Editor")

    assert result.exit_code == 1
    assert list(_entries()) == ["google chrome"]
    assert "Written: 1" in out


def test_a_product_without_a_version_is_watched_and_said_to_have_none(tmp_path):
    result, out = _import(tmp_path, "Google Chrome", programs=(entry("Google Chrome", None, "Google LLC"),))

    assert result.exit_code == 0, result.output
    assert _entries()["google chrome"].installed_version is None
    assert "no version" in out


def test_accepting_again_updates_the_version(tmp_path):
    _import(tmp_path, "Google Chrome")
    _import(tmp_path, "Google Chrome", programs=(entry("Google Chrome", "155.0.8100.12", "Google LLC"),))

    assert _entries()["google chrome"].installed_version == "155.0.8100.12"


def test_a_product_can_be_named_by_any_of_its_registry_entries(tmp_path):
    """Two rows, one product: the survey groups "Google Chrome (x86)" with
    "Google Chrome", and whichever row the person names, the product is Chrome."""
    result, _ = _import(tmp_path, "Google Chrome (x86)",
                        programs=(CHROME, entry("Google Chrome (x86)", "154.0.8037.58", "Google LLC")))

    assert result.exit_code == 0, result.output
    assert list(_entries()) == ["google chrome"]
