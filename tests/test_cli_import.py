"""
PatchRadar — `import` reads a snapshot and writes nothing.

The command exists to size the work before any migration: on the machine it was
written against, 147 registry entries are 109 products, and only five of those
have a vendor source that answers by version. Knowing that number before
designing the watchlist columns is the whole point.

It must also stay harmless. The one thing worse than not importing is importing
silently: a watchlist built from guesses looks exactly like one built from facts.
"""
from __future__ import annotations

import json

from typer.testing import CliRunner

from patchradar.cli import app

runner = CliRunner()


def snapshot_file(tmp_path, *programs) -> str:
    path = tmp_path / "cavia.json"
    path.write_text(json.dumps({
        "schema": "radar.inventory/1",
        "takenAt": "2026-09-27T21:15:42.0000000+02:00",
        "installedSoftware": list(programs),
    }), encoding="utf-8")
    return str(path)


def entry(name: str, version: str = "1.0", publisher: str = "") -> dict:
    return {"name": name, "version": version, "publisher": publisher, "hive": "HKLM"}


def test_the_counts_are_printed(tmp_path):
    path = snapshot_file(tmp_path,
                         entry("Google Chrome", "154.0.8037.58", "Google LLC"),
                         entry("WavePad Sound Editor", "5.99", "NCH Software"))
    result = runner.invoke(app, ["import", path])

    assert result.exit_code == 0, result.output
    assert "2 products" in result.output
    assert "watchable by version" in result.output


def test_it_says_that_nothing_was_written(tmp_path):
    """A report that looks like an import is worse than no import."""
    result = runner.invoke(app, ["import", snapshot_file(tmp_path, entry("X"))])

    assert "Nothing was written" in result.output


def test_the_products_and_the_entries_are_two_numbers(tmp_path):
    """24 of the machine's rows are one Python install. A single total would say
    24 products where there is one."""
    path = snapshot_file(tmp_path,
                         entry("Python 3.14.7 (64-bit)", "3.14.7", "Python Software Foundation"),
                         entry("Python 3.14.7 Core Interpreter (64-bit)", "3.14.7",
                               "Python Software Foundation"),
                         entry("Python 3.14.7 Test Suite (64-bit debug)", "3.14.7",
                               "Python Software Foundation"))
    result = runner.invoke(app, ["import", path])

    assert "1 products in 3 registry entries" in result.output


def test_a_missing_file_is_refused_with_an_exit_code(tmp_path):
    result = runner.invoke(app, ["import", str(tmp_path / "nope.json")])

    assert result.exit_code == 2
    assert "no such file" in result.output


def test_a_file_that_is_not_an_inventory_is_refused(tmp_path):
    path = tmp_path / "altro.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")

    result = runner.invoke(app, ["import", str(path)])

    assert result.exit_code == 2
    assert "not an inventory" in result.output
