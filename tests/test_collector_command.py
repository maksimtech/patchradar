"""`patchradar collector` hands over the script, because `pip install` could not.

The machine worth surveying is by definition the one without a checkout: no git, no
development folder, often no Python until you put it there. Until now the collector
lived in `tools/inventory.ps1` and shipped in the sdist and not in the wheel —
checked against the published 2026.43 on 2026-10-04, 29 files in the wheel and not
one `.ps1` — so the README's "run it by hand, from the checkout" asked for something
that machine does not have.

So the script moved inside the package, where it ships with it, and this command
writes it out.

It writes a file rather than printing to stdout, and that is not a preference. In
Windows PowerShell 5.1 `>` encodes UTF-16LE, so `patchradar collector > inventory.ps1`
would produce a file PowerShell itself cannot parse — on the one platform this
script exists for. `--stdout` is there for a shell that does not do that.

Refusing to overwrite is the other half: the file this command writes is the file
the operator is about to run elevated on a machine under diagnosis, and silently
replacing something already at that path is not a thing to do quietly.
"""

from __future__ import annotations

import importlib.resources

from typer.testing import CliRunner

from patchradar.cli import app

runner = CliRunner()

PACKAGED = importlib.resources.files("patchradar") / "data" / "inventory.ps1"


def test_the_script_travels_with_the_package():
    """The invariant that makes the command possible, and it holds in a checkout
    and in a wheel alike: the package can find its own collector."""
    assert PACKAGED.is_file()
    assert PACKAGED.read_text(encoding="utf-8").lstrip().startswith("<#")


def test_it_writes_the_script_next_to_you(tmp_path):
    target = tmp_path / "inventory.ps1"

    outcome = runner.invoke(app, ["collector", "--output", str(target)])

    assert outcome.exit_code == 0, outcome.output
    assert target.read_text(encoding="utf-8") == PACKAGED.read_text(encoding="utf-8")


def test_what_it_writes_is_what_ships_byte_for_byte(tmp_path):
    """Not "a copy of": the same bytes. A collector that differs from the one the
    contract tests check is a collector nothing has checked."""
    target = tmp_path / "inventory.ps1"

    runner.invoke(app, ["collector", "--output", str(target)])

    assert target.read_bytes() == PACKAGED.read_bytes()


def test_it_says_how_to_run_what_it_just_wrote(tmp_path):
    """Three things trip up a clean machine, and none of them is the script:
    Unblock-File, the execution policy, and administrator rights."""
    outcome = runner.invoke(app, ["collector", "--output", str(tmp_path / "x.ps1")])

    said = outcome.output
    assert "Unblock-File" in said
    assert "ExecutionPolicy" in said
    assert "administrator" in said.lower()
    assert "patchradar import" in said


def test_it_refuses_to_overwrite(tmp_path):
    target = tmp_path / "inventory.ps1"
    target.write_text("il mio script, non il vostro\n", encoding="utf-8")

    outcome = runner.invoke(app, ["collector", "--output", str(target)])

    assert outcome.exit_code != 0
    assert target.read_text(encoding="utf-8") == "il mio script, non il vostro\n"
    assert "--force" in outcome.output


def test_force_overwrites_and_says_nothing_clever(tmp_path):
    target = tmp_path / "inventory.ps1"
    target.write_text("vecchio\n", encoding="utf-8")

    outcome = runner.invoke(app, ["collector", "--output", str(target), "--force"])

    assert outcome.exit_code == 0, outcome.output
    assert target.read_bytes() == PACKAGED.read_bytes()


def test_stdout_is_available_for_a_shell_that_can_take_it(tmp_path):
    """For bash, or PowerShell 7 with `Out-File -Encoding utf8`. The default is a
    file precisely because Windows PowerShell 5.1's `>` cannot."""
    outcome = runner.invoke(app, ["collector", "--stdout"])

    assert outcome.exit_code == 0
    assert outcome.output.lstrip().startswith("<#")
    assert "Unblock-File" not in outcome.output.split(".SYNOPSIS")[0]


def test_the_default_output_is_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    outcome = runner.invoke(app, ["collector"])

    assert outcome.exit_code == 0, outcome.output
    assert (tmp_path / "inventory.ps1").is_file()


# `tests/test_inventory_collector.py` asserts that the collector writes every field
# `inventory.py` reads, and it reads the collector through the same
# `importlib.resources` path this command does — so the contract is about the file an
# operator is handed, by construction. A test asserting that two paths agree stood
# here until `test_every_test_import_is_declared` refused the `from tests.` import it
# needed, which was the better answer: the guarantee belongs in how both find the
# file, not in a third test watching them.
