"""Benchmarks for the Rich table rendering used by the CLI output."""

import io

import pytest
from rich.console import Console

from patchradar import cli


@pytest.fixture
def quiet_console(monkeypatch):
    """Render to an in-memory buffer instead of the terminal."""
    console = Console(file=io.StringIO(), width=140, force_terminal=True)
    monkeypatch.setattr(cli, "console", console)
    return console


def test_print_cves(benchmark, quiet_console, cve_records):
    """`patchradar scan` output: wrapped descriptions and per-row styling."""
    benchmark(lambda: cli._print_cves("proxmox", cve_records))

    assert quiet_console.file.getvalue()


def test_print_cves_table(benchmark, quiet_console, cve_records):
    """`patchradar status` output: compact table over the latest CVEs."""
    benchmark(lambda: cli._print_cves_table(cve_records))

    assert quiet_console.file.getvalue()
