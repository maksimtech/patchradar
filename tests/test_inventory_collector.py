"""
PatchRadar — the collector that writes what `import` reads.

`patchradar import` shipped in 2026.42 documenting its input as "the JSON an
inventory collector writes", and the collector lived on one laptop, in a folder
under Documents, in no repository at all. A command whose input nobody else can
produce is half a feature, and the corpus behind every measurement in the
changelog — 147 registry entries, 109 products — could not be reproduced by
anyone, including from another machine.

`tools/inventory.ps1` is that collector. It is not packaged and not installed: it
is a fixture recorder, run by hand on the machine being surveyed, and the file
boundary in the middle is what lets every judgement live in Python where it can
be tested.

This file tests the seam, which is the part nothing was watching. The two halves
are written in different languages and cannot import each other, so drift between
them is silent: renaming `installedSoftware` in the script, or reading a field
here that it never emits, would leave every existing test passing and `import`
surveying nothing. The assertions are deliberately about the contract and not
about the collection — what the script gathers from Windows cannot be tested off
Windows, and pretending otherwise would be the green check that measures nothing.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import pytest

from patchradar.inventory import read_snapshot, survey

COLLECTOR = pathlib.Path(__file__).resolve().parent.parent / "tools" / "inventory.ps1"

# What `inventory.py` reads: the envelope, and the row fields `classify` touches.
# Kept as literals rather than derived, so that renaming one in Python without
# renaming it in the script fails here instead of silently surveying nothing.
ENVELOPE_KEYS = ("schema", "takenAt", "installedSoftware")
ROW_KEYS = ("name", "version", "publisher")

SCHEMA = "radar.inventory/1"


@pytest.fixture(scope="module")
def script() -> str:
    return COLLECTOR.read_text(encoding="utf-8-sig")


def test_the_collector_is_in_the_repository():
    """The whole point of this file. If this fails, `patchradar import` documents
    an input that nobody can produce."""
    assert COLLECTOR.is_file(), f"{COLLECTOR} is missing"


@pytest.mark.parametrize("key", ENVELOPE_KEYS)
def test_the_collector_emits_every_envelope_key_python_reads(script, key):
    assert re.search(rf"^\s*{key}\s*=", script, re.MULTILINE), (
        f"inventory.py reads {key!r} and inventory.ps1 does not write it"
    )


@pytest.mark.parametrize("key", ROW_KEYS)
def test_the_collector_emits_every_row_field_python_reads(script, key):
    """Inside the installedSoftware block specifically: `name` appears in half
    the script, so finding it anywhere would prove nothing."""
    start = script.index("installedSoftware")
    block = script[start:start + 2000]
    assert re.search(rf"^\s*{key}\s+=", block, re.MULTILINE), (
        f"classify() reads {key!r} from each row and the collector does not emit it"
    )


def test_the_schema_string_is_the_same_on_both_sides(script):
    assert f"'{SCHEMA}'" in script or f'"{SCHEMA}"' in script


def test_the_collector_never_uses_win32_product(script):
    """Enumerating Win32_Product triggers an MSI reconfiguration of every
    installed product — a collector that changes the machine it is measuring.
    The script says so in a comment; this is the part that holds if the comment
    is ever ignored."""
    assert "Win32_Product" not in re.sub(r"#.*", "", script), (
        "Win32_Product enumeration reconfigures every installed MSI"
    )


def test_the_collector_writes_only_its_own_output(script):
    """It runs on a machine under diagnosis, often a broken one, so it may read
    anything and change nothing.

    The forbidden list names verbs and not tools. `pnputil /enum-drivers` is how
    the driver store is read at all — it is the authority that `drivers\\` is not —
    while `pnputil /delete-driver` on the same binary would uninstall a driver
    from the machine being diagnosed. Banning the executable would have banned the
    measurement; the first version of this test did exactly that and had to be
    corrected rather than the script."""
    forbidden = (
        "Set-ItemProperty", "New-ItemProperty", "Remove-ItemProperty",
        "Remove-Item", "Stop-Service", "Start-Service", "Set-Service",
        "Stop-Process", "Restart-Computer", "Set-Content", "Out-File",
        "/delete-driver", "/add-driver", "/install", "/remove-device",
        "/disable-device", "/enable-device", "/restart-device",
    )
    body = re.sub(r"#.*", "", script)
    found = [name for name in forbidden if name.lower() in body.lower()]
    assert not found, f"the collector would change the machine it measures: {found}"


def test_the_collector_reads_the_driver_store_by_enumerating_it(script):
    """The other half of the test above, so that a future edit cannot satisfy it
    by removing the measurement instead of the mutation."""
    assert "/enum-drivers" in script


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell parser is Windows-only here")
def test_the_collector_parses(script):
    """Syntax only, and not a run: the script reads device state, the event log
    and the driver store, which is minutes of work and a machine-specific result.
    A parse error, though, would be found by whoever runs it and not before."""
    checked = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "$e=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile("
         f"'{COLLECTOR}', [ref]$null, [ref]$e); exit $e.Count"],
        capture_output=True, text=True,
    )
    assert checked.returncode == 0, checked.stdout + checked.stderr


def test_a_snapshot_shaped_the_way_the_collector_writes_one_surveys(tmp_path):
    """The contract read forwards: a file with the collector's envelope and one
    row carrying only the fields it emits has to survive read_snapshot and
    survey. Built from the key lists above, so it changes when they do."""
    row = {
        "name": "Google Chrome", "version": "154.0.8037.58",
        "publisher": "Google LLC", "installed": "20260901", "scope": "machine",
        "hive": "HKLM", "location": "C:\\Program Files\\Google\\Chrome",
        "icon": "", "uninstall": "",
    }
    assert set(ROW_KEYS) <= set(row), "the fixture stopped covering what Python reads"
    path = tmp_path / "inventory-20260929-120000.json"
    path.write_text(json.dumps({
        "schema": SCHEMA,
        "takenAt": "2026-09-29T12:00:00.0000000+02:00",
        "elevated": False,
        "installedSoftware": [row],
    }), encoding="utf-8")

    found = survey(read_snapshot(path))

    assert found.rows == 1
    assert found.total == 1
    assert found.families[0].best.installed_version == "154.0.8037.58"


def test_a_snapshot_written_with_a_byte_order_mark_still_reads(tmp_path):
    """PowerShell's `Set-Content -Encoding utf8` writes one, and `json.loads`
    refuses it. This cost four debugging sessions while the corpus was built, so
    the producer's real encoding is pinned rather than remembered."""
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({
        "schema": SCHEMA, "takenAt": "", "installedSoftware": [],
    }).encode("utf-8"))

    assert read_snapshot(path)["schema"] == SCHEMA
