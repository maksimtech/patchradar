"""
PatchRadar — the spinner must leave nothing in Rich's buffer.

While `console.status()` runs, Rich replaces `sys.stdout` and `sys.stderr` with a
`FileProxy` that holds text until it meets a newline. `Live` puts the original
streams back **without flushing that buffer**: a partial line written by a library
stays there, and is printed only when the interpreter finalises the object, at a
point where importing is no longer possible:

    Exception ignored while finalizing file <rich.file_proxy.FileProxy object …>
    ImportError: sys.meta_path is None, Python is likely shutting down

A successful scan therefore ends in a traceback, and whoever is watching has no
way of knowing the result was valid. Observed on APKRadar with rich 15.0.0 and
Python 3.14.7; here the spinner wraps the three collectors, which speak over the
network.

The test runs in a subprocess because finalisation is the thing being measured,
and inside pytest's own process it would never happen. It needs a `Console` that
believes it is a terminal: Rich installs the proxy only in that case, which is why
the defect cannot be seen through a pipe.
"""
import subprocess
import sys

_SHUTDOWN_SCRIPT = """
import sys
from unittest.mock import patch

import typer
from rich.console import Console

import patchradar.cli as cli


async def noisy_fetch(target, **kwargs):
    # Un collector che tiene un riferimento a sys.stdout mantiene vivo il
    # FileProxy di Rich oltre la fine dello spinner, con la riga parziale dentro.
    global held_stdout
    held_stdout = sys.stdout
    sys.stdout.write("partial-line-without-newline")
    return []


async def quiet_fetch(target, **kwargs):
    return []


with patch.object(cli, "fetch_cves", noisy_fetch), \\
     patch.object(cli, "msrc_fetch", quiet_fetch), \\
     patch.object(cli, "kev_fetch", quiet_fetch), \\
     patch.object(cli, "_law_check", lambda *a, **k: None), \\
     patch.object(cli, "console", Console(force_terminal=True, width=250)):
    try:
        cli.app(["scan", "windows"], standalone_mode=False)
    except typer.Exit:
        pass
"""


def test_scan_leaves_nothing_in_the_proxy_buffer():
    proc = subprocess.run(
        [sys.executable, "-c", _SHUTDOWN_SCRIPT],
        capture_output=True, text=True, timeout=120,
        encoding="utf-8", errors="replace",
    )

    assert proc.returncode == 0, proc.stderr
    assert "sys.meta_path is None" not in proc.stderr
    assert "Exception ignored" not in proc.stderr
    # E la riga parziale non va persa: svuotare il buffer significa stamparla,
    # non buttarla. Una correzione che la scartasse passerebbe i due controlli
    # sopra e nasconderebbe l'output di un collector.
    assert "partial-line-without-newline" in proc.stdout
