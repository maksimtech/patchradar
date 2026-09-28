"""
PatchRadar — lo spinner non deve lasciare niente nel buffer di Rich.

Mentre `console.status()` gira, Rich sostituisce `sys.stdout` e `sys.stderr` con
un `FileProxy` che trattiene il testo finché non incontra un newline, e `Live`
ripristina i flussi originali **senza svuotare quel buffer**. Una riga parziale
scritta da una libreria resta lì e viene stampata quando l'interprete finalizza
l'oggetto, quando importare non è più possibile:

    Exception ignored while finalizing file <rich.file_proxy.FileProxy object …>
    ImportError: sys.meta_path is None, Python is likely shutting down

Una scansione riuscita finisce quindi con un traceback, e chi guarda non ha modo
di sapere che il risultato era valido. Osservato su APKRadar con rich 15.0.0 e
Python 3.14.7; qui lo spinner avvolge i tre collector, che parlano in rete.

Il test gira in un sottoprocesso perché la finalizzazione è ciò che si misura, e
dentro il processo di pytest non avverrebbe mai. Serve un `Console` che si crede
un terminale: Rich installa il proxy solo in quel caso, ed è la ragione per cui
in pipe il difetto non si vede.
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
    sys.stdout.write("riga-parziale-senza-newline")
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
    assert "riga-parziale-senza-newline" in proc.stdout
