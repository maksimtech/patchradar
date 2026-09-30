#!/usr/bin/env python3
"""UTF-8 output for the scripts under scripts/, which run on a local console.

`scripts/release.py` prints a shield emoji in its banner, four lines before it
asks for confirmation. On a Windows console the code page is cp1252 and Python
encodes its output with it, so the release tool ended in UnicodeEncodeError on
its own banner — before the prompt, before the push, on the one script nobody
runs except at release time. `PYTHONIOENCODING=utf-8` worked around it, and
having to know that is the defect: the documented path is
`python3 scripts/release.py`.

The package carries the same helper in `patchradar/cli.py`, and this does not
import it. These scripts have to run in a plain checkout with nothing installed,
which is what a freshly configured machine is, and `patchradar.cli` reaches for
typer and rich at import time. Fifteen duplicated lines are cheaper than a
release tool that needs the package it is about to release.

`tests/test_release_script_encoding.py` measures this copy and the package's
against the same cp1252 stream, so the two cannot drift apart unnoticed.
"""

from __future__ import annotations

import contextlib
import sys


def enable_utf8_output() -> None:
    """Make stdout and stderr accept characters the console cannot encode.

    errors="replace" rather than "strict": a glyph the terminal cannot draw
    should come out as a question mark, never as a traceback.

    Streams that cannot be reconfigured are left alone. pytest's capture and
    anything wrapping a pipe are not TextIOWrapper, and replacing them would
    break whatever is reading them; a cosmetic setting is not worth raising
    over, so this gives up quietly.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding == "utf8":
            continue
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")
