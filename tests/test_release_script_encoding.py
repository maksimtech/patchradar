"""The release tool must not die on its own banner.

`patchradar/cli.py` has had `enable_utf8_output()` since 2026-09-24, and the
scripts under `scripts/` never got it. So the CLI printed its emoji fine on a
Windows console while the documented release path,

    python3 scripts/release.py

ended in `UnicodeEncodeError: 'charmap' codec can't encode character
'\\U0001f6e1'` on the shield in the banner — four lines before the confirmation
prompt, which means before anything was pushed, which is the only good thing
about it. It was reached on 2026-09-30 and worked around with
PYTHONIOENCODING=utf-8 set by hand; the workaround is the defect, because the
next person on the next machine does not know it.

The subprocess tests below answer "n" at the prompt, so they print the banner
and stop: no push, no tag, no commit. They run with PYTHONIOENCODING=cp1252,
which is what a Windows console gives Python, and which the Linux runner
reproduces exactly — the codec ships with Python on every platform.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from patchradar import cli

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

sys.path.insert(0, str(SCRIPTS))

import console_encoding  # noqa: E402

# The character that broke it, plus one cp1252 does have — the fix must not cost
# the second to buy the first.
SHIELD = "\U0001f6e1"
AWKWARD = f"{SHIELD} — città"


def cp1252_stream() -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")


def unencodable_in_cp1252(text: str) -> set[str]:
    return {ch for ch in text if not _encodable(ch)}


def _encodable(char: str) -> bool:
    try:
        char.encode("cp1252")
    except UnicodeEncodeError:
        return False
    return True


# Both copies of the helper, measured against the same cases. scripts/ keeps its
# own because these scripts must run in a checkout with nothing installed; the
# duplication is deliberate, and this is what keeps it honest.
HELPERS = [
    pytest.param(cli.enable_utf8_output, id="patchradar.cli"),
    pytest.param(console_encoding.enable_utf8_output, id="scripts.console_encoding"),
]


@pytest.mark.parametrize("enable", HELPERS)
def test_both_copies_switch_a_cp1252_stream_to_utf8(enable, monkeypatch):
    out, err = cp1252_stream(), cp1252_stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)

    enable()

    sys.stdout.write(AWKWARD)
    sys.stdout.flush()
    assert sys.stdout.buffer.getvalue().decode("utf-8") == AWKWARD
    assert sys.stderr.encoding.lower().replace("-", "") == "utf8"


@pytest.mark.parametrize("enable", HELPERS)
def test_both_copies_leave_a_stream_they_cannot_reconfigure_alone(enable, monkeypatch):
    class Plain:
        encoding = "cp1252"

        def write(self, text):
            return len(text)

    monkeypatch.setattr(sys, "stdout", Plain())
    enable()                                  # must not raise
    assert sys.stdout.encoding == "cp1252"


@pytest.mark.parametrize("enable", HELPERS)
def test_both_copies_leave_a_utf8_stream_untouched(enable, monkeypatch):
    original = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", original)

    enable()

    assert sys.stdout is original


def _scripts() -> list[Path]:
    return sorted(SCRIPTS.glob("*.py"))


@pytest.mark.parametrize("path", _scripts(), ids=lambda p: p.name)
def test_a_script_that_prints_and_holds_an_unprintable_character_enables_utf8_first(path):
    """The rule, deliberately wider than the bug.

    "Prints something cp1252 cannot encode" is not decidable by reading the
    source, so the check is coarser: a script that prints at all and contains a
    character cp1252 has no glyph for must call the helper before its first
    print. Coarse in the safe direction — the cost of a false positive is one
    import line, the cost of a false negative is the release tool refusing to
    run on the machine it is run from.

    An em dash is not caught, and should not be: cp1252 has one at 0x97. The
    emoji is what has no encoding there.
    """
    source = path.read_text(encoding="utf-8")
    if "print(" not in source:
        return
    missing = unencodable_in_cp1252(source)
    if not missing:
        return

    call = source.find("enable_utf8_output()")
    assert call != -1, (
        f"{path.name} prints {sorted(missing)}, which cp1252 cannot encode, "
        "and never calls enable_utf8_output()"
    )
    assert call < source.index("print("), (
        f"{path.name} calls enable_utf8_output() after its first print, "
        "which is too late for everything printed before it"
    )


def _run_declining(script: str) -> subprocess.CompletedProcess[str]:
    """Run a script through its banner and answer no at the prompt.

    Both scripts read `Proceed? [y/N]` and abort on anything that is not "y",
    so "n" reaches the banner and nothing else. cp1252 on the pipe is the
    Windows console, reproduced.
    """
    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script)],
        input="n\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(ROOT),
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize("script", ["release.py", "bump_version.py"])
def test_the_banner_prints_on_a_cp1252_console(script):
    done = _run_declining(script)

    assert "UnicodeEncodeError" not in done.stderr, done.stderr
    assert done.returncode == 0, f"stdout:\n{done.stdout}\nstderr:\n{done.stderr}"
    assert SHIELD in done.stdout, "the banner did not print the character that broke it"
    assert "Aborted." in done.stdout


@pytest.mark.parametrize("script", ["release.py", "bump_version.py"])
def test_declining_changes_nothing(script):
    """The safety the two tests above rely on, asserted rather than assumed.

    If a future edit moved a prompt below the first action, these tests would
    start pushing tags and rewriting the version, and this is what would say so
    first: pyproject.toml is what bump_version.py writes, and `$ git` is what
    release.py echoes before it runs anything.
    """
    pyproject = ROOT / "pyproject.toml"
    before = pyproject.read_text(encoding="utf-8")

    done = _run_declining(script)

    assert pyproject.read_text(encoding="utf-8") == before
    assert "$ git" not in done.stdout          # release.py echoes before running
    assert "Git commit" not in done.stdout     # bump_version.py prints after
    assert "gh release create" not in done.stdout
