"""
PatchRadar — CLI output escaping (G3 + G4)

Every string that reaches the terminal originates outside the process: CVE
descriptions come from NVD/MSRC/Debian, software names come from the user or
from POST /api/watchlist/import. Rich interprets ``[...]`` as markup, so those
strings must be rendered verbatim — never parsed.

Two distinct failure modes are covered here:

* G4 — legitimate CVE text crashes or is silently corrupted. Unix paths
  (``[/tmp]``) raise MarkupError; bibliography refs (``[i]``, ``[1]``) are
  swallowed because they happen to name a real Rich style.
* G3 — hostile text forges the output: applying colours, or planting a
  clickable OSC-8 hyperlink in a security tool.
"""
from io import StringIO

import pytest
from rich.console import Console

import patchradar.cli as cli


def render(fn, *args, **kwargs) -> str:
    """Run a renderer against a captured console and return the plain text."""
    buf = StringIO()
    # width=400 keeps short fixtures on a single line so literal substring
    # assertions are not defeated by column wrapping.
    console = Console(file=buf, width=400, force_terminal=False, legacy_windows=False)
    original = cli.console
    cli.console = console
    try:
        fn(*args, **kwargs)
    finally:
        cli.console = original
    return buf.getvalue()


def render_ansi(fn, *args, **kwargs) -> str:
    """Same, but with ANSI emission on, to prove no style was applied."""
    buf = StringIO()
    console = Console(file=buf, width=400, force_terminal=True, legacy_windows=False, color_system="truecolor")
    original = cli.console
    cli.console = console
    try:
        fn(*args, **kwargs)
    finally:
        cli.console = original
    return buf.getvalue()


def make_cve(**overrides) -> dict:
    cve = {
        "id": "CVE-2026-00001",
        "software": "nginx",
        "description": "A benign description.",
        "cvss_score": 5.0,
        "cvss_version": "3.1",
        "severity": "LOW",
        "source": "NVD",
        "url": "https://example.invalid",
    }
    cve.update(overrides)
    return cve


# ─── G4: legitimate CVE text must not crash or be corrupted ──────────────────

@pytest.mark.parametrize(
    "description",
    [
        "see [1] and [/tmp] path",           # unmatched closing tag -> MarkupError
        "writes to [/etc/passwd] on boot",   # ditto, very common in CVE text
        "the [/var] mount is affected",
    ],
)
def test_print_cves_survives_unmatched_closing_tag(description):
    """Unix paths in brackets must not blow up the scan."""
    render(cli._print_cves, "nginx", [make_cve(description=description)])


@pytest.mark.parametrize(
    "fragment",
    [
        "[i]",      # italic  — silently swallowed today
        "[1]",      # bibliography ref
        "[b]",      # bold
        "[0]",      # array index
    ],
)
def test_print_cves_preserves_bracketed_text(fragment):
    """Bracketed fragments are data, not styling: they must survive verbatim."""
    out = render(cli._print_cves, "nginx", [make_cve(description=f"the {fragment} parameter")])
    assert fragment in out, f"{fragment!r} was consumed as markup instead of printed"


def test_print_cves_handles_missing_description():
    """A collector may yield description=None (Debian does); must not crash."""
    render(cli._print_cves, "nginx", [make_cve(description=None)])


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, ""),
        ("", ""),
        ("short", "short"),
        ("A" * 120, "A" * 120),           # exactly at the limit: untouched
        ("A" * 121, "A" * 120 + "..."),   # one over: truncated
    ],
)
def test_truncate_contract(value, expected):
    """Truncation must be total: None is data too, and must not raise."""
    assert cli._truncate(value, 120) == expected


def test_print_cves_truncates_long_description():
    out = render(cli._print_cves, "nginx", [make_cve(description="A" * 500)])
    assert "A" * 200 not in out


# ─── G3: hostile text must not forge the output ──────────────────────────────

def test_print_cves_does_not_apply_injected_style():
    """A CVE description cannot colour itself."""
    payload = "harmless [red]INJECTED[/red] tail"
    out = render(cli._print_cves, "nginx", [make_cve(description=payload)])
    assert "[red]" in out and "[/red]" in out, "injected style tags were interpreted"


def test_print_cves_emits_no_injected_ansi():
    """The same payload must not reach the terminal as a real ANSI colour."""
    payload = "harmless [red]INJECTED[/red] tail"
    out = render_ansi(cli._print_cves, "nginx", [make_cve(description=payload, severity="LOW")])
    assert "\x1b[31m" not in out, "injected [red] produced a real ANSI colour escape"


def test_print_cves_no_hyperlink_injection():
    """A hostile description must not plant a clickable link in a security tool."""
    payload = "click [link=https://evil.invalid]HERE[/link] now"
    out = render_ansi(cli._print_cves, "nginx", [make_cve(description=payload)])
    assert "\x1b]8;" not in out, "injected [link=...] produced an OSC-8 hyperlink"


def test_print_cves_title_escapes_software_name():
    """The software name is interpolated into the table title markup."""
    out = render(cli._print_cves, "evil[bold]x", [make_cve()])
    assert "evil[bold]x" in out


@pytest.mark.parametrize(
    "field, payload",
    [
        ("id", "a[bold]b"),
        ("software", "a[bold]b"),
        # the Source column is width=6, so the payload has to fit inside it
        ("source", "x[b]y"),
    ],
)
def test_print_cves_table_escapes_every_field(field, payload):
    """Each column of the status table renders its value verbatim."""
    out = render(cli._print_cves_table, [make_cve(**{field: payload})])
    assert payload in out


def test_print_cves_table_survives_unmatched_tag_in_field():
    render(cli._print_cves_table, [make_cve(id="CVE-[/x]-1")])


def test_print_cves_escapes_id_column():
    out = render(cli._print_cves, "nginx", [make_cve(id="CVE-[red]-9")])
    assert "CVE-[red]-9" in out


# ─── G3: the plain console.print() call sites ────────────────────────────────

MARKUP_NAME = "evil[bold]x"


def test_cli_add_escapes_software_name(monkeypatch):
    async def fake_add(name):
        return True

    monkeypatch.setattr(cli, "add_to_watchlist", fake_add)
    out = render(cli.add, MARKUP_NAME)
    assert MARKUP_NAME in out


def test_cli_add_escapes_on_duplicate(monkeypatch):
    async def fake_add(name):
        return False

    monkeypatch.setattr(cli, "add_to_watchlist", fake_add)
    out = render(cli.add, MARKUP_NAME)
    assert MARKUP_NAME in out


def test_cli_remove_escapes_software_name(monkeypatch):
    async def fake_remove(name):
        return True

    monkeypatch.setattr(cli, "remove_from_watchlist", fake_remove)
    out = render(cli.remove, MARKUP_NAME)
    assert MARKUP_NAME in out


def test_cli_remove_escapes_on_missing(monkeypatch):
    async def fake_remove(name):
        return False

    monkeypatch.setattr(cli, "remove_from_watchlist", fake_remove)
    out = render(cli.remove, MARKUP_NAME)
    assert MARKUP_NAME in out


def test_cli_list_escapes_watchlist_entries(monkeypatch):
    async def fake_watchlist():
        return [MARKUP_NAME, "nginx"]

    monkeypatch.setattr(cli, "get_watchlist", fake_watchlist)
    out = render(cli.list_watchlist)
    assert MARKUP_NAME in out


def test_scan_target_escapes_target_in_empty_message(monkeypatch):
    """The 'no CVEs found' line interpolates the target into markup."""
    async def no_cves(target, days_back=7):
        return []

    monkeypatch.setattr(cli, "fetch_cves", no_cves)
    monkeypatch.setattr(cli, "msrc_fetch", no_cves)

    def call():
        cli.run(cli._scan_target(MARKUP_NAME, 7))

    out = render(call)
    assert MARKUP_NAME in out


def test_scan_target_survives_unmatched_tag_in_target(monkeypatch):
    """A watchlist entry containing [/x] must not crash the scan spinner."""
    async def no_cves(target, days_back=7):
        return []

    monkeypatch.setattr(cli, "fetch_cves", no_cves)
    monkeypatch.setattr(cli, "msrc_fetch", no_cves)

    def call():
        cli.run(cli._scan_target("bad[/x]name", 7))

    out = render(call)
    assert "bad[/x]name" in out
