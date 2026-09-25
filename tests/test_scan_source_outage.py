"""One source down for the whole scan looks like sixteen unrelated hiccups.

On a 16-entry watchlist with NVD refusing every request, the scan printed:

    ⚠️  NVD http_error (HTTP 404) — results for intel management engine are incomplete
    ⚠️  NVD http_error (HTTP 404) — results for lenovo thinkpad are incomplete
    … fourteen more …

     Total: 33 CVEs found

Each line is true, and together they tell the reader almost nothing: the natural
reading is that NVD is having a bad afternoon. What actually happened is that one
of the two sources answered for nobody, and every one of those 33 CVEs came from
MSRC alone. With a key added and the windows fixed the count was 131.

The difference matters because the totals invite a conclusion. "33 CVEs" with a
warning per line reads as a scan; "33 CVEs, all from MSRC, because NVD answered
for none of the 16 targets" reads as half a scan, which is what it was.

So the per-target lines stay — they are the truth about each target — and the
scan now says at the end which sources were silent throughout. An isolated
failure must not produce that line, or it would mean nothing in the case it is
for.
"""

from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

import patchradar.cli as cli
from patchradar.collectors.errors import CollectorError


def a_cve(cve_id: str, source: str) -> dict:
    return {
        "id": cve_id,
        "software": "nginx",
        "description": "d",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "source": source,
    }


@pytest.fixture
def scanning(monkeypatch):
    """Run `patchradar scan` over several targets with both sources stubbed.

    `behaviour` maps a target to what each source does for it: a list of CVEs,
    or a CollectorError to raise.
    """
    def run(targets, nvd_for, msrc_for):
        async def fake_nvd(target, days_back=7):
            outcome = nvd_for(target)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        async def fake_msrc(target, days_back=7):
            outcome = msrc_for(target)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        monkeypatch.setattr(cli, "fetch_cves", fake_nvd)
        monkeypatch.setattr(cli, "msrc_fetch", fake_msrc)
        monkeypatch.setattr(cli, "save_cve", _no_save)
        monkeypatch.setattr(cli, "get_watchlist", _watchlist(targets))
        monkeypatch.setattr(cli, "_law_check", lambda *a, **kw: None)
        monkeypatch.setattr(cli, "_print_law_check", lambda *a, **kw: None)

        buf = StringIO()
        monkeypatch.setattr(
            cli, "console", Console(file=buf, width=300, force_terminal=False)
        )
        cli.scan(software=None, days=7)
        return buf.getvalue()
    return run


async def _no_save(cve):
    return None


def _watchlist(targets):
    async def get():
        return list(targets)
    return get


TARGETS = ["nginx", "openssl", "curl"]


def down(_target):
    return CollectorError("NVD", "http_error", status=404)


def test_a_source_silent_for_every_target_is_said_once(scanning):
    out = scanning(TARGETS, nvd_for=down, msrc_for=lambda t: [a_cve(f"CVE-{t}", "MSRC")])

    assert "NVD" in out
    assert "none of the 3" in out or "all 3" in out, out


def test_the_summary_names_the_source_that_did_answer(scanning):
    """So the reader knows what the totals are made of."""
    out = scanning(TARGETS, nvd_for=down, msrc_for=lambda t: [a_cve(f"CVE-{t}", "MSRC")])
    summary = out.split("Total:")[1]

    assert "MSRC" in summary or "MSRC" in out.split("no CVEs")[0]


def test_an_isolated_failure_gets_no_such_summary(scanning):
    """One target out of three is the case the per-target line already covers."""
    def one_bad(target):
        return down(target) if target == "openssl" else [a_cve("CVE-OK", "NVD")]

    out = scanning(TARGETS, nvd_for=one_bad, msrc_for=lambda t: [])

    assert "openssl" in out
    assert "none of the 3" not in out


def test_a_clean_scan_says_nothing_about_outages(scanning):
    out = scanning(TARGETS, nvd_for=lambda t: [], msrc_for=lambda t: [])

    assert "none of the" not in out
    assert "no CVEs found" in out


def test_both_sources_down_is_not_reported_as_a_result(scanning):
    """Zero CVEs from zero working sources is not a finding of zero CVEs."""
    out = scanning(
        TARGETS,
        nvd_for=down,
        msrc_for=lambda t: CollectorError("MSRC", "server_error", status=500),
    )

    assert "no CVEs found" not in out
    assert "NVD" in out and "MSRC" in out


def test_the_per_target_lines_are_still_there(scanning):
    """The summary is in addition to them, not instead: which target failed is
    the thing you act on."""
    out = scanning(TARGETS, nvd_for=down, msrc_for=lambda t: [])

    for target in TARGETS:
        assert target in out


def test_a_single_target_scan_needs_no_summary(scanning):
    """With one target there is nothing to generalise from, and the per-target
    line has already said it."""
    out = scanning(["nginx"], nvd_for=down, msrc_for=lambda t: [])

    assert "none of the 1" not in out


def test_a_keyless_rate_limit_points_at_the_remedy(scanning):
    """403 and 429 from NVD are usually the keyless quota, and the user can fix
    that themselves — but only if told how."""
    out = scanning(
        TARGETS,
        nvd_for=lambda t: CollectorError("NVD", "forbidden", status=403),
        msrc_for=lambda t: [],
    )

    assert "NVD_API_KEY" in out


def test_the_remedy_is_not_suggested_to_someone_who_took_it(scanning, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "abcd-1234")
    out = scanning(
        TARGETS,
        nvd_for=lambda t: CollectorError("NVD", "forbidden", status=403),
        msrc_for=lambda t: [],
    )

    assert "NVD_API_KEY" not in out


def test_an_unrelated_failure_gets_no_key_advice(scanning, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    out = scanning(
        TARGETS,
        nvd_for=lambda t: CollectorError("NVD", "network", detail="ConnectTimeout"),
        msrc_for=lambda t: [],
    )

    assert "NVD_API_KEY" not in out
