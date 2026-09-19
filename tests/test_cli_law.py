"""Tests for the law check that `patchradar scan` runs."""
import hashlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchradar import cli, law_fetcher

FIXTURE = Path(__file__).parent / "fixtures" / "gdpr_it_excerpt.html"
runner = CliRunner()


def cve(cve_id, severity="MEDIUM", patch=True, confidentiality="NONE"):
    return {
        "id": cve_id, "software": "nginx", "description": "flaw", "cvss_score": 5.0,
        "cvss_version": "3.1", "severity": severity, "published_at": "2026-09-18T10:00:00",
        "source": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "patch_available": patch, "confidentiality_impact": confidentiality,
    }


def _sha(ref):
    text = law_fetcher.parse_articles(FIXTURE.read_text(encoding="utf-8"), ("25", "32"))[ref]
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture
def eurlex(monkeypatch):
    calls = []

    def fake_fetch_html(url, **kwargs):
        calls.append(url)
        return FIXTURE.read_text(encoding="utf-8")

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch_html)
    return calls


def _scan(monkeypatch, nvd, msrc=(), args=("scan", "nginx")):
    async def fake_nvd(target, days_back=7):
        return list(nvd)

    async def fake_msrc(target, days_back=7):
        return list(msrc)

    monkeypatch.setattr(cli, "fetch_cves", fake_nvd)
    monkeypatch.setattr(cli, "msrc_fetch", fake_msrc)
    return runner.invoke(cli.app, list(args))


def test_scan_cites_articles(monkeypatch, eurlex):
    out = _scan(monkeypatch, [
        cve("CVE-2026-1001", severity="CRITICAL"),
        cve("CVE-2026-1002", patch=False),
        cve("CVE-2026-1003", confidentiality="HIGH"),
    ])

    assert out.exit_code == 0, out.output
    assert "Norme applicate" in out.output
    for title, ref, cve_id in [
        ("CVE critiche", "32(2)", "CVE-2026-1001"),
        ("CVE senza patch", "25", "CVE-2026-1002"),
        ("CVE con impatto sui dati personali", "32", "CVE-2026-1003"),
    ]:
        assert title in out.output
        assert f"Norma applicata: GDPR art. {ref}\n" in out.output
        assert f"SHA256: {_sha(ref)}" in out.output
        assert cve_id in out.output
    assert eurlex == ["https://eur-lex.europa.eu/legal-content/IT/TXT/HTML/?uri=CELEX:32016R0679"]


def test_scan_of_whole_watchlist_cites_once(monkeypatch, eurlex):
    runner.invoke(cli.app, ["add", "nginx"])
    runner.invoke(cli.app, ["add", "openssl"])
    out = _scan(monkeypatch, [cve("CVE-2026-1001", severity="CRITICAL")], args=("scan",))

    assert out.output.count("Norma applicata: GDPR art. 32(2)") == 1
    assert len(eurlex) == 1


def test_scan_without_findings_cites_nothing(monkeypatch, eurlex):
    out = _scan(monkeypatch, [cve("CVE-2026-1004")])

    assert "Norma applicata" not in out.output
    assert eurlex == []


def test_msrc_cves_count_too(monkeypatch, eurlex):
    out = _scan(monkeypatch, [], msrc=[cve("CVE-2026-2001", severity="CRITICAL")])
    assert "Norma applicata: GDPR art. 32(2)" in out.output


def test_unknown_patch_status_note(monkeypatch, eurlex):
    out = _scan(monkeypatch, [cve("CVE-2026-1005", severity="CRITICAL", patch=None)])
    assert "1 CVE senza informazioni sulla patch" in out.output


def test_scan_offline_without_cache(monkeypatch):
    # conftest makes every download fail
    out = _scan(monkeypatch, [cve("CVE-2026-1001", severity="CRITICAL")])

    assert out.exit_code == 0
    assert "SHA256: non disponibile" in out.output


def test_law_check_failure_does_not_fail_scan(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("patchradar.law_checker.check", boom)
    out = _scan(monkeypatch, [cve("CVE-2026-1001", severity="CRITICAL")])

    assert out.exit_code == 0
    assert "unexpected" in out.output
    assert "Total: 1" in out.output


def test_cve_markup_in_evidence_is_not_interpreted(monkeypatch, eurlex):
    out = _scan(monkeypatch, [cve("CVE-[bold]x[/bold]", severity="CRITICAL")])
    assert "CVE-[bold]x[/bold]" in out.output
