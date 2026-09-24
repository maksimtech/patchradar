"""Tests for the law check that `patchradar scan` runs."""
import hashlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchradar import cli, law_fetcher

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "gdpr_it_excerpt.html"
NIS2_PAGE = FIXTURES / "nis2_it_excerpt.html"
runner = CliRunner()


def cve(cve_id, severity="MEDIUM", patch=True, confidentiality="NONE"):
    return {
        "id": cve_id, "software": "nginx", "description": "flaw", "cvss_score": 5.0,
        "cvss_version": "3.1", "severity": severity, "published_at": "2026-09-18T10:00:00",
        "source": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "patch_available": patch, "confidentiality_impact": confidentiality,
    }


def _sha(ref, page=FIXTURE):
    text = law_fetcher.parse_articles(page.read_text(encoding="utf-8"), (ref.split("(")[0],))[ref]
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture
def eurlex(monkeypatch):
    calls = []

    def fake_fetch_html(url, **kwargs):
        calls.append(url)
        page = NIS2_PAGE if "32022L2555" in url else FIXTURE
        return page.read_text(encoding="utf-8")

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
    assert "Provisions applied" in out.output
    for title, ref, cve_id in [
        ("Critical CVEs", "32(2)", "CVE-2026-1001"),
        ("CVEs with no patch", "25", "CVE-2026-1002"),
        ("CVEs affecting personal data", "32", "CVE-2026-1003"),
    ]:
        assert title in out.output
        assert f"Provision applied: GDPR art. {ref}\n" in out.output
        assert f"SHA256: {_sha(ref)}" in out.output
        assert cve_id in out.output
    assert eurlex == ["https://publications.europa.eu/resource/celex/32016R0679"]


def test_critical_unpatched_cites_nis2(monkeypatch, eurlex):
    out = _scan(monkeypatch, [cve("CVE-2026-1006", severity="CRITICAL", patch=False)])

    assert "Critical CVEs with no patch" in out.output
    assert "Provision applied: NIS2 dir. 2022/2555 art. 21\n" in out.output
    assert f"SHA256: {_sha('21', NIS2_PAGE)}" in out.output
    assert "essential and important entities" in out.output
    assert eurlex[-1] == "https://publications.europa.eu/resource/celex/32022L2555"


def test_scan_of_whole_watchlist_cites_once(monkeypatch, eurlex):
    runner.invoke(cli.app, ["add", "nginx"])
    runner.invoke(cli.app, ["add", "openssl"])
    out = _scan(monkeypatch, [cve("CVE-2026-1001", severity="CRITICAL")], args=("scan",))

    assert out.output.count("Provision applied: GDPR art. 32(2)") == 1
    assert len(eurlex) == 1


def test_scan_without_findings_cites_nothing(monkeypatch, eurlex):
    out = _scan(monkeypatch, [cve("CVE-2026-1004")])

    assert "Norma applicata" not in out.output
    assert eurlex == []


def test_msrc_cves_count_too(monkeypatch, eurlex):
    out = _scan(monkeypatch, [], msrc=[cve("CVE-2026-2001", severity="CRITICAL")])
    assert "Provision applied: GDPR art. 32(2)" in out.output


def test_unknown_patch_status_note(monkeypatch, eurlex):
    out = _scan(monkeypatch, [cve("CVE-2026-1005", severity="CRITICAL", patch=None)])
    assert "1 CVEs with no patch information" in out.output


def test_scan_offline_without_cache(monkeypatch):
    # conftest makes every download fail
    out = _scan(monkeypatch, [cve("CVE-2026-1001", severity="CRITICAL")])

    assert out.exit_code == 0
    assert "SHA256: not available" in out.output


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
