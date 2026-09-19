"""Tests for mapping PatchRadar findings to GDPR provisions."""
from datetime import datetime, timezone

import pytest

from patchradar import law_fetcher
from patchradar.law_cache import LawCache
from patchradar.law_checker import (
    FINDING_ARTICLES,
    FINDING_TITLES,
    check,
    findings_of,
    notes_of,
)
from patchradar.law_fetcher import GDPR, LawFetchError, Provision

DAY1 = datetime(2026, 9, 19, 14, 0, tzinfo=timezone.utc)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)


def cve(cve_id="CVE-2026-0001", severity="MEDIUM", patch=True, confidentiality="NONE"):
    return {
        "id": cve_id, "software": "nginx", "severity": severity,
        "patch_available": patch, "confidentiality_impact": confidentiality,
    }


def _fake_fetch(suffix=""):
    calls = []

    def fake(act, articles, now=None, **kwargs):
        calls.append((act, articles))
        stamp = law_fetcher.utc_stamp(now)
        refs = {ref for pairs in FINDING_ARTICLES.values() for _, ref in pairs}
        return {
            ref: Provision.from_text(ref, f"testo di {ref}{suffix}", stamp, act.celex)
            for ref in refs if ref.split("(")[0] in articles
        }

    fake.calls = calls
    return fake


@pytest.fixture
def cache(tmp_path):
    return LawCache(tmp_path / "law_cache.json")


@pytest.fixture
def online(monkeypatch):
    fake = _fake_fetch()
    monkeypatch.setattr(law_fetcher, "fetch_provisions", fake)
    return fake.calls


# ─── mapping ──────────────────────────────────────────────────────────────────

def test_mapping():
    assert FINDING_ARTICLES == {
        "critical": ((GDPR, "32(2)"),),
        "unpatched": ((GDPR, "25"),),
        "personal_data": ((GDPR, "32"),),
    }
    assert set(FINDING_TITLES) == set(FINDING_ARTICLES)


def test_harmless_cves_have_no_findings():
    assert findings_of([cve(), cve("CVE-2026-0002", severity="HIGH")]) == {}
    assert findings_of([]) == {}


def test_critical():
    assert findings_of([cve("CVE-2026-0009", severity="critical"), cve()]) == {"critical": ["CVE-2026-0009"]}


def test_unpatched_only_when_known():
    cves = [cve("CVE-2026-0003", patch=False), cve("CVE-2026-0004", patch=None)]
    assert findings_of(cves) == {"unpatched": ["CVE-2026-0003"]}


def test_unknown_patch_status_is_noted():
    assert notes_of([cve(patch=None), cve(patch=None), cve()]) == [
        "2 CVE senza informazioni sulla patch (non ancora analizzate da NVD): non valutate per l'art. 25"
    ]
    assert notes_of([cve()]) == []


def test_personal_data_is_high_confidentiality_impact():
    cves = [cve("CVE-2026-0005", confidentiality="HIGH"), cve("CVE-2026-0006", confidentiality="LOW")]
    assert findings_of(cves) == {"personal_data": ["CVE-2026-0005"]}


def test_findings_in_report_order_and_ids_deduplicated():
    bad = cve("CVE-2026-0007", severity="CRITICAL", patch=False, confidentiality="HIGH")
    assert findings_of([bad, bad]) == {
        "critical": ["CVE-2026-0007"],
        "unpatched": ["CVE-2026-0007"],
        "personal_data": ["CVE-2026-0007"],
    }


def test_malformed_cve_fields_do_not_crash():
    assert findings_of([{"id": None, "severity": None}, {}]) == {}


# ─── check ────────────────────────────────────────────────────────────────────

def test_no_findings_no_download(cache, online):
    assert check([cve()], cache=cache, now=DAY1).citations == []
    assert online == []


def test_citations(cache, online):
    bad = cve("CVE-2026-0007", severity="CRITICAL", patch=False, confidentiality="HIGH")
    law = check([bad], cache=cache, now=DAY1)

    assert [(c.finding, c.law, c.article) for c in law.citations] == [
        ("critical", "GDPR", "32(2)"),
        ("unpatched", "GDPR", "25"),
        ("personal_data", "GDPR", "32"),
    ]
    assert online == [(GDPR, ("32", "25"))]
    assert all(c.sha256 and c.version_date == "2026-09-19" for c in law.citations)
    assert law.evidence["unpatched"] == ["CVE-2026-0007"]


def test_second_audit_changed_text(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch())
    first = check([cve(severity="CRITICAL")], cache=cache, now=DAY1)
    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch(" (rettificato)"))
    law = check([cve(severity="CRITICAL")], cache=cache, now=DAY2)

    assert law.changed == {"GDPR art. 32(2)": first.citations[0].sha256}
    assert law.citations[0].version_date == "2026-10-01"


def test_offline_uses_cache(cache, online, monkeypatch):
    first = check([cve(severity="CRITICAL")], cache=cache, now=DAY1)

    def offline(*args, **kwargs):
        raise LawFetchError("offline")

    monkeypatch.setattr(law_fetcher, "fetch_provisions", offline)
    law = check([cve(severity="CRITICAL")], cache=cache, now=DAY2)

    assert [s.source for s in law.acts] == ["cache"]
    assert law.citations[0].sha256 == first.citations[0].sha256


def test_offline_without_cache(cache):
    law = check([cve(severity="CRITICAL")], cache=cache, now=DAY1)
    assert [s.source for s in law.acts] == ["unavailable"]
    assert law.citations[0].sha256 is None


def test_default_cache_location(tmp_path, online):
    check([cve(severity="CRITICAL")], now=DAY1)
    assert (tmp_path / "patchradar-home" / "law_cache.json").is_file()
