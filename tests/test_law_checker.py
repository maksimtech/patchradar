"""Tests for mapping PatchRadar findings to GDPR provisions."""
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from patchradar import law_fetcher
from patchradar.law_cache import LawCache
from patchradar.law_checker import (
    FINDING_ARTICLES,
    FINDING_TITLES,
    NIS2_SCOPE_NOTE,
    check,
    findings_of,
    notes_of,
)
from patchradar.law_fetcher import DLGS_138_2024, GDPR, LawFetchError, Provision

DAY1 = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)


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
        }, "Cellar"

    fake.calls = calls
    return fake


@pytest.fixture
def cache(tmp_path):
    return LawCache(tmp_path / "law_cache.json")


@pytest.fixture
def online(monkeypatch):
    fake = _fake_fetch()
    monkeypatch.setattr(law_fetcher, "fetch_provisions_from", fake)
    return fake.calls


# ─── mapping ──────────────────────────────────────────────────────────────────

def test_mapping():
    assert FINDING_ARTICLES == {
        "critical": ((GDPR, "32(2)"),),
        "unpatched": ((GDPR, "25"),),
        "critical_unpatched": ((DLGS_138_2024, "24"),),
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
        "2 CVEs with no patch information (not yet analysed by NVD): "
        "not assessed against GDPR art. 25 or D.Lgs. 138/2024 art. 24"
    ]
    assert notes_of([cve()]) == []


def test_critical_unpatched_needs_both():
    cves = [
        cve("CVE-2026-0010", severity="CRITICAL", patch=False),
        cve("CVE-2026-0011", severity="CRITICAL", patch=True),
        cve("CVE-2026-0012", severity="CRITICAL", patch=None),
        cve("CVE-2026-0013", severity="HIGH", patch=False),
    ]
    assert findings_of(cves)["critical_unpatched"] == ["CVE-2026-0010"]


def test_nis2_scope_is_noted_only_when_nis2_is_cited():
    assert notes_of([cve(severity="CRITICAL", patch=False)]) == [NIS2_SCOPE_NOTE]
    assert notes_of([cve(severity="CRITICAL"), cve(patch=False)]) == []
    assert "essential and important entities" in NIS2_SCOPE_NOTE


def test_personal_data_is_high_confidentiality_impact():
    cves = [cve("CVE-2026-0005", confidentiality="HIGH"), cve("CVE-2026-0006", confidentiality="LOW")]
    assert findings_of(cves) == {"personal_data": ["CVE-2026-0005"]}


def test_findings_in_report_order_and_ids_deduplicated():
    bad = cve("CVE-2026-0007", severity="CRITICAL", patch=False, confidentiality="HIGH")
    assert findings_of([bad, bad]) == {
        "critical": ["CVE-2026-0007"],
        "unpatched": ["CVE-2026-0007"],
        "critical_unpatched": ["CVE-2026-0007"],
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
        ("critical_unpatched", "D.Lgs. 138/2024", "24"),
        ("personal_data", "GDPR", "32"),
    ]
    assert online == [(GDPR, ("32", "25")), (DLGS_138_2024, ("24",))]
    assert [s.source for s in law.acts] == ["verified", "verified"]
    assert NIS2_SCOPE_NOTE in law.notes
    assert all(c.sha256 and c.version_date == "2026-09-19" for c in law.citations)
    assert law.evidence["unpatched"] == ["CVE-2026-0007"]


def test_second_audit_changed_text(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions_from", _fake_fetch())
    first = check([cve(severity="CRITICAL")], cache=cache, now=DAY1)
    monkeypatch.setattr(law_fetcher, "fetch_provisions_from", _fake_fetch(" (rettificato)"))
    law = check([cve(severity="CRITICAL")], cache=cache, now=DAY2)

    assert law.changed == {"GDPR art. 32(2)": first.citations[0].sha256}
    assert law.citations[0].version_date == "2026-10-01"


def test_offline_uses_cache(cache, online, monkeypatch):
    first = check([cve(severity="CRITICAL")], cache=cache, now=DAY1)

    def offline(*args, **kwargs):
        raise LawFetchError("offline")

    monkeypatch.setattr(law_fetcher, "fetch_provisions_from", offline)
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


# ─── a cited reference must be in the text downloaded now ────────────────────
# Cellar is answered at the HTTP boundary with the recorded GDPR page
# (fixtures/gdpr_it_excerpt.html), or with a page derived from it: paragraph 2
# of article 32 renamed out of the ELI paragraph ids, so that the article still
# parses and the paragraph cited for a critical CVE is not in it.

GDPR_PAGE = (Path(__file__).parent / "fixtures" / "gdpr_it_excerpt.html").read_text(encoding="utf-8")
GDPR_PAGE_WITHOUT_32_2_DERIVED = GDPR_PAGE.replace('id="032.002"', 'id="032.002-derived"')
REAL_FETCH_HTML = law_fetcher.fetch_html


def _cellar(page: str | None) -> httpx.Client:
    """Cellar answering `page` for the GDPR, or nothing at all (503) when None;
    EUR-Lex, the fallback, answering 503 as well."""
    def answer(request: httpx.Request) -> httpx.Response:
        if page is not None and str(request.url) == "https://publications.europa.eu/resource/celex/32016R0679":
            return httpx.Response(200, text=page)
        return httpx.Response(503)

    return httpx.Client(transport=httpx.MockTransport(answer))


@pytest.fixture
def real_fetch(monkeypatch):
    """conftest disables fetch_html so that no test reaches the network; the
    client passed here answers only from the recording, so the real one goes back."""
    monkeypatch.setattr(law_fetcher, "fetch_html", REAL_FETCH_HTML)


def test_the_derived_page_lacks_only_the_paragraph_cited():
    """What the tests below rely on."""
    assert FINDING_ARTICLES["critical"] == ((GDPR, "32(2)"),)
    assert GDPR_PAGE_WITHOUT_32_2_DERIVED != GDPR_PAGE
    texts = law_fetcher.parse_articles(GDPR_PAGE_WITHOUT_32_2_DERIVED, ("32",))
    assert "32(1)" in texts and "32(2)" not in texts


def test_a_paragraph_missing_from_the_fresh_text_is_not_verified(real_fetch, cache):
    """Cellar answered and article 32 parsed, but paragraph 2 was not in it: the
    act used to be "verified against Cellar" beside "SHA256: not available"."""
    law = check([cve(severity="CRITICAL")], cache=cache, now=DAY1, client=_cellar(GDPR_PAGE_WITHOUT_32_2_DERIVED))

    [status] = law.acts
    assert status.source == "unavailable", status
    assert "32(2)" in (status.error or "")
    assert law.citations[0].sha256 is None


def test_a_cached_paragraph_is_not_served_as_verified(real_fetch, cache):
    """The same, with the paragraph cached by an earlier audit: its old SHA-256
    and date came back under the "verified" label."""
    first = check([cve(severity="CRITICAL")], cache=cache, now=DAY1, client=_cellar(GDPR_PAGE))
    assert [s.source for s in first.acts] == ["verified"]
    assert first.citations[0].sha256 is not None

    law = check([cve(severity="CRITICAL")], cache=cache, now=DAY2, client=_cellar(GDPR_PAGE_WITHOUT_32_2_DERIVED))

    [status] = law.acts
    assert status.source == "cache", status
    assert law.citations[0].sha256 == first.citations[0].sha256
    assert law.citations[0].version_date == "2026-09-19"


# ─── statuses name the source that was tried ─────────────────────────────────

def test_a_status_says_the_source_answered_without_the_text(real_fetch, cache):
    """The CLI printed "EUR-Lex unreachable" for this: Cellar was reached, and
    only the paragraph cited was missing from its page."""
    check([cve(severity="CRITICAL")], cache=cache, now=DAY1, client=_cellar(GDPR_PAGE))
    [status] = check(
        [cve(severity="CRITICAL")], cache=cache, now=DAY2, client=_cellar(GDPR_PAGE_WITHOUT_32_2_DERIVED)
    ).acts

    assert (status.source, status.tried, status.failure) == ("cache", "Cellar", "not_in_text")
    assert status.reason == "Cellar answered without the text cited"


def test_a_status_names_both_sources_when_neither_answered(real_fetch, cache):
    [status] = check([cve(severity="CRITICAL")], cache=cache, now=DAY1, client=_cellar(None)).acts

    assert (status.source, status.tried, status.failure) == ("unavailable", "Cellar and EUR-Lex", "unreachable")
    assert status.reason == "Cellar and EUR-Lex unreachable"


def test_a_verified_status_has_no_reason(real_fetch, cache):
    [status] = check([cve(severity="CRITICAL")], cache=cache, now=DAY1, client=_cellar(GDPR_PAGE)).acts

    assert (status.source, status.tried, status.failure, status.reason) == ("verified", None, None, None)


# ─── a cache that cannot be written ──────────────────────────────────────────

@pytest.fixture
def read_only_cache(cache):
    """Call it after a first audit: it makes `cache` read-only, the file (what
    stops os.replace on Windows) and its folder (what stops it on POSIX)."""
    import os
    import stat

    def freeze():
        cache.path.chmod(stat.S_IREAD)
        cache.path.parent.chmod(stat.S_IREAD | stat.S_IEXEC)
        try:
            cache.update({}, checked_at="2026-10-01T09:30:00Z")
        except OSError:
            return
        pytest.skip("this user can write a read-only file (root?)")

    yield freeze
    os.chmod(cache.path.parent, stat.S_IRWXU)
    if cache.path.exists():
        os.chmod(cache.path, stat.S_IREAD | stat.S_IWRITE)


def test_a_changed_text_is_reported_when_the_cache_cannot_be_written(cache, read_only_cache, monkeypatch):
    """The change used to be computed only by a successful save: with the cache
    read-only, a law whose text changed was cited with no warning."""
    monkeypatch.setattr(law_fetcher, "fetch_provisions_from", _fake_fetch())
    first = check([cve(severity="CRITICAL")], cache=cache, now=DAY1)
    read_only_cache()

    monkeypatch.setattr(law_fetcher, "fetch_provisions_from", _fake_fetch(" (rettificato)"))
    law = check([cve(severity="CRITICAL")], cache=cache, now=DAY2)

    assert law.changed == {"GDPR art. 32(2)": first.citations[0].sha256}
    assert law.citations[0].sha256 != first.citations[0].sha256
    assert law.citations[0].version_date == "2026-10-01"


def test_an_unchanged_text_keeps_its_version_date_when_the_cache_cannot_be_written(
    cache, read_only_cache, online
):
    """The date of a wording is its first download, saved or not."""
    check([cve(severity="CRITICAL")], cache=cache, now=DAY1)
    read_only_cache()

    law = check([cve(severity="CRITICAL")], cache=cache, now=DAY2)

    assert law.changed == {}
    assert law.citations[0].version_date == "2026-09-19"
