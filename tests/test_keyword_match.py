"""
PatchRadar — a keyword is a word of the product name, in every source

Measured against the live sources on 2026-10-09 with "git" — the command-line
tool — on the watchlist:

    CISA KEV   9 entries by substring, of which one is Git. The other eight are
               GitLab (four), Gitea, reviewdog and two GitHub Actions.
    MSRC       109 of the 2,764 entries of the September 2026 document, of which
               none is Git: 107 say "GitHub", the rest "legitimate", "digital",
               "logitech-hidpp" and "10-digit".

`collectors/debian.py` met the same defect ("python-digitalocean" for git) and
has matched whole words since; KEV and MSRC still matched substrings, so a scan
of one watchlist applied two rules and the reader could not tell which rows were
which. The three now share one, `names.keyword_pattern`: the keyword has to
start the text or follow a separator, and may be followed by anything but a
letter — so "log4j" still finds "Log4j2", "7-zip" finds "7-Zip" and "python"
finds "python3.13".

Nothing legitimate is lost. Counted on the same September document: curl 9
entries by substring and 9 by word (its advisories name curl only in a note),
openssl 18 and 18, python 1 and 1, nginx 3 and 3, openssh 1 and 1.

The fixtures are recorded, not written. `kev_keyword_excerpt.json` holds nine
entries of catalogue 2026.10.08 and `msrc_2026_sep_excerpt.json` six entries of
the September 2026 document; each says in its `_derived` key what was kept.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime

import httpx
import pytest
import respx

from patchradar.collectors import kev, msrc
from patchradar.names import keyword_pattern

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _recorded(name: str) -> dict:
    data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    assert "verbatim" in data.pop("_derived")
    return data


# ── the rule itself ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("keyword, text, found", [
    ("git", "git", True),
    ("git", "Git for Windows", True),
    ("git", "GitLab CE/EE", False),
    ("git", "Gitea", False),
    ("git", "a legitimate link", False),
    ("git", "digital signature", False),
    ("git", "action-setup GitHub Action", False),
    ("git", "python-digitalocean", False),
    ("log4j", "Apache Log4j2", True),           # a digit after the word is a version
    ("7-zip", "7-Zip", True),
    ("python", "python3.13", True),
    ("python", "cpython", False),
    ("ssh", "openssh", False),
    ("openssl", "OpenSSL provider use-after-free", True),
    ("chromium", "Chromium: CVE-2026-85046 Type confusion in V8", True),
])
def test_the_keyword_is_a_word_of_the_text(keyword, text, found):
    assert bool(keyword_pattern(keyword).search(text.lower())) is found


def test_the_keyword_is_taken_literally():
    """"7-zip" and "c++" hold regex metacharacters; they are product names here."""
    assert keyword_pattern("c++").search("microsoft visual c++ 2015")
    assert not keyword_pattern("7.zip").search("7-zip")


# ── CISA KEV ─────────────────────────────────────────────────────────────────

@pytest.fixture
def kev_catalogue(kev_offline_by_default):
    kev.clear_cache()
    with respx.mock:
        respx.get(kev.KEV_URL).mock(return_value=httpx.Response(200, json=_recorded("kev_keyword_excerpt.json")))
        yield
    kev.clear_cache()


async def _kev_ids(keyword: str) -> list[str]:
    return [r["id"] for r in await kev.fetch_cves(keyword)]


@pytest.mark.asyncio
async def test_kev_git_is_git_and_not_gitlab_gitea_or_github(kev_catalogue):
    """CVE-2025-48384 is Git's. The other four entries whose vendor or product
    contains "git" belong to GitLab, Gitea and a GitHub Action, and a scan for
    the git client reported them as exploited — above every real finding."""
    assert await _kev_ids("git") == ["CVE-2025-48384"]


@pytest.mark.asyncio
async def test_kev_gitlab_still_finds_gitlab(kev_catalogue):
    assert await _kev_ids("gitlab") == ["CVE-2023-7028", "CVE-2021-22205"]


@pytest.mark.asyncio
@pytest.mark.parametrize("keyword, expected", [
    ("log4j", ["CVE-2021-44228"]),        # vendor Apache, product Log4j2
    ("7-zip", ["CVE-2025-0411"]),
    ("openssl", ["CVE-2014-0160"]),
    ("chromium", ["CVE-2026-11645"]),     # product "Chromium V8"
    ("GIT", ["CVE-2025-48384"]),
])
async def test_kev_whole_words_still_match_the_catalogue_spelling(kev_catalogue, keyword, expected):
    assert await _kev_ids(keyword) == expected


# ── MSRC ─────────────────────────────────────────────────────────────────────

class _October2026(datetime):
    """The clock on the day the document was recorded, so the months asked for
    are the ones the fixture answers."""

    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 9, 12, 0, tzinfo=tz)


@pytest.fixture
def msrc_september(monkeypatch):
    monkeypatch.setattr(msrc, "datetime", _October2026)
    document = _recorded("msrc_2026_sep_excerpt.json")
    with respx.mock:
        respx.get(f"{msrc.MSRC_API}/cvrf/2026-Sep").mock(return_value=httpx.Response(200, json=document))
        # Every other month asked for has no document yet, which MSRC says with 404.
        respx.get(url__startswith=msrc.MSRC_API).mock(return_value=httpx.Response(404))
        yield


async def _msrc_ids(keyword: str) -> list[str]:
    # 60 days: the recorded entries are dated 2026-09-07 to 09-09 and the clock
    # says 10-09, so a 30-day window would hold the entries to a date and this
    # file is about the keyword. tests/test_msrc_window.py is about the date.
    return [r["id"] for r in await msrc.fetch_cves(keyword, days_back=60)]


@pytest.mark.asyncio
async def test_msrc_git_matches_neither_legitimate_nor_digital_nor_github(msrc_september):
    """Three real entries a scan for git reported on 2026-10-09: a Netlogon flaw
    whose FAQ says "legitimate", a Linux "nfc: digital:" driver fix, and GitHub
    Copilot. None of them concerns Git."""
    assert await _msrc_ids("git") == []


@pytest.mark.asyncio
async def test_msrc_curl_is_still_found_through_its_note(msrc_september):
    """CVE-2026-13608 is titled "OpenLDAP SASL authentication bypass" and names
    curl only in a note of type 8 — the component. Matching whole words must
    not stop reading the notes, or every curl advisory in MSRC disappears."""
    assert await _msrc_ids("curl") == ["CVE-2026-13608"]


@pytest.mark.asyncio
@pytest.mark.parametrize("keyword, expected", [
    ("sharepoint", ["CVE-2026-69268"]),
    ("chromium", ["CVE-2026-85046"]),
    ("github", ["CVE-2026-81380"]),
    ("digital", ["CVE-2026-80803"]),
    ("netlogon", ["CVE-2026-62759"]),
])
async def test_msrc_whole_words_still_match_titles_and_notes(msrc_september, keyword, expected):
    assert await _msrc_ids(keyword) == expected
