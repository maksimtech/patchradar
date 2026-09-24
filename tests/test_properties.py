"""Properties, checked against generated input rather than chosen examples.

test_nvd_window.py already pins the boundary the live API drew — 119 whole,
120 split. What it cannot pin is every other value: the parametrised list holds
eight. These generate them.

The `normalize_text` block is the most valuable one here, and the reason is not
the parser: its output is hashed, and that hash is what tells an operator "the
law changed". A normalisation that is not idempotent would report a change in a
text that nobody edited.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchradar.api.main import sanitize_cve
from patchradar.collectors.nvd import NVD_MAX_WINDOW_DAYS, date_windows
from patchradar.law_fetcher import normalize_text

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)

# ── Splitting a date range NVD will accept ──────────────────────────────────

_DAYS = st.integers(min_value=1, max_value=4000)


@given(_DAYS)
def test_no_chunk_is_ever_wide_enough_to_be_refused(days):
    """The one property that matters: every request must be answerable.

    A chunk of 120 days or more comes back 404, which reads as "no such
    endpoint" and was how `--days 180` silently returned nothing.
    """
    for start, end in date_windows(days, now=NOW):
        assert (end - start).total_seconds() / 86400 <= 120.0, f"{days}: {start}..{end}"


@given(_DAYS)
def test_the_chunks_leave_no_gap_and_cover_the_whole_period(days):
    """A CVE published inside a gap would simply be missing, and nothing would say so."""
    chunks = date_windows(days, now=NOW)
    assert chunks[0][0] <= NOW - timedelta(days=days)
    assert chunks[-1][1] >= NOW
    for (_, earlier_end), (later_start, _) in pairwise(chunks):
        assert later_start <= earlier_end


@given(_DAYS)
def test_the_chunks_come_back_oldest_first(days):
    chunks = date_windows(days, now=NOW)
    assert chunks == sorted(chunks)


@given(_DAYS)
def test_the_split_is_as_thrifty_as_it_can_be(days):
    """No request more than the arithmetic requires: each one costs a rate limit."""
    chunks = date_windows(days, now=NOW)
    assert len(chunks) == max(1, -(-days // NVD_MAX_WINDOW_DAYS))


@given(st.integers(max_value=0))
def test_a_window_of_nothing_is_refused_rather_than_guessed_at(days):
    with pytest.raises(ValueError):
        date_windows(days, now=NOW)


# ── What reaches the browser ────────────────────────────────────────────────

_TEXT = st.text(max_size=3000)
_STR_FIELDS = ["id", "software", "description", "severity", "source", "url",
               "published_at", "cvss_version"]


@given(st.fixed_dictionaries(dict.fromkeys(_STR_FIELDS, _TEXT)))
def test_no_control_character_survives_sanitising(cve):
    """The reason the function exists: a CVE description is attacker-influenced.

    Tab and newline are kept on purpose — _strip_control_chars calls them
    "ordinary line structure" — and a carriage return is not kept but
    rewritten to a newline, so neither it nor ESC, BEL or BS may appear.
    """
    safe = sanitize_cve(cve)
    for field in _STR_FIELDS:
        value = safe[field]
        assert isinstance(value, str)
        assert "\r" not in value, field
        assert not any(ord(c) < 32 and c not in "\t\n" for c in value), field
        assert not any(0x7F <= ord(c) <= 0x9F for c in value), field


@given(st.fixed_dictionaries(dict.fromkeys(_STR_FIELDS, _TEXT)))
def test_every_field_is_bounded(cve):
    """An unbounded string is a denial of service against the page that renders it."""
    safe = sanitize_cve(cve)
    assert len(safe["description"]) <= 2003          # 2000 plus the "..." marker
    for field in _STR_FIELDS:
        if field not in ("description", "url"):
            assert len(safe[field]) <= 200, field


@given(st.fixed_dictionaries(dict.fromkeys(_STR_FIELDS, _TEXT)))
def test_sanitising_an_already_sanitised_cve_changes_nothing(cve):
    """Otherwise a value could keep shrinking each time it passes through."""
    once = sanitize_cve(cve)
    assert sanitize_cve(once) == once


def test_a_cve_missing_every_field_does_not_raise():
    """The collectors do drop fields; the API must not turn that into a 500."""
    assert sanitize_cve({})["id"] is None


# ── The hash that decides "the law changed" ─────────────────────────────────

_LEGAL_TEXT = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=0x2FFF, blacklist_categories=("Cs",)),
    max_size=400,
)


@given(_LEGAL_TEXT)
@settings(max_examples=300)
def test_normalising_twice_says_the_same_as_normalising_once(text):
    """If this ever failed, the cache would report a change nobody made."""
    once = normalize_text(text)
    assert normalize_text(once) == once


@given(_LEGAL_TEXT)
def test_the_normal_form_holds_no_run_of_spaces_and_no_edges(text):
    result = normalize_text(text)
    assert "  " not in result
    assert result == result.strip()


@given(_LEGAL_TEXT)
def test_the_normal_form_never_leaves_a_space_before_punctuation(text):
    """"Consiglio ;" is what a removed footnote reference leaves behind."""
    result = normalize_text(text)
    for mark in ";,.:":
        assert f" {mark}" not in result
