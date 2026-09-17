"""
PatchRadar — MSRC month enumeration (L6)

Months were derived by stepping backwards in 30-day increments:

    for days in range(0, safe_days_back + 30, 30):
        months.add(f"{(now - timedelta(days=days)).year}-{...strftime('%b')}")

A 30-day stride cannot enumerate calendar months. From 2026-03-31 with
days_back=90 it produced ['2025-Dec', '2026-Jan', '2026-Mar'] — February is
skipped entirely, so a whole Patch Tuesday is silently never fetched. False
negatives in a CVE monitor, the mirror image of the Debian false positives.

The replacement walks calendar months directly, so the result is contiguous by
construction.
"""
import ast
import inspect
from datetime import datetime, timedelta

import httpx
import pytest
import respx

from patchradar.collectors import msrc
from patchradar.collectors.msrc import MONTH_ABBR, _months_in_range, fetch_cves

MSRC_PREFIX = "https://api.msrc.microsoft.com"


def to_tuple(month_key: str) -> tuple[int, int]:
    """'2026-Feb' -> (2026, 2)"""
    year, abbr = month_key.split("-")
    return int(year), MONTH_ABBR.index(abbr) + 1


def next_month(year: int, month: int) -> tuple[int, int]:
    return (year + 1, 1) if month == 12 else (year, month + 1)


# ─── the defect ──────────────────────────────────────────────────────────────

def test_february_is_not_skipped():
    """The exact case from the audit."""
    months = _months_in_range(datetime(2026, 3, 31), 90)
    assert "2026-Feb" in months, f"February missing from {months}"


@pytest.mark.parametrize(
    "now, days_back, expected",
    [
        (datetime(2026, 3, 31), 90, ["2025-Dec", "2026-Jan", "2026-Feb", "2026-Mar"]),
        (datetime(2026, 3, 1), 60, ["2025-Dec", "2026-Jan", "2026-Feb", "2026-Mar"]),
        (datetime(2026, 9, 17), 7, ["2026-Sep"]),
        (datetime(2026, 9, 3), 7, ["2026-Aug", "2026-Sep"]),
        (datetime(2026, 1, 15), 60, ["2025-Nov", "2025-Dec", "2026-Jan"]),
        (datetime(2024, 3, 31), 60, ["2024-Jan", "2024-Feb", "2024-Mar"]),  # leap year
    ],
)
def test_known_ranges(now, days_back, expected):
    assert _months_in_range(now, days_back) == expected


def test_months_are_contiguous_across_three_years():
    """Property check: no gap, for every month end and every lookback."""
    for year in (2024, 2025, 2026):
        for month in range(1, 13):
            for day in (1, 15, 28):
                for days_back in (1, 7, 14, 30, 45, 60, 90):
                    now = datetime(year, month, day)
                    months = [to_tuple(m) for m in _months_in_range(now, days_back)]
                    for earlier, later in zip(months, months[1:]):
                        assert next_month(*earlier) == later, (
                            f"gap between {earlier} and {later} "
                            f"for now={now.date()} days_back={days_back}"
                        )


def test_window_endpoints_are_always_covered():
    for day in (1, 10, 28, 31):
        for days_back in (1, 7, 30, 60, 90):
            now = datetime(2026, 3, day) if day <= 31 else datetime(2026, 3, 28)
            months = _months_in_range(now, days_back)
            start = now - timedelta(days=min(max(days_back, 1), 90))
            assert f"{now.year}-{MONTH_ABBR[now.month - 1]}" in months, "current month missing"
            assert f"{start.year}-{MONTH_ABBR[start.month - 1]}" in months, "start month missing"


def test_result_is_ordered_oldest_first_and_deduplicated():
    months = _months_in_range(datetime(2026, 3, 31), 90)
    assert months == sorted(months, key=to_tuple)
    assert len(months) == len(set(months))


# ─── clamping ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("days_back", [0, -5, 1])
def test_small_or_negative_lookback_clamps_to_one_day(days_back):
    months = _months_in_range(datetime(2026, 9, 17), days_back)
    assert months == ["2026-Sep"]


def test_large_lookback_clamps_to_ninety_days():
    assert _months_in_range(datetime(2026, 9, 17), 9999) == _months_in_range(datetime(2026, 9, 17), 90)


def test_clamped_range_never_exceeds_four_months():
    for month in range(1, 13):
        assert len(_months_in_range(datetime(2026, month, 28), 90)) <= 4


# ─── month names must not depend on the machine's locale (W5) ────────────────

def test_month_abbreviations_are_the_english_ones_msrc_expects():
    assert MONTH_ABBR == ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def test_no_locale_dependent_month_formatting():
    """A non-English LC_TIME cannot be exercised in CI (no such locale is
    installable in the sandbox), so guard the code instead: strftime('%b')
    yields 'set' on an Italian machine and every MSRC request 404s in silence.

    Checked over the AST rather than the raw text, so prose mentioning %b in a
    comment does not trip it.
    """
    offenders = []
    for node in ast.walk(ast.parse(inspect.getsource(msrc))):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "strftime"):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if "%b" in arg.value or "%B" in arg.value:
                    offenders.append(arg.value)
    assert not offenders, f"locale-dependent month format {offenders}; use MONTH_ABBR"


# ─── end to end ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_each_month_is_requested_exactly_once():
    requested = []

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(200, json={"Vulnerability": []})

    with respx.mock:
        respx.get(url__startswith=MSRC_PREFIX).mock(side_effect=handler)
        await fetch_cves("nginx", days_back=90)

    months = [url.rsplit("/", 1)[-1] for url in requested]
    assert len(months) == len(set(months)), f"duplicate month requests: {months}"
    assert months == _months_in_range(datetime.now(), 90)


@pytest.mark.asyncio
async def test_results_from_every_month_are_collected():
    """A CVE living in the previously-skipped month must come back."""
    def handler(request):
        month = str(request.url).rsplit("/", 1)[-1]
        return httpx.Response(200, json={"Vulnerability": [{
            "CVE": f"CVE-2026-{month}",
            "Title": {"Value": "nginx issue"},
            "Notes": [{"Type": 1, "Value": "nginx detail"}],
            "CVSSScoreSets": [{"BaseScore": 7.5}],
            "RevisionHistory": [{"Date": "2026-01-01T00:00:00"}],
        }]})

    with respx.mock:
        respx.get(url__startswith=MSRC_PREFIX).mock(side_effect=handler)
        cves = await fetch_cves("nginx", days_back=90)

    expected = {f"CVE-2026-{m}" for m in _months_in_range(datetime.now(), 90)}
    assert {c["id"] for c in cves} == expected
