"""
PatchRadar — Debian release scoping (L4)

`releases.get(release, {})` returned an empty dict when the package had no
entry for the target release at all; `status` was then "", which is not
"resolved", so the CVE was reported as an *open* vulnerability.

Measured against the live tracker (72 MB, Sept 2026), targeting trixie:

    CVEs with a trixie entry     60,031   (resolved 52,767 / open 7,210 / undetermined 54)
    CVEs with NO trixie entry     7,924   <- all reported as open today

Per package the noise ranged from nil to total:

    postgresql   109 reported ->     0 real   (100% false positives)
    python       332 reported ->   173 real   ( 47%)
    linux      2,226 reported -> 1,631 real   ( 26%)
    nginx          4 reported ->     4 real   (  0%)

A CVE only counts against a system if the tracker says something about the
release that system runs.
"""
import httpx
import pytest
import respx

from patchradar.collectors.debian import DEBIAN_RELEASE, fetch_cves

DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"

# The only three status values the tracker emits, confirmed against live data.
REAL_STATUSES = {"resolved", "open", "undetermined"}


def payload(releases, package="nginx", cve_id="CVE-2026-0001"):
    return {package: {cve_id: {"description": "test", "releases": releases}}}


async def fetch(releases, keyword="nginx", **kwargs):
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json=payload(releases)))
        return await fetch_cves(keyword, **kwargs)


# ─── the defect: absent release must not mean "vulnerable" ───────────────────

@pytest.mark.asyncio
async def test_cve_without_an_entry_for_the_target_release_is_excluded():
    """The headline false positive: nothing is known about trixie."""
    cves = await fetch({"bookworm": {"status": "open", "urgency": "high"}})
    assert cves == [], "a CVE with no trixie entry was reported as an open vulnerability"


@pytest.mark.asyncio
@pytest.mark.parametrize("releases", [{}, None, "nope", [], {"sid": {"status": "open"}}])
async def test_missing_or_malformed_releases_block_is_excluded(releases):
    assert await fetch(releases) == []


@pytest.mark.asyncio
async def test_cve_resolved_in_another_release_but_absent_from_target_is_excluded():
    cves = await fetch({
        "bookworm": {"status": "resolved", "urgency": "high"},
        "sid": {"status": "open", "urgency": "high"},
    })
    assert cves == []


@pytest.mark.asyncio
@pytest.mark.parametrize("release_entry", [None, "string", 42, []])
async def test_non_dict_release_entry_is_excluded(release_entry):
    assert await fetch({DEBIAN_RELEASE: release_entry}) == []


# ─── statuses ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["open", "undetermined"])
async def test_unresolved_statuses_are_reported(status):
    cves = await fetch({DEBIAN_RELEASE: {"status": status, "urgency": "high"}})
    assert len(cves) == 1
    assert cves[0]["id"] == "CVE-2026-0001"


@pytest.mark.asyncio
async def test_resolved_status_is_excluded():
    assert await fetch({DEBIAN_RELEASE: {"status": "resolved", "urgency": "high"}}) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["", None, "banana", "OPEN-ish"])
async def test_unrecognised_status_is_excluded(status):
    """Whitelist, not blacklist: an empty status is what caused this bug."""
    assert await fetch({DEBIAN_RELEASE: {"status": status, "urgency": "high"}}) == []


def test_status_whitelist_covers_every_real_status():
    from patchradar.collectors import debian

    handled = debian.UNRESOLVED_STATUSES | {"resolved"}
    assert REAL_STATUSES <= handled, (
        f"tracker statuses not accounted for: {sorted(REAL_STATUSES - handled)}"
    )
    assert debian.UNRESOLVED_STATUSES <= REAL_STATUSES


# ─── the release is a parameter, not a constant ──────────────────────────────

@pytest.mark.asyncio
async def test_release_argument_selects_the_scope():
    releases = {
        "bookworm": {"status": "open", "urgency": "high"},
        "trixie": {"status": "resolved", "urgency": "high"},
    }
    assert await fetch(releases, release="bookworm")
    assert await fetch(releases, release="trixie") == []


@pytest.mark.asyncio
async def test_unknown_release_name_yields_nothing():
    releases = {"trixie": {"status": "open", "urgency": "high"}}
    assert await fetch(releases, release="nonexistent") == []


# ─── realistic mixed payload ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mixed_payload_reports_only_what_affects_the_target_release():
    mixed = {
        "postgresql-15": {
            # absent from trixie entirely — the postgresql case, 100% noise
            "CVE-2026-1001": {"description": "a", "releases": {"bookworm": {"status": "open", "urgency": "high"}}},
            "CVE-2026-1002": {"description": "b", "releases": {"sid": {"status": "open", "urgency": "high"}}},
            # genuinely open in trixie
            "CVE-2026-1003": {"description": "c", "releases": {"trixie": {"status": "open", "urgency": "high"}}},
            # fixed in trixie
            "CVE-2026-1004": {"description": "d", "releases": {"trixie": {"status": "resolved", "urgency": "high"}}},
        }
    }
    with respx.mock:
        respx.get(DEBIAN_URL).mock(return_value=httpx.Response(200, json=mixed))
        cves = await fetch_cves("postgresql")
    assert {c["id"] for c in cves} == {"CVE-2026-1003"}


@pytest.mark.asyncio
async def test_severity_still_derives_from_urgency_after_scoping():
    """L5 must keep working through the new release filter."""
    cves = await fetch({DEBIAN_RELEASE: {"status": "open", "urgency": "high"}})
    assert cves[0]["severity"] == "HIGH"
