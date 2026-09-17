"""
PatchRadar — collector parsing robustness (L1, L2, L3)

The collectors wrapped only the HTTP call in try/except; everything after it
indexed into the decoded JSON directly. A single malformed field anywhere in
an upstream feed therefore aborted the whole scan:

* L1 — nvd.py: ``d["lang"]`` raised KeyError on a description entry missing it.
* L2 — nvd.py: ``item.get("cve", {})`` returns None when the key is present but
  null, and the default never fires; a non-dict top-level payload did the same.
* L3 — msrc.py: ``vuln.get("RevisionHistory", [{}])[0]`` raised IndexError on a
  present-but-empty list, and because the except sat *outside* the per-vuln
  loop, that one entry silently discarded every remaining CVE of that month.

The governing principle across all three: one bad record may drop itself, never
its neighbours and never the batch.
"""
import httpx
import pytest
import respx

from patchradar.collectors.msrc import fetch_cves as msrc_fetch
from patchradar.collectors.nvd import fetch_cves as nvd_fetch

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MSRC_PREFIX = "https://api.msrc.microsoft.com"


def nvd_payload(*cves):
    return {"vulnerabilities": [{"cve": c} for c in cves]}


def good_cve(cve_id="CVE-2026-0001"):
    return {
        "id": cve_id,
        "published": "2026-08-15T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "a real description"}],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "version": "3.1", "baseSeverity": "CRITICAL"},
                 "baseSeverity": "CRITICAL"}
            ]
        },
    }


async def fetch_nvd(payload, keyword="nginx"):
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=payload))
        return await nvd_fetch(keyword, days_back=7)


# ─── L1: description extraction ──────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "descriptions",
    [
        [{"value": "no lang key"}],                       # KeyError 'lang'
        [{"lang": "en"}],                                 # KeyError 'value'
        [{}],
        None,
        "not a list",
        [None],
        ["a bare string"],
        [{"lang": None, "value": None}],
    ],
)
async def test_malformed_descriptions_do_not_crash(descriptions):
    cve = good_cve()
    cve["descriptions"] = descriptions
    cves = await fetch_nvd(nvd_payload(cve))
    assert len(cves) == 1
    assert isinstance(cves[0]["description"], str)


@pytest.mark.asyncio
async def test_english_description_is_selected():
    cve = good_cve()
    cve["descriptions"] = [
        {"lang": "es", "value": "descripcion"},
        {"lang": "en", "value": "the english one"},
    ]
    cves = await fetch_nvd(nvd_payload(cve))
    assert cves[0]["description"] == "the english one"


@pytest.mark.asyncio
async def test_missing_english_description_falls_back_to_empty():
    cve = good_cve()
    cve["descriptions"] = [{"lang": "fr", "value": "seulement francais"}]
    cves = await fetch_nvd(nvd_payload(cve))
    assert cves[0]["description"] == ""


@pytest.mark.asyncio
async def test_malformed_entry_does_not_hide_a_later_english_one():
    cve = good_cve()
    cve["descriptions"] = [{"value": "broken"}, {"lang": "en", "value": "good"}]
    cves = await fetch_nvd(nvd_payload(cve))
    assert cves[0]["description"] == "good"


# ─── L2: payload shape ───────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[1, 2], "a string", 42, None, {"vulnerabilities": None},
                                     {"vulnerabilities": "nope"}, {}])
async def test_unexpected_top_level_payload_returns_empty(payload):
    assert await fetch_nvd(payload) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("item", [None, "string", 42, {}, {"cve": None}, {"cve": "string"}])
async def test_unexpected_item_shape_is_skipped(item):
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": [item]}))
        assert await nvd_fetch("nginx", days_back=7) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "metrics",
    [None, "nope", {}, {"cvssMetricV31": []}, {"cvssMetricV31": None},
     {"cvssMetricV31": [None]}, {"cvssMetricV31": [{}]}, {"cvssMetricV31": [{"cvssData": None}]}],
)
async def test_malformed_metrics_degrade_to_unknown(metrics):
    cve = good_cve()
    cve["metrics"] = metrics
    cves = await fetch_nvd(nvd_payload(cve))
    assert len(cves) == 1
    assert cves[0]["severity"] == "UNKNOWN"
    assert cves[0]["cvss_score"] is None


@pytest.mark.asyncio
async def test_cve_without_id_is_skipped():
    """id is the database primary key; a blank one would collide."""
    cve = good_cve()
    del cve["id"]
    assert await fetch_nvd(nvd_payload(cve)) == []


@pytest.mark.asyncio
async def test_one_bad_record_does_not_drop_the_good_ones():
    """The whole point: a poisoned entry must not cost us the rest of the batch."""
    payload = {"vulnerabilities": [
        {"cve": good_cve("CVE-2026-1111")},
        {"cve": None},
        {"cve": {"id": "CVE-2026-2222", "descriptions": [{"value": "no lang"}]}},
        "garbage",
        {"cve": good_cve("CVE-2026-3333")},
    ]}
    with respx.mock:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=payload))
        cves = await nvd_fetch("nginx", days_back=7)
    ids = {c["id"] for c in cves}
    assert {"CVE-2026-1111", "CVE-2026-3333"} <= ids
    assert "CVE-2026-2222" in ids, "a recoverable entry was dropped entirely"


@pytest.mark.asyncio
async def test_good_record_still_parses_fully():
    """Regression guard: hardening must not change the happy path."""
    cves = await fetch_nvd(nvd_payload(good_cve()))
    assert cves[0]["id"] == "CVE-2026-0001"
    assert cves[0]["severity"] == "CRITICAL"
    assert cves[0]["cvss_score"] == 9.8
    assert cves[0]["cvss_version"] == "3.1"
    assert cves[0]["software"] == "nginx"
    assert cves[0]["source"] == "NVD"
    assert cves[0]["url"].endswith("CVE-2026-0001")


# ─── parser-level guarantees ─────────────────────────────────────────────────
# The loops wrap each record in try/except, which would mask a fragile parser:
# the batch survives either way. These call the parsers directly, so they pin
# the parsing itself rather than the safety net around it.

@pytest.mark.parametrize("item", [None, "string", 42, {}, {"cve": None}, {"cve": "string"},
                                  {"cve": []}, {"cve": {"id": None}}, {"cve": {}}])
def test_parse_item_returns_none_without_raising(item):
    from patchradar.collectors.nvd import _parse_item

    assert _parse_item(item, "nginx") is None


@pytest.mark.parametrize("cve", [{}, {"descriptions": None}, {"descriptions": [{"value": "x"}]},
                                 {"descriptions": [{"lang": "en"}]}, {"descriptions": "nope"},
                                 {"descriptions": [None]}])
def test_extract_description_never_raises(cve):
    from patchradar.collectors.nvd import _extract_description

    assert isinstance(_extract_description(cve), str)


@pytest.mark.parametrize("vuln", [{}, {"RevisionHistory": []}, {"RevisionHistory": None},
                                  {"RevisionHistory": [None]}, {"RevisionHistory": "nope"},
                                  {"RevisionHistory": [{}]}])
def test_published_at_never_raises(vuln):
    from patchradar.collectors.msrc import _published_at

    assert isinstance(_published_at(vuln), str)


@pytest.mark.parametrize("vuln", [{}, {"CVSSScoreSets": []}, {"CVSSScoreSets": None},
                                  {"CVSSScoreSets": [None]}, {"CVSSScoreSets": [{}]},
                                  {"CVSSScoreSets": "nope"}])
def test_base_score_never_raises(vuln):
    from patchradar.collectors.msrc import _base_score

    assert _base_score(vuln) is None


@pytest.mark.parametrize("vuln", [None, "string", {}, {"Title": None}, {"Notes": None},
                                  {"Notes": [None]}, {"Title": "bare string"}])
def test_parse_vuln_never_raises(vuln):
    from patchradar.collectors.msrc import _parse_vuln

    assert _parse_vuln(vuln, "nginx") is None


# ─── L3: MSRC ────────────────────────────────────────────────────────────────

def msrc_vuln(cve_id="CVE-2026-9999", **overrides):
    vuln = {
        "CVE": cve_id,
        "Title": {"Value": "nginx elevation of privilege"},
        "Notes": [{"Type": 1, "Value": "nginx description"}],
        "CVSSScoreSets": [{"BaseScore": 8.1}],
        "RevisionHistory": [{"Date": "2026-08-12T00:00:00"}],
    }
    vuln.update(overrides)
    return vuln


async def fetch_msrc(*vulns, keyword="nginx"):
    with respx.mock:
        respx.get(url__startswith=MSRC_PREFIX).mock(
            return_value=httpx.Response(200, json={"Vulnerability": list(vulns)})
        )
        return await msrc_fetch(keyword, days_back=7)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "history",
    [[], None, "nope", [None], ["string"], [{}], {"not": "a list"}],
)
async def test_malformed_revision_history_does_not_crash(history):
    cves = await fetch_msrc(msrc_vuln(RevisionHistory=history))
    assert cves, "the CVE was dropped instead of degrading its published date"
    assert isinstance(cves[0]["published_at"], str)


@pytest.mark.asyncio
@pytest.mark.parametrize("title", [None, "a string", {}, {"Value": None}])
async def test_malformed_title_does_not_crash(title):
    await fetch_msrc(msrc_vuln(Title=title))


@pytest.mark.asyncio
@pytest.mark.parametrize("notes", [None, "nope", [None], ["string"], [{"Type": 1}]])
async def test_malformed_notes_do_not_crash(notes):
    await fetch_msrc(msrc_vuln(Notes=notes))


@pytest.mark.asyncio
@pytest.mark.parametrize("scores", [None, "nope", [], [None], ["x"], [{}], [{"BaseScore": None}]])
async def test_malformed_score_sets_degrade_to_unknown(scores):
    cves = await fetch_msrc(msrc_vuln(CVSSScoreSets=scores))
    assert cves[0]["severity"] == "UNKNOWN"
    assert cves[0]["cvss_score"] is None


@pytest.mark.asyncio
async def test_one_bad_vuln_does_not_discard_the_rest_of_the_month():
    """The costly half of L3: the except sat outside the per-vuln loop, so a
    single IndexError silently dropped every later CVE in that month."""
    cves = await fetch_msrc(
        msrc_vuln("CVE-2026-AAAA"),
        msrc_vuln("CVE-2026-BBBB", RevisionHistory=[]),   # used to raise IndexError
        msrc_vuln("CVE-2026-CCCC"),
        None,
        msrc_vuln("CVE-2026-DDDD"),
    )
    ids = {c["id"] for c in cves}
    assert {"CVE-2026-AAAA", "CVE-2026-CCCC", "CVE-2026-DDDD"} <= ids, (
        f"later CVEs were lost after a malformed entry; got {sorted(ids)}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[1, 2], "string", None, {"Vulnerability": None},
                                     {"Vulnerability": "nope"}, {}])
async def test_unexpected_msrc_payload_returns_empty(payload):
    with respx.mock:
        respx.get(url__startswith=MSRC_PREFIX).mock(
            return_value=httpx.Response(200, json=payload)
        )
        assert await msrc_fetch("nginx", days_back=7) == []


@pytest.mark.asyncio
async def test_msrc_vuln_without_cve_id_is_skipped():
    cves = await fetch_msrc(msrc_vuln(CVE=None), msrc_vuln("CVE-2026-KEEP"))
    assert {c["id"] for c in cves} == {"CVE-2026-KEEP"}


@pytest.mark.asyncio
async def test_msrc_good_record_still_parses_fully():
    cves = await fetch_msrc(msrc_vuln())
    assert cves[0]["id"] == "CVE-2026-9999"
    assert cves[0]["cvss_score"] == 8.1
    assert cves[0]["severity"] == "HIGH"
    assert cves[0]["description"] == "nginx description"
    assert cves[0]["source"] == "MSRC"
