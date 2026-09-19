"""
PatchRadar — the CVE fields the law check needs.

`patch_available` and `confidentiality_impact` come from the same NVD and MSRC
payloads the collectors already download: NVD reference tags and CVSS data,
MSRC remediations and CVSS vector.
"""
import pytest

from patchradar.collectors.msrc import _parse_vuln
from patchradar.collectors.nvd import _parse_item


def nvd_item(status="Analyzed", tags=(), metrics=None):
    return {"cve": {
        "id": "CVE-2026-0001",
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": "nginx flaw"}],
        "references": [{"url": "https://example.com/advisory", "tags": list(tags)}],
        "metrics": metrics if metrics is not None else {},
    }}


def v31(confidentiality):
    return {"cvssMetricV31": [{"cvssData": {
        "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
        "confidentialityImpact": confidentiality,
    }}]}


# ─── NVD: patch_available ────────────────────────────────────────────────────

def test_nvd_patch_reference_means_patch_available():
    cve = _parse_item(nvd_item(tags=["Patch", "Vendor Advisory"]), "nginx")
    assert cve["patch_available"] is True


@pytest.mark.parametrize("status", ["Analyzed", "Modified"])
def test_nvd_analysed_without_patch_reference_means_no_patch(status):
    cve = _parse_item(nvd_item(status=status, tags=["Third Party Advisory"]), "nginx")
    assert cve["patch_available"] is False


@pytest.mark.parametrize("status", ["Awaiting Analysis", "Undergoing Analysis", "Received", "Deferred", None])
def test_nvd_not_analysed_is_unknown(status):
    # NVD tags references only when it analyses a CVE: no tag says nothing yet
    cve = _parse_item(nvd_item(status=status), "nginx")
    assert cve["patch_available"] is None


@pytest.mark.parametrize("references", [None, "x", [None, 3], [{"tags": "Patch"}], [{"tags": [None]}]])
def test_nvd_malformed_references_do_not_crash(references):
    item = nvd_item(tags=["Patch"])
    item["cve"]["references"] = references
    cve = _parse_item(item, "nginx")
    assert cve["id"] == "CVE-2026-0001"
    assert cve["patch_available"] in (False, None)


# ─── NVD: confidentiality_impact ─────────────────────────────────────────────

@pytest.mark.parametrize("value", ["HIGH", "LOW", "NONE"])
def test_nvd_cvss3_confidentiality(value):
    assert _parse_item(nvd_item(metrics=v31(value)), "nginx")["confidentiality_impact"] == value


def test_nvd_cvss4_confidentiality():
    metrics = {"cvssMetricV40": [{"cvssData": {
        "version": "4.0", "baseScore": 9.3, "baseSeverity": "CRITICAL",
        "vulnConfidentialityImpact": "HIGH",
    }}]}
    assert _parse_item(nvd_item(metrics=metrics), "nginx")["confidentiality_impact"] == "HIGH"


@pytest.mark.parametrize("v2, expected", [("COMPLETE", "HIGH"), ("PARTIAL", "LOW"), ("NONE", "NONE")])
def test_nvd_cvss2_confidentiality(v2, expected):
    metrics = {"cvssMetricV2": [{"cvssData": {"version": "2.0", "baseScore": 7.5, "confidentialityImpact": v2}}]}
    assert _parse_item(nvd_item(metrics=metrics), "nginx")["confidentiality_impact"] == expected


@pytest.mark.parametrize("metrics", [{}, {"cvssMetricV31": [{"cvssData": {}}]},
                                     {"cvssMetricV31": [{"cvssData": {"confidentialityImpact": 3}}]}])
def test_nvd_confidentiality_unknown(metrics):
    assert _parse_item(nvd_item(metrics=metrics), "nginx")["confidentiality_impact"] is None


# ─── MSRC ─────────────────────────────────────────────────────────────────────

def msrc_vuln(remediations=None, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
    vuln = {
        "CVE": "CVE-2026-0002",
        "Title": {"Value": "nginx for Windows remote code execution"},
        "CVSSScoreSets": [{"BaseScore": 9.8, "Vector": vector}],
    }
    if remediations is not None:
        vuln["Remediations"] = remediations
    return vuln


def test_msrc_vendor_fix_means_patch_available():
    # Remediation type 2 is a vendor fix (security update)
    cve = _parse_vuln(msrc_vuln([{"Type": 2}, {"Type": 3}]), "nginx")
    assert cve["patch_available"] is True


@pytest.mark.parametrize("remediations", [None, [], [{"Type": 6}], "x", [None]])
def test_msrc_without_vendor_fix_is_unknown(remediations):
    # Third-party CVEs listed for information carry no remediation at all
    cve = _parse_vuln(msrc_vuln(remediations), "nginx")
    assert cve["patch_available"] is None


@pytest.mark.parametrize("vector, expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "LOW"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:O/RC:C", "NONE"),
    ("", None),
    (None, None),
    ("garbage", None),
])
def test_msrc_confidentiality_from_vector(vector, expected):
    assert _parse_vuln(msrc_vuln(vector=vector), "nginx")["confidentiality_impact"] == expected
