"""
PatchRadar — reading a machine's inventory, and saying what could be watched.

`inventory.ps1` collects and judges nothing: it reads the registry and writes
JSON. This is the other end. It answers one question — for each installed
program, is there a source that can say whether *this build* is still affected? —
and it answers it without writing anything.

Why it reports instead of importing. The translation from what the registry
writes to what a vendor API wants cannot be deduced from the name with any
certainty: measured on this corpus, 30% mapped by themselves and the rest did
not, and when a guess was allowed through it produced `MX5` → a Juniper router
and `Visual C++ 2012` → `visual_c++:2008`. An import that decided on its own
would build a wrong watchlist and nothing would say so.

Every string in these tests is one this machine actually holds, from
`dopo-aggiornamenti-20260927-211542.json` — 147 programs, 6 with no version at
all, 4 with no publisher.

The categories are four, not three, because of what the real list looks like: of
those 147, thirteen are Visual C++ runtimes, twenty-nine are NVIDIA pieces and
twenty-five belong to Python. Counting a runtime as an unwatched product would
report work that does not exist — it is patched by whatever installed it.
"""
from __future__ import annotations

import json

import pytest

from patchradar.inventory import (
    CERTAIN,
    COMPONENT,
    PROPOSED,
    UNCOVERED,
    classify,
    read_snapshot,
    survey,
)


def program(name: str, version: str = "1.0", publisher: str = "", **extra) -> dict:
    return {"name": name, "version": version, "publisher": publisher, "hive": "HKLM", **extra}


def snapshot(*programs: dict) -> dict:
    return {
        "schema": "radar.inventory/1",
        "takenAt": "2026-09-27T21:15:42.0000000+02:00",
        "installedSoftware": list(programs),
    }


# ── what a vendor source can answer for by version ──────────────────────────

def test_chrome_is_identified_by_publisher_and_name():
    found = classify(program("Google Chrome", "154.0.8037.58", "Google LLC"))

    assert found.confidence is CERTAIN
    assert found.source == "chrome"
    assert found.installed_version == "154.0.8037.58"


def test_edge_is_identified_the_same_way():
    found = classify(program("Microsoft Edge", "154.0.4258.37", "Microsoft Corporation"))
    assert found.confidence is CERTAIN
    assert found.source == "edge"


def test_the_webview_runtime_is_a_proposal_not_a_certainty():
    """The Edge feed lists a WebView2 product; which channel this install
    belongs to is not stated in the registry, and the answer decides the
    verdict."""
    found = classify(program("Microsoft Edge WebView2 Runtime", "154.0.4258.37",
                             "Microsoft Corporation"))
    assert found.confidence is PROPOSED
    assert found.source == "edge"
    assert found.reason


def test_a_microsoft_product_reaches_msrc_but_not_with_a_product_id():
    """MSRC lists 13 products for one Office CVE, LTSC 2021 at 32 and 64 bit
    among them, and that difference decides the verdict. A name from the
    registry does not pick one of the 13."""
    found = classify(program("Microsoft Visual Studio Code", "1.138.0", "Microsoft Corporation"))
    assert found.confidence is PROPOSED
    assert found.source == "msrc"


# ── components, which are not products to watch ─────────────────────────────

@pytest.mark.parametrize("name", [
    "Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030",
    "Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.51.36247",
    "Microsoft Visual C++ v14 Redistributable (x64) - 14.51.36247.0",
])
def test_a_visual_cpp_runtime_is_a_component(name):
    """Thirteen of this machine's seventeen Microsoft entries are these. They
    arrive with whatever needed them and are updated the same way."""
    assert classify(program(name, publisher="Microsoft Corporation")).confidence is COMPONENT


@pytest.mark.parametrize("name,publisher", [
    ("Google Update Helper", "Google Inc."),
    ("Java Auto Updater", "Oracle Corporation"),
    ("Adobe Refresh Manager", "Adobe Systems Incorporated"),
    ("Mozilla Maintenance Service", "Mozilla"),
])
def test_an_updater_is_a_component_of_the_thing_it_updates(name, publisher):
    """These four are on the machine and none of them is a product anyone
    patches on its own. Adobe Refresh Manager arrived with Reader and carries a
    certificate that expired in 2017."""
    assert classify(program(name, publisher=publisher)).confidence is COMPONENT


def test_a_component_still_says_which_product_it_came_with_when_it_is_known():
    found = classify(program("Java Auto Updater", "2.8.503.1", "Oracle Corporation"))
    assert found.confidence is COMPONENT
    assert "java" in found.reason.lower()


# ── no version-precise source ───────────────────────────────────────────────

def test_java_has_no_vendor_api_and_the_reason_says_what_is_possible_instead():
    """Oracle publishes quarterly bulletins and no per-CVE API. NVD by CPE does
    work here, and the patch level lives in the CPE `update` field: all of Java 8
    is version 8, and `update_503` is what distinguishes this install."""
    found = classify(program("Java 8 Update 503", "8.0.5030.1", "Oracle Corporation"))

    assert found.confidence is UNCOVERED
    assert "cpe" in found.reason.lower()


def test_a_program_nobody_publishes_an_api_for_is_uncovered():
    found = classify(program("WavePad Sound Editor", "5.99", "NCH Software"))
    assert found.confidence is UNCOVERED
    assert found.source is None


def test_uncovered_does_not_mean_nothing_is_known():
    """Keyword search still answers, with the noise it has: 806 CVEs for Chrome,
    708 of them unscored. The reason has to say that, or "uncovered" reads as
    "safe"."""
    found = classify(program("WavePad Sound Editor", "5.99", "NCH Software"))
    assert "keyword" in found.reason.lower() or "cpe" in found.reason.lower()


# ── what the snapshot itself cannot supply ──────────────────────────────────

def test_a_program_without_a_version_can_be_asked_nothing():
    """Six of the 147 have no version in the registry — `UltraVnc` was one
    before it was updated. Whatever the source, there is no build to compare."""
    found = classify(program("UltraVnc", "", "uvnc"))

    assert found.installed_version is None
    assert found.needs_version is True


def test_a_version_that_is_not_a_version_is_not_a_version():
    for raw in ("*", "-", "unknown", "   "):
        assert classify(program("X", raw)).installed_version is None


def test_an_empty_publisher_does_not_stop_the_name_from_deciding():
    """Four entries have no publisher at all. A name that identifies a product
    on its own still does."""
    assert classify(program("Google Chrome", "154.0.8037.58", "")).source == "chrome"


# ── the survey ──────────────────────────────────────────────────────────────

def test_the_survey_counts_each_category_once():
    data = snapshot(
        program("Google Chrome", "154.0.8037.58", "Google LLC"),
        program("Microsoft Edge", "154.0.4258.37", "Microsoft Corporation"),
        program("Microsoft Visual Studio Code", "1.138.0", "Microsoft Corporation"),
        program("Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030", "11.0",
                "Microsoft Corporation"),
        program("WavePad Sound Editor", "5.99", "NCH Software"),
        program("UltraVnc", "", "uvnc"),
    )
    result = survey(data)

    assert result.total == 6
    assert result.certain == 2
    assert result.proposed == 1
    assert result.components == 1
    assert result.uncovered == 2
    assert result.without_version == 1


def test_the_survey_groups_the_proposals_by_source():
    """What has to be confirmed by hand, gathered by who will be asked — because
    confirming ten Microsoft products in one pass is one job, and ten scattered
    ones are ten."""
    data = snapshot(
        program("Microsoft Visual Studio Code", "1.1", "Microsoft Corporation"),
        program("Microsoft Edge WebView2 Runtime", "154.0", "Microsoft Corporation"),
    )
    by_source = survey(data).proposals_by_source

    assert set(by_source) == {"msrc", "edge"}
    assert len(by_source["msrc"]) == 1


def test_the_survey_says_when_it_was_taken():
    """A survey of a snapshot from three weeks ago describes a machine that has
    since changed, and nothing else in the output would say so."""
    assert survey(snapshot()).taken_at == "2026-09-27T21:15:42.0000000+02:00"


def test_an_empty_snapshot_is_a_survey_of_nothing_not_an_error():
    result = survey(snapshot())
    assert result.total == 0
    assert result.certain == 0


# ── reading the file ────────────────────────────────────────────────────────

def test_a_snapshot_is_read_from_disk(tmp_path):
    path = tmp_path / "cavia.json"
    path.write_text(json.dumps(snapshot(program("Google Chrome", "154.0", "Google LLC"))),
                    encoding="utf-8")

    assert len(read_snapshot(path)["installedSoftware"]) == 1


def test_a_byte_order_mark_does_not_break_the_read(tmp_path):
    """PowerShell's `Set-Content -Encoding utf8` writes one, and `json.loads`
    refuses it. It cost four separate debugging sessions on this corpus."""
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(snapshot()).encode("utf-8"))

    assert read_snapshot(path)["installedSoftware"] == []


def test_a_file_that_is_not_a_snapshot_says_so_instead_of_reporting_zero(tmp_path):
    """Zero programs and "this is not an inventory" must not look the same: the
    first reads as a clean machine."""
    path = tmp_path / "altro.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")

    with pytest.raises(ValueError, match="installedSoftware"):
        read_snapshot(path)


def test_a_missing_file_is_reported_as_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_snapshot(tmp_path / "nope.json")


# ── families: rows are not products ─────────────────────────────────────────
#
# The registry lists features, not products. On the measured machine, 25 of the
# 147 rows are Python 3.14.7 — Core Interpreter, Standard Library, Test Suite,
# Tcl/Tk, pip Bootstrap, each in three variants — and they are one install.
# Reporting 25 unwatched products would size the work at ten times what it is.

PYTHON_ROWS = [
    "Python 3.14.7 (64-bit)",
    "Python 3.14.7 Core Interpreter (64-bit)",
    "Python 3.14.7 Core Interpreter (64-bit debug)",
    "Python 3.14.7 Core Interpreter (64-bit symbols)",
    "Python 3.14.7 Standard Library (64-bit)",
    "Python 3.14.7 Tcl/Tk Support (64-bit debug)",
    "Python 3.14.7 pip Bootstrap (64-bit)",
    "Python 3.14.7 Test Suite (64-bit symbols)",
]


def test_the_features_of_one_install_are_one_family():
    data = snapshot(*(program(name, "3.14.7", "Python Software Foundation")
                      for name in PYTHON_ROWS))
    result = survey(data)

    assert result.rows == len(PYTHON_ROWS)
    assert result.total == 1, "one install, whatever the registry lists"
    assert result.families[0].rows == len(PYTHON_ROWS)


def test_the_same_product_listed_twice_is_one_family():
    """`TeraCopy version 3.21` and `TeraCopy` are both on the machine: the old
    entry was left behind by the update."""
    result = survey(snapshot(program("TeraCopy version 3.21", "3.21", "Code Sector"),
                             program("TeraCopy", "4.0.3.2", "Code Sector")))
    assert result.total == 1


def test_the_visual_cpp_runtimes_are_one_family_of_components():
    """Thirteen rows on the measured machine. The year in the name is identity
    when mapping a product — `Visual C++ 2012` is not 2008 — but none of these is
    watched on its own, and the family exists so thirteen rows do not read as
    thirteen products."""
    rows = [
        "Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219",
        "Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030",
        "Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.51.36247",
        "Microsoft Visual C++ v14 Redistributable (x64) - 14.51.36247.0",
    ]
    result = survey(snapshot(*(program(n, "1.0", "Microsoft Corporation") for n in rows)))

    assert result.total == 1
    assert result.families[0].confidence is COMPONENT
    assert result.components == 1


def test_a_family_is_as_watchable_as_its_best_row():
    """`Python 3.14.7 (64-bit)` is the product and the rest are its features: if
    one row of a family can be watched, the family can."""
    data = snapshot(program("Google Chrome", "154.0.8037.58", "Google LLC"),
                    program("Google Update Helper", "1.3.33.5", "Google Inc."))
    result = survey(data)

    assert result.total == 2, "the helper is not a feature of Chrome's own entry"
    assert result.certain == 1
    assert result.components == 1


def test_the_biggest_families_are_named_so_nothing_hides_behind_a_count():
    data = snapshot(*(program(name, "3.14.7", "Python Software Foundation")
                      for name in PYTHON_ROWS),
                    program("Google Chrome", "154.0", "Google LLC"))
    biggest = survey(data).largest_families(1)

    assert len(biggest) == 1
    assert biggest[0].rows == len(PYTHON_ROWS)
    assert "python" in biggest[0].key


# ── the driver package, which arrives as two dozen rows ─────────────────────

NVIDIA_PLUMBING = [
    "NVIDIA Container", "NVIDIA Backend", "NVIDIA LocalSystem Container",
    "NVIDIA Message Bus for NvContainer", "NVIDIA NVAPI Monitor plugin for NvContainer",
    "NVIDIA Watchdog Plugin for NvContainer", "NVIDIA TelemetryApi helper for NvContainer",
    "NvModuleTracker", "NVIDIA Telemetry Client", "NVIDIA Update Core",
    "Aggiornamenti NVIDIA 39.2.2.0", "NVIDIA Virtual Host Controller",
    "NVIDIA Virtual Audio 4.39.0.0", "NVIDIA NodeJS", "NVIDIA SHIELD Streaming",
    "NVIDIA GPX Common OSS binaries (POCO, OpenSSL, libprotobuf)",
    "NVIDIA FrameView SDK 1.2.7704.31296923", "Nvidia Share",
    "NVIDIA ShadowPlay 3.24.0.135", "NVIDIA Install Application",
]

NVIDIA_PRODUCTS = [
    "NVIDIA Driver grafico 475.14",
    "NVIDIA GeForce Experience 3.24.0.135",
    "NVIDIA Driver audio HD 1.3.38.60",
]


@pytest.mark.parametrize("name", NVIDIA_PLUMBING)
def test_the_pieces_of_a_driver_package_are_components(name):
    """Twenty-eight NVIDIA rows on the measured machine, of which three are
    products. Containers, plugins, telemetry clients and update cores all arrive
    inside the driver package and leave with it — none is patched on its own, and
    counting them as unwatched products invents twenty-five jobs."""
    assert classify(program(name, "1.0", "NVIDIA Corporation")).confidence is COMPONENT


@pytest.mark.parametrize("name", NVIDIA_PRODUCTS)
def test_the_driver_itself_is_a_product(name):
    """The rule has to stop somewhere: a graphics driver has its own bulletins
    and its own version, and so does GeForce Experience."""
    assert classify(program(name, "475.14", "NVIDIA Corporation")).confidence is not COMPONENT


def test_the_container_rule_needs_the_publisher():
    """"Container" in a name is not evidence of anything on its own: Docker
    Desktop would qualify."""
    assert classify(program("Docker Container Tools", "1.0", "Docker Inc.")).confidence is not COMPONENT
