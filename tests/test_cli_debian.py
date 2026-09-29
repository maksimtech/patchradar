"""
PatchRadar — `debian` answers "what is Debian doing about this, and what can we do".

The command exists because of a decision that could not be made from what we had.
Holding a release "until Debian fixes it" assumes there is a fix coming; for two
of our five Debian findings there is none in any suite, and for the other three
Debian has already said the fix arrives in a point release and not as a security
update. Those are three different plans, and the scanners report all of them the
same way: one line, "no fix available".

The command reads a tracker snapshot, so it must never require the network in a
test. `--file` exists for that, and for a person who wants to ask the same
question twice without downloading 75 MB twice.
"""
from __future__ import annotations

import json

from typer.testing import CliRunner

from patchradar.cli import app

runner = CliRunner()

TRIXIE_OPEN = {
    "status": "open",
    "urgency": "not yet assigned",
    "repositories": {"trixie": "1:1.3.dfsg+really1.3.1-1"},
}


def tracker_file(tmp_path, data) -> str:
    path = tmp_path / "tracker.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_an_open_finding_names_the_debian_bug(tmp_path):
    """zlib CVE-2026-85091 as the tracker held it on 2026-09-29."""
    path = tracker_file(tmp_path, {"zlib": {"CVE-2026-85091": {
        "description": "heap overflow in gzprintf",
        "debianbug": 1146895,
        "releases": {"trixie": TRIXIE_OPEN, "sid": dict(TRIXIE_OPEN)},
    }}})
    result = runner.invoke(app, ["debian", "CVE-2026-85091", "--file", path])

    assert result.exit_code == 0, result.output
    assert "1146895" in result.output
    assert "open" in result.output


def test_a_point_release_finding_says_the_waiting_ends(tmp_path):
    """attr CVE-2026-54371. Reported by Snyk as "no fix available", which is
    true and useless: Debian has scheduled it."""
    path = tracker_file(tmp_path, {"attr": {"CVE-2026-54371": {
        "debianbug": 1141107,
        "releases": {
            "trixie": {"status": "open", "urgency": "not yet assigned",
                       "nodsa": "Will be fixed first in unstable, then point "
                                "release update; not to be backported by "
                                "individual patches", "nodsa_reason": ""},
            "sid": {"status": "resolved", "fixed_version": "1:2.6.0-1",
                    "urgency": "not yet assigned"},
        },
    }}})
    result = runner.invoke(app, ["debian", "CVE-2026-54371", "--file", path])

    assert result.exit_code == 0, result.output
    assert "point-release" in result.output
    assert "1:2.6.0-1" in result.output


def test_several_cves_are_answered_in_one_run(tmp_path):
    path = tracker_file(tmp_path, {
        "zlib": {"CVE-1": {"releases": {"trixie": TRIXIE_OPEN}}},
        "acl": {"CVE-2": {"releases": {"trixie": TRIXIE_OPEN}}},
    })
    result = runner.invoke(app, ["debian", "CVE-1", "CVE-2", "--file", path])

    assert result.exit_code == 0, result.output
    assert "CVE-1" in result.output
    assert "CVE-2" in result.output


def test_a_cve_debian_never_heard_of_is_reported_and_not_swallowed(tmp_path):
    """The quiet failure this command could have: printing nothing and exiting
    0, which reads as "nothing to worry about"."""
    path = tracker_file(tmp_path, {"zlib": {}})
    result = runner.invoke(app, ["debian", "CVE-9999-1", "--file", path])

    assert result.exit_code == 0, result.output
    assert "untracked" in result.output


def test_the_release_can_be_chosen(tmp_path):
    path = tracker_file(tmp_path, {"zlib": {"CVE-1": {"releases": {
        "trixie": TRIXIE_OPEN,
        "bookworm": {"status": "resolved", "fixed_version": "1:1.2.13-1"},
    }}}})
    result = runner.invoke(app, ["debian", "CVE-1", "--file", path,
                                "--release", "bookworm"])

    assert result.exit_code == 0, result.output
    assert "resolved" in result.output
    assert "1:1.2.13-1" in result.output


def test_a_package_can_be_named(tmp_path):
    path = tracker_file(tmp_path, {
        "zlib": {"CVE-1": {"releases": {"trixie": TRIXIE_OPEN}}},
        "minizip": {"CVE-1": {"releases": {"trixie": TRIXIE_OPEN}}},
    })
    result = runner.invoke(app, ["debian", "CVE-1", "--file", path,
                                "--package", "minizip"])

    assert result.exit_code == 0, result.output
    assert "minizip" in result.output
    assert "zlib" not in result.output


def test_a_missing_snapshot_file_is_an_error_and_not_an_empty_answer(tmp_path):
    result = runner.invoke(app, ["debian", "CVE-1", "--file",
                                 str(tmp_path / "nope.json")])

    assert result.exit_code == 2
    assert "nope.json" in result.output


def test_a_snapshot_that_is_not_the_tracker_is_an_error(tmp_path):
    path = tmp_path / "tracker.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    result = runner.invoke(app, ["debian", "CVE-1", "--file", str(path)])

    assert result.exit_code == 2
