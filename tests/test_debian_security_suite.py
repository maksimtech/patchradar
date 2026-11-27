"""
PatchRadar — "in trixie" names the version of every suite of the release (#139)

`patchradar debian CVE-2024-30187` printed

    CVE-2024-30187  anope  resolved
      in trixie: 2.0.17-1   urgency: not yet assigned

and the tracker's `repositories` for trixie are `{"trixie": "2.0.17-1",
"trixie-security": "2.0.17-1+deb13u1"}`. A trixie system with the security suite
enabled, as Debian's images are, runs the second one, which the line dropped. In
the dump of 2026-11-26 that was 33,779 of the 83,547 pairs listed for trixie.

"Always take the security suite" would be as wrong the other way: openssl's
point release put 3.5.9 in trixie while trixie-security still has 3.5.7. So the
release's own version stays, and the other suites follow it when they differ.

The fixture is the dump's own entries, verbatim (its `_derived` key says which).
"""
from __future__ import annotations

import json
import pathlib

import pytest
from typer.testing import CliRunner

from patchradar.cli import app
from patchradar.debian_status import standings

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "debian_tracker_security_suite.json"


@pytest.fixture
def tracker() -> dict:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert "verbatim" in data.pop("_derived")
    return data


def test_the_recording_says_what_it_claims(tracker):
    anope = tracker["anope"]["CVE-2024-30187"]["releases"]["trixie"]["repositories"]
    openssl = tracker["openssl"]["CVE-2026-84786"]["releases"]["trixie"]["repositories"]
    assert anope == {"trixie": "2.0.17-1", "trixie-security": "2.0.17-1+deb13u1"}
    assert openssl == {"trixie": "3.5.9-1~deb13u1", "trixie-security": "3.5.7-1~deb13u3"}


def test_the_security_suite_travels_with_the_release_s_version(tracker):
    [found] = standings(tracker, "CVE-2024-30187", release="trixie")
    assert found.in_release == "2.0.17-1"
    assert found.in_other_suites == {"trixie-security": "2.0.17-1+deb13u1"}


def test_an_older_security_suite_is_shown_too_not_preferred(tracker):
    [found] = standings(tracker, "CVE-2026-84786", release="trixie")
    assert found.in_release == "3.5.9-1~deb13u1"
    assert found.in_other_suites == {"trixie-security": "3.5.7-1~deb13u3"}


def test_a_suite_with_the_same_version_is_not_repeated():
    data = {"zlib": {"CVE-1": {"releases": {"trixie": {
        "status": "open", "urgency": "low",
        "repositories": {"trixie": "1:1.3.dfsg-1", "trixie-security": "1:1.3.dfsg-1"}}}}}}
    [found] = standings(data, "CVE-1", release="trixie")
    assert found.in_other_suites == {}


def test_another_release_s_suite_is_not_one_of_ours():
    """`trixie-backports` is trixie's; `trixiefoo` is not, and neither is bookworm-security."""
    data = {"zlib": {"CVE-1": {"releases": {"trixie": {
        "status": "open", "urgency": "low",
        "repositories": {"trixie": "1.0-1", "trixie-backports": "1.1-1~bpo13+1",
                         "trixiefoo": "9-9", "bookworm-security": "0.9-1"}}}}}}
    [found] = standings(data, "CVE-1", release="trixie")
    assert found.in_other_suites == {"trixie-backports": "1.1-1~bpo13+1"}


def test_describe_names_both(tracker):
    [found] = standings(tracker, "CVE-2024-30187", release="trixie")
    assert "installed in trixie: 2.0.17-1 (trixie-security: 2.0.17-1+deb13u1)" in found.describe()


def test_the_cli_names_both(tracker, tmp_path):
    snapshot = tmp_path / "tracker.json"
    snapshot.write_text(json.dumps(tracker), encoding="utf-8")
    result = CliRunner().invoke(app, ["debian", "CVE-2024-30187", "--file", str(snapshot)])
    assert result.exit_code == 0, result.output
    flat = " ".join(result.output.split())
    assert "in trixie: 2.0.17-1 (trixie-security: 2.0.17-1+deb13u1)" in flat
