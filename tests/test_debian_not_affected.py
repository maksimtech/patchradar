"""
PatchRadar — a fixed_version of "0" is the tracker's spelling for "never affected"

Found on 2026-10-09 by asking the real tracker about CVEs a real scan had found:

    $ patchradar debian CVE-2026-90439
    CVE-2026-90439  nginx  resolved
      in trixie: 1.26.3-3+deb13u7   urgency: unimportant
      fixed here: 0
      fixed in bookworm: 0
      → Debian fixed it in nginx 0 for trixie. A scanner still reporting it is
        reading an image built before that update: rebuild and republish.

There is no nginx 0, and nothing to rebuild. The tracker writes `"fixed_version":
"0"` with status resolved for a release whose package was never vulnerable — the
`<not-affected>` of its own data files — and 5,723 of the trixie entries in the
dump of that day say so. Read as a version, it told the reader to go and rebuild
an image that was never exposed, which is the one piece of work this command
exists to spare.

The same dump answered a second question wrongly. CVE-2026-106585 is listed
for openssh and for openssh-gssapi, and the latter is in sid and forky only:

    CVE-2026-106585  openssh-gssapi  untracked
      → The tracker says nothing about openssh-gssapi and CVE-2026-106585.

The tracker says quite a lot about them; what it has no entry for is trixie. The
standing stays `untracked` — silence about a release is not "not affected", as
the collector learned — but the sentence now says which releases the tracker
does list, so a reader can tell "not in this release" from "not triaged".

The fixture is the dump's own entries, verbatim: `debian_tracker_not_affected.json`
says in its `_derived` key what was kept.
"""
from __future__ import annotations

import json
import pathlib

import pytest
from typer.testing import CliRunner

from patchradar.cli import app
from patchradar.debian_status import Position, standings

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "debian_tracker_not_affected.json"


@pytest.fixture
def tracker() -> dict:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert "verbatim" in data.pop("_derived")
    return data


def test_the_recording_says_what_it_claims(tracker):
    """The tests below rely on these three facts about the real entries."""
    nginx = tracker["nginx"]["CVE-2026-90439"]["releases"]
    assert nginx["trixie"] == {**nginx["trixie"], "status": "resolved", "fixed_version": "0"}
    assert nginx["bookworm"]["fixed_version"] == "0"
    assert nginx["sid"]["fixed_version"] == "1.30.4-7"
    assert set(tracker["openssh-gssapi"]["CVE-2026-106585"]["releases"]) == {"sid", "forky"}


# ── never affected ───────────────────────────────────────────────────────────

def test_a_fixed_version_of_zero_is_not_affected(tracker):
    [standing] = standings(tracker, "CVE-2026-90439", release="trixie")
    assert standing.position is Position.NOT_AFFECTED


def test_not_affected_names_no_version_to_rebuild_to(tracker):
    [standing] = standings(tracker, "CVE-2026-90439", release="trixie")
    assert standing.fixed_here is None, "0 is a marker, not a version"
    action = standing.action()
    assert "nginx 0" not in action
    assert "rebuild" not in action.lower()
    assert "never affected" in action or "not affected" in action


def test_a_zero_in_another_suite_is_not_a_fix_elsewhere(tracker):
    """bookworm says 0 too; sid and forky carry a real fixed version."""
    [standing] = standings(tracker, "CVE-2026-90439", release="trixie")
    assert standing.fixed_elsewhere == {"sid": "1.30.4-7", "forky": "1.30.4-7"}


def test_a_real_fixed_version_is_still_resolved(tracker):
    [standing] = standings(tracker, "CVE-2026-106585", release="sid", package="openssh")
    assert standing.position is Position.RESOLVED
    assert standing.fixed_here == "1:10.6p1-1"


def test_the_cli_says_not_affected_and_not_fixed_in_zero(tracker, tmp_path):
    snapshot = tmp_path / "tracker.json"
    snapshot.write_text(json.dumps(tracker), encoding="utf-8")
    result = CliRunner().invoke(app, ["debian", "CVE-2026-90439", "--file", str(snapshot)])
    assert result.exit_code == 0, result.output
    assert "not-affected" in result.output
    assert "nginx 0" not in result.output
    assert "fixed here: 0" not in result.output
    assert "fixed in bookworm: 0" not in result.output


# ── listed, but not for this release ─────────────────────────────────────────

def test_a_package_listed_for_other_releases_is_untracked_here(tracker):
    found = {s.package: s for s in standings(tracker, "CVE-2026-106585", release="trixie")}
    assert found["openssh-gssapi"].position is Position.UNTRACKED
    assert found["openssh"].position is Position.NO_DSA


def test_untracked_says_which_releases_the_tracker_does_list(tracker):
    found = {s.package: s for s in standings(tracker, "CVE-2026-106585", release="trixie")}
    action = found["openssh-gssapi"].action()
    assert "says nothing about openssh-gssapi" not in action
    assert "forky" in action and "sid" in action
    assert "trixie" in action


def test_a_cve_the_tracker_does_not_carry_still_says_so(tracker):
    [standing] = standings(tracker, "CVE-2026-1", release="trixie")
    assert standing.position is Position.UNTRACKED
    assert "says nothing about" in standing.action()
