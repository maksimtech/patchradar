"""
PatchRadar — what Debian's own position is, and therefore what we can do.

"We do not release until Debian fixes it" is a policy that cannot end: Debian
marks `CVE-2026-85091` in zlib *not fixed*, and may formally decide never to fix
it in a stable release. Waiting on that means never shipping our own fixes again.

The way out is not to wait harder but to know which kind of open a finding is.
The tracker says so, in fields the collector reads past — and the five kinds have
five different next steps:

    resolved        fixed here; a scanner still reporting it is reading an old image
    fix-elsewhere   fixed in sid, open in trixie → ask for a stable update
    no-dsa          Debian decided not to update this release → waiting will not end
    open            no fix anywhere → follow the bug, or put evidence on it
    undetermined    nobody checked whether this release is affected → we can settle it

`undetermined` is the one worth spending a person on: it is not a wait, it is an
unanswered question, and answering it is a contribution upstream rather than a
complaint about upstream.

The fixtures carry the real shape, read from the live tracker on 2026-09-29: the
per-release fields it emits are exactly `status`, `repositories`, `urgency`,
`fixed_version`, `nodsa` and `nodsa_reason`.
"""
from __future__ import annotations

import pytest

from patchradar.debian_status import Position, standings

TRIXIE = "trixie"


def tracker(**packages) -> dict:
    return packages


def entry(releases: dict, *, bug: int | None = 1146895, scope: str = "local") -> dict:
    out: dict = {"description": "a flaw", "releases": releases}
    if bug is not None:
        out["debianbug"] = bug
    if scope:
        out["scope"] = scope
    return out


def release(status: str = "open", *, urgency: str = "not yet assigned",
            repo: str | None = "1.2-3", **extra) -> dict:
    node: dict = {"status": status, "urgency": urgency}
    if repo:
        node["repositories"] = {"whatever": repo}
    node.update(extra)
    return node


# ── the five positions ──────────────────────────────────────────────────────

def test_open_everywhere_is_open():
    """zlib CVE-2026-85091 on 2026-09-29: open in bookworm, trixie, sid and
    forky, with no fixed_version anywhere."""
    data = tracker(zlib={"CVE-2026-85091": entry({
        "trixie": release("open"), "sid": release("open"),
    })})
    found = standings(data, "CVE-2026-85091", release=TRIXIE)

    assert len(found) == 1
    assert found[0].position is Position.OPEN
    assert found[0].package == "zlib"


def test_a_fix_in_another_suite_is_not_the_same_as_no_fix():
    """The difference that decides whether there is anything to ask for."""
    data = tracker(acl={"CVE-1": entry({
        "trixie": release("open"),
        "sid": release("resolved", fixed_version="2.3.2-2"),
    })})
    found = standings(data, "CVE-1", release=TRIXIE)[0]

    assert found.position is Position.FIX_ELSEWHERE
    assert found.fixed_elsewhere == {"sid": "2.3.2-2"}


def test_a_decision_not_to_update_is_its_own_answer():
    """`nodsa` means Debian looked and chose. Reporting it as plain `open` invites
    a wait that will not end."""
    data = tracker(perl={"CVE-1": entry({
        "trixie": release("open", nodsa="Minor issue", nodsa_reason="postponed"),
    })})
    found = standings(data, "CVE-1", release=TRIXIE)[0]

    assert found.position is Position.NO_DSA
    assert found.nodsa == "Minor issue"
    assert found.nodsa_reason == "postponed"


def test_a_fix_promised_for_the_next_point_release_is_not_a_refusal():
    """The real wording on attr and acl, read on 2026-09-29. It is filed as
    `no-dsa`, which reads like a refusal, and says the opposite: the fix is in
    unstable and will reach trixie in a point release rather than as a security
    update. That waiting has an end, so it is not the same answer as `no-dsa`."""
    data = tracker(attr={"CVE-2026-54371": entry({
        "trixie": release("open", nodsa=(
            "Will be fixed first in unstable, then point release update; "
            "not to be backported by individual patches"), nodsa_reason=""),
        "sid": release("resolved", fixed_version="1:2.6.0-1"),
    }, bug=1141107)})
    found = standings(data, "CVE-2026-54371", release=TRIXIE)[0]

    assert found.position is Position.POINT_RELEASE
    assert found.fixed_elsewhere == {"sid": "1:2.6.0-1"}
    assert "point release" in found.action()
    assert "1141107" in found.action()


def test_wording_we_do_not_recognise_falls_back_to_the_stricter_reading():
    """`nodsa` is free text, so the point-release phrase is a phrase match and
    can miss. Missing it must cost us an unnecessary review, never a fix we
    thought was coming: the fallback is `no-dsa`, and the note is quoted verbatim
    so a person can see what the match did not."""
    data = tracker(attr={"CVE-1": entry({
        "trixie": release("open", nodsa="Some future wording nobody predicted"),
    })})
    found = standings(data, "CVE-1", release=TRIXIE)[0]

    assert found.position is Position.NO_DSA
    assert "Some future wording nobody predicted" in found.action()


def test_postponed_and_ignored_do_not_read_the_same():
    """`nodsa_reason` is a controlled vocabulary — `postponed`, `ignored`, or
    empty — and the two words are opposite verdicts: one is later, one is never.
    Collapsing them would put a review date on something Debian has closed."""
    postponed = standings(tracker(acl={"CVE-1": entry({
        "trixie": release("open", nodsa="Minor issue", nodsa_reason="postponed"),
    })}), "CVE-1", release=TRIXIE)[0].action().lower()
    ignored = standings(tracker(zlib={"CVE-1": entry({
        "trixie": release("open", nodsa="contrib/minizip not built",
                          nodsa_reason="ignored"),
    })}), "CVE-1", release=TRIXIE)[0].action().lower()

    assert "postpone" in postponed
    assert "postpone" not in ignored
    assert postponed != ignored


def test_a_decision_not_to_update_still_reports_a_fix_elsewhere():
    """Both facts matter: there is a fix, and Debian chose not to carry it here.
    Keeping only the first invites a request that has already been refused."""
    data = tracker(perl={"CVE-1": entry({
        "trixie": release("open", nodsa="Minor issue"),
        "sid": release("resolved", fixed_version="5.42.3-1"),
    })})
    found = standings(data, "CVE-1", release=TRIXIE)[0]

    assert found.position is Position.NO_DSA
    assert found.fixed_elsewhere == {"sid": "5.42.3-1"}


def test_resolved_here_is_resolved():
    data = tracker(zlib={"CVE-1": entry({
        "trixie": release("resolved", fixed_version="1:1.3-2"),
    })})
    found = standings(data, "CVE-1", release=TRIXIE)[0]

    assert found.position is Position.RESOLVED
    assert found.fixed_here == "1:1.3-2"


def test_undetermined_is_a_question_nobody_answered():
    data = tracker(attr={"CVE-1": entry({"trixie": release("undetermined")})})
    assert standings(data, "CVE-1", release=TRIXIE)[0].position is Position.UNDETERMINED


def test_a_release_the_tracker_says_nothing_about_is_untracked():
    """Not "not affected". The collector learned this the hard way: treating the
    silence as `open` produced 7,924 phantom vulnerabilities tracker-wide."""
    data = tracker(zlib={"CVE-1": entry({"sid": release("open")})})
    assert standings(data, "CVE-1", release=TRIXIE)[0].position is Position.UNTRACKED


def test_a_cve_the_tracker_does_not_carry_at_all_is_untracked():
    found = standings(tracker(zlib={}), "CVE-NOT-THERE", release=TRIXIE)

    assert len(found) == 1
    assert found[0].position is Position.UNTRACKED
    assert found[0].package == "", "no package can be named for it"


# ── what it says to do ──────────────────────────────────────────────────────

def test_the_action_names_the_bug_when_there_is_one():
    """1146895 for zlib, 1148455 for perl. A bug number is where evidence can be
    added, and adding it is the only thing that moves an unfixed flaw."""
    data = tracker(zlib={"CVE-1": entry({"trixie": release("open")}, bug=1146895)})
    action = standings(data, "CVE-1", release=TRIXIE)[0].action()

    assert "1146895" in action


def test_the_action_for_no_dsa_says_the_waiting_will_not_end():
    data = tracker(perl={"CVE-1": entry({
        "trixie": release("open", nodsa="Minor issue"),
    })})
    action = standings(data, "CVE-1", release=TRIXIE)[0].action().lower()

    assert "not" in action and ("wait" in action or "update" in action)


def test_the_action_for_a_fix_elsewhere_asks_for_the_stable_update():
    data = tracker(acl={"CVE-1": entry({
        "trixie": release("open"), "sid": release("resolved", fixed_version="2.3.2-2"),
    })})
    action = standings(data, "CVE-1", release=TRIXIE)[0].action()

    assert "2.3.2-2" in action
    assert "sid" in action


def test_the_action_for_undetermined_says_it_is_ours_to_settle():
    data = tracker(attr={"CVE-1": entry({"trixie": release("undetermined")})})
    action = standings(data, "CVE-1", release=TRIXIE)[0].action().lower()

    assert "undetermined" in action or "nobody" in action or "establish" in action


def test_the_action_for_resolved_points_at_the_image_and_not_at_debian():
    """A scanner reporting a resolved CVE is reading an image older than the
    update — which is a fact about our publishing, not about Debian."""
    data = tracker(zlib={"CVE-1": entry({
        "trixie": release("resolved", fixed_version="1:1.3-2"),
    })})
    action = standings(data, "CVE-1", release=TRIXIE)[0].action().lower()

    assert "image" in action or "rebuild" in action


# ── finding the package ─────────────────────────────────────────────────────

def test_the_same_cve_in_two_packages_is_two_standings():
    """A CVE can affect several source packages, and they can be in different
    positions. Picking one would be picking an answer."""
    data = tracker(
        zlib={"CVE-1": entry({"trixie": release("open")})},
        minizip={"CVE-1": entry({"trixie": release("resolved", fixed_version="1.2")})},
    )
    found = standings(data, "CVE-1", release=TRIXIE)

    assert {s.package for s in found} == {"zlib", "minizip"}
    assert {s.position for s in found} == {Position.OPEN, Position.RESOLVED}


def test_a_package_can_be_named_to_narrow_it():
    data = tracker(
        zlib={"CVE-1": entry({"trixie": release("open")})},
        minizip={"CVE-1": entry({"trixie": release("open")})},
    )
    found = standings(data, "CVE-1", release=TRIXIE, package="zlib")

    assert [s.package for s in found] == ["zlib"]


def test_naming_a_package_that_does_not_carry_the_cve_says_so():
    data = tracker(zlib={"CVE-1": entry({"trixie": release("open")})})
    found = standings(data, "CVE-1", release=TRIXIE, package="perl")

    assert found[0].position is Position.UNTRACKED
    assert found[0].package == "perl"


@pytest.mark.parametrize("release_name", ["trixie", "sid", "bookworm"])
def test_the_release_is_a_parameter_and_not_a_constant(release_name):
    data = tracker(zlib={"CVE-1": entry({
        "bookworm": release("open"),
        "trixie": release("resolved", fixed_version="1:1.3-2"),
        "sid": release("undetermined"),
    })})
    positions = {
        # Read from bookworm, trixie's fix *is* a fix elsewhere — which is the
        # answer an oldstable user needs, and the reason the suite cannot be a
        # constant in this module: the same entry means three different things
        # depending on where you are standing.
        "bookworm": Position.FIX_ELSEWHERE,
        "trixie": Position.RESOLVED,
        "sid": Position.UNDETERMINED,
    }
    assert standings(data, "CVE-1", release=release_name)[0].position is positions[release_name]


def test_the_urgency_and_the_installed_version_travel_with_it():
    """Both are printed, and neither is turned into a severity here: the
    collector already maps urgency, and "not yet assigned" is 77% of the tracker."""
    data = tracker(zlib={"CVE-1": entry({
        "trixie": release("open", urgency="high", repo="1:1.3.dfsg-1"),
    })})
    found = standings(data, "CVE-1", release=TRIXIE)[0]

    assert found.urgency == "high"
    assert found.in_release == "1:1.3.dfsg-1"
