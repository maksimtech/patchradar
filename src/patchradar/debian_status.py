"""
What Debian's own position on a CVE is, and therefore what we can do about it.

The collectors ask the security tracker one question — "is this package still
affected in trixie?" — and throw away the answer to a more useful one: *why* it
is still affected, and whether anyone is going to change that. Those are
different situations with different next steps, and the tracker distinguishes
them in fields `collectors/debian.py` reads past: `fixed_version`, `nodsa`,
`nodsa_reason` and `debianbug`, plus the status in the other suites.

Five positions, five next steps:

    resolved        Debian fixed it here. A scanner still reporting it is reading
                    an image older than the update, so the work is ours.
    fix-elsewhere   Fixed in sid or testing, open in trixie. A fix exists and can
                    be asked for — this is the only case where chasing Debian has
                    a defined ending.
    point-release   Filed as no-dsa, and the note says the fix reaches this
                    release in the next point release instead of as a security
                    update. Waiting *does* end, at a dated event: rebuild after
                    it. Reading this as a refusal is the expensive mistake, and
                    it is the actual standing of attr and acl in trixie.
    no-dsa          Debian looked and decided not to update this release. Waiting
                    has no ending; the choice is to record it or drop the package.
    open            No fix in any suite. Nothing to ask for yet. What moves it is
                    evidence on the bug, not another rebuild.
    undetermined    Nobody has established whether this release is affected. Not
                    a wait at all: an unanswered question, and the one case where
                    an afternoon of ours settles something upstream.

The module is pure: it reads a snapshot (`collectors.debian.get_tracker_snapshot`
returns one) and computes. Nothing here downloads, caches or prints.

Two things it deliberately does not do. It does not turn `urgency` into a
severity — `collectors/debian.py` already owns that mapping, and "not yet
assigned" covers most of the tracker anyway. And it does not read a missing
release entry as "not affected": the collector was bitten by exactly that
inference, and silence from the tracker is silence, reported as `untracked`.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

__all__ = ["Position", "Standing", "standings"]

BUG_URL = "https://bugs.debian.org/{bug}"
TRACKER_URL = "https://security-tracker.debian.org/tracker/{cve}"

# The suites a fix can arrive in before it reaches a stable release, in the order
# a fix travels: unstable first, then testing. Anything else in `releases` is
# another stable suite, and a fix there says nothing about ours.
_UPSTREAM_SUITES = ("sid", "forky", "trixie", "bookworm")

_RESOLVED = "resolved"
_UNDETERMINED = "undetermined"

# `nodsa_reason` is a controlled vocabulary of two words plus empty, and the two
# words are opposite verdicts: `postponed` is "later", `ignored` is "never".
_POSTPONED = "postponed"
_IGNORED = "ignored"

# `nodsa` itself is free text. Debian's standard phrasing for "the fix is coming,
# through the point release rather than through a security update" contains this,
# in both wordings seen in the tracker ("…then point release update; not to be
# backported by individual patches" and "Minor issue; can be fixed in point
# release"). A phrase match can miss, so it only ever *upgrades* the reading from
# no-dsa: an unrecognised note stays the stricter answer, quoted verbatim.
_POINT_RELEASE_PHRASE = "point release"


class Position(StrEnum):
    """Debian's standing on one CVE in one package in one release."""

    RESOLVED = "resolved"
    FIX_ELSEWHERE = "fix-elsewhere"
    POINT_RELEASE = "point-release"
    NO_DSA = "no-dsa"
    OPEN = "open"
    UNDETERMINED = "undetermined"
    UNTRACKED = "untracked"


@dataclass(frozen=True)
class Standing:
    """One (package, CVE, release) triple, as the tracker describes it."""

    cve: str
    package: str
    release: str
    position: Position
    status: str = ""
    urgency: str = ""
    in_release: str | None = None
    fixed_here: str | None = None
    fixed_elsewhere: dict[str, str] = field(default_factory=dict)
    nodsa: str | None = None
    nodsa_reason: str | None = None
    debian_bug: int | None = None
    scope: str = ""
    description: str = ""

    @property
    def bug_url(self) -> str | None:
        return BUG_URL.format(bug=self.debian_bug) if self.debian_bug else None

    @property
    def tracker_url(self) -> str:
        return TRACKER_URL.format(cve=self.cve)

    def _bug_clause(self) -> str:
        """Where evidence about this flaw goes — a noun phrase, always.

        Without a bug this returned a whole sentence, "No Debian bug is recorded;
        the tracker page is …", and both callers put it after a preposition. What
        came out was two sentences spliced together:

            What moves it is evidence on No Debian bug is recorded; the tracker
            page is https://security-tracker.debian.org/tracker/CVE-2026-102010

        Read on 2026-09-30 while writing exeradar's record of CVE-2026-102010,
        which is where these sentences end up: they are quoted into
        SECURITY-EXCEPTIONS.toml as the reason a finding is accepted.
        """
        if self.debian_bug:
            return f"Debian bug {self.debian_bug} ({self.bug_url})"
        return f"the tracker page, {self.tracker_url}, since no Debian bug is recorded"

    def _elsewhere_clause(self) -> str:
        return ", ".join(f"{suite} {version}"
                         for suite, version in self.fixed_elsewhere.items())

    def action(self) -> str:
        """What can be done about it — one sentence, and never "wait" alone."""
        if self.position is Position.RESOLVED:
            return (
                f"Debian fixed it in {self.package} {self.fixed_here} for "
                f"{self.release}. A scanner still reporting it is reading an "
                f"image built before that update: rebuild and republish."
            )
        if self.position is Position.POINT_RELEASE:
            fixed = self._elsewhere_clause()
            where = f" — it is already in {fixed}" if fixed else ""
            return (
                f"Debian is not issuing a security update, because the fix reaches "
                f"{self.release} in the next point release instead{where}. This "
                f"waiting has an end and a date: watch for the point release, then "
                f"rebuild. Nothing to ask for, and no individual backport to "
                f'request — Debian says "{self.nodsa}". {self._bug_clause()}.'
            )
        if self.position is Position.NO_DSA:
            decided = self.nodsa or "no reason given"
            fixed = self._elsewhere_clause()
            tail = (
                f" A fix does exist in {fixed}, and Debian has chosen not to "
                f"carry it into {self.release}, so asking for a stable update "
                f"has already been answered."
                if fixed else
                " There is no fix in any suite either."
            )
            if self.nodsa_reason == _IGNORED:
                verdict = (
                    f"Debian has marked it ignored for {self.release}: it will not "
                    f"be fixed here at all. The note usually says why the package "
                    f"is not really exposed, and it is worth reading before "
                    f"treating this as an open risk."
                )
            elif self.nodsa_reason == _POSTPONED:
                verdict = (
                    f"Debian has postponed it for {self.release}: a fix is "
                    f"intended, with no date and no security update. Not a refusal, "
                    f"but not something to hold a release for either."
                )
            else:
                verdict = (
                    f"Debian will not issue an update for {self.release}, and has "
                    f"not classified it further. Waiting for one is not a plan "
                    f"that ends."
                )
            return (
                f'{verdict} Debian says "{decided}".{tail} Record it with a review '
                f"date, or stop shipping the package. {self._bug_clause()}."
            )
        if self.position is Position.FIX_ELSEWHERE:
            return (
                f"A fix exists in {self._elsewhere_clause()} and not in "
                f"{self.release}. This is the one case worth chasing: ask for a "
                f"stable update on {self._bug_clause()}, naming the "
                f"version that already carries the fix."
            )
        if self.position is Position.UNDETERMINED:
            return (
                f"Nobody has established whether {self.release} is affected — the "
                f"tracker says undetermined, not fixed and not vulnerable. This is "
                f"ours to settle: check the version we ship against the flaw and "
                f"say so on {self._bug_clause()}."
            )
        if self.position is Position.OPEN:
            return (
                f"No fix in any suite, so there is nothing to ask for and nothing "
                f"to wait for. What moves it is evidence on {self._bug_clause()} — "
                f"a reachability note, a reproducer, or the upstream patch."
            )
        return (
            f"The tracker says nothing about {self.package or 'any package'} and "
            f"{self.cve}. Either the scanner named a binary package where Debian "
            f"names the source one, or Debian has not triaged it: check "
            f"{self.tracker_url}."
        )

    def describe(self) -> str:
        parts = [f"{self.cve}  {self.package or '?'}  {self.release}  "
                 f"[{self.position.value}]"]
        if self.in_release:
            parts.append(f"  installed in {self.release}: {self.in_release}")
        if self.urgency:
            parts.append(f"  urgency: {self.urgency}")
        if self.fixed_here:
            parts.append(f"  fixed here: {self.fixed_here}")
        if self.fixed_elsewhere:
            parts.append(f"  fixed elsewhere: {self._elsewhere_clause()}")
        if self.nodsa_reason:
            parts.append(f"  no-dsa reason: {self.nodsa_reason}")
        parts.append(f"  → {self.action()}")
        return "\n".join(parts)


def _version_in(node: Mapping, release: str) -> str | None:
    """The version of the package in that release, from `repositories`.

    The tracker keys `repositories` by suite, but not always by the suite name we
    asked for (`trixie` against `trixie-security`, for one). With a single entry
    there is no ambiguity to resolve.
    """
    repositories = node.get("repositories")
    if not isinstance(repositories, Mapping) or not repositories:
        return None
    for suite, version in repositories.items():
        if suite == release:
            return version
    if len(repositories) == 1:
        return next(iter(repositories.values()))
    for suite, version in repositories.items():
        if suite.startswith(release):
            return version
    return None


def _fixes_elsewhere(releases: Mapping, release: str) -> dict[str, str]:
    """Suites other than ours that carry a fix, nearest-to-unstable first."""
    found: dict[str, str] = {}
    ordered = [s for s in _UPSTREAM_SUITES if s in releases and s != release]
    ordered += [s for s in releases if s not in _UPSTREAM_SUITES and s != release]
    for suite in ordered:
        node = releases.get(suite)
        if not isinstance(node, Mapping):
            continue
        fixed = node.get("fixed_version")
        if node.get("status") == _RESOLVED and fixed:
            found[suite] = fixed
    return found


def _position_of(node: Mapping, fixed_here: str | None, nodsa: str | None,
                 fixed_elsewhere: Mapping) -> Position:
    status = node.get("status", "")
    if status == _RESOLVED:
        return Position.RESOLVED
    # `nodsa` before anything else that is still open: it is a decision, and a
    # decision outranks the observation that a fix exists somewhere. The fix is
    # still reported, because a request that has already been refused should not
    # be made twice.
    if nodsa is not None:
        if _POINT_RELEASE_PHRASE in nodsa.lower():
            return Position.POINT_RELEASE
        return Position.NO_DSA
    if status == _UNDETERMINED:
        return Position.UNDETERMINED
    if fixed_elsewhere:
        return Position.FIX_ELSEWHERE
    if fixed_here:
        # Open with a version named: the tracker does this while an upload is in
        # flight. A fix exists by name, which is the actionable part.
        return Position.FIX_ELSEWHERE
    return Position.OPEN


def _standing(cve: str, package: str, entry: Mapping, release: str) -> Standing:
    raw_releases = entry.get("releases")
    releases: Mapping = raw_releases if isinstance(raw_releases, Mapping) else {}
    node = releases.get(release)
    # The six shared fields are written out in both returns below rather than
    # splatted from one dict: `**common` hides the field types from the checker,
    # which then cannot tell `debian_bug: int | None` from `scope: str`.
    bug = entry.get("debianbug")
    debian_bug = bug if isinstance(bug, int) else None
    scope = str(entry.get("scope") or "")
    description = str(entry.get("description") or "")

    if not isinstance(node, Mapping):
        # Silence, not absolution. Whether this release is affected is unknown
        # here, and saying "not affected" would invent the answer.
        return Standing(
            cve=cve, package=package, release=release,
            position=Position.UNTRACKED,
            debian_bug=debian_bug, scope=scope, description=description,
        )

    fixed_here = node.get("fixed_version") or None
    raw_nodsa = node.get("nodsa")
    nodsa = str(raw_nodsa) if raw_nodsa is not None else None
    elsewhere = _fixes_elsewhere(releases, release)
    reason = node.get("nodsa_reason")
    return Standing(
        cve=cve, package=package, release=release,
        position=_position_of(node, fixed_here, nodsa, elsewhere),
        status=str(node.get("status") or ""),
        urgency=str(node.get("urgency") or ""),
        in_release=_version_in(node, release),
        fixed_here=fixed_here,
        fixed_elsewhere=elsewhere,
        nodsa=nodsa,
        nodsa_reason=str(reason) if reason is not None else None,
        debian_bug=debian_bug, scope=scope, description=description,
    )


def standings(data: Mapping, cve: str, *, release: str,
              package: str | None = None) -> list[Standing]:
    """Debian's position on `cve` in `release`, one entry per source package.

    A CVE can affect several source packages, and they can be in different
    positions — zlib open while minizip is fixed. Returning one of them would be
    choosing an answer, so all of them come back. `package` narrows it when the
    caller already knows which one a scanner named.

    The result is never empty: a CVE the tracker does not carry comes back as a
    single `untracked` standing, because "no rows" and "Debian has not triaged
    it" read the same at a call site and mean very different things.
    """
    found = [
        _standing(cve, name, entry, release)
        for name, entries in data.items()
        if isinstance(entries, Mapping)
        and (package is None or name == package)
        and isinstance(entry := entries.get(cve), Mapping)
    ]
    if found:
        return sorted(found, key=lambda s: s.package)
    return [Standing(cve=cve, package=package or "", release=release,
                     position=Position.UNTRACKED)]
