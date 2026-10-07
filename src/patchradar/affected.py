"""Which versions a CVE affects, and where NVD says it was fixed.

The data is already in the payload the NVD collector downloads, in the
`cpeMatch` nodes of `configurations`, and until now nothing read it: a scan could
say a CVE mentions Notepad++ and not whether 8.9.8 is one of the versions it
affects. The shapes below were all observed on real payloads (Notepad++ 21 CVEs,
QNAP QTS 5.1.0 23 CVEs):

    versionEndExcluding: 8.9.6.4                       fixed in 8.9.6.4
    versionEndIncluding: 8.5.6                         last affected 8.5.6
    versionStartIncluding 8.9.4 + EndExcluding 8.9.6   8.9.4 <= v < 8.9.6
    criteria ...:notepad\\+\\+:8.9.3:*:*                that version only
    vulnerable: false                                  not an affected entry

**The distinction the honesty of the answer rests on.** `versionEndExcluding: X`
*is* the fixed version: NVD states the flaw is absent from X on. It is the only
form from which "fixed in" may be asserted. `versionEndIncluding: X` says only
that X is the last affected one — the release that fixed it exists and NVD does
not name it, so deducing "fixed in 8.5.7" from `versionEndIncluding: 8.5.6`
would publish a version number no source ever stated. There `fixed_version`
stays None and the note says what is actually known.

**A zero is not an absolution.** Notepad++ 8.9.8 has no CVE in NVD and five
vulnerabilities its author declared in the 8.9.8.1 release notes — a UAC
operation performed without verifying the caller among them — none of which was
ever assigned an identifier. `Summary.caveat` carries that sentence so a caller
cannot print "no known vulnerabilities" without it.

Not wired into the scan yet, and deliberately: "fixed in X" is a fact about a
product, and a keyword scan has neither a CPE nor an installed version to ask
about. That needs the watchlist columns of the versionradar design (§5) —
`cpe`, `installed_version`. This module is the half of the feature that can be
written and tested before the migration, and `tests/test_priority_wiring.py`
holds the boundary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from patchradar.collectors.nvd import CVSS_METRIC_KEYS, scoring_entry
from patchradar.cvss import severity_for

# A dotted numeric version, optionally ending in lower-case letters the way
# OpenSSL numbered its releases before 3.0: 1.1.1t, then 1.1.1u, and after
# 1.0.2z came 1.0.2za. NVD records those fixes as they are written
# (`versionEndExcluding: 1.1.1u`), and refusing them answered "not affected" for
# every lettered 1.0.2 and 1.1.1 release. The letters are ordered as text, which is
# the order OpenSSL released them in. No other suffix: none of the sources read
# here put `-rc1` in a fixed version, and accepting one would mean inventing an
# order between rc1 and rc2 that no source confirms.
_NUMERIC = re.compile(r"^(\d+(?:\.\d+)*)([a-z]*)$")

# The CPE wildcards. `*` is ANY and `-` is NA; neither is a low version number,
# and treating them as one is how a range comes to match everything.
_NOT_A_VERSION = {"*", "-", ""}

# Two versions whose component counts differ by more than this, and whose first
# components differ too, are treated as belonging to different schemes and are
# not ordered. `2.07` (a ThinkPad BIOS) against `16.0.14334.20918` (an Office
# build) is not a comparison with a wrong answer, it is a comparison with no
# meaning; `8.9.6` against `8.9.6.4` happens inside one scheme and must work.
# So must `8.9` against `8.9.6.4`: a shared major version is one scheme however
# many components either side writes, and refusing it answered "not affected"
# for a version older than the fix.
_SCHEME_TOLERANCE = 1


# One (number, letters) pair per component. Only the last can carry letters,
# and "" sorts before "a", so 1.1.1 < 1.1.1a < 1.1.1z < 1.1.1za < 1.1.2.
_Version = tuple[tuple[int, str], ...]


def _parts(text: object) -> _Version | None:
    """The version as (number, letters) pairs, or None when the text is not a version.

    Private on purpose. The tolerant reader for what Windows writes into the
    registry — '5, 1, 2, 3000', '2010' with a service pack, '1.7.0' with its
    update in a separate field — lives on the `feature/version-gap` branch as
    `versions.py`, and when that lands this should defer to it rather than grow
    a second dialect.
    """
    if not isinstance(text, str):
        return None
    cleaned = text.strip()
    found = _NUMERIC.match(cleaned)
    if cleaned in _NOT_A_VERSION or not found:
        return None
    numbers = [int(chunk) for chunk in found.group(1).split(".")]
    letters = [""] * (len(numbers) - 1) + [found.group(2)]
    return tuple(zip(numbers, letters, strict=True))


def _comparable(left: _Version, right: _Version) -> tuple[_Version, _Version] | None:
    if abs(len(left) - len(right)) > _SCHEME_TOLERANCE and left[0][0] != right[0][0]:
        return None
    width = max(len(left), len(right))
    zero = ((0, ""),)
    return left + zero * (width - len(left)), right + zero * (width - len(right))


@dataclass(frozen=True)
class Range:
    """A span of affected versions, in the terms NVD expressed it.

    `end_inclusive` is what separates "fixed in X" from "X is the last one
    known to be affected", so it is kept rather than normalised away.
    """

    exact: str | None = None
    start: str | None = None
    start_inclusive: bool = True
    end: str | None = None
    end_inclusive: bool = False
    # No exact, no start, no end: NVD naming the product with a `*` version,
    # which means every version of it.
    unbounded: bool = False

    def contains(self, version: str) -> bool:
        have = _parts(version)
        if have is None:
            return False
        if self.exact is not None:
            other = _parts(self.exact)
            if other is None:
                return False
            pair = _comparable(have, other)
            return pair is not None and pair[0] == pair[1]
        if self.unbounded:
            return True

        for bound, inclusive, below in ((self.start, self.start_inclusive, True),
                                        (self.end, self.end_inclusive, False)):
            if bound is None:
                continue
            limit = _parts(bound)
            if limit is None:
                return False
            pair = _comparable(have, limit)
            if pair is None:
                # Different version schemes: not a match, and not an error.
                return False
            mine, theirs = pair
            if below:
                if mine < theirs or (not inclusive and mine == theirs):
                    return False
            elif mine > theirs or (not inclusive and mine == theirs):
                return False
        return True

    def describe(self) -> str:
        if self.exact is not None:
            return f"only {self.exact}"
        if self.unbounded:
            return "every version"
        bounds = []
        if self.start is not None:
            bounds.append(f"{'>=' if self.start_inclusive else '>'} {self.start}")
        if self.end is not None:
            bounds.append(f"{'<=' if self.end_inclusive else '<'} {self.end}")
        return " and ".join(bounds)

    @property
    def fixed_version(self) -> str | None:
        """The version that fixes it, only where NVD states one.

        `versionEndExcluding` yes; `versionEndIncluding` no, because it names the
        last affected release and not the first sound one.
        """
        return self.end if (self.end is not None and not self.end_inclusive) else None


@dataclass(frozen=True)
class Hit:
    """One CVE that affects the version asked about."""

    cve: str
    score: float | None
    cvss_version: str | None
    severity: str
    published: str
    fixed_version: str | None
    affected_range: str
    note: str
    description: str = ""


@dataclass(frozen=True)
class Summary:
    """The answer in the form a report prints it."""

    version: str
    total: int
    worst: float | None
    target: str | None
    closed_by_target: int
    unresolved: int
    caveat: str
    hits: tuple[Hit, ...] = ()


# Said whether or not anything was found: a count of zero from NVD means no one
# requested an identifier, which is not the same as nothing being wrong.
CAVEAT = (
    "counted in NVD only. A CVE exists when someone asked for an identifier: "
    "Notepad++ 8.9.8 has none in NVD and five vulnerabilities its author "
    "declared in the 8.9.8.1 release notes."
)


def _score_of(cve: dict) -> tuple[float | None, str | None, str]:
    """(score, cvss version, severity), reading the metrics in the same order
    the NVD collector does — two parts of one tool must not disagree about which
    metric counts."""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None, None, "UNKNOWN"
    for key in CVSS_METRIC_KEYS:
        entry = scoring_entry(metrics.get(key))
        if entry is None:
            continue
        # Bound before the check, so the narrowing applies to what is read below.
        raw = entry.get("cvssData")
        data = raw if isinstance(raw, dict) else {}
        score = data.get("baseScore")
        version = data.get("version")
        severity = entry.get("baseSeverity") or data.get("baseSeverity")
        # Derived rather than guessed: `cvss.severity_for` is the one place that
        # knows the v2 and v3 scales are different and that v4 has its own.
        return score, version, (severity or severity_for(score, version))
    return None, None, "UNKNOWN"


def ranges_in(cve: dict, *, vendor: str, cpe_product: str | None = None) -> list[Range]:
    """The affected ranges this CVE declares for that vendor, and product.

    `cpe_product` is the product field of the CPE in its escaped form — the
    `notepad\\+\\+` that the API wants, not the `Notepad++` a person reads.
    Passing the readable name raises nothing and matches nothing, which reads as
    "no vulnerabilities".
    """
    found: list[Range] = []
    for configuration in cve.get("configurations") or []:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for entry in node.get("cpeMatch") or []:
                if not isinstance(entry, dict) or not entry.get("vulnerable", False):
                    # `vulnerable: false` describes the context in which another
                    # component is vulnerable. On CVE-2017-8803 the Notepad++
                    # node is exactly that, and counting it reports a CVE that
                    # does not concern the program.
                    continue
                fields = str(entry.get("criteria", "")).split(":")
                if len(fields) < 6 or fields[3] != vendor:
                    continue
                if cpe_product is not None and fields[4] != cpe_product:
                    continue

                start = entry.get("versionStartIncluding") or entry.get("versionStartExcluding")
                end = entry.get("versionEndIncluding") or entry.get("versionEndExcluding")
                if start is None and end is None:
                    version = fields[5]
                    found.append(Range(exact=version) if version not in _NOT_A_VERSION
                                 else Range(unbounded=True))
                    continue
                found.append(Range(
                    start=start,
                    start_inclusive="versionStartIncluding" in entry,
                    end=end,
                    end_inclusive="versionEndIncluding" in entry,
                ))
    return found


def _note_for(span: Range) -> str:
    if span.fixed_version:
        return f"NVD states the fix is in {span.fixed_version}"
    if span.end is not None and span.end_inclusive:
        return (f"last affected version {span.end}; NVD does not state which "
                f"release fixed it")
    return "no fixed version stated"


def affects(payload: dict, *, version: str, vendor: str,
            cpe_product: str | None = None) -> list[Hit]:
    """The CVEs in an NVD payload that affect `version`, worst first.

    An unscored CVE sorts last rather than as a zero: no score is not a low
    score, and it is the state 708 of the 806 CVEs a keyword scan for Chrome
    returned were in.
    """
    hits: list[Hit] = []
    for item in payload.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict):
            continue
        for span in ranges_in(cve, vendor=vendor, cpe_product=cpe_product):
            if not span.contains(version):
                continue
            score, cvss_version, severity = _score_of(cve)
            description = next((d.get("value", "") for d in cve.get("descriptions") or []
                                if isinstance(d, dict) and d.get("lang") == "en"), "")
            hits.append(Hit(
                cve=str(cve.get("id", "")),
                score=score,
                cvss_version=cvss_version,
                severity=severity,
                published=str(cve.get("published", ""))[:10],
                fixed_version=span.fixed_version,
                affected_range=span.describe(),
                note=_note_for(span),
                description=description,
            ))
            # One CVE is counted once, however many of its nodes match.
            break
    return sorted(hits, key=lambda hit: (hit.score is not None, hit.score or 0.0), reverse=True)


def target_version(hits: list[Hit]) -> str | None:
    """The highest fix any of them declares: where to go to close what can be
    closed with one update. None when nobody declares one — and then no number
    is invented."""
    candidates = [(parts, hit.fixed_version) for hit in hits
                  if hit.fixed_version and (parts := _parts(hit.fixed_version)) is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda pair: pair[0])[1]


def summarise(payload: dict, *, version: str, vendor: str,
              cpe_product: str | None = None) -> Summary:
    """What a report prints: how many, how bad, and what one update closes.

    `closed_by_target` and `unresolved` are separate numbers because they answer
    different questions. The ones left open are open because NVD does not state
    where they were fixed, not because the update is insufficient — and a single
    "3 of 10" without that distinction invites the opposite reading.
    """
    hits = affects(payload, version=version, vendor=vendor, cpe_product=cpe_product)
    target = target_version(hits)
    closed = 0
    if target is not None:
        goal = _parts(target)
        for hit in hits:
            fix = _parts(hit.fixed_version) if hit.fixed_version else None
            if fix is None or goal is None:
                continue
            pair = _comparable(fix, goal)
            if pair is not None and pair[0] <= pair[1]:
                closed += 1
    scores = [hit.score for hit in hits if hit.score is not None]
    return Summary(
        version=version,
        total=len(hits),
        worst=max(scores) if scores else None,
        target=target,
        closed_by_target=closed,
        unresolved=len(hits) - closed,
        caveat=CAVEAT,
        hits=tuple(hits),
    )
