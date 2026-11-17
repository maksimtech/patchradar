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

**Wired into both scans**, the CLI's and the API's, for a watchlist entry that
has both an installed version and a CPE (docs/DESIGN.md §5): `judge` gives each
CVE found by name one of three verdicts — affected, not affected, not evaluable
— `mark` applies it to a scan's records, and `closed_by` says what one update
closes. The verdict is stored with the version it was given for (§5.5).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from patchradar.collectors.nvd import CVSS_METRIC_KEYS, scoring_entry
from patchradar.cpe import WILDCARDS, Cpe, split_fields
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


def orderable(version: str) -> bool:
    """Whether `version` is one the ranges can be compared with at all."""
    return _parts(version) is not None


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
    # What else NVD's statement needs, besides the version, that the watchlist
    # cannot confirm: an update or edition the watched CPE does not name ("for
    # update beta"), or another product an AND configuration requires ("on
    # Android"). A range with conditions never makes a version "affected".
    conditions: tuple[str, ...] = ()

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

    def comparable(self, version: str) -> bool:
        """Whether `contains` can give a real answer about `version`.

        `contains` says False both for a version outside the range and for one
        it cannot order against the range — another scheme, or no version at
        all — and only the first is "not affected". This is what tells them
        apart.
        """
        have = _parts(version)
        if have is None:
            return False
        if self.unbounded:
            return True
        bounds = [self.exact] if self.exact is not None else [self.start, self.end]
        for bound in bounds:
            if bound is None:
                continue
            limit = _parts(bound)
            if limit is None or _comparable(have, limit) is None:
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


# The CPE 2.3 fields after the version, by their index in the formatted string,
# and how a reason names a value of each.
_FIELDS = {
    6: lambda v: "for the release with no update" if v == "-" else f"for update {v}",
    7: lambda v: f"for edition {v}",
    8: lambda v: f"for language {v}",
    9: lambda v: "for the standard edition" if v == "-" else f"for the {v} edition",
    10: lambda v: f"for target software {v}",
    11: lambda v: f"for target hardware {v}",
    12: lambda v: f"for {v}",
}

# How the operating systems NVD's AND configurations require are called in a
# reason; any other product is named by its CPE product field.
_PLATFORM_NAMES = {
    "android": "Android", "macos": "macOS", "mac_os_x": "macOS", "mac_os": "macOS",
    "windows": "Windows", "linux_kernel": "Linux", "iphone_os": "iOS", "ipados": "iPadOS",
    "chrome_os": "ChromeOS", "chromeos": "ChromeOS",
}


def _same(fields: list[str], vendor: str, product: str | None) -> bool:
    return (len(fields) >= 6 and fields[3].lower() == vendor
            and (product is None or fields[4].lower() == product))


def _platform(entries: list[dict]) -> str:
    """The products a node lists, as a reason names them: "on Android"."""
    names, systems = [], True
    for entry in entries:
        fields = split_fields(str(entry.get("criteria", "")))
        if len(fields) < 5:
            continue
        product = fields[4].lower()
        name = _PLATFORM_NAMES.get(product, product.replace("\\", "").replace("_", " "))
        systems = systems and fields[2] == "o"
        if name not in names:
            names.append(name)
    listed = " or ".join(names) or "another product"
    return f"on {listed}" if systems else f"with {listed}"


def _field_conditions(fields: list[str], seen: dict[int, set[str]],
                      watched: Cpe | None) -> list[str] | None:
    """What the fields after the version require, or None when the watched CPE
    names a different value: then the statement is about another update or
    edition, and does not apply.

    A specific value (`beta`, `esr`) is always a condition. `-` ("none": the
    release with no update, the standard edition) is one only when the record
    also names the product with another value in that field — Firefox's `-`
    beside `esr`; VS Code's lone `target_sw: -` chooses between nothing.
    """
    conditions = []
    for index, say in _FIELDS.items():
        value = fields[index].lower() if len(fields) > index else "*"
        if value == "*":
            continue
        mine = watched.field(index) if watched is not None else "*"
        if mine != "*":
            if mine != value:
                return None
            continue
        if value == "-" and not (seen.get(index, set()) - WILDCARDS):
            continue
        conditions.append(say(value))
    return conditions


def _ranges(cve: dict, vendor: str, cpe_product: str | None,
            watched: Cpe | None) -> tuple[list[Range], int]:
    """The ranges for that vendor and product, and how many entries were left
    out because the watched CPE names another update or edition."""
    vendor = vendor.lower()
    product = cpe_product.lower() if cpe_product is not None else None
    configurations = [c for c in cve.get("configurations") or [] if isinstance(c, dict)]

    # Which values each field takes across the product's vulnerable entries,
    # which is what makes a `-` a choice between editions or not.
    seen: dict[int, set[str]] = {}
    for configuration in configurations:
        for node in configuration.get("nodes") or []:
            for entry in (node.get("cpeMatch") or []) if isinstance(node, dict) else []:
                if isinstance(entry, dict) and entry.get("vulnerable", False):
                    fields = split_fields(str(entry.get("criteria", "")))
                    if _same(fields, vendor, product):
                        for index in _FIELDS:
                            seen.setdefault(index, set()).add(fields[index].lower() if len(fields) > index else "*")

    found: list[Range] = []
    excluded = 0
    for configuration in configurations:
        nodes = [n for n in configuration.get("nodes") or [] if isinstance(n, dict)]
        joined = str(configuration.get("operator", "")).upper() == "AND"
        for node in nodes:
            entries = [e for e in node.get("cpeMatch") or [] if isinstance(e, dict)]
            node_joined = str(node.get("operator", "")).upper() == "AND"
            for entry in entries:
                if not entry.get("vulnerable", False):
                    # `vulnerable: false` describes the context in which another
                    # component is vulnerable. On CVE-2017-8803 the Notepad++
                    # node is exactly that, and counting it reports a CVE that
                    # does not concern the program.
                    continue
                fields = split_fields(str(entry.get("criteria", "")))
                if not _same(fields, vendor, product):
                    continue
                conditions = _field_conditions(fields, seen, watched)
                if conditions is None:
                    excluded += 1
                    continue
                # An AND of this node with others: Chrome *and* Android. The
                # statement is about the product on, or with, what they list.
                if joined:
                    conditions += [_platform([e for e in other.get("cpeMatch") or [] if isinstance(e, dict)])
                                   for other in nodes if other is not node]
                if node_joined:
                    conditions += [_platform([other]) for other in entries if other is not entry]

                start = entry.get("versionStartIncluding") or entry.get("versionStartExcluding")
                end = entry.get("versionEndIncluding") or entry.get("versionEndExcluding")
                if start is None and end is None:
                    version = fields[5]
                    found.append(Range(exact=version, conditions=tuple(conditions))
                                 if version not in _NOT_A_VERSION
                                 else Range(unbounded=True, conditions=tuple(conditions)))
                    continue
                found.append(Range(
                    start=start,
                    start_inclusive="versionStartIncluding" in entry,
                    end=end,
                    end_inclusive="versionEndIncluding" in entry,
                    conditions=tuple(conditions),
                ))
    return found, excluded


def ranges_in(cve: dict, *, vendor: str, cpe_product: str | None = None,
              watched: Cpe | None = None) -> list[Range]:
    """The affected ranges this CVE declares for that vendor, and product.

    `cpe_product` is the product field of the CPE in its escaped form — the
    `notepad\\+\\+` that the API wants, not the `Notepad++` a person reads.
    Passing the readable name raises nothing and matches nothing, which reads as
    "no vulnerabilities". Vendor and product are compared without regard to
    case, as CPE 2.3 names are matched.

    `watched` is the watchlist entry's CPE: an entry whose update or edition it
    contradicts is left out, and one whose update or edition it does not name
    carries that as a condition (`Range.conditions`), as does one in an AND
    configuration.
    """
    return _ranges(cve, vendor, cpe_product, watched)[0]


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
            # A range with conditions says "affected, if": not a hit
            if span.conditions or not span.contains(version):
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


def _highest_fix(fixed_versions) -> str | None:
    candidates = [(parts, fixed) for fixed in fixed_versions
                  if fixed and (parts := _parts(fixed)) is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda pair: pair[0])[1]


def target_version(hits: list[Hit]) -> str | None:
    """The highest fix any of them declares: where to go to close what can be
    closed with one update. None when nobody declares one — and then no number
    is invented."""
    return _highest_fix(hit.fixed_version for hit in hits)


def closed_by(fixed_versions) -> tuple[str | None, int]:
    """(the update to take, how many of these it closes), from the fixed
    versions of the CVEs that affect a version — None where NVD states none.

    A CVE without a stated fix is never counted as closed: NVD naming its last
    affected release says nothing about which one is sound.
    """
    fixes = list(fixed_versions)
    target = _highest_fix(fixes)
    goal = _parts(target) if target is not None else None
    if goal is None:
        return target, 0
    closed = 0
    for fixed in fixes:
        fix = _parts(fixed) if fixed else None
        if fix is None:
            continue
        pair = _comparable(fix, goal)
        if pair is not None and pair[0] <= pair[1]:
            closed += 1
    return target, closed


def summarise(payload: dict, *, version: str, vendor: str,
              cpe_product: str | None = None) -> Summary:
    """What a report prints: how many, how bad, and what one update closes.

    `closed_by_target` and `unresolved` are separate numbers because they answer
    different questions. The ones left open are open because NVD does not state
    where they were fixed, not because the update is insufficient — and a single
    "3 of 10" without that distinction invites the opposite reading.
    """
    hits = affects(payload, version=version, vendor=vendor, cpe_product=cpe_product)
    target, closed = closed_by(hit.fixed_version for hit in hits)
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


# ─── One CVE found by name, judged against the installed version ─────────────

AFFECTED = "affected"
NOT_AFFECTED = "not affected"
NOT_EVALUABLE = "not evaluable"


@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str
    fixed_version: str | None = None


def judge(record: dict, *, version: str, vendor: str, cpe_product: str,
          watched: Cpe | None = None) -> Verdict:
    """The verdict on one scan record for the installed `version` (DESIGN §5.3).

    The record carries NVD's `configurations` when NVD returned it — an empty
    list when NVD has not analysed the CVE yet — and no such key when it came
    from another source alone. Only a statement NVD made about this product
    decides: anything short of that is "not evaluable", never "not affected".

    Nor "affected": a range that contains the version but holds only on a
    platform, or for an update or edition, the watched CPE (`watched`) does not
    name makes the CVE "not evaluable", with the condition in the reason. The
    watchlist knows the version, not the operating system: Chrome on Windows
    was "affected" by a CVE NVD lists for Chrome on Android only.
    """
    configurations = record.get("configurations")
    if configurations is None:
        return Verdict(NOT_EVALUABLE, "NVD's record of it was not part of this scan")
    if not isinstance(configurations, list) or not configurations:
        return Verdict(NOT_EVALUABLE, "NVD has not yet stated which products it affects")

    spans, excluded = _ranges({"configurations": configurations}, vendor, cpe_product, watched)
    if not spans:
        if excluded:
            return Verdict(NOT_AFFECTED, f"NVD lists {vendor}:{cpe_product} only with an update or "
                                         f"edition other than the one the watched CPE names")
        return Verdict(NOT_AFFECTED, f"NVD lists the products it affects, and "
                                     f"{vendor}:{cpe_product} is not among them")
    conditional = None
    for span in spans:
        if span.contains(version):
            if not span.conditions:
                return Verdict(AFFECTED, _note_for(span), span.fixed_version)
            conditional = conditional or span
    if conditional is not None:
        return Verdict(NOT_EVALUABLE, f"NVD lists it as affecting {version} only "
                                      f"{' and '.join(conditional.conditions)}, which the "
                                      f"watchlist does not record")

    stated = "; ".join(span.describe() for span in spans)
    if not all(span.comparable(version) for span in spans):
        return Verdict(NOT_EVALUABLE, f"NVD's affected versions ({stated}) cannot be "
                                      f"compared with {version}")
    return Verdict(NOT_AFFECTED, f"NVD states the affected versions ({stated}); "
                                 f"{version} is not among them")


def mark(records: list[dict], installed: tuple[str, str, str] | None,
         watched: Cpe | None = None) -> None:
    """Give each scan record its verdict for `installed` — (version, vendor,
    product), or None for an entry matched by name — and take NVD's
    configurations off it, which nothing after the verdict reads. `watched` is
    the entry's CPE, whose update and edition fields the verdict reads too.

    The one place the CLI and the API judge, so the two cannot disagree. The
    record keeps the version it was judged for, which is what lets a stored
    verdict be told apart from one about a version no longer installed.
    """
    for record in records:
        if installed is not None:
            version, vendor, product = installed
            verdict = judge(record, version=version, vendor=vendor, cpe_product=product, watched=watched)
            record.update(verdict=verdict.status, verdict_reason=verdict.reason,
                          verdict_fixed_version=verdict.fixed_version, judged_version=version)
        record.pop("configurations", None)
