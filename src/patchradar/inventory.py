"""A machine's installed software, and what could be watched by version.

`inventory.ps1` collects and judges nothing: it reads the registry and writes
JSON. This is the other end, and it reports rather than imports.

**Why it does not decide.** Turning what the registry writes into what a vendor
API wants cannot be deduced from a name with any certainty. Measured on this
corpus: 30% mapped by themselves, and where a guess was allowed through it gave
`MX5` → a Juniper router and `Visual C++ 2012` → `visual_c++:2008`. An import
that decided on its own would build a wrong watchlist, and nothing in the output
would say so. So this proposes, a person confirms, and the confirmation is what
gets stored — once per product, not once per scan.

**Four categories, not three**, because of what a real list looks like. Of the
147 programs on the machine measured on 2026-09-27, thirteen are Visual C++
runtimes, twenty-nine are NVIDIA pieces and twenty-five belong to Python.
Counting a runtime as an unwatched product reports work that does not exist: it
is patched by whatever installed it.

Nothing here writes to the database. Storing a confirmed mapping needs the
watchlist columns the versionradar design sets out (`vendor`, `product_id`,
`installed_version`, `channel`, `cpe`), and that migration is deliberately not
part of this.
"""
from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field
from enum import Enum

# What a version field holds when it holds nothing. `*` and `-` are the CPE
# wildcards and arrive here through exports that borrow the notation; neither is
# a low version number.
_NOT_A_VERSION = {"", "*", "-", "unknown", "n/a", "none"}


class Confidence(Enum):
    """How far the evidence in the snapshot goes."""

    CERTAIN = "certain"        # a source, and the product it needs, both identified
    PROPOSED = "proposed"      # the source is clear, which product is not
    COMPONENT = "component"    # shipped with something else, not patched on its own
    UNCOVERED = "uncovered"    # no source that answers by version

    def __str__(self) -> str:
        return self.value


CERTAIN = Confidence.CERTAIN
PROPOSED = Confidence.PROPOSED
COMPONENT = Confidence.COMPONENT
UNCOVERED = Confidence.UNCOVERED


@dataclass(frozen=True)
class Candidate:
    """One installed program, and what could be asked about it."""

    name: str
    installed_version: str | None
    publisher: str
    confidence: Confidence
    source: str | None
    product_id: str | None
    reason: str

    @property
    def needs_version(self) -> bool:
        """Whether the snapshot left nothing to compare a fix against.

        Separate from `confidence`: a program can have a perfectly identified
        source and still be unanswerable because the registry holds no version.
        """
        return self.installed_version is None


# A row of the registry is not a product. On the measured machine 25 rows are
# Python 3.14.7 — Core Interpreter, Standard Library, Test Suite, Tcl/Tk, pip
# Bootstrap, each in a plain, a debug and a symbols variant — and they are one
# install. Thirteen more are Visual C++ runtimes. Reporting those as 38 unwatched
# products would size the work at ten times what it is.
_FAMILY_SPECIALS: tuple[tuple[re.Pattern[str], str], ...] = (
    # The version stays in the key: Python 3.13 and 3.14 installed side by side
    # are two products, and they are patched separately.
    (re.compile(r"^(python\s+\d+(?:\.\d+)*)\b", re.I), r"\1"),
    # Deliberately one family across the years. The year is identity when
    # mapping a product — Visual C++ 2012 is not 2008 — but none of these is
    # watched on its own, and the family exists so thirteen rows do not read as
    # thirteen products.
    (re.compile(r"visual c\+\+", re.I), "microsoft visual c++ runtimes"),
)

# Noise a registry name carries around the product it names.
_PARENTHESISED = re.compile(r"\s*\([^)]*\)")
_TRAILING_DASH_VERSION = re.compile(r"\s*[-–]\s*v?\d+(?:\.\d+)*\s*$")
_TRAILING_VERSION = re.compile(r"\s+v?\d+(?:\.\d+){1,}\s*$")
_VERSION_WORD = re.compile(r"\s+(version|versione|ver\.?)\s+v?\d+(?:\.\d+)*", re.I)
_ARCHITECTURE = re.compile(r"\s+(x64|x86|amd64|64[-\s]?bit|32[-\s]?bit)\b", re.I)


def family_key(name: str) -> str:
    """The product several registry rows belong to.

    Normalising is not renaming: the key groups, and every row keeps its own name
    and version. A key that dropped too much would merge two products — hence
    the version staying inside the Python key.
    """
    text = str(name or "").strip()
    for pattern, replacement in _FAMILY_SPECIALS:
        match = pattern.search(text)
        if match:
            return pattern.sub(replacement, match.group(0)).strip().lower()

    text = _PARENTHESISED.sub("", text)
    text = _VERSION_WORD.sub("", text)
    text = _TRAILING_DASH_VERSION.sub("", text)
    text = _TRAILING_VERSION.sub("", text)
    text = _ARCHITECTURE.sub("", text)
    return " ".join(text.split()).strip(" -–").lower()


# Which answer wins when the rows of one family disagree. A family with one
# watchable row is watchable; COMPONENT is last, because a family that holds a
# product and its helper is a product.
_CONFIDENCE_ORDER = {CERTAIN: 3, PROPOSED: 2, UNCOVERED: 1, COMPONENT: 0}


@dataclass
class Family:
    """The registry rows that belong to one installed product."""

    key: str
    candidates: list[Candidate] = field(default_factory=list)

    @property
    def rows(self) -> int:
        return len(self.candidates)

    @property
    def best(self) -> Candidate:
        return max(self.candidates, key=lambda c: _CONFIDENCE_ORDER[c.confidence])

    @property
    def confidence(self) -> Confidence:
        return self.best.confidence

    @property
    def name(self) -> str:
        """The shortest name among the rows: the features are longer than the
        product they belong to."""
        return min((c.name for c in self.candidates), key=len)


@dataclass
class Survey:
    """The counts a person reads before deciding what to confirm."""

    taken_at: str
    candidates: list[Candidate] = field(default_factory=list)

    @property
    def families(self) -> list[Family]:
        """One entry per installed product, in order of first appearance."""
        grouped: dict[str, Family] = {}
        for candidate in self.candidates:
            key = family_key(candidate.name)
            grouped.setdefault(key, Family(key=key)).candidates.append(candidate)
        return list(grouped.values())

    def largest_families(self, count: int = 5) -> list[Family]:
        """The families holding the most rows, so nothing hides behind a total."""
        return sorted(self.families, key=lambda f: -f.rows)[:count]

    @property
    def rows(self) -> int:
        """Registry entries read, which is not the number of products."""
        return len(self.candidates)

    @property
    def total(self) -> int:
        return len(self.families)

    def _count(self, confidence: Confidence) -> int:
        return sum(1 for f in self.families if f.confidence is confidence)

    @property
    def certain(self) -> int:
        return self._count(CERTAIN)

    @property
    def proposed(self) -> int:
        return self._count(PROPOSED)

    @property
    def components(self) -> int:
        return self._count(COMPONENT)

    @property
    def uncovered(self) -> int:
        return self._count(UNCOVERED)

    @property
    def without_version(self) -> int:
        """Families whose best row has no version to compare a fix against."""
        return sum(1 for f in self.families if f.best.needs_version)

    @property
    def proposals_by_source(self) -> dict[str, list[Candidate]]:
        """What has to be confirmed, gathered by who will be asked.

        Confirming ten Microsoft products in one pass is one job; ten scattered
        ones are ten.
        """
        grouped: dict[str, list[Candidate]] = {}
        for family in self.families:
            best = family.best
            if best.confidence is PROPOSED and best.source:
                grouped.setdefault(best.source, []).append(best)
        return grouped


# ── the rules ────────────────────────────────────────────────────────────────
#
# Every rule below cites the string that made it necessary, all of them from the
# machine measured on 2026-09-27. Order matters: the component rules run first,
# because "Java Auto Updater" contains "Java" and "Mozilla Maintenance Service"
# contains "Mozilla".

# Names that are a piece of another product. A runtime, a helper, a maintenance
# service: they arrive with what needed them and leave with it.
_COMPONENTS: tuple[tuple[re.Pattern[str], re.Pattern[str] | None, str], ...] = (
    (re.compile(r"visual c\+\+.*(runtime|redistributable)", re.I), None,
     "a Visual C++ runtime: it arrives with whatever needed it and is updated the same way"),
    (re.compile(r"\bjava auto updater\b", re.I), None,
     "Oracle's updater for Java, installed alongside the JRE and patched with it"),
    (re.compile(r"\bgoogle update helper\b", re.I), None,
     "part of Google Update, installed alongside Chrome"),
    (re.compile(r"\badobe refresh manager\b", re.I), None,
     "installed by Adobe Reader; on this machine its certificate expired in 2017"),
    (re.compile(r"maintenance service", re.I), None,
     "a maintenance service installed by its own product and updated with it"),
    (re.compile(r"\bpackage installer\b", re.I), None,
     "the bootstrapper that installed the product, left on disk beside it"),
    # The plumbing of a driver package. Twenty-eight NVIDIA rows on the machine
    # measured on 2026-09-27, of which three are products — the graphics driver,
    # the HD audio driver and GeForce Experience. The rest are containers,
    # plugins, telemetry clients and update cores that arrive inside the package
    # and leave with it; counting them as unwatched products invents 25 jobs.
    #
    # The publisher is required: "Container" in a name proves nothing on its own.
    # No word boundaries: the names come glued as well as spaced —
    # `NvModuleTracker`, `TelemetryApi helper for NvContainer` — and a `\b` in
    # front of `module` fails on the first while a `\b` behind `telemetry` fails
    # on the second. `share` keeps its boundaries so it cannot match `shareware`.
    (re.compile(r"(container|backend|plugin|telemetry\w*|update core|aggiornamenti|"
                r"module ?tracker|virtual (host controller|audio)|nodejs|shield|sdk|"
                r"oss binaries|\bshare\b|shadowplay|install application|optimus|"
                r"streaming|message bus|monitor|watchdog|session|localsystem|"
                r"networkservice)", re.I),
     re.compile(r"^nvidia", re.I),
     "a piece of the NVIDIA driver package: installed and updated with it"),
    (re.compile(r"\b(physx|hd audio driver|3d vision)\b", re.I), None,
     "shipped inside a driver package and updated with it"),
)

# publisher + name → a source that answers by version, and the product it needs.
_CERTAIN_RULES: tuple[tuple[re.Pattern[str], re.Pattern[str] | None, str, str], ...] = (
    # Google publishes the served builds per rollout group; the name is exact.
    (re.compile(r"^google chrome$", re.I), re.compile(r"google", re.I), "chrome", "chrome"),
    # The Edge enterprise feed names the channel; "Microsoft Edge" is one entry.
    (re.compile(r"^microsoft edge$", re.I), re.compile(r"microsoft", re.I), "edge", "Edge"),
)

# publisher → the source that would answer, without the product it needs.
_PROPOSED_BY_PUBLISHER: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^microsoft", re.I), "msrc",
     "MSRC answers by build, and lists many products per CVE — 13 for one Office "
     "advisory, LTSC 2021 at 32 and 64 bit among them. Which one this install is "
     "has to be stated"),
    (re.compile(r"^mozilla", re.I), "mozilla",
     "Mozilla publishes current versions as JSON (product-details); the product "
     "and channel have to be named"),
)

# Names that reach a specific source before the publisher rules get a say.
_PROPOSED_BY_NAME: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"edge webview2", re.I), "edge",
     "the Edge feed lists a WebView2 product; which channel this install follows "
     "is not in the registry, and it decides the verdict"),
)

# No vendor API, and what is possible instead. Named rather than lumped in with
# everything else, because "no API" and "no idea" are different answers.
_UNCOVERED_REASONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^oracle", re.I),
     "Oracle publishes quarterly bulletins and no per-CVE API. NVD by CPE does "
     "work here: all of Java 8 is version 8, and the patch level lives in the "
     "CPE update field (update_503)"),
    (re.compile(r"^adobe", re.I),
     "Adobe states fixed versions in APSB bulletins, as HTML. NVD by CPE is the "
     "usable route"),
    (re.compile(r"^nvidia", re.I),
     "NVIDIA publishes security bulletins per driver branch, as HTML"),
)

_UNCOVERED_DEFAULT = (
    "no source that answers by version. Keyword search still answers, with the "
    "noise it has — 806 CVEs for Chrome, 708 of them unscored — and NVD by CPE "
    "narrows it once a CPE is known"
)


def _version_of(raw: object) -> str | None:
    """The version as the registry wrote it, or None when it wrote nothing.

    Not parsed and not normalised: what gets compared against a vendor's fixed
    build is the vendor's own notation, and reshaping it here would lose the
    difference between `8.0.5030.1` and the `update_503` that identifies it.
    """
    text = str(raw or "").strip()
    return None if text.lower() in _NOT_A_VERSION else text


def classify(entry: dict) -> Candidate:
    """What could be asked about one installed program."""
    name = str(entry.get("name") or "").strip()
    publisher = str(entry.get("publisher") or "").strip()
    version = _version_of(entry.get("version"))

    def candidate(confidence: Confidence, source: str | None,
                  product_id: str | None, reason: str) -> Candidate:
        return Candidate(name=name, installed_version=version, publisher=publisher,
                         confidence=confidence, source=source,
                         product_id=product_id, reason=reason)

    for pattern, publisher_rule, reason in _COMPONENTS:
        if pattern.search(name) and (publisher_rule is None or publisher_rule.search(publisher)):
            return candidate(COMPONENT, None, None, reason)

    for name_rule, publisher_rule, source, product in _CERTAIN_RULES:
        if not name_rule.search(name):
            continue
        # The publisher corroborates and is not required: four entries on the
        # measured machine have none, and a name that identifies a product on its
        # own still does.
        if publisher and publisher_rule is not None and not publisher_rule.search(publisher):
            continue
        return candidate(CERTAIN, source, product,
                         f"{source} publishes the versions it serves; the name identifies "
                         f"the product exactly")

    for pattern, source, reason in _PROPOSED_BY_NAME:
        if pattern.search(name):
            return candidate(PROPOSED, source, None, reason)

    for pattern, source, reason in _PROPOSED_BY_PUBLISHER:
        if pattern.search(publisher):
            return candidate(PROPOSED, source, None, reason)

    for pattern, reason in _UNCOVERED_REASONS:
        if pattern.search(publisher):
            return candidate(UNCOVERED, None, None, reason)

    return candidate(UNCOVERED, None, None, _UNCOVERED_DEFAULT)


def survey(snapshot: dict) -> Survey:
    """Classify every program in a snapshot."""
    programs = snapshot.get("installedSoftware") or []
    return Survey(
        taken_at=str(snapshot.get("takenAt") or ""),
        candidates=[classify(entry) for entry in programs if isinstance(entry, dict)],
    )


def read_snapshot(path: str | pathlib.Path) -> dict:
    """An inventory snapshot from disk.

    Read as utf-8-sig: PowerShell's `Set-Content -Encoding utf8` writes a byte
    order mark, `json.loads` refuses it, and that cost four separate debugging
    sessions while this corpus was being built.

    A file that is not an inventory raises rather than surveying nothing: zero
    programs and "this is not an inventory" must not look the same, because the
    first one reads as a clean machine.
    """
    target = pathlib.Path(path)
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or "installedSoftware" not in data:
        raise ValueError(
            f"{target.name} carries no installedSoftware: it is not an inventory snapshot"
        )
    if not isinstance(data["installedSoftware"], list):
        raise ValueError(f"{target.name}: installedSoftware is not a list")
    return data
