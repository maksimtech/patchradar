"""What to look at first, which is not what scores highest.

Measured on a real machine on 2026-09-26: ordering 695 matched CVEs by CVSS put
five 10.0 entries on top, none of them being exploited, while the four listed in
CISA KEV scored 9.8, 8.8, 8.6 and 7.8 — below all five. The operational question
is "what is being used against me now", not "how bad would it be", and only the
second one CVSS can answer.

2026.41 put the fact in the scan by adding the KEV collector. This reads it.

KEV is a short list, though — 1,726 entries — and it is a record of the past: a
CVE reaches it once exploitation has been *observed*. Everything not on it was
ranked by CVSS alone, which is why EPSS (`patchradar.epss`, from FIRST) now sits
between the two as `RANK_EPSS`. It is a forecast rather than an observation, so
it ranks below CISA having seen the thing happen and above a severity that only
says how bad it would be.

Two steps, and the first is not optional. `_scan_target` concatenates three
collectors and de-duplicates nothing, so a CVE that NVD scored and CISA lists
arrives twice: once with a score and no exploitation, once exploited with
`severity: "UNKNOWN"`. Ranking that list as it stands produces two rows for one
CVE, ranked differently, and neither of them is right — so `merge_by_cve` runs
first and `order_by_priority` calls it.

Nothing here invents a fact. A field no source supplied stays absent: a
`known_exploited: False` added by this module would be indistinguishable from
CISA having been consulted and having said no.
"""
from __future__ import annotations

from dataclasses import dataclass

# The ranks, in the order they outrank each other. Numbers rather than an Enum
# because they are compared, summed into a sort key and printed.
RANK_UNSCORED = 0          # no score from any source, not known to be exploited
RANK_SCORED = 1            # a scoring body assigned a score
RANK_EPSS = 2              # FIRST forecasts exploitation as likely
RANK_KEV = 3               # CISA has observed it being exploited
RANK_KEV_RANSOMWARE = 4    # …and in ransomware campaigns

RANK_LABELS = {
    RANK_UNSCORED: "unscored",
    RANK_SCORED: "scored",
    RANK_EPSS: "likely",
    RANK_KEV: "exploited",
    RANK_KEV_RANSOMWARE: "ransomware",
}

# Where "likely" starts, as a 30-day exploitation probability. 0.1 rather than a
# rounder-looking number because of where the distribution lies: EPSS is heavily
# skewed — the large majority of scored CVEs sit below 0.01 — so a threshold of
# 0.5 would promote almost nothing and 0.01 would promote a third of the scan,
# and a rank that applies to a third of the rows ranks nothing. 0.1 selects the
# tail without selecting the bulk.
#
# A score below it is not discarded: `priority` still reports it, because "FIRST
# puts this at 3%" is a reason to leave a 9.8 until next week and the reader
# should see it. It only does not promote the row.
EPSS_THRESHOLD = 0.1

# Severities that state the absence of a severity. KEV uses the first one
# deliberately — it states no severity and must not appear to supply one — so a
# merge has to treat it as "nothing said", never as a value to keep.
_NO_SEVERITY = {"", "UNKNOWN", "NONE_STATED"}

# The value CISA writes when a ransomware link is established. The field holds
# "Known", "Unknown" or "" — never a boolean — and `bool("Unknown")` is True,
# so truthiness on it would promote 1,610 of the 1,726 live entries to the top
# rank. `collectors.kev` already converts; a record arriving from the database
# or from another tool may not have been through it.
_RANSOMWARE_YES = "known"

# Only inside a sort key, never in a report: an absent score must not become
# 0.0 anywhere a reader can see it, because 0.0 is a real CVSS measurement.
_NO_SCORE_IN_SORT = -1.0


def _is_true(value: object) -> bool:
    """A boolean from a field that may hold a string a vendor chose.

    `True`/`False` pass through; "Known" is a yes and "Unknown" is not, which is
    the whole reason this is not `bool(value)`.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == _RANSOMWARE_YES
    return bool(value)


@dataclass(frozen=True)
class Priority:
    """The rank, the number that broke the tie, and why.

    `score` stays None when no source scored the CVE. The sort substitutes a
    sentinel for it internally; the sentinel never reaches a caller.
    """

    rank: int
    score: float | None
    reason: str

    @property
    def label(self) -> str:
        return RANK_LABELS[self.rank]

    def sort_key(self) -> tuple[float, float]:
        """Descending: highest rank first, then highest score.

        CVSS breaks the tie at every rank, including RANK_EPSS — the probability
        decides which band a row is in, and severity orders it within the band.
        Sorting the EPSS band by probability instead would mean two rows next to
        each other were ordered by two different measures, which is the kind of
        ordering nobody can read off the table.
        """
        return (-self.rank, -(self.score if self.score is not None else _NO_SCORE_IN_SORT))


def _probability(value: object) -> float | None:
    """A probability from an EPSS field, or None when it holds no usable number.

    Strict in the way the CVSS read below is strict, and for a sharper reason: a
    string is refused because `patchradar.epss` converts before it writes, so a
    string in this field did not come from FIRST — and a value outside [0, 1] is
    refused rather than clamped, because clamping would promote the row.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    if number != number or not 0.0 <= number <= 1.0:   # NaN fails both halves
        return None
    return number


def _epss_phrase(score: float, percentile: float | None) -> str:
    """EPSS as a reader can act on it: a percentage, with the percentile if known.

    A percentage rather than the raw 0.0-1.0 figure because the raw figures are
    mostly leading zeros — 0.00054 — and "0.05%" is the same number said in a
    way that does not need counting. The percentile travels with it because the
    absolute probability on its own is hard to place: 7% sounds small and is in
    fact the top 1% of all CVEs.

    Neither number is allowed to round up into a claim the data does not make.
    Log4Shell reads 0.99999 — one decimal place turns that into "100.0%", which
    is certainty, and its percentile 0.99997 into "p100", which is a top rank
    that does not exist. The first is reported as ">99.9%" and the second is
    floored, which is what a percentile means anyway: p99 is "in the top 1%".
    """
    shown = f"{score * 100:.1f}"
    if shown == "100.0" and score < 1.0:
        shown = ">99.9"
    where = f" (p{int(percentile * 100)})" if percentile is not None else ""
    return f"EPSS {shown}%{where}"


def priority(record: dict) -> Priority:
    """The priority of one CVE record, from the facts the record carries.

    Reads the fields, never the source name: a record whose `source` mentions
    CISA without carrying `known_exploited` is not evidence of exploitation.
    """
    score = record.get("cvss_score")
    score = float(score) if isinstance(score, int | float) and not isinstance(score, bool) else None

    exploited = _is_true(record.get("known_exploited"))
    ransomware = exploited and _is_true(record.get("kev_ransomware"))
    added = record.get("kev_date_added") or record.get("published_at") or ""
    since = f" since {added}" if added else ""

    if ransomware:
        return Priority(RANK_KEV_RANSOMWARE, score,
                        f"in CISA KEV{since}, known use in ransomware campaigns")
    if exploited:
        due = record.get("kev_due_date")
        deadline = f", CISA remediation date {due}" if due else ""
        return Priority(RANK_KEV, score, f"in CISA KEV{since}, exploitation observed{deadline}")

    version = record.get("cvss_version")
    scale = f" (v{version})" if version else ""
    cvss = f"CVSS {score}{scale}" if score is not None else "no score from any source"

    epss = _probability(record.get("epss_score"))
    if epss is not None:
        phrase = _epss_phrase(epss, _probability(record.get("epss_percentile")))
        if epss >= EPSS_THRESHOLD:
            return Priority(RANK_EPSS, score,
                            f"{phrase} — exploitation likely within 30 days, "
                            f"{cvss}, not in CISA KEV")
        # Below the threshold the number still earns its place in the reason: it
        # is what tells a reader a 9.8 can wait for the next patch window.
        cvss = f"{cvss}, {phrase}"

    if score is not None:
        return Priority(RANK_SCORED, score, f"{cvss}, not in CISA KEV")
    return Priority(RANK_UNSCORED, None, f"{cvss}, not in CISA KEV")


def _merge_into(kept: dict, other: dict) -> None:
    """Add to `kept` what `other` knows and it does not.

    First writer wins on everything already present, so a scan reads the same
    way twice: the exception is a severity that states no severity, which must
    give way to a real one rather than erase it.
    """
    for key, value in other.items():
        if key == "source":
            continue
        if key == "severity":
            if str(kept.get(key, "")).upper() in _NO_SEVERITY and str(value).upper() not in _NO_SEVERITY:
                kept[key] = value
            continue
        if key == "cvss_score" and kept.get(key) is None and value is not None:
            kept[key] = value
            # The version belongs to the score it describes; taking one without
            # the other would label a score with the wrong scale.
            if other.get("cvss_version") is not None:
                kept["cvss_version"] = other["cvss_version"]
            continue
        if key not in kept or kept[key] is None:
            kept[key] = value

    # Provenance accumulates: a row two sources agreed on must not be reported
    # as one source's finding.
    sources = [s for s in (kept.get("source"), other.get("source")) if s]
    seen: list[str] = []
    for source in sources:
        for name in str(source).split(", "):
            if name and name not in seen:
                seen.append(name)
    if seen:
        kept["source"] = ", ".join(seen)


def merge_by_cve(records: list[dict]) -> list[dict]:
    """One row per CVE, in order of first appearance.

    Keyed on the id case-insensitively — the sources agree on upper case today
    and nothing should depend on that — while the row keeps the id as the first
    source spelled it.

    A record without an id cannot be identified with any other and is kept as
    it is: merging them together would invent a relationship, and dropping them
    would quietly lower the count the scan reports.
    """
    merged: dict[str, dict] = {}
    order: list[str] = []
    loose: list[dict] = []

    for record in records:
        cve_id = str(record.get("id") or "").strip()
        if not cve_id:
            loose.append(dict(record))
            continue
        key = cve_id.upper()
        if key not in merged:
            merged[key] = dict(record)
            order.append(key)
        else:
            _merge_into(merged[key], record)

    return [merged[key] for key in order] + loose


def sort_by_priority(rows: list[dict]) -> list[dict]:
    """Already-merged rows, most urgent first.

    Separate from `order_by_priority` because EPSS has to land between the two
    steps: the enrichment needs one row per CVE to ask FIRST about, and the sort
    needs the enrichment to have happened — ranking first and enriching after
    would order the scan on the facts it had a moment ago.

    Stable within a rank and score, so two scans of the same machine print the
    same report and a diff of the two means something.
    """
    return sorted(rows, key=lambda row: priority(row).sort_key())


def order_by_priority(records: list[dict]) -> list[dict]:
    """The scan's CVEs, merged, most urgent first."""
    return sort_by_priority(merge_by_cve(records))
