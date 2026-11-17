"""
PatchRadar — EU and Italian law provisions for audit findings.

Maps what an audit found to the provisions it concerns, and cites each one
with the SHA-256 of the exact text applied and the date of that wording. The
text is downloaded on every audit (EUR-Lex, or Normattiva for Italian law)
and compared with the local cache; without network the cached copy is cited.

Shared by the Radar tools: only the mapping section is specific to PatchRadar.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from patchradar import law_fetcher
from patchradar.law_cache import Key, LawCache, merge
from patchradar.law_fetcher import DLGS_138_2024, GDPR, Act, LawFetchError, Provision

# ─── Mapping: PatchRadar findings → provisions ────────────────────────────────

# Finding → cited provisions, in report order
FINDING_ARTICLES = {
    "critical": ((GDPR, "32(2)"),),
    "unpatched": ((GDPR, "25"),),
    "critical_unpatched": ((DLGS_138_2024, "24"),),
    "personal_data": ((GDPR, "32"),),
}

FINDING_TITLES = {
    "critical": "Critical CVEs",
    "unpatched": "CVEs with no patch",
    "critical_unpatched": "Critical CVEs with no patch",
    "personal_data": "CVEs affecting personal data",
}

# Articles downloaded and cached even when not cited, by act
ALSO_FETCH: dict = {}

NIS2_SCOPE_NOTE = (
    "D.Lgs. 138/2024 art. 24 binds essential and important entities (art. 3 of the decree): "
    "check that the organisation falls within scope"
)


def _is_critical(cve: dict) -> bool:
    severity = cve.get("severity")
    return isinstance(severity, str) and severity.strip().upper() == "CRITICAL"


def findings_of(cves: list[dict]) -> dict[str, list[str]]:
    """
    Findings in the CVEs of a scan, with the CVE ids that triggered each.

    - critical: severity CRITICAL (CVSS >= 9.0)
    - unpatched: `patch_available` is False, i.e. NVD analysed the CVE and
      tagged none of its references as a patch. None (not analysed yet, or
      MSRC without a vendor fix listed) is not counted: it is unknown.
    - critical_unpatched: both at once, the NIS2 case
    - personal_data: CVSS confidentiality impact HIGH — the vulnerability
      discloses the data the software processes, which PatchRadar cannot tell
      apart from personal data.
    """
    ids: dict[str, list[str]] = {finding: [] for finding in FINDING_ARTICLES}
    for cve in cves:
        cve_id = str(cve.get("id") or "?")
        critical = _is_critical(cve)
        unpatched = cve.get("patch_available") is False
        if critical:
            ids["critical"].append(cve_id)
        if unpatched:
            ids["unpatched"].append(cve_id)
        if critical and unpatched:
            ids["critical_unpatched"].append(cve_id)
        if cve.get("confidentiality_impact") == "HIGH":
            ids["personal_data"].append(cve_id)
    return {finding: sorted(set(found)) for finding, found in ids.items() if found}


def notes_of(cves: list[dict]) -> list[str]:
    notes = []
    unknown = sum(1 for cve in cves if cve.get("patch_available") is None)
    if unknown:
        notes.append(
            f"{unknown} CVEs with no patch information (not yet analysed by NVD): "
            "not assessed against GDPR art. 25 or D.Lgs. 138/2024 art. 24"
        )
    if any(_is_critical(cve) and cve.get("patch_available") is False for cve in cves):
        notes.append(NIS2_SCOPE_NOTE)
    return notes


# ─── Citations ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Citation:
    finding: str
    law: str                      # act as cited: "GDPR"
    article: str                  # "32(1)(a)"
    sha256: str | None         # None when the text could not be obtained
    version_date: str | None   # YYYY-MM-DD the wording was downloaded


@dataclass(frozen=True)
class ActStatus:
    act: Act
    # "verified": every reference cited was in the text downloaded now; "cache": the source was
    # unreachable or its text lacked a reference, cached copy; "unavailable": no text at all
    source: str
    error: str | None = None
    # Where a verified text came from: "Cellar", "EUR-Lex" (the fallback) or "Normattiva"; None otherwise
    origin: str | None = None
    # When not verified: the source tried last ("Cellar", "EUR-Lex", "Normattiva", "Cellar and
    # EUR-Lex"; None if unknown), and why it was not used: "unreachable" (no page) or "not_in_text"
    # (a page, without the text cited)
    tried: str | None = None
    failure: str | None = None

    @property
    def reason(self) -> str | None:
        """Why the act was not verified, as a report says it: "Cellar and EUR-Lex unreachable"."""
        if self.source == "verified":
            return None
        tried = self.tried or self.act.source
        if self.failure == "not_in_text":
            return f"{tried} answered without the text cited"
        return f"{tried} unreachable"


@dataclass
class LawCheckResult:
    citations: list[Citation]
    acts: list[ActStatus] = field(default_factory=list)
    # What triggered each finding, e.g. {"critical": ["CVE-2026-1234"]}
    evidence: dict[str, list[str]] = field(default_factory=dict)
    # "GDPR art. 32" → SHA-256 of its previous text, for cited provisions
    # whose text changed since the last audit
    changed: dict[str, str] = field(default_factory=dict)
    # Remarks without a citation, e.g. why no verdict was possible
    notes: list[str] = field(default_factory=list)


def check(
    subject,
    *,
    cache: LawCache | None = None,
    now: datetime | None = None,
    client: httpx.Client | None = None,
    **context,
) -> LawCheckResult:
    """
    Cite the provisions that apply to the findings about `subject`.

    `context` is passed on to findings_of and notes_of: what the audit found
    besides `subject` itself.
    """
    evidence = findings_of(subject, **context)
    notes = notes_of(subject, **context)
    cited = [
        (finding, act, ref)
        for finding in evidence
        for act, ref in FINDING_ARTICLES[finding]
    ]
    if not cited:
        return LawCheckResult(citations=[], notes=notes)

    cache = cache or LawCache()
    now = now or datetime.now(UTC)

    acts = list(dict.fromkeys(act for _, act, _ in cited))
    # Keyed by (celex, article) — the cache's key, not the fetcher's.
    fresh: dict[Key, Provision] = {}
    errors: dict[Act, LawFetchError] = {}
    origins: dict[Act, str] = {}
    for act in acts:
        refs = list(dict.fromkeys(ref for _, a, ref in cited if a == act))
        # The articles cited ("32(1)(a)" is part of article 32) and ALSO_FETCH
        articles = tuple(dict.fromkeys(
            [ref.split("(")[0] for ref in refs] + list(ALSO_FETCH.get(act, ()))
        ))
        try:
            by_article, origin = law_fetcher.fetch_provisions_from(act, articles, now=now, client=client)
            # The article being there is not enough: each reference cited is
            # checked against the text just parsed. A paragraph the parser
            # missed used to fall back to the cache, old hash and date included,
            # under the "verified" label, or to no hash at all.
            missing = [ref for ref in refs if ref not in by_article]
            if missing:
                raise LawFetchError(
                    f"{act.name} art. {', '.join(missing)} not found in the text from {origin}",
                    source=origin, reached=True,
                )
        except LawFetchError as e:
            errors[act] = e
        else:
            origins[act] = origin
            fresh.update({p.key: p for p in by_article.values()})

    # Merged here, not by the save: a cache that cannot be written (read-only,
    # disk full) must not hide a change in the law, nor date an unchanged
    # wording to today.
    provisions, changed = merge(cache.load(), fresh)
    if fresh:
        # Unsaved, the text just downloaded can still be cited
        with contextlib.suppress(OSError):
            cache.update(fresh, checked_at=law_fetcher.utc_stamp(now))

    statuses = []
    for act in acts:
        if act not in errors:
            statuses.append(ActStatus(act, "verified", origin=origins[act]))
        else:
            error = errors[act]
            cached = any((act.celex, ref) in provisions for _, a, ref in cited if a == act)
            statuses.append(ActStatus(
                act, "cache" if cached else "unavailable", str(error),
                tried=error.source, failure="not_in_text" if error.reached else "unreachable",
            ))

    citations = []
    for finding, act, ref in cited:
        provision = provisions.get((act.celex, ref))
        citations.append(Citation(
            finding=finding,
            law=act.name,
            article=ref,
            sha256=provision.sha256 if provision else None,
            version_date=provision.fetched_at[:10] if provision else None,
        ))

    names = {act.celex: act.name for act in acts}
    cited_keys = {(act.celex, ref) for _, act, ref in cited}
    return LawCheckResult(
        citations=citations,
        acts=statuses,
        evidence=evidence,
        changed={
            f"{names[celex]} art. {article}": sha
            for (celex, article), sha in changed.items()
            if (celex, article) in cited_keys
        },
        notes=notes,
    )


def format_citation(citation: Citation) -> str:
    return (
        f"Provision applied: {citation.law} art. {citation.article}\n"
        f"SHA256: {citation.sha256 or 'not available'}\n"
        f"Version of: {citation.version_date or 'not available'}"
    )
