"""
PatchRadar — EU and Italian law provisions for audit findings.

Maps what an audit found to the provisions it concerns, and cites each one
with the SHA-256 of the exact text applied and the date of that wording. The
text is downloaded on every audit (EUR-Lex, or Normattiva for Italian law)
and compared with the local cache; without network the cached copy is cited.

Shared by the Radar tools: only the mapping section is specific to PatchRadar.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from patchradar import law_fetcher
from patchradar.law_cache import Key, LawCache
from patchradar.law_fetcher import GDPR, NIS2, Act, LawFetchError, Provision

# ─── Mapping: PatchRadar findings → provisions ────────────────────────────────

# Finding → cited provisions, in report order
FINDING_ARTICLES = {
    "critical": ((GDPR, "32(2)"),),
    "unpatched": ((GDPR, "25"),),
    "critical_unpatched": ((NIS2, "21"),),
    "personal_data": ((GDPR, "32"),),
}

FINDING_TITLES = {
    "critical": "CVE critiche",
    "unpatched": "CVE senza patch",
    "critical_unpatched": "CVE critiche senza patch",
    "personal_data": "CVE con impatto sui dati personali",
}

# Articles downloaded and cached even when not cited, by act
ALSO_FETCH: dict = {}

NIS2_SCOPE_NOTE = (
    "NIS2 art. 21 obbliga i soggetti essenziali e importanti (art. 3 della direttiva): "
    "verificare che l'organizzazione rientri nell'ambito"
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
            f"{unknown} CVE senza informazioni sulla patch (non ancora analizzate da NVD): "
            "non valutate per l'art. 25 GDPR e l'art. 21 NIS2"
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
    # "verified": downloaded now from the act's source (EUR-Lex or Normattiva);
    # "cache": source unreachable, cached copy; "unavailable": no text at all
    source: str
    error: str | None = None


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
    errors: dict[Act, str] = {}
    for act in acts:
        # The articles cited ("32(1)(a)" is part of article 32) and ALSO_FETCH
        articles = tuple(dict.fromkeys(
            [ref.split("(")[0] for _, a, ref in cited if a == act] + list(ALSO_FETCH.get(act, ()))
        ))
        try:
            by_article = law_fetcher.fetch_provisions(act, articles, now=now)
        except LawFetchError as e:
            errors[act] = str(e)
        else:
            fresh.update({p.key: p for p in by_article.values()})

    changed: dict[Key, str] = {}
    try:
        if fresh:
            provisions, changed = cache.update(fresh, checked_at=law_fetcher.utc_stamp(now))
        else:
            provisions = cache.load()
    except OSError:
        provisions = {**cache.load(), **fresh}   # the text just downloaded can still be cited

    statuses = []
    for act in acts:
        if act not in errors:
            statuses.append(ActStatus(act, "verified"))
        else:
            cached = any((act.celex, ref) in provisions for _, a, ref in cited if a == act)
            statuses.append(ActStatus(act, "cache" if cached else "unavailable", errors[act]))

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
        f"Norma applicata: {citation.law} art. {citation.article}\n"
        f"SHA256: {citation.sha256 or 'non disponibile'}\n"
        f"Versione del: {citation.version_date or 'non disponibile'}"
    )
