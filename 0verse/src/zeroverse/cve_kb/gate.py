"""The shared pipeline gate every profile calls, and the ``windows_novelty`` bridge.

``novelty(finding, store)`` is the one entrypoint a linux-kernel / windows-driver
/ binary / web finding runs through to earn its ``novelty`` field. It layers the
three query modes in order of trust:

  1. **Mode A (structured)** — authoritative. A KNOWN-CVE/ADVISORY here settles it.
  2. **Mode B (embedding dedup)** — only when A found no record; surfaces
     nearest known-CVEs / prior findings as low-confidence *review* candidates.
  3. **Web/CVE-search fallback** — only when A found no record and a searcher is
     wired; carries the closed-source/firmware cases where local structure is
     thin. Reuses ``windows_novelty``'s classifier so the vocabulary matches.

The result is always honest: KNOWN-* (with the CVE ids + evidence) or
NO-PUBLIC-RECORD-FOUND (+ caveat, + any review candidates). Never "novel".

The bridge (:class:`KnowledgeBaseSearcher`) makes the driver gate a CONSUMER of
this KB rather than a duplicate: it implements ``windows_novelty.NoveltySearcher``
by answering queries out of the local store, so an existing
``assess_novelty(identity, searcher)`` call resolves segwindrvx64 -> CVE-2024-33228
**offline**, before any live web search.
"""

from __future__ import annotations

from collections.abc import Sequence

from .embed import CorpusEntry, EmbeddingBackend, dedup
from .match import known_cve
from .models import (
    KNOWN_ADVISORY,
    KNOWN_CVE,
    NO_PUBLIC_RECORD,
    NO_PUBLIC_RECORD_CAVEAT,
    CveCandidate,
    FindingFingerprint,
    NoveltyResult,
)
from .store import CveStore


def _split_tokens(text: str) -> list[str]:
    return "".join(c if c.isalnum() else " " for c in text).split()


def novelty(
    finding: FindingFingerprint,
    store: CveStore,
    *,
    corpus: Sequence[CorpusEntry] | None = None,
    embed_backend: EmbeddingBackend | None = None,
    web_searcher: object | None = None,
) -> NoveltyResult:
    """Run the layered gate. See module docstring for the trust order."""
    result = known_cve(store, finding)
    if result.is_known:
        return result

    # A found nothing decisive. Gather review candidates (never auto-drop).
    methods = ["structured"]
    review_candidates: list[CveCandidate] = list(result.candidates)
    evidence = dict(result.evidence)

    if corpus:
        dedup_hits = dedup(finding, corpus, backend=embed_backend)
        methods.append("embedding")
        evidence["embedding_dedup"] = [h.to_dict() for h in dedup_hits]
        for h in dedup_hits:
            if h.ref_kind == "cve" and not any(c.record_id == h.ref_id for c in review_candidates):
                review_candidates.append(
                    CveCandidate(
                        cve_id=h.ref_id if h.ref_id.upper().startswith("CVE-") else "",
                        record_id=h.ref_id,
                        source="embedding",
                        score=h.similarity,
                        reasons=(f"fingerprint similarity {h.similarity:.2f}",),
                    )
                )

    if web_searcher is not None:
        web_result = _web_fallback(finding, web_searcher)
        methods.append("web")
        evidence["web_fallback"] = web_result.to_dict()
        if web_result.is_known:
            # Web found a public record structured ingest missed. Trust it but
            # mark method + medium confidence (external, not locally verified).
            return NoveltyResult(
                verdict=web_result.verdict,
                confidence="medium",
                candidates=web_result.candidates,
                method="+".join(methods),
                caveat="",
                evidence=evidence,
            )

    return NoveltyResult(
        verdict=NO_PUBLIC_RECORD,
        confidence="low",
        candidates=tuple(review_candidates),
        method="+".join(methods),
        caveat=NO_PUBLIC_RECORD_CAVEAT,
        evidence=evidence,
    )


# --- windows_novelty bridge --------------------------------------------------

def finding_from_driver_identity(identity: object) -> FindingFingerprint:
    """Convert a ``windows_novelty.DriverIdentity`` into a FindingFingerprint."""
    return FindingFingerprint(
        vendor=getattr(identity, "vendor", ""),
        ecosystem="windows-driver",
        file=getattr(identity, "filename", ""),
        device_family=getattr(identity, "device_family", ""),
        extra_terms=tuple(getattr(identity, "extra_terms", ()) or ()),
    )


class KnowledgeBaseSearcher:
    """Implements ``windows_novelty.NoveltySearcher`` against the local KB.

    For each derived query it returns one ``SearchHit`` per KB record that
    attributes to the query (filename/family/text overlap), embedding the CVE id
    into the title + a ``nvd.nist.gov/vuln/detail`` URL so ``classify_hits``
    recovers it exactly as it would from a live web hit. This is the subsumption
    seam: the driver gate keeps its classifier, but resolves offline first.
    """

    def __init__(self, store: CveStore) -> None:
        self.store = store

    def __call__(self, query: str) -> Sequence[object]:
        # Imported lazily so cve_kb has no hard dependency on windows_novelty.
        from ..windows_novelty import SearchHit

        q_lower = query.lower()
        q_tokens = {t for t in _split_tokens(q_lower) if len(t) > 2}
        hits: list[object] = []
        seen: set[str] = set()
        for rec in self.store.all():
            hay = rec.haystack()
            file_stems = {f.rsplit(".", 1)[0] for f in rec.files}
            attributed = bool(file_stems & q_tokens) or any(f in q_lower for f in rec.files)
            if not attributed:
                # also attribute if a query token names the record file in prose
                attributed = any(len(s) > 4 and s in q_tokens and s in hay for s in file_stems)
            if not attributed:
                continue
            cve = rec.cve_ids[0] if rec.cve_ids else ""
            if rec.id in seen:
                continue
            seen.add(rec.id)
            title = f"{cve or rec.id}: {rec.product or rec.description[:80]}"
            url = (
                f"https://nvd.nist.gov/vuln/detail/{cve}"
                if cve
                else (rec.references[0] if rec.references else "https://www.loldrivers.io/")
            )
            hits.append(SearchHit(query=query, title=title, url=url, snippet=rec.description[:240]))
        return hits


def _web_fallback(finding: FindingFingerprint, web_searcher: object) -> NoveltyResult:
    """Run ``windows_novelty.assess_novelty`` with the given live searcher and
    translate its assessment back into a :class:`NoveltyResult`."""
    from ..windows_novelty import (
        KNOWN_ADVISORY as W_ADV,
    )
    from ..windows_novelty import (
        KNOWN_CVE as W_CVE,
    )
    from ..windows_novelty import (
        DriverIdentity,
        assess_novelty,
    )

    identity = DriverIdentity(
        filename=finding.file,
        vendor=finding.vendor,
        device_family=finding.device_family,
        extra_terms=finding.extra_terms,
    )
    assessment = assess_novelty(identity, web_searcher)  # type: ignore[arg-type]
    verdict = {W_CVE: KNOWN_CVE, W_ADV: KNOWN_ADVISORY}.get(assessment.verdict, NO_PUBLIC_RECORD)
    candidates = tuple(
        CveCandidate(
            cve_id=c, record_id=c, source="web", score=0.5, reasons=("web/CVE-search hit",)
        )
        for c in assessment.cve_ids
    )
    return NoveltyResult(
        verdict=verdict,
        confidence="medium" if verdict != NO_PUBLIC_RECORD else "low",
        candidates=candidates,
        method="web",
        caveat=NO_PUBLIC_RECORD_CAVEAT if verdict == NO_PUBLIC_RECORD else "",
        evidence={"web_assessment": assessment.to_dict()},
    )
