"""Mode A — ``known_cve(finding)``: structured match FIRST.

Scores every KB record against a :class:`FindingFingerprint` on structured
signals (filename, device family, product, vendor, CWE, sink function) and
classifies the result. This is the primary path and, for closed-source drivers,
the ONLY reliable one: it resolves segwindrvx64 -> CVE-2024-33228 purely off the
``.sys`` filename appearing in the real NVD description, with no CPE and no web
search.

Discipline (inherited from ``windows_novelty``):

* **Never emit NOVEL.** The strongest verdict is NO-PUBLIC-RECORD-FOUND + caveat.
* **Attribution gate.** A record only supports a KNOWN verdict if it names a
  STRONG token of the finding (filename stem, device family, or product) — a
  bare CWE- or vendor-only overlap can never mark a finding KNOWN (that would be
  a false-dedup). Weak overlaps are still *surfaced* as low-confidence
  candidates for human review (recall-first), never used to auto-drop.
* **Recall over precision for "known".** When in doubt, flag for review.
"""

from __future__ import annotations

from .models import (
    KNOWN_ADVISORY,
    KNOWN_CVE,
    NO_PUBLIC_RECORD,
    NO_PUBLIC_RECORD_CAVEAT,
    CveCandidate,
    CveRecord,
    FindingFingerprint,
    NoveltyResult,
)
from .store import CveStore

# Signal weights. Filename is the strongest closed-source attributor.
_W_FILENAME_EXACT = 0.60
_W_FILENAME_PROSE = 0.50
_W_DEVICE_FAMILY = 0.40
_W_PRODUCT = 0.28
_W_VENDOR = 0.15
_W_CWE = 0.15
_W_FUNCTION = 0.22

# A record must reach this via STRONG (attribution) signals to support KNOWN.
_STRONG_ATTRIBUTION_MIN = 0.40


def _tokens(s: str) -> set[str]:
    return {t for t in "".join(c if c.isalnum() else " " for c in s.lower()).split() if len(t) > 2}


def score_record(finding: FindingFingerprint, rec: CveRecord) -> tuple[float, float, list[str]]:
    """Return (total_score, strong_attribution_score, reasons)."""
    reasons: list[str] = []
    total = 0.0
    strong = 0.0
    hay = rec.haystack()

    stem = finding.file_stem
    if stem:
        file_blob = "\n".join(rec.files)
        exact = any(stem in (f.rsplit(".", 1)[0], f) for f in rec.files) or f"{stem}." in file_blob
        if exact:
            total += _W_FILENAME_EXACT
            strong += _W_FILENAME_EXACT
            reasons.append(f"filename '{finding.file}' matches record file list")
        elif stem in hay:
            total += _W_FILENAME_PROSE
            strong += _W_FILENAME_PROSE
            reasons.append(f"filename stem '{stem}' named in record text")

    if finding.device_family and finding.device_family.lower() in hay:
        total += _W_DEVICE_FAMILY
        strong += _W_DEVICE_FAMILY
        reasons.append(f"device family '{finding.device_family}' named in record")

    if finding.product:
        prod_tokens = _tokens(finding.product)
        rec_tokens = _tokens(rec.product) | _tokens(rec.description)
        overlap = prod_tokens & rec_tokens
        if prod_tokens and len(overlap) >= max(1, len(prod_tokens) // 2):
            total += _W_PRODUCT
            strong += _W_PRODUCT
            reasons.append(f"product tokens overlap: {sorted(overlap)}")

    if finding.vendor and rec.vendor:
        if _tokens(finding.vendor) & _tokens(rec.vendor):
            total += _W_VENDOR
            reasons.append(f"vendor overlap '{finding.vendor}' ~ '{rec.vendor}'")
    elif finding.vendor and _tokens(finding.vendor) & _tokens(rec.description):
        total += _W_VENDOR
        reasons.append(f"vendor '{finding.vendor}' named in record text")

    if finding.cwe and finding.cwe.upper() in {c.upper() for c in rec.cwes}:
        total += _W_CWE
        reasons.append(f"CWE match {finding.cwe}")

    if finding.function and len(finding.function) > 2:
        fn = finding.function.lower()
        if fn in hay or fn in {f.lower() for f in rec.functions}:
            total += _W_FUNCTION
            strong += _W_FUNCTION
            reasons.append(f"sink function '{finding.function}' named in record")

    return total, strong, reasons


def _record_is_advisory(rec: CveRecord) -> bool:
    return rec.source in ("loldrivers", "seed") or bool(rec.references)


def _candidate_pool(store: CveStore, finding: FindingFingerprint) -> list[CveRecord]:
    """Narrow the search: index hits (file / CWE / product) unioned. Falls back to
    the whole store only if no index key is available (keeps it fast at scale)."""
    pool: dict[str, CveRecord] = {}
    stem = finding.file_stem
    if finding.file:
        for rec in store.by_file(finding.file.lower()):
            pool[rec.id] = rec
    if stem:
        for rec in store.by_file(f"{stem}.sys"):
            pool[rec.id] = rec
        # filename-in-prose: scan records that have any file token OR match by CWE
    if finding.cwe:
        for rec in store.by_cwe(finding.cwe):
            pool[rec.id] = rec
    # Prose filename / device-family / product matches aren't indexable exactly,
    # so include every record for the text pass. The store is small (curated +
    # targeted ingest); a full scan here is cheap and maximizes recall.
    for rec in store.all():
        pool.setdefault(rec.id, rec)
    return list(pool.values())


def known_cve(
    store: CveStore,
    finding: FindingFingerprint,
    *,
    max_candidates: int = 10,
    weak_review_threshold: float = 0.15,
) -> NoveltyResult:
    """Structured Mode A. Returns a :class:`NoveltyResult` — KNOWN-CVE /
    KNOWN-ADVISORY / NO-PUBLIC-RECORD-FOUND with scored candidates + confidence."""
    scored: list[tuple[CveRecord, float, float, list[str]]] = []
    for rec in _candidate_pool(store, finding):
        total, strong, reasons = score_record(finding, rec)
        if total <= 0:
            continue
        scored.append((rec, total, strong, reasons))
    scored.sort(key=lambda t: t[1], reverse=True)

    candidates: list[CveCandidate] = []
    for rec, total, _strong, reasons in scored[:max_candidates]:
        if total < weak_review_threshold:
            continue
        candidates.append(
            CveCandidate(
                cve_id=(rec.cve_ids[0] if rec.cve_ids else ""),
                cve_ids=rec.cve_ids,
                record_id=rec.id,
                source=rec.source,
                score=total,
                reasons=tuple(reasons),
            )
        )

    # Attribution-gated verdict: only strongly-attributed records decide KNOWN.
    strong_hits = [
        (rec, total, strong)
        for rec, total, strong, _ in scored
        if strong >= _STRONG_ATTRIBUTION_MIN
    ]
    strong_with_cve = [(rec, total) for rec, total, _ in strong_hits if rec.cve_ids]

    if strong_with_cve:
        verdict = KNOWN_CVE
        top_score = max(t for _, t in strong_with_cve)
        confidence = "high" if top_score >= 0.6 else "medium"
    elif any(_record_is_advisory(rec) for rec, _, _ in strong_hits):
        verdict = KNOWN_ADVISORY
        confidence = "medium"
    else:
        verdict = NO_PUBLIC_RECORD
        # weak candidates may still exist -> low-confidence review, not a claim
        confidence = "low"

    evidence = {
        "mode": "A/structured",
        "candidates_considered": len(scored),
        "strong_attribution_hits": [rec.id for rec, _, _ in strong_hits],
        "finding": finding.to_dict(),
    }
    return NoveltyResult(
        verdict=verdict,
        confidence=confidence,
        candidates=tuple(candidates),
        method="structured",
        caveat=NO_PUBLIC_RECORD_CAVEAT if verdict == NO_PUBLIC_RECORD else "",
        evidence=evidence,
    )
