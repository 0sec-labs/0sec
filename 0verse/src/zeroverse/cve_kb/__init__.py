"""0verse shared CVE knowledge base + novelty/dedup gate.

A cross-profile capability that answers three questions against a local store of
normalized public advisories (NVD, OSV/GHSA, loldrivers-by-name) + our own prior
findings:

* **Mode A — ``known_cve(finding)``**: is this finding a KNOWN CVE? Structured
  attribution match first (filename/product/CWE/function), then embedding, then a
  web fallback. Recall-first; never auto-drops; never says "novel".
* **Mode B — ``dedup(finding, corpus)``**: embedding-nearest-neighbor over a
  technical fingerprint vs known-CVEs + prior findings, for review not auto-merge.
* **Mode C — ``cves_for(product, version)``**: deterministic CPE/range lookup —
  the blackbox-test-seeding path.

``novelty(finding, store)`` is the layered gate every profile calls; every
finding record then carries a ``novelty`` field {known_cve|no-record, evidence}.

The strongest honest verdict is NO-PUBLIC-RECORD-FOUND (+ caveat), explicitly
NOT a proof of novelty.
"""

from __future__ import annotations

from .cpe import CoverageHit, compare_versions, cves_for
from .embed import (
    CorpusEntry,
    DedupCandidate,
    EmbeddingBackend,
    HindsightBackend,
    LexicalBackend,
    dedup,
    get_backend,
)
from .gate import KnowledgeBaseSearcher, finding_from_driver_identity, novelty
from .ingest import build_store, load_bundled
from .match import known_cve, score_record
from .models import (
    KNOWN_ADVISORY,
    KNOWN_CVE,
    NO_PUBLIC_RECORD,
    NO_PUBLIC_RECORD_CAVEAT,
    SCHEMA,
    AffectedRange,
    CpeMatch,
    CveCandidate,
    CveRecord,
    FindingFingerprint,
    NoveltyResult,
)
from .store import CveStore

__all__ = [
    "KNOWN_ADVISORY",
    "KNOWN_CVE",
    "NO_PUBLIC_RECORD",
    "NO_PUBLIC_RECORD_CAVEAT",
    # models
    "SCHEMA",
    "AffectedRange",
    "CorpusEntry",
    "CoverageHit",
    "CpeMatch",
    "CveCandidate",
    "CveRecord",
    # store + ingest
    "CveStore",
    "DedupCandidate",
    "EmbeddingBackend",
    "FindingFingerprint",
    "HindsightBackend",
    "KnowledgeBaseSearcher",
    "LexicalBackend",
    "NoveltyResult",
    "build_store",
    "compare_versions",
    # mode C
    "cves_for",
    # mode B
    "dedup",
    "finding_from_driver_identity",
    "get_backend",
    # mode A
    "known_cve",
    "load_bundled",
    # gate + bridge
    "novelty",
    "score_record",
]
