"""Mode B — embedding-nearest-neighbor dedup over technical fingerprints.

``dedup(finding, corpus)`` ranks a finding against known-CVE records + our own
prior findings by similarity of a *technical fingerprint* (bug class, CWE, sink
function, location, product) and returns ranked candidates for precise verify —
it NEVER blind-auto-merges.

Embeddings are pluggable behind :class:`EmbeddingBackend`:

* :class:`HindsightBackend` reuses the LOCAL embeddings service (Hindsight at
  ``localhost:8888``) — no external API, no data egress. It is best-effort: if
  the service is unreachable or the endpoint shape differs, it returns ``None``
  and the caller transparently falls back.
* :class:`LexicalBackend` is the dependency-free fallback — a weighted token
  bag with cosine similarity. It is deliberately conservative: good enough to
  surface obvious same-bug pairs for review, and it keeps the whole gate working
  offline (the service was down during bring-up). Structured Mode A remains the
  authority; Mode B is a recall aid, not an adjudicator.
"""

from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from .models import CveRecord, FindingFingerprint

HINDSIGHT_URL_ENV = "ZEROVERSE_HINDSIGHT_URL"
DEFAULT_HINDSIGHT_URL = "http://localhost:8888"


class EmbeddingBackend(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]] | None:
        """Return one vector per text, or None if unavailable (caller falls back)."""
        ...

    @property
    def name(self) -> str: ...


@dataclass
class HindsightBackend:
    """Best-effort client for the local Hindsight embeddings service.

    Tries a couple of common embed-endpoint shapes; any failure -> None so the
    caller degrades to lexical. No external hosts are ever contacted.
    """

    base_url: str = ""
    timeout: float = 8.0

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = os.environ.get(HINDSIGHT_URL_ENV, DEFAULT_HINDSIGHT_URL)

    @property
    def name(self) -> str:
        return f"hindsight({self.base_url})"

    def embed(self, texts: Sequence[str]) -> list[list[float]] | None:
        for path, key in (("/embed", "embeddings"), ("/v1/embeddings", "data")):
            try:
                data = json.dumps({"input": list(texts), "texts": list(texts)}).encode()
                req = urllib.request.Request(
                    self.base_url.rstrip("/") + path,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                vecs = _extract_vectors(payload, key)
                if vecs and len(vecs) == len(texts):
                    return vecs
            except (urllib.error.URLError, OSError, ValueError, KeyError):
                continue
        return None


def _extract_vectors(payload: object, key: str) -> list[list[float]] | None:
    if isinstance(payload, dict) and key in payload and isinstance(payload[key], list):
        items = payload[key]
        if items and isinstance(items[0], dict) and "embedding" in items[0]:
            return [list(map(float, it["embedding"])) for it in items]
        if items and isinstance(items[0], list):
            return [list(map(float, v)) for v in items]
    return None


@dataclass
class LexicalBackend:
    """Dependency-free fallback: weighted token bag -> unit vector over a shared
    vocabulary built from the batch. Cosine on these is a Jaccard-ish similarity."""

    name: str = "lexical"

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        toked = [_tokenize(t) for t in texts]
        vocab: dict[str, int] = {}
        for toks in toked:
            for tok in toks:
                vocab.setdefault(tok, len(vocab))
        vecs: list[list[float]] = []
        for toks in toked:
            v = [0.0] * len(vocab)
            for tok, w in toks.items():
                v[vocab[tok]] = w
            vecs.append(_l2_normalize(v))
        return vecs


# Bug-class / CWE tokens carry more signal than generic prose; weight them up.
_HEAVY = 3.0
_HEAVY_HINTS = (
    "cwe", "uaf", "oob", "overflow", "rw", "physical", "ioctl", "ssrf", "smuggling", "toctou",
)


def _tokenize(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for raw in "".join(c if c.isalnum() else " " for c in text.lower()).split():
        if len(raw) <= 2:
            continue
        w = _HEAVY if any(h in raw for h in _HEAVY_HINTS) else 1.0
        out[raw] = out.get(raw, 0.0) + w
    return out


def _l2_normalize(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v))
    return [x / n for x in v] if n else v


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    return max(0.0, min(1.0, dot))


@dataclass(frozen=True)
class DedupCandidate:
    ref_id: str          # CVE id or prior-finding id
    ref_kind: str        # cve | finding
    similarity: float
    text: str

    def to_dict(self) -> dict[str, object]:
        return {
            "ref_id": self.ref_id,
            "ref_kind": self.ref_kind,
            "similarity": round(self.similarity, 4),
            "text": self.text[:200],
        }


def get_backend(prefer_hindsight: bool = True) -> EmbeddingBackend:
    """Return the best available backend: Hindsight if it answers, else lexical.

    Probes Hindsight with a tiny embed; on any failure returns the lexical
    fallback so callers never have to branch."""
    if prefer_hindsight:
        hs = HindsightBackend()
        if hs.embed(["probe"]) is not None:
            return hs
    return LexicalBackend()


@dataclass(frozen=True)
class CorpusEntry:
    ref_id: str
    ref_kind: str  # cve | finding
    text: str

    @classmethod
    def from_cve(cls, rec: CveRecord) -> CorpusEntry:
        cid = rec.cve_ids[0] if rec.cve_ids else rec.id
        text = " ".join(
            [cid, " ".join(rec.cwes), rec.product, rec.description, " ".join(rec.files)]
        ).strip()
        return cls(ref_id=cid, ref_kind="cve", text=text)

    @classmethod
    def from_finding(cls, f: FindingFingerprint) -> CorpusEntry:
        return cls(ref_id=f.finding_id or f.file or f.product or "finding",
                   ref_kind="finding", text=f.fingerprint_text())


def dedup(
    finding: FindingFingerprint,
    corpus: Sequence[CorpusEntry],
    *,
    backend: EmbeddingBackend | None = None,
    top_k: int = 5,
    min_similarity: float = 0.35,
) -> list[DedupCandidate]:
    """Mode B: rank ``finding`` against ``corpus`` by fingerprint similarity.

    Returns up to ``top_k`` candidates above ``min_similarity``, most-similar
    first. Empty corpus or empty fingerprint -> [] (nothing to dedup against)."""
    if not corpus:
        return []
    ftext = finding.fingerprint_text()
    if not ftext:
        return []
    backend = backend or get_backend()
    texts = [ftext] + [c.text for c in corpus]
    vecs = backend.embed(texts)
    if vecs is None:  # backend declined mid-flight -> lexical
        vecs = LexicalBackend().embed(texts)
    fvec, cvecs = vecs[0], vecs[1:]
    scored = [
        DedupCandidate(
            ref_id=c.ref_id, ref_kind=c.ref_kind, similarity=cosine(fvec, cv), text=c.text
        )
        for c, cv in zip(corpus, cvecs, strict=False)
    ]
    scored = [s for s in scored if s.similarity >= min_similarity]
    scored.sort(key=lambda s: s.similarity, reverse=True)
    return scored[:top_k]
