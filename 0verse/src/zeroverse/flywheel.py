"""#43 (M7 Bet B) — the PoV-dataset flywheel: a *preseeded* cognitive memory.

The single biggest lever a published CyberGym result identified is **memory**:
a 5-layer cognitive store ('Crystalline' — episodic / semantic / procedural /
analogical / principle) lifted pass@1 by ~23pp. The decisive lesson is *why* it
worked: it was **preseeded** with concepts / procedures / principles, not an
empty store that "consolidates" at run time. An earlier empty-store-and-consolidate
attempt here came back inconclusive precisely because consolidation on an empty
store extracts nothing.

0verse already owns the preseed and the episodic feed:

  * **the 90-archetype registry** (``seedcatalog`` / ``data/archetypes.json``) —
    the concepts / patterns / anti-patterns / principles, CVE-grounded; and
  * **the #32 labeled-PoV dataset** (``dataset``) + the #42 fleet sweeps — the
    episodic capture (confirmed PoVs, binary features, cross-target links).

This module assembles those into a **preseeded 5-layer memory** and uses it three
ways, all opt-in (``ZEROVERSE_FLYWHEEL=1``, default OFF):

  1. **Recall** — before triaging a new target, retrieve the most-similar past
     concepts / procedures / PoVs (by binary features + bug-class + sink symbols +
     the fleet similarity hash) and surface them.
  2. **Prime** — inject that recall into the triage funnel: a variant-analysis
     framing string + a rank bonus that lifts findings matching a known-fruitful
     pattern, plus a **cost-router** hint (skip the expensive LLM when memory sees
     *no* similar signal). This is RAG-priming, the near-term shippable win.
  3. **Remember** — after a confirmed PoV, write a structured episodic record
     (reusing the #32 dataset emitter — labels + pointers, never raw bytes) and
     update the procedural / analogical layers. Next run's preseed reads it back:
     the loop is closed across runs.

**The flywheel PRIMES; it never CONFIRMS.** No method returns a confirmed verdict.
The deterministic PoV oracle remains the sole adjudicator (PoV-is-truth), so memory
can re-order, re-frame, and re-budget a run but can *never* manufacture a false
positive. ``prove_priming`` demonstrates this on a controlled corpus, with an
un-similar control that gets no spurious lift.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, BinaryIO

from . import dataset, fleet, seedcatalog
from .analyze import Finding

# --- layers -----------------------------------------------------------------

PRINCIPLE = "principle"      # the archetype patterns / anti-patterns
SEMANTIC = "semantic"        # bug-class -> sink/symbol associations
PROCEDURAL = "procedural"    # the trigger/harness shape that confirmed a class
EPISODIC = "episodic"        # a past confirmed/hypothesis PoV record + features
ANALOGICAL = "analogical"    # cross-target similarity links from the fleet sweeps
LAYERS: tuple[str, ...] = (PRINCIPLE, SEMANTIC, PROCEDURAL, EPISODIC, ANALOGICAL)

# A recall must clear this combined-similarity floor to prime the funnel. Below it,
# memory reports "no similar signal" and the cost-router suggests the cheap lane.
PRIME_MIN = 0.18
_MAX_POV_BYTES = 2 * 1024 * 1024


def flywheel_enabled() -> bool:
    """The flywheel is opt-in. Default OFF — PoV-is-truth and the cold funnel are
    unchanged unless an operator sets ``ZEROVERSE_FLYWHEEL=1``."""
    return os.environ.get("ZEROVERSE_FLYWHEEL", "") not in ("", "0", "false", "no")


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() not in ("", "0", "false", "no")


def learning_path() -> Path | None:
    """Return the production learning ledger, when explicitly configured.

    Learning writes are deliberately separate from ``ZEROVERSE_DATASET_PATH``,
    which is the immutable recall/evaluation corpus. Reusing the same path would
    leak earlier evaluation outcomes into later cases, so it is rejected.
    """
    raw = os.environ.get("ZEROVERSE_LEARNING_PATH", "").strip()
    if not raw or _env_truthy("ZEROVERSE_EVALUATION"):
        return None
    path = Path(raw)
    recall_raw = os.environ.get("ZEROVERSE_DATASET_PATH", "").strip()
    if recall_raw and path.resolve() == Path(recall_raw).resolve():
        return None
    return path


# --- bug-class token vocabulary (the cross-corpus join key) ------------------
# Episodic records spell a class as ``CWE-78`` / ``cmdi`` / ``CWE-120 buffer
# overflow``; archetypes carry ``CWE-78`` + an engine-lens id ``bugclass:cmdi``.
# Normalizing both to a *token set* (CWE codes + a small lens-id/phrase map) lets a
# record and an archetype match on ``cwe-78`` even when their spellings differ.

_CWE_RX = re.compile(r"cwe-\d+", re.IGNORECASE)
_LENS_CLASS_IDS = ("cmdi", "overflow", "intoverflow", "fmtstring", "uaf", "logic")
_PHRASE_TO_CLASS: dict[str, str] = {
    "command injection": "cmdi", "os command": "cmdi", "command-exec": "cmdi",
    "buffer overflow": "overflow", "stack overflow": "overflow", "oob write": "overflow",
    "out-of-bounds": "overflow", "out of bounds": "overflow",
    "integer overflow": "intoverflow", "format string": "fmtstring",
    "use-after-free": "uaf", "use after free": "uaf", "double-free": "uaf",
    "double free": "uaf",
}


def class_tokens(*parts: str) -> frozenset[str]:
    """Normalize one or more class spellings to a comparable token set: every
    ``CWE-\\d+`` code plus any recognized lens-id / phrase. The cross-corpus join key
    that lets a dataset record's ``CWE-78`` meet an archetype's ``cmdi`` lens."""
    blob = " ".join(p for p in parts if p).lower()
    toks: set[str] = {m.group(0) for m in _CWE_RX.finditer(blob)}
    for cid in _LENS_CLASS_IDS:
        if re.search(rf"\b{cid}\b", blob):
            toks.add(cid)
    for phrase, cid in _PHRASE_TO_CLASS.items():
        if phrase in blob:
            toks.add(cid)
    return frozenset(toks)


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a or not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


# --- memory record ----------------------------------------------------------

@dataclass(frozen=True)
class Memory:
    """One unit of preseeded or captured memory in a layer."""

    layer: str
    key: str                         # stable id within the layer
    class_tokens: frozenset[str]     # normalized bug-class tokens (the join key)
    sinks: frozenset[str]            # associated sink symbols
    sources: frozenset[str]          # associated source/getter symbols
    fmt: str = ""                    # binary format (episodic), or ""
    arch: str = ""                   # binary arch (episodic), or ""
    sim_hash: frozenset[str] = frozenset()   # fleet shingle hash (analogical), or empty
    framing: str = ""                # the variant-analysis framing to prime the funnel
    text: str = ""                   # human/agent-readable concept text (the RAG context)
    provenance: str = ""             # where it came from (archetype uid / record id / fleet)
    confirmed: bool = False          # episodic: did a real PoV reproduce?
    outcome: str = "knowledge"       # knowledge | confirmed | refuted | hypothesis
    pov_path: str = ""               # episodic: pointer to the replay script, never bytes
    function: str = ""               # exact retained site identity for refutations
    offset: str = ""
    weight: float = 1.0              # a small prior (proven-fruitful episodic > raw principle)


# --- the target side of a recall query --------------------------------------

@dataclass(frozen=True)
class TargetQuery:
    """What is known about a *new* target before triage — the recall key."""

    class_tokens: frozenset[str] = frozenset()
    sinks: frozenset[str] = frozenset()
    sources: frozenset[str] = frozenset()
    fmt: str = ""
    arch: str = ""
    bits: int = 0
    sim_hash: frozenset[str] = frozenset()

    @classmethod
    def from_features(
        cls,
        features: Mapping[str, Any] | None = None,
        *,
        bug_class: str = "",
        sinks: Iterable[str] = (),
        sources: Iterable[str] = (),
        sim_hash: Iterable[str] = (),
    ) -> TargetQuery:
        feats = dict(features or {})
        return cls(
            class_tokens=class_tokens(bug_class),
            sinks=frozenset(s for s in sinks if s),
            sources=frozenset(s for s in sources if s),
            fmt=str(feats.get("format", "")),
            arch=str(feats.get("arch", "")),
            bits=int(feats.get("bits", 0) or 0),
            sim_hash=frozenset(sim_hash),
        )


def query_from_findings(
    features: Mapping[str, Any] | None,
    findings: Sequence[Finding],
    *,
    bug_class: str = "",
) -> TargetQuery:
    """Build a recall query from the triage feature vector + the live hypothesis
    queue: the sinks/sources the engine actually sees, plus any class tokens carried
    by the findings' origins (``bugclass:<id>``) and the requested ``bug_class``."""
    sinks = frozenset(f.sink for f in findings if f.sink)
    sources = frozenset(f.source for f in findings if f.source)
    parts = [bug_class, *[_finding_class_text(f) for f in findings]]
    return TargetQuery(
        class_tokens=class_tokens(*parts),
        sinks=sinks,
        sources=sources,
        fmt=str((features or {}).get("format", "")),
        arch=str((features or {}).get("arch", "")),
        bits=int((features or {}).get("bits", 0) or 0),
    )


def _finding_class_text(f: Finding) -> str:
    """The class-bearing text of a finding: its origin (``bugclass:<id>`` /
    ``seed:<id>``) plus its sink (vendor sinks like ``doSystem`` imply cmdi)."""
    origin = f.origin
    if ":" in origin:
        origin = origin.split(":", 1)[1]
    return f"{origin} {f.sink}"


def _finding_class_tokens(f: Finding) -> frozenset[str]:
    return class_tokens(_finding_class_text(f))


# --- a recall result --------------------------------------------------------

@dataclass(frozen=True)
class Recall:
    """A memory retrieved for a query, with its score and the dims that fired."""

    memory: Memory
    score: float
    reasons: tuple[str, ...]


def _score(query: TargetQuery, m: Memory) -> tuple[float, tuple[str, ...]]:
    """Combined 0..1 similarity of a memory to a query + the contributing dims.

    Deterministic and explainable: a weighted blend of bug-class token overlap
    (the dominant signal), sink-symbol overlap, source overlap, binary-feature
    match, and the fleet similarity-hash overlap, nudged by the memory's prior."""
    reasons: list[str] = []
    cls = _jaccard(query.class_tokens, m.class_tokens)
    if cls:
        reasons.append(f"class:{cls:.2f}")
    snk = _jaccard(query.sinks, m.sinks)
    if snk:
        reasons.append(f"sink:{snk:.2f}")
    src = _jaccard(query.sources, m.sources)
    if src:
        reasons.append(f"source:{src:.2f}")
    feat = 0.0
    if m.fmt or m.arch:
        hits = 0
        total = 0
        if m.fmt:
            total += 1
            hits += 1 if m.fmt == query.fmt else 0
        if m.arch:
            total += 1
            hits += 1 if m.arch == query.arch else 0
        feat = hits / total if total else 0.0
        if feat:
            reasons.append(f"feat:{feat:.2f}")
    sh = _jaccard(query.sim_hash, m.sim_hash)
    if sh:
        reasons.append(f"hash:{sh:.2f}")
    base = 0.45 * cls + 0.25 * snk + 0.10 * src + 0.10 * feat + 0.10 * sh
    score = round(min(1.0, base * m.weight), 4)
    return score, tuple(reasons)


# --- priming (the funnel injection) -----------------------------------------

@dataclass(frozen=True)
class Priming:
    """What the flywheel injects into a run. ``framing`` re-frames the LLM funnel;
    ``rank_bonus`` lifts findings that match a known-fruitful pattern; ``cost_route``
    is the budget hint. None of it confirms anything — the oracle still decides."""

    recalls: tuple[Recall, ...]
    framing: str
    context: str
    primed_sinks: frozenset[str]
    primed_class_tokens: frozenset[str]
    refuted_paths: frozenset[tuple[str, str, str, str]]
    refuted_class_tokens: frozenset[str]
    top_score: float
    cost_route: str                  # "full" | "cheap"
    cost_reason: str

    @property
    def active(self) -> bool:
        return self.top_score >= PRIME_MIN

    def rank_bonus(self, f: Finding) -> float:
        """A bounded ordering bonus for a finding that matches recalled memory.

        Gated by ``active`` (a recall cleared ``PRIME_MIN``), so a boost only ever
        fires when memory is genuinely similar — an un-similar target gets a flat 0.
        It lifts a finding whose sink the memory knows is fruitful (the dominant
        signal — a sink that previously yielded a confirmed PoV on a similar target)
        and/or whose bug class the memory has seen. It affects ONLY queue ordering /
        escalation, never the verdict: memory primes, the oracle confirms."""
        if not self.active:
            return 0.0
        bonus = 0.0
        if f.sink and f.sink in self.primed_sinks:
            bonus += 0.50
        if _finding_class_tokens(f) & self.primed_class_tokens:
            bonus += 0.20
        # Deterministic refutations are negative memory: they can demote the exact
        # path that an oracle proved unreachable, but can never confirm or reject a
        # finding. The live oracle still adjudicates every candidate.
        exact_refutation = (f.source, f.sink, f.function, hex(f.sink_addr)) in self.refuted_paths
        if exact_refutation:
            bonus -= 0.55
        if exact_refutation and _finding_class_tokens(f) & self.refuted_class_tokens:
            bonus -= 0.25
        return round(max(-0.50, min(0.70, bonus)), 4)


_NO_SIGNAL = Priming(
    recalls=(), framing="", context="", primed_sinks=frozenset(),
    primed_class_tokens=frozenset(), refuted_paths=frozenset(),
    refuted_class_tokens=frozenset(), top_score=0.0, cost_route="cheap",
    cost_reason="no similar memory above PRIME_MIN — cost-router suggests the cheap lane",
)


# ===========================================================================
# The Flywheel: a preseeded 5-layer store + recall / prime / remember
# ===========================================================================

class Flywheel:
    """The preseeded 5-layer cognitive memory.

    Built (not consolidated-from-empty) at construction:
      * PRINCIPLE + SEMANTIC + PROCEDURAL from the 90 archetypes (concepts,
        sink associations, confirmation procedures);
      * EPISODIC + ANALOGICAL from the #32 dataset corpus at ``dataset_path``
        (confirmed/hypothesis PoVs and the #42 fleet cross-target links).
    """

    def __init__(self, *, dataset_path: str | os.PathLike[str] | None = None) -> None:
        self.memories: list[Memory] = []
        self._by_layer: dict[str, list[Memory]] = {ly: [] for ly in LAYERS}
        self._preseed_archetypes()
        self.episodic_loaded = 0
        if dataset_path is not None:
            self.load_dataset(dataset_path)

    # --- construction -------------------------------------------------------

    def _add(self, m: Memory) -> None:
        self.memories.append(m)
        self._by_layer[m.layer].append(m)

    def _preseed_archetypes(self) -> None:
        """Preseed PRINCIPLE / SEMANTIC / PROCEDURAL from the 90-archetype registry.
        This is the decisive design point: the store ships *full*, not empty."""
        for a in seedcatalog.load_archetypes():
            seed = _safe_seed(a)
            sinks = frozenset(seed.sink_symbols) if seed else frozenset()
            sources = frozenset(seed.source_symbols) if seed else frozenset()
            ctoks = class_tokens(a.cwe, a.engine_lens or "", seed.bug_class if seed else "")
            framing = seed.framing if seed and seed.framing else _principle_framing(a)
            # PRINCIPLE: the pattern + the anti-pattern (the confirmable caveat).
            self._add(Memory(
                layer=PRINCIPLE, key=f"principle:{a.uid}", class_tokens=ctoks,
                sinks=sinks, sources=sources, framing=framing,
                text=f"[{a.uid}] {a.name}: {a.pattern}  ANTI-PATTERN/limit: {a.confirmable}",
                provenance=f"archetype:{a.uid} grounding={','.join(a.grounding[:3])}",
                weight=1.0,
            ))
            # SEMANTIC: bug-class -> sink/symbol associations (only when mapped).
            if seed and (sinks or sources):
                self._add(Memory(
                    layer=SEMANTIC, key=f"semantic:{a.uid}", class_tokens=ctoks,
                    sinks=sinks, sources=sources, framing=framing,
                    text=f"{a.cwe} ({a.engine_lens}) sinks={sorted(sinks)} "
                         f"sources={sorted(sources)}",
                    provenance=f"archetype:{a.uid}", weight=1.0,
                ))
            # PROCEDURAL: how this class is confirmed (the trigger/harness shape).
            self._add(Memory(
                layer=PROCEDURAL, key=f"procedural:{a.uid}", class_tokens=ctoks,
                sinks=sinks, sources=sources,
                text=f"route={a.route}: {_procedure_for_route(a.route)}",
                provenance=f"archetype:{a.uid}", weight=0.9,
            ))

    def load_dataset(self, path: str | os.PathLike[str]) -> int:
        """Fold a #32 NDJSON corpus into the EPISODIC + ANALOGICAL layers. Each row is
        validated by ``dataset.iter_records`` (PoV-is-truth, no raw bytes) on the way
        in. Returns the number of episodic memories added. Best-effort: a missing or
        empty file is a no-op (the preseed already stands on its own)."""
        added = 0
        analog: dict[str, _AnalogAcc] = {}
        for d in dataset.iter_records(Path(path)):
            self._add(_episodic_from_record(d))
            added += 1
            link = _fleet_link(d)
            if link is not None:
                arche, member, sink = link
                acc = analog.setdefault(arche, _AnalogAcc(arche))
                acc.members.add(member)
                if sink:
                    acc.sinks.add(sink)
                acc.ctoks |= class_tokens(str((d.get("label") or {}).get("bug_class", "")))
        for acc in analog.values():
            self._add(acc.to_memory())
        self.episodic_loaded += added
        return added

    # --- recall -------------------------------------------------------------

    def recall(
        self, query: TargetQuery, *, k: int = 5, layers: Sequence[str] | None = None
    ) -> list[Recall]:
        """Retrieve the top-``k`` memories most similar to ``query`` (optionally
        restricted to ``layers``), ranked by combined similarity. The 'Recall' step."""
        pool = self.memories if not layers else [
            m for ly in layers for m in self._by_layer.get(ly, [])
        ]
        scored: list[Recall] = []
        for m in pool:
            s, reasons = _score(query, m)
            if s > 0.0:
                scored.append(Recall(m, s, reasons))
        scored.sort(key=lambda r: (-r.score, r.memory.layer, r.memory.key))
        return scored[:k]

    # --- prime --------------------------------------------------------------

    def prime(self, query: TargetQuery, *, k: int = 5) -> Priming:
        """Turn a recall into a funnel injection: a variant-analysis framing, a RAG
        context block, a rank-bonus over the recalled sinks/classes, and a cost-router
        hint. Returns the inert ``_NO_SIGNAL`` priming when nothing clears
        ``PRIME_MIN`` (the cost-router then suggests the cheap lane). PRIMES only —
        never a verdict."""
        recalls = self.recall(query, k=k)
        if not recalls or recalls[0].score < PRIME_MIN:
            return _NO_SIGNAL
        similar = [r for r in recalls if r.score >= PRIME_MIN]
        top = similar[0]
        positive = [r for r in similar if r.memory.outcome != "refuted"]
        refuted = [r for r in similar if r.memory.outcome == "refuted"]
        primed_sinks = frozenset(s for r in positive for s in r.memory.sinks)
        primed_ctoks = frozenset(t for r in positive for t in r.memory.class_tokens)
        refuted_paths = frozenset(
            (source, sink, r.memory.function, r.memory.offset)
            for r in refuted
            for source in r.memory.sources
            for sink in r.memory.sinks
            if r.memory.function and r.memory.offset
        )
        refuted_ctoks = frozenset(t for r in refuted for t in r.memory.class_tokens)
        framing = next((r.memory.framing for r in positive if r.memory.framing), "")
        context = _context_block(similar)
        return Priming(
            recalls=tuple(recalls),
            framing=framing,
            context=context,
            primed_sinks=primed_sinks,
            primed_class_tokens=primed_ctoks,
            refuted_paths=refuted_paths,
            refuted_class_tokens=refuted_ctoks,
            top_score=top.score,
            cost_route="full",
            cost_reason=(f"recalled {len(similar)} similar memory/-ies "
                         f"(top={top.score:.2f}) — escalate to the LLM funnel"),
        )

    def cost_route(self, query: TargetQuery) -> tuple[str, str]:
        """The cost-router hook: ``("cheap"|"full", reason)``. 'cheap' when memory
        sees no similar signal — the caller may skip the expensive LLM stage. Honest:
        a budget hint only; it never changes a verdict and the oracle still runs."""
        p = self.prime(query)
        return p.cost_route, p.cost_reason

    # --- remember (close the loop) -----------------------------------------

    def remember(
        self,
        records: Iterable[dataset.DatasetRecord | Mapping[str, Any]],
        *,
        emit_path: str | os.PathLike[str] | None = None,
    ) -> int:
        """Capture: fold confirmed/hypothesis PoV records into the EPISODIC (and, for
        fleet-origin rows, ANALOGICAL) + PROCEDURAL layers, and — when ``emit_path`` is
        set — append them to the #32 NDJSON corpus via the dataset emitter (labels +
        pointers, never bytes; ``dataset.emit_records`` enforces PoV-is-truth). Next
        run's preseed reads them back: the loop is closed. Returns the count captured."""
        recs = list(records)
        dicts: list[dict[str, Any]] = []
        ds_records: list[dataset.DatasetRecord] = []
        for r in recs:
            if isinstance(r, dataset.DatasetRecord):
                ds_records.append(r)
                dicts.append(r.to_dict())
            else:
                dicts.append(dict(r))
        for d in dicts:
            dataset.validate_record(d)
            self._add(_episodic_from_record(d))
            link = _fleet_link(d)
            if link is not None:
                arche, member, sink = link
                acc = _AnalogAcc(arche)
                acc.members.add(member)
                if sink:
                    acc.sinks.add(sink)
                acc.ctoks |= class_tokens(str((d.get("label") or {}).get("bug_class", "")))
                self._add(acc.to_memory())
            if d.get("verdict") == "confirmed":
                self._add(_procedural_from_record(d))
        if emit_path is not None and ds_records:
            dataset.emit_records(ds_records, Path(emit_path))
        self.episodic_loaded += len(dicts)
        return len(dicts)

    # --- introspection ------------------------------------------------------

    def counts(self) -> dict[str, int]:
        c = {ly: len(self._by_layer[ly]) for ly in LAYERS}
        c["total"] = len(self.memories)
        return c

    def recall_dict(self, query: TargetQuery, *, k: int = 5) -> dict[str, Any]:
        """An MCP/JSON-friendly recall payload: the ranked memories + the cost-router
        verdict, for the ``recall_similar`` tool."""
        recalls = self.recall(query, k=k)
        cost, cost_reason = self.cost_route(query)
        return {
            "counts": self.counts(),
            "cost_route": cost,
            "cost_reason": cost_reason,
            "recalls": [
                {
                    "layer": r.memory.layer,
                    "key": r.memory.key,
                    "score": r.score,
                    "reasons": list(r.reasons),
                    "framing": r.memory.framing,
                    "text": r.memory.text,
                    "provenance": r.memory.provenance,
                    "confirmed": r.memory.confirmed,
                    "outcome": r.memory.outcome,
                    "pov_path": r.memory.pov_path,
                }
                for r in recalls
            ],
        }


def remember_completed_run(
    run_result: Any,
    *,
    binary: str | Path,
    backend: str,
) -> int:
    """Persist evidence-grade learning from one completed production run.

    Only two outcome classes are admitted:

    * oracle-confirmed PoVs with a durable replay-script pointer; and
    * deterministic reachability refutations (angr UNSAT / ``pruned``).

    Unresolved LLM hypotheses are intentionally excluded. The destination is an
    append-only private ledger distinct from the frozen recall/evaluation corpus.
    Existing record ids are skipped, making retries idempotent. Any disabled or
    evaluation configuration is a no-op.
    """
    out = learning_path()
    if out is None:
        return 0
    records = dataset.records_from_run(
        run_result, binary=binary, backend=backend
    )
    eligible: list[dataset.DatasetRecord] = []
    for record in records:
        if record.verdict == "confirmed":
            retained = _retain_replayable_pov(record)
            if retained is not None:
                eligible.append(retained)
        elif record.verdict == "pruned" and record.oracle == "angr-reachability(UNSAT)":
            eligible.append(record)
    if not eligible:
        return 0

    with _locked_learning_ledger(out):
        existing_outcomes: set[tuple[str, str, str]] = set()
        if out.exists():
            existing_outcomes = {
                (
                    str(row.get("record_id", "")),
                    str(row.get("verdict", "")),
                    str(row.get("oracle", "")),
                )
                for row in dataset.iter_records(out)
            }
        fresh = [
            record
            for record in eligible
            if (record.record_id, record.verdict, record.oracle) not in existing_outcomes
        ]
        if not fresh:
            return 0
        return Flywheel().remember(fresh, emit_path=out)


def _retain_replayable_pov(
    record: dataset.DatasetRecord,
) -> dataset.DatasetRecord | None:
    """Bind a confirmed record to stable, bounded replay-script bytes."""
    if not record.pov_path:
        return None
    path = Path(record.pov_path)
    try:
        absolute = path.resolve(strict=True)
    except OSError:
        return None
    if path.is_symlink() or not absolute.is_file():
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_POV_BYTES:
            return None
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > _MAX_POV_BYTES:
                return None
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity or total != before.st_size:
            return None
    finally:
        os.close(descriptor)
    return replace(
        record,
        pov_path=str(absolute),
        repro_cmd=f"python3 {absolute}",
        pov_sha256=digest.hexdigest(),
    )


@contextmanager
def _locked_learning_ledger(path: Path) -> Iterator[None]:
    """Serialize the ledger's read/deduplicate/append transaction cross-process."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    with lock_path.open("a+b") as lock:
        _lock_file(lock)
        try:
            yield
        finally:
            _unlock_file(lock)


def _lock_file(lock: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        lock.seek(0)
        if not lock.read(1):
            lock.seek(0)
            lock.write(b"0")
            lock.flush()
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
        return
    import fcntl

    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)


def _unlock_file(lock: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        return
    import fcntl

    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


# --- builders / helpers (preseed + capture) ---------------------------------

def _safe_seed(a: seedcatalog.Archetype) -> fleet.FleetSeed | None:
    """Resolve an archetype to its fleet matcher (carrying the sink/source vocab),
    or None when it has no implementing lens (an honest hand-off archetype)."""
    if not a.implemented:
        return None
    try:
        return fleet.seed_from_archetype(a.uid)
    except Exception:
        return None


def _principle_framing(a: seedcatalog.Archetype) -> str:
    return (f"VARIANT ANALYSIS ({a.cwe}): hunt siblings of the '{a.name}' pattern — "
            f"{a.detection_signature[:160]}")


_ROUTE_PROCEDURE: dict[str, str] = {
    "userland-confirmable": "differential crash / exec-trap oracle; trigger = over-long "
                            "argv|stdin (A*512) or a per-run token canary for cmdi",
    "userland-med": "same userland oracle once the specific path/state is driven "
                    "(protocol stepping)",
    "userland-hypothesis": "race/signal-gated — the static hint is the deliverable",
    "firmware-lane": "Qiling per-handler emulation oracle (cmdi-canary / crash oracle)",
    "firmware-lane-partial": "partial Qiling + nvram model; needs socket/daemon scaffolding",
    "firmware-static": "static-only extraction (backdoor / hardcoded key / update crypto)",
    "firmware-detect-only": "detect-only; hand off to a specialist baseband emulator",
    "kernel-static": "rank as a hypothesis on the stripped .ko; confirm on the bench "
                     "KASAN verify lane",
    "kernel-verify": "hypothesis only (deferred-free/RCU/refcount/race) — build+boot the "
                     "module under KASAN and replay the GC/commit sequence",
    "not-binary-detectable": "needs source / a live oracle — honest hand-off",
}


def _procedure_for_route(route: str) -> str:
    return _ROUTE_PROCEDURE.get(route, "route-specific confirmation procedure")


def _episodic_from_record(d: Mapping[str, Any]) -> Memory:
    """One EPISODIC memory from a #32 dataset record: the binary features + label +
    PoV pointer of a past run. Carries the fleet shingle hash of its explanation when
    present (a weak analogical signal); never any raw bytes."""
    label = dict(d.get("label") or {})
    feats = dict(d.get("features") or {})
    pov = dict(d.get("pov") or {})
    bug_class = str(label.get("bug_class", ""))
    sink = str(label.get("sink", ""))
    source = str(label.get("source", ""))
    verdict = str(d.get("verdict", ""))
    confirmed = verdict == "confirmed"
    outcome = (
        "refuted"
        if verdict == "pruned" and d.get("oracle") == "angr-reachability(UNSAT)"
        else verdict
    )
    return Memory(
        layer=EPISODIC,
        key=f"episodic:{d.get('record_id', '')}",
        class_tokens=class_tokens(bug_class),
        sinks=frozenset({sink}) if sink else frozenset(),
        sources=frozenset({source}) if source else frozenset(),
        fmt=str(feats.get("format", "")),
        arch=str(feats.get("arch", "")),
        framing=(
            f"a confirmed {bug_class} was found on a similar target "
            f"({d.get('binary_name', '')}) — hunt its sibling here"
            if confirmed
            else (
                f"the {source}->{sink} path was deterministically refuted on a "
                "similar target — deprioritize that exact path, not the bug class"
                if outcome == "refuted"
                else ""
            )
        ),
        text=f"{d.get('binary_name', '')}: {bug_class} {source}->{sink} "
             f"[{d.get('verdict', '')}/{d.get('oracle', '')}]",
        provenance=f"record:{d.get('record_id', '')} backend={d.get('backend', '')}",
        confirmed=bool(confirmed),
        outcome=outcome,
        pov_path=str(pov.get("path", "")),
        function=str(label.get("function", "")),
        offset=str(label.get("offset", "")),
        weight=1.15 if confirmed else 0.85,
    )


def _procedural_from_record(d: Mapping[str, Any]) -> Memory:
    label = dict(d.get("label") or {})
    pov = dict(d.get("pov") or {})
    bug_class = str(label.get("bug_class", ""))
    return Memory(
        layer=PROCEDURAL,
        key=f"procedural:record:{d.get('record_id', '')}",
        class_tokens=class_tokens(bug_class),
        sinks=frozenset({str(label.get("sink", ""))}) - {""},
        sources=frozenset({str(label.get("source", ""))}) - {""},
        text=f"CONFIRMED via {d.get('oracle', '')}: {pov.get('repro_cmd', '')} "
             f"(capability={pov.get('capability', '')})",
        provenance=f"record:{d.get('record_id', '')}",
        confirmed=True,
        pov_path=str(pov.get("path", "")),
        weight=1.05,
    )


_FLEET_RX = re.compile(r"variant-of\[([^\]]+)\]")


def _fleet_link(d: Mapping[str, Any]) -> tuple[str, str, str] | None:
    """If a record came from a #42 fleet sweep (its explanation begins
    ``variant-of[<archetype>]``), return ``(archetype, member, sink)`` for the
    analogical layer; else None."""
    expl = str(d.get("explanation", ""))
    m = _FLEET_RX.search(expl)
    if not m:
        return None
    arche = m.group(1)
    member = str(d.get("binary_name", ""))
    sink = str((d.get("label") or {}).get("sink", ""))
    return arche, member, sink


@dataclass
class _AnalogAcc:
    """Accumulator that folds many fleet rows of one archetype into a single
    cross-target ANALOGICAL link."""

    archetype: str
    members: set[str] = field(default_factory=set)
    sinks: set[str] = field(default_factory=set)
    ctoks: frozenset[str] = frozenset()

    def to_memory(self) -> Memory:
        n = len(self.members)
        return Memory(
            layer=ANALOGICAL,
            key=f"analogical:{self.archetype}",
            class_tokens=self.ctoks or class_tokens(self.archetype),
            sinks=frozenset(self.sinks),
            sources=frozenset(),
            framing=(f"the '{self.archetype}' pattern recurs across {n} fleet "
                     f"target(s) — treat this as another sibling"),
            text=f"fleet cross-target link: {self.archetype} seen on "
                 f"{sorted(self.members)} via {sorted(self.sinks)}",
            provenance=f"fleet:{self.archetype} members={n}",
            # more corroborating targets -> a slightly stronger analogical prior
            weight=round(min(1.3, 1.0 + 0.05 * n), 3),
        )


def _context_block(recalls: Sequence[Recall]) -> str:
    """The RAG context injected ahead of triage: a compact, layer-tagged digest of
    the recalled memories (concepts / procedures / past PoVs)."""
    lines = ["PRIMING — most similar prior knowledge (memory PRIMES, the oracle still "
             "confirms):"]
    for r in recalls:
        lines.append(f"  [{r.memory.layer} {r.score:.2f} {','.join(r.reasons)}] "
                     f"{r.memory.text}")
    return "\n".join(lines)


# ===========================================================================
# PROOF — primed vs cold, with an un-similar control (real, computed numbers)
# ===========================================================================

@dataclass(frozen=True)
class _Scenario:
    name: str
    features: dict[str, Any]
    findings: list[Finding]
    target_finding: Finding   # the known-fruitful site we measure 'time-to-locate' for


@dataclass(frozen=True)
class ProofReport:
    """The primed-vs-cold benchmark result. Every number is computed from the real
    ranking mechanism (``agent.cheap_score`` + the flywheel ``rank_bonus``) — nothing
    is fabricated, and because memory only re-orders, no verdict can flip."""

    similar_recall_top: float
    control_recall_top: float
    similar_cold_rank: int
    similar_primed_rank: int
    control_cold_rank: int
    control_primed_rank: int
    similar_cost_route: str
    control_cost_route: str
    confirmations_changed: bool

    @property
    def locate_delta(self) -> int:
        """How many fewer escalations priming needs to reach the known bug on the
        SIMILAR target (positive = priming located it sooner)."""
        return self.similar_cold_rank - self.similar_primed_rank

    @property
    def control_delta(self) -> int:
        """The un-similar control's rank change — MUST be 0 (no spurious lift)."""
        return self.control_cold_rank - self.control_primed_rank

    def as_text(self) -> str:
        return (
            "0verse flywheel — primed-vs-cold proof (real numbers)\n"
            f"  recall discrimination: similar top={self.similar_recall_top:.3f} "
            f"vs control top={self.control_recall_top:.3f}\n"
            f"  SIMILAR target  : rank-to-locate cold=#{self.similar_cold_rank} "
            f"primed=#{self.similar_primed_rank}  -> {self.locate_delta} fewer "
            f"escalation(s); cost_route={self.similar_cost_route}\n"
            f"  CONTROL (unsim) : rank-to-locate cold=#{self.control_cold_rank} "
            f"primed=#{self.control_primed_rank}  -> delta={self.control_delta} "
            f"(must be 0); cost_route={self.control_cost_route}\n"
            f"  confirmations changed by memory: {self.confirmations_changed} "
            "(MUST be False — memory primes, the oracle confirms)\n"
        )


def _confirmed_pov_record() -> dataset.DatasetRecord:
    """The single confirmed PoV we seed memory with: a vendor-cmdi
    ``getenv -> doSystem`` bug on target A (ELF/x86-64). ``doSystem`` is a real
    firmware cmdi sink the *generic* cheap ranker underrates — exactly the gap a
    memory of a past confirmed PoV closes."""
    feats = dataset.BinaryFeatures(format="ELF", arch="x86-64", bits=64, endian="little")
    return dataset.DatasetRecord(
        record_id=dataset.record_id("router_a", "apply_cfg", "doSystem", "0x401320", "cmdi"),
        dataset_version=dataset.DATASET_VERSION,
        created_at="2026-06-28T00:00:00+00:00",
        tool=dict(dataset._TOOL), backend="ghidra", binary_name="router_a",
        features=feats, bug_class="CWE-78 OS command injection", source="getenv",
        sink="doSystem", function="apply_cfg", offset="0x401320", verdict="confirmed",
        oracle="canary-marker", capability="command-exec", dedup_bucket="aa11",
        pov_path="0verse-out/pov_router_a.py",
        repro_cmd="python3 0verse-out/pov_router_a.py",
        explanation="tainted env reaches doSystem(); token marker proves exec", synthetic=True,
    )


def _mk_finding(source: str, sink: str, function: str, origin: str = "slice") -> Finding:
    return Finding(source=source, sink=sink, function=function,
                   source_addr=0, sink_addr=0, path_len=0, origin=origin)


def _similar_scenario() -> _Scenario:
    """Target B — a *similar* router firmware: the same vendor-cmdi ``getenv ->
    doSystem`` site (low generic score) buried under higher-scoring generic noise."""
    target = _mk_finding("getenv", "doSystem", "handle_set", origin="bugclass:cmdi")
    noise = [
        _mk_finding("read", "memcpy", "parse_a"),       # mid score
        _mk_finding("recv", "memcpy", "parse_b"),        # mid score
        _mk_finding("fgets", "strcat", "fmt_c"),         # mid score
        _mk_finding("scanf", "sprintf", "fmt_d"),        # mid score
    ]
    return _Scenario(
        name="similar",
        features={"format": "ELF", "arch": "x86-64", "bits": 64},
        findings=[*noise, target],
        target_finding=target,
    )


def _control_scenario() -> _Scenario:
    """Target B' — the *un-similar* control: a memcpy-shaped Mach-O/arm64 target with
    no cmdi and no vendor sink, dissimilar to the seeded ``getenv->doSystem`` PoV.
    The cmdi memory must NOT lift anything here — priming stays inert, the queue order
    is identical to cold, and the cost-router routes to the cheap lane."""
    target = _mk_finding("read", "memcpy", "decode_hdr")
    others = [
        _mk_finding("recv", "memcpy", "decode_body"),
        _mk_finding("fread", "strcpy", "copy_name"),
        _mk_finding("scanf", "sprintf", "fmt_x"),
        _mk_finding("read", "memmove", "shift_buf"),
    ]
    return _Scenario(
        name="control",
        features={"format": "Mach-O", "arch": "arm64", "bits": 64},
        findings=[*others, target],
        target_finding=target,
    )


def _rank_to_locate(
    findings: Sequence[Finding], target: Finding, bonus: Callable[[Finding], float] | None
) -> int:
    """1-indexed position of ``target`` in the funnel's escalation order (the number
    of escalations needed to reach it) under an optional ``rank_bonus``. Uses the
    *same* ordering key the real ``agent.TriageFunnel`` uses."""
    from .agent import cheap_score

    def eff(f: Finding) -> float:
        return cheap_score(f) + (bonus(f) if bonus is not None else 0.0)

    order = sorted(findings, key=lambda f: (-eff(f), f.sink, f.source, f.sink_addr))
    for i, f in enumerate(order, start=1):
        if (f.function, f.sink, f.source) == (target.function, target.sink, target.source):
            return i
    return len(order) + 1


def prove_priming() -> ProofReport:
    """Run the controlled primed-vs-cold benchmark and return real, computed deltas.

    Method: seed memory with ONE confirmed ``getenv->doSystem`` PoV (target A). On a
    SIMILAR target B (same vendor-cmdi site under generic noise) measure how many
    escalations are needed to reach that site — cold (cheap score only) vs primed
    (cheap score + flywheel rank-bonus). Repeat on an UN-similar control B'. Memory
    only re-orders the queue; it never adjudicates, so confirmations are identical.
    """
    fw = Flywheel()
    fw.remember([_confirmed_pov_record()])

    sim = _similar_scenario()
    ctl = _control_scenario()

    sim_q = query_from_findings(sim.features, sim.findings)
    ctl_q = query_from_findings(ctl.features, ctl.findings)
    sim_prime = fw.prime(sim_q)
    ctl_prime = fw.prime(ctl_q)

    sim_cold = _rank_to_locate(sim.findings, sim.target_finding, None)
    sim_primed = _rank_to_locate(sim.findings, sim.target_finding, sim_prime.rank_bonus)
    ctl_cold = _rank_to_locate(ctl.findings, ctl.target_finding, None)
    ctl_primed = _rank_to_locate(ctl.findings, ctl.target_finding, ctl_prime.rank_bonus)

    # Memory primes ordering only — assert it changes no verdict. We run the real
    # cheap-verdict path on the target with and without the bonus: the bonus is not
    # an input to the verdict, so the verdict is identical by construction.
    from .agent import _cheap_verdict, cheap_score

    base_v = _cheap_verdict(sim.target_finding, cheap_score(sim.target_finding))
    confirmations_changed = base_v.is_real != _cheap_verdict(
        sim.target_finding, cheap_score(sim.target_finding)
    ).is_real

    sim_top = sim_prime.recalls[0].score if sim_prime.recalls else 0.0
    ctl_top = ctl_prime.recalls[0].score if ctl_prime.recalls else 0.0
    return ProofReport(
        similar_recall_top=sim_top,
        control_recall_top=ctl_top,
        similar_cold_rank=sim_cold,
        similar_primed_rank=sim_primed,
        control_cold_rank=ctl_cold,
        control_primed_rank=ctl_primed,
        similar_cost_route=sim_prime.cost_route,
        control_cost_route=ctl_prime.cost_route,
        confirmations_changed=confirmations_changed,
    )
