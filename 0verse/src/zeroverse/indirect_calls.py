"""First-pass indirect / virtual-call resolver + taint propagation (M1 #1).

Motivation. The recovered call graph (``ProgramMeta.callgraph``) only contains
edges Ghidra could resolve to a concrete callee. Real targets dispatch through
**function pointers**, **lazy-loaders** and C++ **vtables**, so the call sites
that reach the bug are recorded as *unresolved* (``CALLIND``/``CALLOTHER``) and
the target functions end up as disconnected islands. Reachability / taint over
that graph then scores every ground-truth function 0.00 — taint cannot flow
across edges that do not exist.

This module recovers **speculative** indirect edges from data 0verse already
extracts (no live Ghidra re-run), and propagates taint over the union of direct
and indirect edges with an ``indirect`` decay so a resolved edge still carries
taint, weighted below a direct call.

Honesty / precision. These edges are *speculative* — an address-taken function is
a *candidate* target of an indirect site, not a proven one, so the pass trades
precision for recall. False edges are bounded by:
  * only wiring **from** functions that actually contain an indirect call site
    (``unresolved_edges``), never from every function;
  * only wiring **to** address-taken functions (or proven fn-pointer-table
    members), never to arbitrary functions;
  * dropping targets already directly reachable from the caller (no redundant
    edges), optional arity matching, and a per-site fan-out cap;
  * a strictly lower taint weight than a direct edge, so a path that needs an
    indirect hop ranks below a fully-direct one.
The weights are decay factors, not probabilities — tune on bench.
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

# Speculative-edge taint weights (decay applied when taint crosses the edge).
# A proven fn-pointer-table member is stronger evidence than a bare address-taken
# guess, so it decays less; both sit below a direct edge (weight 1.0).
ADDR_TAKEN_WEIGHT = 0.35
PTR_TABLE_WEIGHT = 0.55
# Cap speculative targets per indirect site so one site can't explode the graph.
MAX_TARGETS_PER_SITE = 32

_INDIRECT_OPS = ("CALLIND", "CALLOTHER")


@dataclass(frozen=True)
class IndirectEdge:
    """A speculative caller -> callee edge recovered for an indirect call site."""

    caller: str
    callee: str
    kind: str      # "addr-taken" | "ptr-table"
    weight: float  # taint decay across this edge (0, 1]


# --- inputs ----------------------------------------------------------------

def _callgraph(meta: Any) -> dict[str, list[str]]:
    return {k: list(v) for k, v in (getattr(meta, "callgraph", {}) or {}).items()}


def indirect_call_sites(meta: Any) -> dict[str, list[dict[str, Any]]]:
    """Map ``caller -> [site record, ...]`` for every recorded indirect call site.

    Sources the sites from ``ProgramMeta.unresolved_edges`` (already emitted by the
    Ghidra extractor for ``CALLIND``/``CALLOTHER`` / unresolvable targets)."""
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in getattr(meta, "unresolved_edges", None) or []:
        op = str(e.get("op", ""))
        if op in _INDIRECT_OPS or e.get("indirect"):
            func = str(e.get("func", ""))
            if func:
                out[func].append(dict(e))
    return dict(out)


def address_taken(meta: Any) -> set[str]:
    """Functions whose address is taken (candidate indirect-call targets).

    Prefers the explicitly extracted ``ProgramMeta.address_taken`` (from Ghidra
    data references). Falls back to a textual scan of the decompiled C — reusing
    ``analyze._address_taken`` — so the resolver still fires from a cache/export
    that predates the extraction hook."""
    explicit = {str(x) for x in (getattr(meta, "address_taken", None) or [])}
    if explicit:
        return explicit
    dc: dict[str, str] = getattr(meta, "decompiled_c", None) or {}
    if not dc:
        return set()
    from .analyze import _address_taken  # lazy: avoid import cycle at module load

    cg = getattr(meta, "callgraph", None) or {}
    candidates = (set(dc) | {c for cs in cg.values() for c in cs}) & set(dc)
    return _address_taken(candidates, dc)


def _site_arities(sites: Iterable[dict[str, Any]]) -> set[int]:
    ars: set[int] = set()
    for s in sites:
        a = s.get("arity")
        if isinstance(a, int):
            ars.add(a)
    return ars


# --- resolver --------------------------------------------------------------

def resolve_indirect_edges(
    meta: Any,
    *,
    max_targets_per_site: int = MAX_TARGETS_PER_SITE,
    func_arity: Mapping[str, int] | None = None,
) -> list[IndirectEdge]:
    """Recover speculative indirect edges for ``meta``.

    Heuristic 1 (address-taken): from every function that has an indirect call
    site, add an edge to each address-taken function (candidate target), skipping
    self-edges and targets already directly called. If both the site arity and a
    candidate's arity are known (via ``func_arity``), keep only arity matches.

    Heuristic 2 (fn-pointer / vtable table): every member of a recovered
    ``ptr_tables`` entry is an indirect target; wire the table's ``loaders`` (or,
    if unknown, all indirect-call-site callers) to each member. Table membership
    is stronger evidence than address-taken, so these edges decay less.
    """
    cg = _callgraph(meta)
    sites = indirect_call_sites(meta)
    edges: dict[tuple[str, str], IndirectEdge] = {}

    # 1. address-taken -> candidate targets of indirect sites.
    taken = sorted(address_taken(meta))
    for caller, recs in sites.items():
        existing = set(cg.get(caller, ()))
        want_ars = _site_arities(recs)
        added = 0
        for target in taken:
            if target == caller or target in existing:
                continue
            if (func_arity is not None and want_ars and target in func_arity
                    and func_arity[target] not in want_ars):
                continue
            edges[(caller, target)] = IndirectEdge(
                caller, target, "addr-taken", ADDR_TAKEN_WEIGHT)
            added += 1
            if added >= max_targets_per_site:
                break

    # 2. fn-pointer / vtable tables -> members are targets (overrides weaker
    #    addr-taken edge on the same pair — stronger evidence).
    all_callers = list(sites)
    for tbl in getattr(meta, "ptr_tables", None) or []:
        members = [str(m) for m in tbl.get("members", []) or []]
        loaders = [str(x) for x in tbl.get("loaders", []) or []] or all_callers
        for caller in loaders:
            existing = set(cg.get(caller, ()))
            for m in members:
                if m == caller or m in existing:
                    continue
                edges[(caller, m)] = IndirectEdge(
                    caller, m, "ptr-table", PTR_TABLE_WEIGHT)

    return sorted(edges.values(), key=lambda e: (e.caller, e.callee, e.kind))


def augmented_callgraph(meta: Any) -> dict[str, list[str]]:
    """A NEW ``caller -> callees`` dict = direct edges + resolved indirect edges.

    Non-mutating: the integrator can assign it back to ``meta.callgraph`` (or pass
    it to reachability) to let existing reachability/ranking cross indirect
    dispatch. Direct edges are preserved; speculative targets are appended."""
    cg = _callgraph(meta)
    for e in resolve_indirect_edges(meta):
        cg.setdefault(e.caller, [])
        if e.callee not in cg[e.caller]:
            cg[e.caller].append(e.callee)
    return cg


# --- taint propagation -----------------------------------------------------

def propagate_taint(
    callgraph: Mapping[str, Iterable[str]],
    sources: Iterable[str],
    *,
    indirect_edges: Iterable[IndirectEdge] = (),
    hop_decay: float = 1.0,
    min_taint: float = 1e-9,
) -> dict[str, float]:
    """Propagate taint (1.0 at each source) forward over the call graph, returning
    ``function -> taint score`` for every reached function.

    Direct edges carry weight 1.0; each ``IndirectEdge`` carries its (lower) weight.
    A function's taint is the best (max) product of edge weights along any
    source→function path, times ``hop_decay`` per hop — so a node reachable only
    through a speculative indirect edge still scores non-zero, but strictly below
    an equivalent all-direct path. Implemented as max-product Dijkstra (edge
    weights ≤ 1 ⇒ taint is non-increasing along a path ⇒ it terminates even with
    cycles). Functions never reached are simply absent (score 0.0)."""
    adj: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for caller, callees in callgraph.items():
        for callee in callees:
            adj[caller].append((callee, 1.0))
    for e in indirect_edges:
        adj[e.caller].append((e.callee, e.weight))

    best: dict[str, float] = {}
    heap: list[tuple[float, str]] = []
    for s in sources:
        if best.get(s, 0.0) < 1.0:
            best[s] = 1.0
            heapq.heappush(heap, (-1.0, s))

    finalized: set[str] = set()
    while heap:
        negt, node = heapq.heappop(heap)
        if node in finalized:
            continue
        finalized.add(node)
        t = -negt
        for nb, w in adj.get(node, ()):
            nt = t * w * hop_decay
            if nt <= min_taint or nb in finalized:
                continue
            if nt > best.get(nb, 0.0):
                best[nb] = nt
                heapq.heappush(heap, (-nt, nb))
    return best
