"""Backward slicer + call tracker + source/sink path finder.

Pure traversal over the abstract IL (``il.py``); all engine-specific queries go
through ``ILAdapter``. Strategy follows mole (DESIGN-NOTES Decision 4): slice
sources and sinks independently, then emit a finding where the two backward
slices intersect. Kept dependency-free — a tiny internal digraph stands in for
networkx until the Ghidra backend lands.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .il import ILAdapter, Inst, Kind


@dataclass
class Slice:
    """A backward slice: the set of instruction ids reached, plus use→def edges."""

    root: int
    nodes: set[int] = field(default_factory=set)
    edges: dict[int, set[int]] = field(default_factory=dict)  # use_id -> {def_id}

    def add_edge(self, a: int, b: int) -> None:
        self.edges.setdefault(a, set()).add(b)


class CallTracker:
    """Bounds recursion/depth so cyclic call graphs and loops terminate."""

    def __init__(self, max_call_level: int = 4, max_depth: int = 200) -> None:
        self.max_call_level = max_call_level
        self.max_depth = max_depth


class BackwardSlicer:
    def __init__(self, adapter: ILAdapter, tracker: CallTracker | None = None) -> None:
        self.a = adapter
        self.t = tracker or CallTracker()

    def slice(self, start_id: int) -> Slice:
        sl = Slice(root=start_id)
        work: deque[int] = deque([start_id])
        steps = 0
        while work and steps < self.t.max_depth:
            steps += 1
            cur = work.popleft()
            if cur in sl.nodes:
                continue
            sl.nodes.add(cur)
            for nxt in self._predecessors(self.a.inst(cur)):
                sl.add_edge(cur, nxt)
                if nxt not in sl.nodes:
                    work.append(nxt)
        return sl

    def _predecessors(self, inst: Inst) -> list[int]:
        """The defs that flow into `inst`, resolved via the adapter."""
        k = inst.kind
        if k is Kind.CONST:
            return []
        if k is Kind.VAR:
            d = self.a.get_def(inst.var, inst.func) if inst.var else None
            return [d] if d is not None else []
        if k is Kind.LOAD:
            return [*self.a.get_memory_defs(inst), *inst.operands]
        if k is Kind.PARAM:
            # Walk UP the call graph: every caller's matching argument.
            param_idx = inst.operands[0] if inst.operands else 0
            return [arg for _call, arg in self.a.get_callers(inst.func, param_idx)]
        if k is Kind.CALL:
            rets = self.a.get_callee_returns(inst)
            return rets if rets else list(inst.args)
        # PHI / BINOP / UNOP / STORE / RET / OTHER: structural recursion.
        return list(inst.operands)


@dataclass
class PathFinding:
    source_id: int
    sink_id: int
    nodes: list[int]          # a concrete path sink -> ... -> source


def find_source_to_sink(
    slicer: BackwardSlicer, source_ids: list[int], sink_ids: list[int]
) -> list[PathFinding]:
    """Slice each sink, slice each source, and report a finding for every sink
    whose backward slice contains a source instruction (graph reachability)."""
    src_slices = {s: slicer.slice(s) for s in source_ids}
    findings: list[PathFinding] = []
    for snk in sink_ids:
        snk_slice = slicer.slice(snk)
        for src, _src_slice in src_slices.items():
            if src in snk_slice.nodes:
                path = _shortest_path(snk_slice, snk, src)
                if path:
                    findings.append(PathFinding(source_id=src, sink_id=snk, nodes=path))
    return findings


def _shortest_path(sl: Slice, start: int, goal: int) -> list[int]:
    """BFS over the slice's use→def edges from `start` (sink) to `goal` (source)."""
    if start == goal:
        return [start]
    prev: dict[int, int] = {start: start}
    q: deque[int] = deque([start])
    while q:
        cur = q.popleft()
        for nxt in sl.edges.get(cur, ()):
            if nxt not in prev:
                prev[nxt] = cur
                if nxt == goal:
                    path = [goal]
                    while path[-1] != start:
                        path.append(prev[path[-1]])
                    return list(reversed(path))
                q.append(nxt)
    return []
