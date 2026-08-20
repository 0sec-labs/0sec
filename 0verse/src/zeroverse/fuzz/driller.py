"""#17 — Driller-style hybrid concolic assist.

The proven AIxCC pattern (Driller / Atlantis): a fuzzer is fast on the bulk of a
program but stalls at a hard gate — a magic comparison, a checksum, a tightly
constrained branch it cannot brute-force. When AFL++ goes a window with **no new
coverage**, we hand a stuck queue input to angr (the #5 ``concolic`` engine),
which solves the blocking constraint symbolically and yields a fresh input that
crosses the gate. That input is **re-seeded** into AFL++, which then takes over
again on the far side. Fuzzer-first, symbolic-as-fallback — never the spine.

This module is the *coordinator*, kept independent of angr so it is unit-testable
with a fake solver: ``DrillerHybrid`` tracks fuzzer progress (``note_progress``),
decides when a stall warrants an assist, and turns stuck inputs into new seeds
(``assist``). The default ``AngrConcolicSolver`` wires ``concolic.check_reachability``
in; CMPLOG/redqueen (in the #15 driver) is the cheaper first line of defence, so
the concolic assist is reserved for what CMPLOG cannot crack (e.g. checksums).

#41 (``DistanceDriller``) upgrades the trigger from a *total-coverage* stall to a
*distance* gradient toward the nearest unconfirmed sink — see the second half of
this module.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..concolic import AngrConfig, check_reachability


class Solver(Protocol):
    """Solve for an input that drives ``binary`` from ``func_addr`` to
    ``target_addr`` (the deeper, currently-unreached block). Returns the
    triggering bytes, or ``None`` when it cannot (UNSAT / timeout / no angr)."""

    def solve(
        self, binary: Path, stuck_input: bytes, *, func_addr: int, target_addr: int
    ) -> bytes | None: ...


class AngrConcolicSolver:
    """Default solver: angr slice-scoped reachability (#5). Symbolically executes
    the target function and concretizes a witness stdin that reaches the deeper
    block, which AFL++ then uses as a seed."""

    def __init__(self, config: AngrConfig | None = None) -> None:
        self.config = config or AngrConfig()

    def solve(
        self, binary: Path, stuck_input: bytes, *, func_addr: int, target_addr: int
    ) -> bytes | None:
        verdict = check_reachability(
            binary, func_addr, target_addr, config=self.config
        )
        if verdict.reachable and verdict.stdin:
            return verdict.stdin
        return None


@dataclass
class DrillerConfig:
    stall_rounds: int = 2     # consecutive no-coverage rounds before an assist
    max_assists: int = 4      # cap the (expensive) concolic consults per run


@dataclass
class DrillerState:
    prev_paths: int = -1
    stalls: int = 0
    assists: int = 0


class DrillerHybrid:
    """Coordinates fuzzer-stall detection and concolic re-seeding."""

    def __init__(self, solver: Solver, config: DrillerConfig | None = None) -> None:
        self.solver = solver
        self.config = config or DrillerConfig()
        self.state = DrillerState()

    def note_progress(self, current_paths: int) -> bool:
        """Record the fuzzer's current path/coverage count and report whether it
        has STALLED long enough to warrant a concolic assist."""
        st = self.state
        if st.prev_paths >= 0 and current_paths <= st.prev_paths:
            st.stalls += 1
        else:
            st.stalls = 0
        st.prev_paths = current_paths
        return self.should_assist()

    def should_assist(self) -> bool:
        return (
            self.state.stalls >= self.config.stall_rounds
            and self.state.assists < self.config.max_assists
        )

    def assist(
        self,
        binary: Path,
        stuck_inputs: list[bytes],
        *,
        func_addr: int,
        target_addr: int,
    ) -> list[bytes]:
        """Hand each stuck input to the solver; collect the solved inputs to
        re-seed AFL++. Bounded by ``max_assists`` and resets the stall counter."""
        new_seeds: list[bytes] = []
        for stuck in stuck_inputs:
            if self.state.assists >= self.config.max_assists:
                break
            self.state.assists += 1
            solved = self.solver.solve(
                binary, stuck, func_addr=func_addr, target_addr=target_addr
            )
            if solved is not None and solved not in new_seeds:
                new_seeds.append(solved)
        self.state.stalls = 0
        return new_seeds


# === #41 — DistanceDriller: stall-rescue upgraded to a distance gradient =====
#
# The base ``DrillerHybrid`` fires concolic only on a *total* coverage stall — a
# blunt "the whole run died" trigger. The DistanceDriller upgrades it to a
# *distance* gradient (directed-fuzzing design §3.3): it tracks how close the
# corpus has driven toward the nearest unconfirmed sink and assists on a
# **distance plateau** (no progress toward a sink), solving for the *next
# uncovered block on the shortest path to the closest target* rather than always
# the final sink. That is the difference between "crack the whole gate stack at
# once" (often UNSAT/timeout) and "crack the next gate, re-seed, let the fuzzer
# take the far side" — what makes stacked gates tractable.
#
# Honest caveat baked in: the distance metric is the AFLGo harmonic-mean over a
# *recovered* CFG, so indirect-call edges are imprecise (AFLGopher / SyzDirect).
# We therefore use distance only as a *ranking* signal to choose where to assist,
# never as a hard feasibility cut (no BEACON-style path pruning on a recovered
# CFG). Without angr / a usable CFG it degrades to ``NullDistance`` — reached-vs-
# not toward the sink — which still drives the proof's single-checksum gate.


@runtime_checkable
class DistanceModel(Protocol):
    """How close has execution driven toward the targets, and where to push next."""

    def reached_distance(self, executed: frozenset[int]) -> float:
        """Smallest BB→nearest-target distance achieved by ``executed`` (lower is
        closer; ``inf`` when nothing on a path to a target was reached)."""
        ...

    def next_target(self, executed: frozenset[int]) -> tuple[int, int] | None:
        """``(func_entry, intermediate_target_addr)`` — the next uncovered block on
        the shortest path to the closest target, for the solver to drive to. None
        when every target is already reached."""
        ...


@dataclass
class NullDistance:
    """CFG-free fallback: distance is binary (sink block reached or not) and the
    next target is the nearest unreached sink itself. This is the honest minimum
    when no CFG is available — it still converts a coverage stall into a
    *sink-directed* concolic assist (vs. the base driller's blind one)."""

    targets: list[tuple[int, int]]   # [(func_entry, sink_addr)] ordered by priority

    def reached_distance(self, executed: frozenset[int]) -> float:
        return 0.0 if any(sink in executed for _, sink in self.targets) else 1.0

    def next_target(self, executed: frozenset[int]) -> tuple[int, int] | None:
        for entry, sink in self.targets:
            if sink not in executed:
                return (entry, sink)
        return None


class AngrCfgDistance:
    """AFLGo-style harmonic-mean BB→target distance over an angr ``CFGFast``.

    Built once per binary and cached. Distances are normalised so a block on the
    direct path to a target scores low and off-path blocks high; ``next_target``
    returns the closest target whose sink block is not yet covered, together with
    its function entry, so the solver climbs one gate at a time. Never raises —
    a CFG build failure leaves ``ok=False`` and the caller falls back to
    ``NullDistance``."""

    def __init__(
        self,
        binary: Path,
        targets: list[tuple[int, int]],
        *,
        timeout_s: float = 30.0,
    ) -> None:
        self.binary = Path(binary)
        self.targets = targets
        self.timeout_s = max(0.0, timeout_s)
        self._deadline = time.monotonic() + self.timeout_s
        self.ok = False
        self._dist: dict[int, float] = {}
        self._build()

    def _expired(self) -> bool:
        return time.monotonic() >= self._deadline

    def _build(self) -> None:
        if self._expired():
            return
        try:
            import angr
            import networkx as nx
        except ImportError:
            return
        if self._expired():
            return
        try:
            proj = angr.Project(str(self.binary), auto_load_libs=False)
            if self._expired():
                return
            cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)
            if self._expired():
                return
            g = cfg.graph
            addr_nodes = {n.addr: n for n in g.nodes()}
            rev = g.reverse(copy=False)
            per_target: list[dict[int, int]] = []
            for _, sink in self.targets:
                if self._expired():
                    return
                node = addr_nodes.get(sink) or self._enclosing(addr_nodes, sink)
                if node is None:
                    continue
                per_target.append(nx.single_source_shortest_path_length(rev, node))
            if not per_target:
                return
            for addr in addr_nodes:
                if self._expired():
                    return
                inv = [1.0 / (d[addr] + 1) for d in per_target if addr in d]
                if inv:
                    self._dist[addr] = len(inv) / sum(inv)  # harmonic mean
            self.ok = bool(self._dist)
        except Exception:
            self.ok = False

    @staticmethod
    def _enclosing(addr_nodes: dict[int, object], sink: int) -> object | None:
        best: tuple[int, object] | None = None
        for a, n in addr_nodes.items():
            size = getattr(n, "size", 0) or 0
            if a <= sink < a + size and (best is None or a > best[0]):
                best = (a, n)
        return best[1] if best else None

    def reached_distance(self, executed: frozenset[int]) -> float:
        ds = [self._dist[a] for a in executed if a in self._dist]
        return min(ds) if ds else float("inf")

    def next_target(self, executed: frozenset[int]) -> tuple[int, int] | None:
        unreached = [
            (entry, sink) for entry, sink in self.targets if sink not in executed
        ]
        if not unreached:
            return None
        unreached.sort(key=lambda t: self._dist.get(t[1], float("inf")))
        return unreached[0]


@dataclass
class DistanceState:
    prev_distance: float = float("inf")
    plateaus: int = 0
    assists: int = 0


class DistanceDriller(DrillerHybrid):
    """Driller whose assist trigger is a *distance* plateau toward the nearest
    unconfirmed sink, and whose assist target is the next uncovered block on the
    path to it (one gate at a time)."""

    def __init__(
        self,
        solver: Solver,
        distance: DistanceModel,
        config: DrillerConfig | None = None,
    ) -> None:
        super().__init__(solver, config)
        self.distance = distance
        self.dstate = DistanceState()

    def note_distance(self, executed: frozenset[int]) -> bool:
        """Record the best distance-to-target the corpus has reached this window;
        report whether it has PLATEAUED long enough (no improvement for
        ``stall_rounds`` windows) to warrant a distance-directed assist."""
        d = self.distance.reached_distance(executed)
        st = self.dstate
        if d >= st.prev_distance:          # no closer to any target
            st.plateaus += 1
        else:
            st.plateaus = 0
        st.prev_distance = min(st.prev_distance, d)
        return self.should_assist_distance()

    def should_assist_distance(self) -> bool:
        return (
            self.dstate.plateaus >= self.config.stall_rounds
            and self.dstate.assists < self.config.max_assists
        )

    def assist_distance(
        self,
        binary: Path,
        stuck_inputs: list[bytes],
        executed: frozenset[int],
        *,
        before_solve: Callable[[], bool] | None = None,
    ) -> list[bytes]:
        """Solve toward the next uncovered block on the path to the closest target
        and return fresh seeds for AFL++. Resets the plateau counter. Bounded by
        ``max_assists`` (concolic is the expensive line of defence)."""
        step = self.distance.next_target(executed)
        if step is None:
            self.dstate.plateaus = 0
            return []
        func_addr, target_addr = step
        new_seeds: list[bytes] = []
        for stuck in stuck_inputs:
            if self.dstate.assists >= self.config.max_assists:
                break
            if before_solve is not None and not before_solve():
                break
            self.dstate.assists += 1
            solved = self.solver.solve(
                binary, stuck, func_addr=func_addr, target_addr=target_addr
            )
            if solved is not None and solved not in new_seeds:
                new_seeds.append(solved)
        self.dstate.plateaus = 0
        return new_seeds
