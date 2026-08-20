"""#39 — directed fuzzing toward seed-flagged sinks (ATLANTIS UniAFL model).

0verse's AFL++ lane is pure coverage-guided: it fuzzes for blind new coverage and
throws away the one signal the rest of the engine already produces — *which* call
site is the suspected bug. The slice (`analyze.Finding.sink_addr`), the bug-class
lenses (`bugclasses`), and the 90 seed-archetypes (`seedbugs.SeedBugClass.matches`)
all name a sink; this module turns that into steering.

**Why UniAFL, not AFLGo/BULLSEYE.** The canonical directed greybox fuzzers bake a
compile-time BB→target *distance* into the binary (an LLVM pass) — impossible on
0verse's stripped targets. ATLANTIS's UniAFL avoids custom instrumentation: it
*scores corpus seeds by how many key addresses near the sink they execute* and
selects with a deliberately mixed **25 % pure-random / 25 % among seeds touching
≥1 key address / 50 % score-weighted** policy (paper §6.3) to steer without
overfitting. That is binary-only-friendly because the #40 ``CoverageProbe`` already
gives us per-seed key-address hits from a qemu block trace.

Two pieces:

  * ``DirectedTargets`` / ``collect_targets`` — fold slice sink addrs, bug-class
    lens hypotheses, and seed-archetype matches into a deduped, weighted
    ``SinkTarget`` set. Empty ⇒ the orchestrator skips the directed lane (honest
    no-op when the archetype layer gave us nothing).
  * ``DirectedScheduler`` — after each AFL++ sync window, re-score the corpus with
    the probe and re-prioritise it with the 25/25/50 policy, dropping sinks the
    oracle already confirmed. No recompilation; pure seed scheduling. It also
    emits the ``AFL_QEMU_INST_RANGES`` string that concentrates the live bitmap on
    the slice functions (the SelectFuzz binary-only analog).

This module changes only *where* the fuzzer spends energy. PoV-is-truth is
untouched — the oracle still adjudicates every crash.
"""

from __future__ import annotations

import contextlib
import random
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..analyze import Finding
from .coverage import AddressIndex, CoverageProbe, SeedScore

# A `CALL <sym>` / `bl <sym>` site in objdump-style disassembly (sink VA recovery).
_CALL_SITE = re.compile(r"^\s*([0-9a-fA-F]+):.*\b(?:call|callq|bl|jal)\b.*<([^>+]+)")


@dataclass(frozen=True)
class SinkTarget:
    """One sink to drive the fuzzer toward. Satisfies ``coverage.Target``."""

    function: str
    func_entry: int        # concolic.function_entry(...) — the angr start address
    sink_addr: int         # the call-site / suspected bug site to drive to
    origin: str            # "slice" | "bugclass:<id>" | "seed:<id>"
    weight: float = 1.0    # archetype confidence → scheduling / driller priority

    def key(self) -> tuple[str, int]:
        return (self.function, self.sink_addr)


@dataclass
class DirectedTargets:
    """A live, deduped, weighted target set. Targets are *dynamically updated*: a
    sink the oracle confirms is dropped (don't keep steering at a solved bug), and
    new lens/LLM candidates can be added mid-run."""

    targets: list[SinkTarget] = field(default_factory=list)
    _confirmed: set[int] = field(default_factory=set)

    def add(self, t: SinkTarget) -> bool:
        if t.sink_addr in self._confirmed:
            return False
        for existing in self.targets:
            if existing.key() == t.key():
                # keep the higher-confidence origin/weight
                if t.weight > existing.weight:
                    self.targets.remove(existing)
                    break
                return False
        self.targets.append(t)
        return True

    def confirm(self, sink_addr: int) -> None:
        """Drop a sink once the oracle has confirmed a PoV there."""
        self._confirmed.add(sink_addr)
        self.targets = [t for t in self.targets if t.sink_addr != sink_addr]

    @property
    def confirmed_sinks(self) -> frozenset[int]:
        return frozenset(self._confirmed)

    @property
    def active(self) -> list[SinkTarget]:
        return list(self.targets)

    def __bool__(self) -> bool:
        return bool(self.targets)

    def __len__(self) -> int:
        return len(self.targets)


def _call_sites(disasm: str) -> dict[str, list[int]]:
    """Map ``callee_symbol -> [call-site VAs]`` from objdump-style disassembly, so a
    lens/archetype that names a *symbol* sink can be pinned to its *instruction*."""
    out: dict[str, list[int]] = {}
    for line in disasm.splitlines():
        m = _CALL_SITE.match(line)
        if m:
            va = int(m.group(1), 16)
            out.setdefault(m.group(2).split("@")[0], []).append(va)
    return out


def collect_targets(
    findings: Iterable[Finding],
    *,
    seed_matches: Iterable[tuple[str, str, int]] = (),
    disasm: str = "",
    func_entries: dict[str, int] | None = None,
) -> DirectedTargets:
    """Fold the engine's sink signals into a weighted target set.

    Sources, in priority/weight order (directed-fuzzing design §3.1):
      1. **Slice / foxguard findings** carrying a real ``sink_addr`` (already an
         address) — weight by origin (a #2 slice finding outranks a foxguard
         hypothesis).
      2. **Seed-archetype matches** ``(function, sink_token, weight_pct)`` — the
         archetype located the *function*; we pin the *instruction* by resolving
         the sink token to its ``CALL`` site VA in ``disasm`` (the Ghidra xref/
         objdump path). Weight from the archetype's confidence.

    ``func_entries`` maps function → entry VA (``concolic.function_entry``) so the
    driller knows where angr should start. Empty target set ⇒ the caller skips the
    directed lane."""
    dt = DirectedTargets()
    entries = func_entries or {}
    sites = _call_sites(disasm) if disasm else {}

    for f in findings:
        if not f.sink_addr:
            continue
        weight = 1.0 if f.origin == "slice" else 0.7
        dt.add(SinkTarget(
            function=f.function,
            func_entry=entries.get(f.function, f.source_addr or f.sink_addr),
            sink_addr=f.sink_addr,
            origin=f.origin,
            weight=weight,
        ))

    for function, sink_token, weight_pct in seed_matches:
        for va in sites.get(sink_token, []):
            dt.add(SinkTarget(
                function=function,
                func_entry=entries.get(function, va),
                sink_addr=va,
                origin=f"seed:{sink_token}",
                weight=max(0.1, min(1.0, weight_pct / 100.0)),
            ))
    return dt


# --- UniAFL 25/25/50 corpus re-prioritisation -------------------------------

@dataclass
class SchedulerConfig:
    """UniAFL weighted-random policy (paper §6.3) + annealing knobs."""

    p_random: float = 0.25       # pure-random pick (explore, anti-overfit)
    p_keyline: float = 0.25      # among seeds touching ≥1 key address
    # remaining 0.50 = score-weighted (exploit)
    keep_k: int = 16             # corpus size retained for the next window
    anneal: bool = True          # shrink keep_k over windows (explore→exploit)
    min_k: int = 4
    seed: int = 0                # RNG seed (deterministic tests)


class DirectedScheduler:
    """Re-prioritises the AFL++ corpus toward the sinks between fuzz windows.

    Each window: score every corpus seed with the #40 ``CoverageProbe`` (key
    addresses near a sink hit), then build the next window's input set by the
    UniAFL 25/25/50 weighted-random policy. Sinks the oracle confirmed are dropped
    from the target set first (no wasted energy on a solved bug). This is a
    *coarse* binary-only approximation of AFLGo's per-seed annealing energy — we
    re-rank the corpus across windows rather than per-mutation — and is honest
    about being so."""

    def __init__(
        self,
        probe: CoverageProbe,
        targets: DirectedTargets,
        config: SchedulerConfig | None = None,
    ) -> None:
        self.probe = probe
        self.targets = targets
        self.config = config or SchedulerConfig()
        self._rng = random.Random(self.config.seed)
        self.window = 0
        self.last_scores: list[SeedScore] = []

    def _keep_k(self) -> int:
        k = self.config.keep_k
        if self.config.anneal:
            k = max(self.config.min_k, k - self.window * 2)
        return k

    def score_corpus(self, seeds: Iterable[bytes]) -> list[SeedScore]:
        active = self.targets.active
        scores = [self.probe.score_seed(s, active) for s in seeds]
        self.last_scores = scores
        return scores

    def reprioritize(self, seeds: list[bytes]) -> list[bytes]:
        """Return the next window's seed corpus, re-prioritised by the 25/25/50
        policy. Deterministic given the config RNG seed."""
        if not seeds:
            return seeds
        if not self.targets:
            # all sinks confirmed / none collected → no steering, keep the corpus
            return seeds
        scores = self.score_corpus(seeds)
        k = min(self._keep_k(), len(scores))
        chosen = self._weighted_select(scores, k)
        self.window += 1
        return [s.seed for s in chosen]

    def _weighted_select(self, scores: list[SeedScore], k: int) -> list[SeedScore]:
        cfg = self.config
        keyline = [s for s in scores if s.key_hits > 0]
        # score = key_hits, with a reached-sink bonus so a seed already at the sink
        # block (the last-mile candidate) is most likely to be exploited.
        weights = {id(s): float(s.key_hits) + 3.0 * len(s.sinks_reached) for s in scores}
        chosen: list[SeedScore] = []
        chosen_ids: set[int] = set()

        def _take(pool: list[SeedScore], weighted: bool) -> None:
            avail = [s for s in pool if id(s) not in chosen_ids]
            if not avail:
                return
            if weighted and any(weights[id(s)] > 0 for s in avail):
                pick = self._rng.choices(
                    avail, weights=[weights[id(s)] + 0.01 for s in avail], k=1
                )[0]
            else:
                pick = self._rng.choice(avail)
            chosen.append(pick)
            chosen_ids.add(id(pick))

        for _ in range(k):
            r = self._rng.random()
            if r < cfg.p_random or not keyline:
                _take(scores, weighted=False)
            elif r < cfg.p_random + cfg.p_keyline:
                _take(keyline, weighted=False)
            else:
                _take(scores, weighted=True)
        return chosen

    def last_mile_candidates(self, seeds: Iterable[bytes]) -> list[SinkTarget]:
        """Sinks a corpus seed reached but the oracle never confirmed — handed to
        the DistanceDriller (#41) / LLM last-mile pass."""
        return self.probe.uncrashed_but_reached(  # type: ignore[return-value]
            seeds, self.targets.active,
            confirmed_sinks=self.targets.confirmed_sinks,
        )


# --- AFL_QEMU_INST_RANGES — concentrate the live bitmap on the slice --------

def inst_ranges_for_slice(
    targets: Iterable[SinkTarget],
    index: AddressIndex,
    *,
    func_ranges: dict[str, tuple[int, int]] | None = None,
) -> str:
    """Union of ``[func_start, func_end)`` for every function carrying a target, as
    an ``AFL_QEMU_INST_RANGES`` string (``start-end,start-end``). Set on the AFL++
    env so QEMU-mode stops diluting the coverage bitmap with libc / unrelated
    handlers — every new-coverage signal AFL chases is then *on the way to a sink*
    (the SelectFuzz binary-only analog, zero recompilation). Empty string when no
    range is known (caller simply omits the env var)."""
    ranges = dict(func_ranges or {})
    funcs = {t.function for t in targets}
    spans: list[tuple[int, int]] = []
    for f in funcs:
        span = ranges.get(f) or _span_from_index(index, f)
        if span:
            spans.append(span)
    spans.sort()
    return ",".join(f"0x{lo:x}-0x{hi:x}" for lo, hi in spans)


def _span_from_index(index: AddressIndex, func: str) -> tuple[int, int] | None:
    addrs = index._addrs_by_func.get(func)
    if not addrs:
        return None
    # +16 so the last instruction's bytes are inside the range.
    return (addrs[0], addrs[-1] + 16)


def func_ranges_from_disasm(disasm: str) -> dict[str, tuple[int, int]]:
    """Recover ``{func: (start, end)}`` from objdump-style ``<name>:`` headers — the
    benchmark / no-Ghidra path for ``inst_ranges_for_slice`` and ``AddressIndex``."""
    header = re.compile(r"^([0-9a-fA-F]+) <([^>]+)>:")
    starts: list[tuple[int, str]] = []
    last_addr = 0
    for line in disasm.splitlines():
        m = header.match(line)
        if m:
            starts.append((int(m.group(1), 16), m.group(2)))
            continue
        ln = line.split(":", 1)
        if ln and ln[0].strip():
            with contextlib.suppress(ValueError):
                last_addr = int(ln[0].strip(), 16)
    out: dict[str, tuple[int, int]] = {}
    for i, (addr, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else last_addr + 16
        out[name] = (addr, end)
    return out


def confirm_targets(targets: DirectedTargets, pov_sink_addrs: Iterable[int]) -> None:
    """Drop every sink the oracle just confirmed from the live target set."""
    for a in pov_sink_addrs:
        targets.confirm(a)
