"""#40 — coverage → address map + the reached-but-uncrashed last-mile signal.

The enabler for directed fuzzing (#39): the rest of the pipeline treats AFL++
coverage as a black box, so it cannot reason about *which* seed got closest to a
flagged sink, nor about the high-value "we reached the sink basic block but the
oracle did not fire" moment. This module closes that gap, binary-only.

**The honest binary-only constraint.** AFL++ QEMU-mode coverage is an *edge
bitmap* keyed by ``(cur_loc ^ prev_loc) >> 1`` — a hash, **not** an address — so
the bitmap alone cannot be inverted back to instruction addresses (this is the
load-bearing reason BULLSEYE/AFLGo's compile-time distance pass does not apply to
0verse; see the directed-fuzzing design doc §2). We therefore recover executed
*addresses* the only way a stripped target allows: a **qemu-user block trace**
(``qemu-x86_64 -d exec``), whose per-translation-block guest PC is a real static
VA for a non-relocated image (the same VA space Ghidra's ``Inst.addr`` lives in).
Those addresses are then **joined to the Ghidra address↔function map** carried on
``ProgramMeta`` / the recovered ``Inst`` list.

Two consumers:

  * ``CoverageProbe.score_seed`` — UniAFL-style "key addresses near the sink hit"
    energy for the #39 directed scheduler.
  * ``reached_sinks`` / ``uncrashed_but_reached`` — the **last-mile-assist**
    signal: a sink whose basic block a corpus seed already *reached* but the
    oracle never confirmed a crash there is exactly the input the DistanceDriller
    (#41) and the LLM last-mile pass should pick up.

Everything degrades honestly: no ``qemu-x86_64`` / unreadable trace ⇒ an empty
``BlockTrace`` (no addresses), and the directed lane falls back to plain coverage
fuzzing rather than inventing a signal.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..il import Inst
from ..preflight import BudgetTracker


class Target(Protocol):
    """The structural contract a directed-fuzzing target satisfies (see
    ``directed.SinkTarget``). Kept as a Protocol so this lower layer never imports
    the directed scheduler (no import cycle)."""

    @property
    def function(self) -> str: ...
    @property
    def func_entry(self) -> int: ...
    @property
    def sink_addr(self) -> int: ...


# --- qemu-user block trace (executed addresses) -----------------------------

# qemu `-d exec` prints one line per executed translation block:
#   Trace 0: 0x7f.. [hi/<guest_pc>/flags/cs_base]
# The bracket's SECOND field is the guest PC (the basic-block leader VA). For a
# non-relocated (``-no-pie`` / fixed-base) image this equals the static Ghidra VA;
# for a PIE image the caller supplies ``load_base`` to subtract.
_TRACE_LINE = re.compile(r"\[[0-9a-fA-F]+/0*([0-9a-fA-F]+)/")


def parse_qemu_exec_log(text: str, *, load_base: int = 0) -> frozenset[int]:
    """Extract executed basic-block leader addresses from a qemu ``-d exec`` log.

    Pure + deterministic so it is unit-testable on a fixture log. ``load_base`` is
    subtracted from every address (0 for a fixed-base image whose guest PC already
    equals the static VA; the PIE load base otherwise)."""
    out: set[int] = set()
    for m in _TRACE_LINE.finditer(text):
        addr = int(m.group(1), 16)
        if addr >= load_base:
            out.add(addr - load_base)
    return frozenset(out)


@dataclass(frozen=True)
class BlockTrace:
    """Executed basic-block leader addresses (static VAs) for one input run.

    ``addrs`` is empty when tracing is unavailable — callers treat that as "no
    address signal" and degrade, never as "reached nothing"."""

    addrs: frozenset[int] = frozenset()
    note: str = ""

    @property
    def available(self) -> bool:
        return bool(self.addrs)


def qemu_user_bin(arch: str = "") -> str | None:
    """Locate the ``qemu-<arch>`` user-mode emulator used for the block trace
    (host arch when ``arch`` is empty)."""
    cand = f"qemu-{arch}" if arch else "qemu-x86_64"
    return shutil.which(cand)


def trace_blocks(
    binary: str | Path,
    input_bytes: bytes,
    *,
    qemu_arch: str = "",
    load_base: int = 0,
    argv: list[str] | None = None,
    timeout_s: float = 20.0,
    qemu_path: str | None = None,
    qemu_resolved: bool = False,
) -> BlockTrace:
    """Run ``binary`` on ``input_bytes`` (stdin) under qemu-user with ``-d exec``
    and return the set of executed basic-block leader addresses. Never raises —
    any failure (no qemu, crash, timeout) yields an empty ``BlockTrace`` carrying
    a note, so the directed lane degrades to plain coverage fuzzing."""
    qemu = qemu_path if qemu_resolved else (qemu_path or qemu_user_bin(qemu_arch))
    if qemu is None:
        return BlockTrace(note=f"qemu-user ({qemu_arch or 'host'}) not on PATH")
    logf = Path(f"{binary}.qexec.{os.getpid()}.log")
    cmd = [qemu, "-d", "exec", "-D", str(logf), str(binary), *(argv or [])]
    try:
        subprocess.run(
            cmd, input=input_bytes, capture_output=True,
            timeout=timeout_s, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logf.unlink(missing_ok=True)
        return BlockTrace(note=f"trace failed: {type(e).__name__}")
    try:
        text = logf.read_text(errors="replace")
    except OSError:
        return BlockTrace(note="trace log unreadable")
    finally:
        logf.unlink(missing_ok=True)
    addrs = parse_qemu_exec_log(text, load_base=load_base)
    return BlockTrace(addrs=addrs, note=f"{len(addrs)} blocks")


# --- the Ghidra address↔function join --------------------------------------

@dataclass
class AddressIndex:
    """Joins executed addresses to Ghidra's recovered functions: ``func_of(addr)``
    plus, per function, the sorted basic-block leader addresses so we can ask
    "which block *contains* a sink address" and "what are the key addresses on the
    approach to it". Built from the recovered ``Inst`` list (every ``Inst`` carries
    ``.addr`` + ``.func``)."""

    _addrs_by_func: dict[str, list[int]] = field(default_factory=dict)
    _func_of: dict[int, str] = field(default_factory=dict)
    _ranges: dict[str, tuple[int, int]] = field(default_factory=dict)

    @classmethod
    def from_insts(cls, insts: Iterable[Inst]) -> AddressIndex:
        by_func: dict[str, set[int]] = {}
        func_of: dict[int, str] = {}
        for i in insts:
            if not i.addr or not i.func:
                continue
            by_func.setdefault(i.func, set()).add(i.addr)
            func_of[i.addr] = i.func
        return cls(
            _addrs_by_func={f: sorted(a) for f, a in by_func.items()},
            _func_of=dict(func_of),
        )

    @classmethod
    def from_ranges(cls, ranges: dict[str, tuple[int, int]]) -> AddressIndex:
        """Coarse index from ``{func: (start, end)}`` when a full instruction list
        is not available (the benchmark lane, where addresses come from ``nm`` /
        objdump rather than Ghidra). ``func_of`` resolves by range membership."""
        return cls(
            _addrs_by_func={f: [r[0]] for f, r in ranges.items()},
            _ranges=dict(ranges),
        )

    def func_of(self, addr: int) -> str | None:
        hit = self._func_of.get(addr)
        if hit is not None:
            return hit
        for f, (lo, hi) in self._ranges.items():
            if lo <= addr < hi:
                return f
        return None

    def covering_block(self, func: str, target_addr: int) -> int | None:
        """The greatest known basic-block leader ``<= target_addr`` in ``func`` —
        i.e. the leader of the block that *contains* the target instruction. This
        is the address whose presence in an execution trace means "the sink block
        ran". Falls back to the function start for a range-only index."""
        addrs = self._addrs_by_func.get(func)
        if addrs:
            covering: int | None = None
            for a in addrs:
                if a <= target_addr:
                    covering = a
                else:
                    break
            if covering is not None:
                return covering
        rng = self._ranges.get(func)
        if rng and rng[0] <= target_addr < rng[1]:
            return rng[0]
        return None

    def key_addresses(self, func: str, upto_addr: int) -> frozenset[int]:
        """The "key addresses" for a sink (UniAFL's "key lines"): every known
        basic-block leader in the sink's function at or before the sink — the
        approach path plus the sink block. A seed touching more of these is, by
        construction, closer to driving the sink."""
        addrs = self._addrs_by_func.get(func, [])
        keys = {a for a in addrs if a <= upto_addr}
        rng = self._ranges.get(func)
        if rng and rng[0] <= upto_addr:
            keys.add(rng[0])
        return frozenset(keys)


# --- the probe: score seeds + the reached/uncrashed signal ------------------

@dataclass
class SeedScore:
    """One seed's directed-coverage score against the live target set."""

    seed: bytes
    key_hits: int            # number of key (approach+sink) addresses executed
    sinks_reached: tuple[int, ...]  # sink_addrs whose block this seed reached
    total_blocks: int        # total distinct blocks (tie-break / liveness)

    @property
    def reached_any(self) -> bool:
        return bool(self.sinks_reached)


class CoverageProbe:
    """Address-level coverage for the directed lane. Wraps one (binary, arch,
    load_base) and an ``AddressIndex``; traces a seed once and answers the two
    directed questions: *how many key-near-sink addresses did it hit* (energy for
    the scheduler) and *which sink blocks did it reach* (the last-mile signal)."""

    def __init__(
        self,
        binary: str | Path,
        index: AddressIndex,
        *,
        qemu_arch: str = "",
        load_base: int = 0,
        sink_window: int = 0,
        budget: BudgetTracker | None = None,
        timeout_s: float = 20.0,
        qemu_path: str | None = None,
        qemu_resolved: bool = False,
    ) -> None:
        self.binary = Path(binary)
        self.index = index
        self.qemu_arch = qemu_arch
        self.load_base = load_base
        # When the index is range-only (no per-block leaders), a sink is "reached"
        # if a block within ``sink_window`` bytes before it executed.
        self.sink_window = sink_window
        self.budget = budget
        self.timeout_s = timeout_s
        self.qemu_path = qemu_path
        self.qemu_resolved = qemu_resolved
        self._cache: dict[bytes, BlockTrace] = {}

    def trace(self, seed: bytes) -> BlockTrace:
        bt = self._cache.get(seed)
        if bt is not None:
            return bt
        timeout = self.timeout_s
        if self.budget is not None:
            reserved, reason = self.budget.reserve_attempt()
            if not reserved:
                return BlockTrace(note=f"coverage trace budget skipped: {reason}")
            remaining = self.budget.remaining_seconds()
            if remaining <= 0:
                self.budget.reservation_failures += 1
                return BlockTrace(note="coverage trace deadline exhausted")
            timeout = min(timeout, remaining)
        bt = trace_blocks(
            self.binary,
            seed,
            qemu_arch=self.qemu_arch,
            load_base=self.load_base,
            timeout_s=timeout,
            qemu_path=self.qemu_path,
            qemu_resolved=self.qemu_resolved,
        )
        self._cache[seed] = bt
        return bt

    def available(self) -> bool:
        """Whether address-level coverage is usable (qemu present and the trace of
        a trivial input produced any blocks)."""
        return self.trace(b"\x00").available

    def _block_reached(self, func: str, sink_addr: int, executed: frozenset[int]) -> bool:
        block = self.index.covering_block(func, sink_addr)
        if block is not None and block in executed:
            return True
        # Window fallback: the sink's exact block leader may not be a traced leader
        # (the function was entered mid-block, or the index is range-only), so treat
        # a leader within ``sink_window`` bytes *before* the sink as "reached".
        if self.sink_window:
            lo = sink_addr - self.sink_window
            return any(lo <= a <= sink_addr for a in executed)
        return False

    def score_seed(self, seed: bytes, targets: Sequence[Target]) -> SeedScore:
        bt = self.trace(seed)
        executed = bt.addrs
        key_hits = 0
        reached: list[int] = []
        for t in targets:
            keys = self.index.key_addresses(t.function, t.sink_addr)
            key_hits += len(keys & executed)
            if self._block_reached(t.function, t.sink_addr, executed):
                reached.append(t.sink_addr)
        return SeedScore(
            seed=seed, key_hits=key_hits, sinks_reached=tuple(reached),
            total_blocks=len(executed),
        )

    def reached_sinks(self, seed: bytes, targets: Sequence[Target]) -> list[Target]:
        """Targets whose sink basic block ``seed`` executed (reached, crash or
        not)."""
        bt = self.trace(seed)
        return [
            t for t in targets
            if self._block_reached(t.function, t.sink_addr, bt.addrs)
        ]

    def uncrashed_but_reached(
        self,
        seeds: Iterable[bytes],
        targets: Sequence[Target],
        *,
        confirmed_sinks: frozenset[int] = frozenset(),
    ) -> list[Target]:
        """The last-mile-assist signal: sinks whose block at least one corpus seed
        already reached but the oracle has **not** confirmed a crash for. These are
        the highest-value inputs for the DistanceDriller / LLM last-mile pass — the
        trigger is *almost* there, it just needs to be driven over the edge."""
        reached_addrs: set[int] = set()
        for s in seeds:
            reached_addrs.update(t.sink_addr for t in self.reached_sinks(s, targets))
        out: list[Target] = []
        seen: set[int] = set()
        for t in targets:
            if (
                t.sink_addr in reached_addrs
                and t.sink_addr not in confirmed_sinks
                and t.sink_addr not in seen
            ):
                seen.add(t.sink_addr)
                out.append(t)
        return out
