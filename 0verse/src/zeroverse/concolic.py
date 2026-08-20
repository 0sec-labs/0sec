"""Stage 5.5 — angr concolic reachability check (slice-scoped).

Discharges static hypotheses with symbolic execution *before* the dynamic oracle.
Following the M1 guidance (§#5): start at a ``call_state`` on the **target
function** (never program entry — that sidesteps angr's environment-modeling
weakness), make the arguments + stdin symbolic, and ``explore(find=sink_addr,
avoid=...)``. Three outcomes, all useful:

  * ``witness``  — a concrete input that drives the slice to the sink, concretized
                   via ``state.solver.eval``; also flags control-hijack when the
                   ``unconstrained`` stash is hit (symbolic PC == SegFaultOnPc).
  * ``unsat``    — explore exhausts every path without reaching the sink: the
                   static hypothesis is unreachable, so we PRUNE it (kills LLM /
                   over-tainting false positives cheaply).
  * ``unknown``  — timeout / state explosion / angr choke: inconclusive, so we
                   fall straight through to the dynamic oracle (never block).

angr is a timeboxed scalpel, not the spine (guidance §4): every run is hard
wall-clock bounded, and only functions that sit on the #2 slice are ever
symbolically executed. ``auto_load_libs=False`` means angr auto-stubs libc / PLT
imports with its built-in SimProcedures, so only the target code stays symbolic.

angr is an optional engine extra; this module imports it lazily so the package
loads (and the rest of the pipeline runs) without it installed.
"""

from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Outcome = Literal["witness", "unsat", "unknown"]


def angr_available() -> bool:
    """True when the symbolic-execution extra is importable."""
    try:
        import angr  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class AngrConfig:
    """Tunables for one slice-scoped reachability run. Defaults are conservative —
    angr is a quick consult, not the spine."""

    timeout_s: float = 30.0          # hard wall-clock budget per finding
    sym_arg_count: int = 3           # number of symbolic argument registers
    sym_stdin_len: int = 256         # symbolic stdin bytes (the input vector)
    loop_bound: int = 16             # LoopSeer bound — kill runaway loops
    max_active: int = 64             # cap the active stash (state-explosion guard)
    veritesting: bool = True         # merge paths through diamond CFGs


@dataclass
class AngrVerdict:
    """The result of one reachability query. ``outcome`` is the load-bearing field;
    a ``witness`` carries a concrete input, an ``unsat`` says *prune the hypothesis*."""

    outcome: Outcome
    note: str = ""
    stdin: bytes | None = None                 # concretized crashing/triggering stdin
    arg_values: list[int] = field(default_factory=list)  # concretized argument regs
    control_hijack: bool = False               # unconstrained PC reached (symbolic IP)
    steps: int = 0
    elapsed_s: float = 0.0

    @property
    def pruned(self) -> bool:
        """An ``unsat`` verdict means angr proved the sink unreachable → prune."""
        return self.outcome == "unsat"

    @property
    def reachable(self) -> bool:
        return self.outcome == "witness"


def check_reachability(
    binary: str | Path,
    func_addr: int,
    sink_addr: int,
    *,
    avoid_addrs: tuple[int, ...] = (),
    config: AngrConfig | None = None,
) -> AngrVerdict:
    """Symbolically execute ``func_addr`` with symbolic args/stdin and ask whether
    ``sink_addr`` is reachable. Never raises — any angr failure degrades to an
    ``unknown`` verdict so the pipeline falls through to the dynamic oracle.

    The contract that keeps this safe to wire in front of the oracle: we only
    return ``unsat`` (which prunes a finding) when exploration provably *exhausted*
    every path with no timeout, no error, and no capped/spilled states. Any doubt
    → ``unknown`` → the finding still goes to the oracle.
    """
    cfg = config or AngrConfig()
    try:
        import angr
        import claripy
    except ImportError:
        return AngrVerdict("unknown", note="angr not installed")

    # angr is chatty; keep its logging out of the pipeline's stdout.
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    logging.getLogger("pyvex").setLevel(logging.ERROR)
    logging.getLogger("claripy").setLevel(logging.ERROR)

    start = time.monotonic()
    deadline = start + cfg.timeout_s
    try:
        proj = angr.Project(str(binary), auto_load_libs=False)

        arg_bvs = [
            claripy.BVS(f"arg_{i}", proj.arch.bits) for i in range(cfg.sym_arg_count)
        ]
        sym_stdin = angr.SimFileStream(
            name="stdin",
            content=claripy.BVS("stdin_bytes", cfg.sym_stdin_len * 8),
            has_end=True,
        )
        # Returns from the target land on this sentinel; avoid it so a normal
        # return is a clean deadend, never an "execute unmapped sentinel" error.
        ret_sentinel = int(proj.simos.return_deadend)
        opts = {
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        }
        state = proj.factory.call_state(
            func_addr, *arg_bvs, stdin=sym_stdin, ret_addr=ret_sentinel, add_options=opts
        )
        avoid = (*avoid_addrs, ret_sentinel)
        simgr = proj.factory.simulation_manager(
            state, veritesting=cfg.veritesting, save_unconstrained=True
        )
        et = angr.exploration_techniques
        simgr.use_technique(et.LoopSeer(bound=cfg.loop_bound))
        # Spiller needs an on-disk store; tolerate hosts where it can't init.
        with contextlib.suppress(Exception):
            simgr.use_technique(et.Spiller())

        state_box = {"timed_out": False, "capped": False, "steps": 0}

        def _step(sm: Any) -> Any:
            state_box["steps"] += 1
            if time.monotonic() > deadline:
                state_box["timed_out"] = True
                sm.move(from_stash="active", to_stash="_timeout")
            if len(sm.active) > cfg.max_active:
                state_box["capped"] = True
                sm.split(from_stash="active", to_stash="_capped", limit=cfg.max_active)
            return sm

        simgr.explore(find=sink_addr, avoid=avoid, step_func=_step)
        elapsed = time.monotonic() - start

        if simgr.found:
            found = simgr.found[0]
            try:
                stdin_bytes = found.posix.dumps(0)
            except Exception:
                stdin_bytes = None
            arg_vals: list[int] = []
            for a in arg_bvs:
                try:
                    arg_vals.append(int(found.solver.eval(a)))
                except Exception:
                    break
            return AngrVerdict(
                "witness",
                note=f"sink reachable @ {hex(sink_addr)}",
                stdin=stdin_bytes,
                arg_values=arg_vals,
                steps=state_box["steps"],
                elapsed_s=elapsed,
            )

        if simgr.unconstrained:
            # Symbolic instruction pointer — a control-hijack witness even though we
            # never reached the *named* sink. Still a positive (don't prune).
            return AngrVerdict(
                "witness",
                note="unconstrained PC (symbolic IP) reached",
                control_hijack=True,
                steps=state_box["steps"],
                elapsed_s=elapsed,
            )

        # Inconclusive if anything stopped exploration short of exhaustion.
        if state_box["timed_out"] or state_box["capped"] or simgr.errored or simgr.active:
            why = (
                "timeout" if state_box["timed_out"]
                else "state-cap" if state_box["capped"]
                else "errored" if simgr.errored
                else "active-remaining"
            )
            return AngrVerdict(
                "unknown", note=f"inconclusive ({why})",
                steps=state_box["steps"], elapsed_s=elapsed,
            )

        # Exhausted every path, none reached the sink → provably unreachable.
        return AngrVerdict(
            "unsat", note="all paths explored, sink unreachable",
            steps=state_box["steps"], elapsed_s=elapsed,
        )
    except Exception as e:
        return AngrVerdict(
            "unknown", note=f"angr error: {type(e).__name__}: {e}",
            elapsed_s=time.monotonic() - start,
        )


def function_entry(insts: list[Any], func: str) -> int | None:
    """Lowest instruction address in ``func`` — its entry point, the angr start
    address. ``insts`` are ``zeroverse.il.Inst`` (kept loosely typed to avoid a
    heavy import here)."""
    addrs = [i.addr for i in insts if i.func == func and i.addr]
    return min(addrs) if addrs else None
