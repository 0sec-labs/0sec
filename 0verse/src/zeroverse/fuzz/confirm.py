"""Fuzz crash → PoV, via the existing M1 oracle (#6) and PoV emitter (#7).

A fuzzer hands us a crashing input; this turns it into a confirmed PoV using the
*same* deterministic oracles M1 already ships — no reinvention:

  * the **differential-allocator oracle** (``oracle.differential_allocator``):
    re-run the input under the stock vs an Electric-Fence guard allocator. A
    silent heap OOB that only faults under the guard (``clean -> crash``) is a
    high-confidence real bug, pinned to the faulting instruction; a stack smash
    that already faults under stock is confirmed too.
  * **CASR** (``oracle.run_casr_gdb``) for native exploitability + backtrace,
    with the guard env so the fault is captured.

The no-PoV-no-finding gate is preserved: ``confirm_crash`` returns ``None`` unless
an oracle independently reproduces the crash. The PoV carries the guard env when
the bug is guard-only, so the standalone replay reproduces it natively.
"""

from __future__ import annotations

from pathlib import Path

from .. import oracle
from ..preflight import BudgetTracker
from ..report import PoV
from ..sandbox_exec import Executor


def confirm_crash(
    replay_bin: str | Path,
    crash_input: bytes,
    *,
    vector: str = "stdin",
    function: str = "?",
    sink: str = "?",
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    native_compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> PoV | None:
    """Adjudicate a fuzzer crash with the differential-allocator oracle; emit a
    PoV only if it independently reproduces. ``replay_bin`` must be a *non*-AFL,
    *non*-ASAN build so the guard-allocator differential is meaningful."""
    replay_bin = str(replay_bin)
    if budget is not None and not budget.reserve_attempts(2)[0]:
        return None
    timeout = budget.remaining_seconds() if budget is not None else 10.0
    if timeout <= 0:
        return None
    diff = oracle.differential_allocator(
        replay_bin,
        crash_input,
        vector=vector,
        timeout=timeout,
        deadline_monotonic=(budget.deadline_monotonic if budget is not None else None),
        executor=executor,
        budget=budget,
        compiler_path=native_compiler_path,
        compiler_resolved=compiler_resolved,
    )
    if not diff.confirmed:
        return None

    guard_only = diff.real_heap_bug and not diff.stock.crashed
    # Carry the SAME deterministic quarantine guard the differential oracle
    # confirmed under, so the standalone replay reproduces the silent heap bug.
    repro_env = (
        oracle.confirm_guard_env(
            executor=executor,
            budget=budget,
            compiler_path=native_compiler_path,
            compiler_resolved=compiler_resolved,
        )
        if guard_only
        else {}
    )
    crash_signal = diff.stock.signal if diff.stock.crashed else diff.guard.signal
    argv = [crash_input.decode("latin-1")] if vector == "argv" else []

    pov = PoV(
        input_bytes=crash_input if vector == "stdin" else None,
        argv=argv,
        env=repro_env,
        crash_class=crash_signal or "SIGSEGV",
        crash_trace=(diff.stock.stderr or diff.guard.stderr)[-400:],
        reproduced=True,
        capability="crash",
        execution_provenance=dict(
            diff.stock.provenance if diff.stock.crashed else diff.guard.provenance
        ),
    )
    pov.diff_allocator = (
        f"stock={'crash' if diff.stock.crashed else 'clean'}"
        f"({diff.stock.signal or '-'}) "
        f"guard={'crash' if diff.guard.crashed else 'clean'}"
        f"({diff.guard.signal or '-'})"
        + (" [clean->crash: real silent heap OOB]" if diff.real_heap_bug else "")
    )

    casr = None
    if budget is None or budget.reserve_attempt()[0]:
        timeout = budget.remaining_seconds() if budget is not None else 60.0
        if timeout > 0:
            casr = oracle.run_casr_gdb(
                replay_bin,
                stdin_bytes=crash_input if vector == "stdin" else None,
                argv=argv if vector == "argv" else None,
                env=repro_env or None,
                timeout=timeout,
                executor=executor,
            )
    if casr is not None:
        pov.casr_severity = casr.severity
        pov.casr_desc = f"{casr.short_desc}: {casr.description}".strip(": ")
        pov.capability = casr.capability
        pov.frames = casr.frames
        pov.dedup_bucket = oracle.dedup_key(casr.severity, casr.frames)
    else:
        pov.dedup_bucket = oracle.dedup_key(pov.crash_class, [f"{function}:{sink}"])
    return pov
