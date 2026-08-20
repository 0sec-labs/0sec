"""M2 fuzzing backbone — find bugs without a clean static slice.

The binary-only gap the #2 slice cannot close: a guarded / hand-rolled bug with no
recognizable libc sink. This package supplies the three M2 pieces that complement
the M1 static path and feed the same M1 oracle/PoV:

  * :mod:`zeroverse.fuzz.harness`   — #16 LLM fuzz-harness synthesis (the keystone)
  * :mod:`zeroverse.fuzz.aflpp`     — #15 AFL++ QEMU/persistent driver + CMPLOG
  * :mod:`zeroverse.fuzz.driller`   — #17 Driller-style concolic assist on a stall
  * :mod:`zeroverse.fuzz.confirm`   — fuzz crash → PoV via the M1 oracle (#6/#7)
  * :mod:`zeroverse.fuzz.orchestrator` — wires them into one stage

M7 directed fuzzing (#39/#40/#41) drives the AFL++ lane *toward* the flagged sinks:

  * :mod:`zeroverse.fuzz.coverage`  — #40 coverage→address map + last-mile signal
  * :mod:`zeroverse.fuzz.directed`  — #39 UniAFL sink-scored corpus scheduling
  * ``driller.DistanceDriller``     — #41 distance-gradient concolic assist
"""

from __future__ import annotations

from .aflpp import AflConfig, FuzzResult, SubprocessAfl, afl_available
from .coverage import AddressIndex, CoverageProbe
from .directed import DirectedScheduler, DirectedTargets, SinkTarget, collect_targets
from .driller import AngrCfgDistance, DistanceDriller, NullDistance
from .harness import HarnessSpec, HarnessSynthesizer, build_harness, recover_signature
from .orchestrator import (
    FuzzFinding,
    FuzzOutcome,
    directed_fuzz_function,
    directed_fuzz_stage,
    fuzz_function,
    run_fuzz_stage,
)

__all__ = [
    "AddressIndex",
    "AflConfig",
    "AngrCfgDistance",
    "CoverageProbe",
    "DirectedScheduler",
    "DirectedTargets",
    "DistanceDriller",
    "FuzzFinding",
    "FuzzOutcome",
    "FuzzResult",
    "HarnessSpec",
    "HarnessSynthesizer",
    "NullDistance",
    "SinkTarget",
    "SubprocessAfl",
    "afl_available",
    "build_harness",
    "collect_targets",
    "directed_fuzz_function",
    "directed_fuzz_stage",
    "fuzz_function",
    "recover_signature",
    "run_fuzz_stage",
]
