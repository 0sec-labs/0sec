"""#39/#40/#41 — the directed-vs-coverage lane wiring, end to end.

Proves the *orchestration*: with sink targets, the DistanceDriller's concolic
re-seed (a fake solver standing in for angr) drives the corpus past a gate the
coverage lane never crosses, and the oracle confirms the crash — while the same
backend with an EMPTY target set (the coverage ablation) records ``none``.

Hermetic apart from the AFL/cc toolchain (the binaries are really built and the
crash is really oracle-confirmed); the AFL run itself is replaced by a scripted
backend so the proof is deterministic. The heavy *real-AFL* proof lives in
``benchmarks/m7_directed_proof.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from zeroverse.fuzz.aflpp import AflConfig, FuzzResult, afl_available
from zeroverse.fuzz.directed import DirectedTargets, SinkTarget
from zeroverse.fuzz.driller import NullDistance
from zeroverse.fuzz.harness import recover_signature
from zeroverse.fuzz.orchestrator import HarnessSpec, directed_fuzz_function

pytestmark = pytest.mark.skipif(
    not afl_available(), reason="afl-clang-fast needed to build the fuzz binaries"
)

ROOT = Path(__file__).resolve().parent.parent
PARSER_C = ROOT / "benchmarks" / "parser.c"
GHIDRA_DECOMP = "int parse_record(byte *data,int len)\n{\n  /* ... */\n}\n"
HARNESS = (
    "#include <unistd.h>\n"
    "extern int parse_record(const unsigned char*,int);\n"
    "int main(void){static unsigned char b[4096];"
    "int n=(int)read(0,b,sizeof b);if(n<0)n=0;parse_record(b,n);return 0;}\n"
)
# A real "REC0" record whose length byte (40) overflows the 32-byte heap buffer —
# the oracle's differential allocator confirms this as a heap OOB write.
OVERFLOW = b"REC0" + bytes([40]) + b"A" * 60


class _ScriptedAfl:
    """A deterministic AFL stand-in: it 'finds' the overflow only once the solved
    input is in the seed corpus — i.e. only after the DistanceDriller assists."""

    def __init__(self, trigger: bytes) -> None:
        self.trigger = trigger
        self.windows = 0

    def fuzz(
        self, fuzz_bin: Path, *, in_dir: Path, out_dir: Path,
        config: AflConfig, cmplog_bin: Path | None = None,
    ) -> FuzzResult:
        self.windows += 1
        if self.trigger in config.seeds:
            cdir = out_dir / "default" / "crashes"
            cdir.mkdir(parents=True, exist_ok=True)
            (cdir / "id:000000,sig:06,scripted").write_bytes(self.trigger)
            return FuzzResult(crashes=[self.trigger], execs=100, note="scripted-crash")
        return FuzzResult(crashes=[], execs=50, note="scripted-nocrash")


class _FakeSolver:
    """Stands in for angr: 'solves' the gate by returning the overflow witness."""

    def __init__(self, solved: bytes) -> None:
        self.solved = solved
        self.calls = 0

    def solve(
        self, binary: Path, stuck_input: bytes, *, func_addr: int, target_addr: int
    ) -> bytes | None:
        self.calls += 1
        return self.solved


def _spec() -> HarnessSpec:
    sig = recover_signature("parse_record", GHIDRA_DECOMP)
    assert sig is not None
    return HarnessSpec(
        func="parse_record", signature=sig, decompiled_c=GHIDRA_DECOMP,
        constants=["REC0"],
    )


def test_coverage_lane_misses_without_targets(tmp_path: Path) -> None:
    # Empty target set → plain coverage run → the scripted backend never crashes.
    outcome = directed_fuzz_function(
        _spec(), [PARSER_C], targets=DirectedTargets(),
        backend=_ScriptedAfl(OVERFLOW), solver=_FakeSolver(OVERFLOW),
        harness_src=HARNESS, config=AflConfig(duration_s=1),
        workdir=tmp_path / "cov",
    )
    assert outcome.harness_built
    assert outcome.crash_found is False
    assert outcome.pov is None


def test_directed_lane_confirms_via_concolic_assist(tmp_path: Path) -> None:
    targets = DirectedTargets([
        SinkTarget("parse_record", 0x1000, 0x1100, "slice", weight=1.0)
    ])
    solver = _FakeSolver(OVERFLOW)
    backend = _ScriptedAfl(OVERFLOW)
    outcome = directed_fuzz_function(
        _spec(), [PARSER_C], targets=targets,
        distance=NullDistance([(0x1000, 0x1100)]),
        solver=solver, backend=backend, harness_src=HARNESS,
        config=AflConfig(duration_s=1), workdir=tmp_path / "dir", max_windows=3,
    )
    assert outcome.crash_found is True
    assert outcome.pov is not None and outcome.pov.reproduced
    assert "concolic-assisted" in outcome.note
    assert solver.calls >= 1                 # the driller really assisted
    assert backend.windows >= 2              # crash only after the re-seed window
    # the confirmed sink is dropped from the live target set
    assert len(targets) == 0
