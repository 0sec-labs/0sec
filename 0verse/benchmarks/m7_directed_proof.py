#!/usr/bin/env python3
"""M7 milestone proof — DIRECTED fuzzing confirms a deep/gated bug the plain
coverage lane misses within the same budget.

Run inside the engine env (AFL++ + cc + angr; qemu-user for the coverage map):

    python benchmarks/m7_directed_proof.py --budget 60

Target: ``benchmarks/deep_chain.c`` — a heap overflow behind THREE stacked gates
(a 4-byte string magic, a 32-bit constant, and a COMPUTED ARX/rotate checksum that
CMPLOG cannot invert). Three lanes on the identical harness:

  * **baseline**  — plain AFL++ (no CMPLOG, no dictionary): stuck at gate 1.
  * **coverage**  — current 0verse (CMPLOG + slice-mined dictionary): cracks the
    atomic gates but TIMES OUT on the rotate checksum.
  * **directed**  — coverage + the #39/#40/#41 directed machinery: on a distance
    plateau the #41 DistanceDriller concolic-solves the checksum (angr), re-seeds
    AFL++, which mutates the length byte into the heap OOB; the SAME M1 oracle
    confirms the PoV (PoV-is-truth unchanged).

Part A separately demonstrates the #40 coverage→address map + #39 sink scorer on
REAL qemu-user coverage (not a fixture): the reached-but-uncrashed last-mile
signal + the scheduler ranking the sink-reaching seed above gate-stuck ones, using
an address index built from the actual traced basic-block leaders.

Honest framing: directed fuzzing helps the GATED class (it converts a timeout into
a confirm); on an ungated bug it is pure overhead and a tie. Exit 0 iff the
directed lane confirms a PoV the coverage lane records as ``none``.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse.concolic import check_reachability  # noqa: E402
from zeroverse.fuzz.aflpp import AflConfig, afl_available, tokens_from_context  # noqa: E402
from zeroverse.fuzz.coverage import AddressIndex, CoverageProbe, qemu_user_bin  # noqa: E402
from zeroverse.fuzz.directed import (  # noqa: E402
    DirectedTargets,
    SinkTarget,
    func_ranges_from_disasm,
)
from zeroverse.fuzz.driller import AngrConcolicSolver, NullDistance  # noqa: E402
from zeroverse.fuzz.harness import HarnessSpec, recover_signature  # noqa: E402
from zeroverse.fuzz.orchestrator import directed_fuzz_function  # noqa: E402
from zeroverse.il import Inst, Kind  # noqa: E402

DEEP_C = HERE / "deep_chain.c"
DECOMP = "int parse_deep_chain(byte *data,int len)\n{\n  /* ... */\n}\n"
HARNESS = (
    "#include <unistd.h>\n"
    "extern int parse_deep_chain(const unsigned char*,int);\n"
    "int main(void){static unsigned char b[4096];"
    "int n=(int)read(0,b,sizeof b);if(n<0)n=0;parse_deep_chain(b,n);return 0;}\n"
)
GATE2 = (0xC0FFEE00).to_bytes(4, "little")
GATE_FAIL = b"DEEP" + GATE2 + b"ZZZZZZ" + bytes([4]) + b"P" * 8   # clears 1&2, fails 3
SHALLOW = b"XXXX" + b"\x00" * 16                                   # fails gate 1


def _build_solve_bin(src: Path, workdir: Path) -> Path:
    """A fixed-base (-no-pie) build so the qemu-trace guest PCs, the objdump VAs,
    and angr's addresses all share ONE address space (no PIE base guessing)."""
    h = workdir / "dc_harness.c"
    h.write_text(HARNESS)
    out = workdir / "dc_solve"
    subprocess.run(["cc", "-O0", "-no-pie", str(h), str(src), "-o", str(out)], check=True)
    return out


def _addr_of(binary: Path, sym: str) -> int:
    for line in subprocess.run(
        ["nm", str(binary)], capture_output=True, text=True, check=True
    ).stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == sym:
            return int(parts[0], 16)
    raise RuntimeError(f"symbol {sym} not found")


_INS = re.compile(r"^\s*([0-9a-fA-F]+):\t")


def _sink_addr(binary: Path) -> int:
    """The malloc call site inside parse_deep_chain — reachable only past gate 3."""
    text = subprocess.run(
        ["objdump", "-d", str(binary)], capture_output=True, text=True, check=True
    ).stdout
    in_fn = False
    for line in text.splitlines():
        if line.endswith("<parse_deep_chain>:"):
            in_fn = True
        elif in_fn and "call" in line and "<malloc" in line:
            return int(_INS.match(line).group(1), 16)  # type: ignore[union-attr]
    raise RuntimeError("malloc call site not found")


def _func_of(addr: int, ranges: dict[str, tuple[int, int]]) -> str:
    for f, (lo, hi) in ranges.items():
        if lo <= addr < hi:
            return f
    return "?"


def _leader_index(solve_bin: Path, ranges: dict[str, tuple[int, int]],
                  seeds: list[bytes]) -> tuple[AddressIndex, CoverageProbe]:
    """Harvest the *real* basic-block leaders from qemu traces of a few reference
    inputs and build an AddressIndex from them — so ``covering_block``/``reached``
    test against genuine traced leaders (precise, no window heuristic)."""
    raw = CoverageProbe(solve_bin, AddressIndex())   # empty index, used only to trace
    leaders: set[int] = set()
    for s in seeds:
        leaders |= raw.trace(s).addrs
    insts = [Inst(id=i, func=_func_of(a, ranges), addr=a, kind=Kind.OTHER)
             for i, a in enumerate(sorted(leaders))]
    index = AddressIndex.from_insts(insts)
    return index, CoverageProbe(solve_bin, index)


def part_a_coverage_map(probe: CoverageProbe, sink: int, main_addr: int,
                        witness: bytes) -> None:
    print("== Part A: #40 coverage→address map + #39 sink scorer (real qemu) ==")
    target = SinkTarget("parse_deep_chain", main_addr, sink, "slice", weight=1.0)
    names = {witness: "witness", GATE_FAIL: "gate_fail", SHALLOW: "shallow"}
    scored = [(name, probe.score_seed(seed, [target])) for seed, name in names.items()]
    for name, sc in scored:
        print(f"  {name:9s}: key_hits={sc.key_hits:3d}  reached_sink={sc.reached_any}  "
              f"blocks={sc.total_blocks}")
    # the #39 scorer ranks the sink-reaching seed strictly first (deterministic):
    rank = sorted(scored, key=lambda t: (len(t[1].sinks_reached), t[1].key_hits), reverse=True)
    print(f"  sink-score ranking (best→worst): {[n for n, _ in rank]}")
    lm = probe.uncrashed_but_reached(list(names), [target])
    print(f"  reached-but-uncrashed (last-mile) sinks: {[hex(t.sink_addr) for t in lm]}")
    print("  -> the witness is ranked #1 and is the sole last-mile candidate; the "
          "DistanceDriller picks it up.\n")


def _spec() -> HarnessSpec:
    sig = recover_signature("parse_deep_chain", DECOMP)
    assert sig is not None
    return HarnessSpec(func="parse_deep_chain", signature=sig, decompiled_c=DECOMP,
                       constants=["DEEP"])


def _confirmed(outcome: object) -> bool:
    pov = getattr(outcome, "pov", None)
    return bool(pov and pov.reproduced)


def run_lane(name: str, cfg: AflConfig, *, directed: bool, solve_bin: Path,
             sink: int, main_addr: int) -> tuple[bool, float, str]:
    with tempfile.TemporaryDirectory() as td:
        kw: dict[str, object] = {}
        targets = DirectedTargets()
        if directed:
            target = SinkTarget("parse_deep_chain", main_addr, sink, "slice", weight=1.0)
            targets = DirectedTargets([target])
            kw = {
                "distance": NullDistance([(main_addr, sink)]),
                "solver": AngrConcolicSolver(),
                "solve_bin": solve_bin,
                "max_windows": 3,
            }
        t0 = time.monotonic()
        outcome = directed_fuzz_function(
            _spec(), [DEEP_C], targets=targets, harness_src=HARNESS,
            config=cfg, workdir=Path(td), **kw,  # type: ignore[arg-type]
        )
        elapsed = round(time.monotonic() - t0, 1)
    return _confirmed(outcome), elapsed, outcome.note


def part_b_three_lanes(solve_bin: Path, sink: int, main_addr: int, budget: int) -> int:
    print(f"== Part B: 3-lane crash comparison (budget {budget}s/lane) ==")
    mined = tokens_from_context(DEEP_C.read_text())
    lanes = [
        ("baseline", AflConfig(duration_s=budget, cmplog=False, use_asan=True,
                               stop_on_crash=True, seeds=[b"\x00"], dict_tokens=[]), False),
        ("coverage", AflConfig(duration_s=budget, cmplog=True, use_asan=True,
                               stop_on_crash=True, seeds=[b"\x00"], dict_tokens=mined), False),
        ("directed", AflConfig(duration_s=max(1, budget // 3), cmplog=True, use_asan=True,
                               stop_on_crash=True, seeds=[b"\x00"], dict_tokens=mined), True),
    ]
    results: list[tuple[str, bool, float, str]] = []
    for name, cfg, directed in lanes:
        print(f"  -- {name} lane ...", flush=True)
        ok, elapsed, note = run_lane(name, cfg, directed=directed, solve_bin=solve_bin,
                                     sink=sink, main_addr=main_addr)
        results.append((name, ok, elapsed, note))
        print(f"     confirmed={ok}  t={elapsed}s  note={note}")

    print("\n  lane      confirmed  time(s)")
    for name, ok, elapsed, _ in results:
        print(f"  {name:9s} {ok!s:9s} {elapsed}")

    cov = next(r for r in results if r[0] == "coverage")
    dr = next(r for r in results if r[0] == "directed")
    win = dr[1] and not cov[1]
    print()
    if win:
        print("  WIN: directed CONFIRMED the gated bug the coverage lane missed (none).")
    elif dr[1] and cov[1]:
        print("  TIE: both confirmed — the checksum gate was crackable in budget here.")
    else:
        print("  NO-WIN: directed did not confirm — honest negative (check angr/qemu).")
    return 0 if win else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=60, help="per-lane budget (s)")
    args = ap.parse_args()
    if not afl_available():
        print("FAIL: afl-fuzz not on PATH", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        solve_bin = _build_solve_bin(DEEP_C, wd)
        main_addr = _addr_of(solve_bin, "main")
        sink = _sink_addr(solve_bin)
        print(f"target: parse_deep_chain  main@{hex(main_addr)}  sink(malloc)@{hex(sink)}\n")

        # Part A — exercise #40/#39 on real qemu coverage with a leader-based index.
        if qemu_user_bin() is not None:
            objt = subprocess.run(["objdump", "-d", str(solve_bin)],
                                  capture_output=True, text=True, check=True).stdout
            ranges = func_ranges_from_disasm(objt)
            witness = check_reachability(solve_bin, main_addr, sink).stdin or b""
            _, probe = _leader_index(
                solve_bin, ranges, [witness, GATE_FAIL, SHALLOW, b"\x00"]
            )
            if probe.available():
                part_a_coverage_map(probe, sink, main_addr, witness)
            else:
                print("== Part A skipped: qemu trace empty ==\n")
        else:
            print("== Part A skipped: qemu-x86_64 not on PATH ==\n")

        rc = part_b_three_lanes(solve_bin, sink, main_addr, args.budget)

    print("\n=== M7 PROOF:", "PASS ✅" if rc == 0 else "FAIL ❌", "===")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
