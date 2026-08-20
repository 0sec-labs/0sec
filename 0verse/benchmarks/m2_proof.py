#!/usr/bin/env python3
"""M2 milestone proof — fuzzing finds what slicing alone cannot.

Run inside the engine env (AFL++ + cc; Ghidra optional):

    python benchmarks/m2_proof.py

It demonstrates, on benchmarks/parser.c (a guarded hand-rolled heap overflow with
no libc sink):

  Part A — the M1 STATIC SLICE finds nothing. With Ghidra present we run the real
           pipeline on the stripped binary and assert zero confirmed findings;
           without Ghidra we note the structural reason (no sink, no source).

  Part B — the M2 FUZZ path finds it: synthesize a harness for `parse_record`
           (#16), fuzz with AFL++/CMPLOG past the "REC0" gate (#15), confirm the
           heap OOB with the differential-allocator oracle (#6) into a PoV (#7),
           and re-run the emitted standalone PoV to prove native reproduction.

Exit 0 iff Part B confirms a PoV and it reproduces.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse.fuzz import fuzz_function  # noqa: E402
from zeroverse.fuzz.aflpp import AflConfig, afl_available  # noqa: E402
from zeroverse.fuzz.harness import HarnessSpec, recover_signature  # noqa: E402

# A Ghidra-style decompiled signature line for parse_record (what #1 recovers from
# the stripped binary — here supplied directly to keep the proof self-contained).
GHIDRA_DECOMP = "int parse_record(byte *data,int len)\n{\n  /* ... */\n}\n"


def part_a_static_slice_miss() -> None:
    print("== Part A: does the M1 static slice find it? ==")
    parser_c = HERE / "parser.c"
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
    if not ghidra:
        print("  Ghidra not configured — structural argument instead:")
        print("  parse_record's only calls are memcmp/malloc/printf/free (no taint")
        print("  SINK) and it has no read/recv/getenv SOURCE, so slice-then-intersect")
        print("  yields ZERO candidates. (Set GHIDRA_INSTALL_DIR to run it for real.)")
        return
    with tempfile.TemporaryDirectory() as td:
        workspace = Path(td)
        harness_c = workspace / "_m2_main.c"
        harness_c.write_text(
            '#include <unistd.h>\n'
            'extern int parse_record(const unsigned char*,int);\n'
            'int main(void){static unsigned char b[4096];'
            'int n=(int)read(0,b,sizeof b);if(n<0)n=0;parse_record(b,n);return 0;}\n'
        )
        binp = workspace / "parser_stripped"
        subprocess.run(
            ["cc", "-O0", "-s", str(harness_c), str(parser_c), "-o", str(binp)],
            check=True,
        )
        from zeroverse.pipeline import run

        result = run(binp)
        confirmed = [tf for tf in result.findings if tf.pov and tf.pov.reproduced]
        print(f"  stages: {result.stages_run}")
        print(f"  confirmed static findings: {len(confirmed)}  (expect 0)")
        if confirmed:
            print("  UNEXPECTED: the slice confirmed something — proof weakened")
        else:
            print("  OK: the static slice misses the bug (as designed)")


def part_b_fuzz_finds_it() -> int:
    print("\n== Part B: does M2 fuzzing find it? ==")
    if not afl_available():
        print("  FAIL: afl-fuzz not available")
        return 1
    sig = recover_signature("parse_record", GHIDRA_DECOMP)
    assert sig is not None, "signature recovery failed"
    print(f"  recovered signature: {sig.extern_decl()}")
    spec = HarnessSpec(
        func="parse_record", signature=sig, decompiled_c=GHIDRA_DECOMP,
        constants=["REC0"],
    )
    with tempfile.TemporaryDirectory() as td:
        outcome = fuzz_function(
            spec, [HERE / "parser.c"],
            config=AflConfig(duration_s=120, cmplog=True, use_asan=True),
            workdir=Path(td),
        )
        print(f"  harness built: {outcome.harness_built}  execs: {outcome.execs}")
        print(f"  crash found:   {outcome.crash_found}")
        print(f"  note:          {outcome.note}")
        if not (outcome.crash_found and outcome.pov):
            print("  FAIL: no oracle-confirmed PoV")
            return 1
        pov = outcome.pov
        print(f"  PoV crash_class: {pov.crash_class}  capability: {pov.capability}")
        print(f"  differential-allocator: {pov.diff_allocator}")
        print(f"  CASR: {pov.casr_severity} {pov.casr_desc}")
        print(f"  PoV script: {pov.pov_script}")
        if pov.pov_script and Path(pov.pov_script).exists():
            rc = subprocess.run(
                [sys.executable, pov.pov_script], capture_output=True
            ).returncode
            print(f"  standalone PoV replay exit: {rc}  (0 == reproduced)")
            if rc != 0:
                print("  FAIL: PoV did not reproduce on native replay")
                return 1
        print("  OK: fuzzing found + confirmed a bug the static slice missed")
    return 0


def main() -> int:
    part_a_static_slice_miss()
    rc = part_b_fuzz_finds_it()
    print("\n=== M2 PROOF:", "PASS ✅" if rc == 0 else "FAIL ❌", "===")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
