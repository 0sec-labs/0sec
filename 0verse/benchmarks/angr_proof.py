#!/usr/bin/env python3
"""Proof harness for the #5 angr concolic stage.

Compiles benchmarks/guarded.c and runs the slice-scoped reachability check on the
two callers of the same sink:

  * reachable_path  -> expect a WITNESS (angr concretizes x == 0xdeadbeef)
  * dead_path       -> expect UNSAT    (angr prunes the unreachable hypothesis)

Run on bench (heavy):  python benchmarks/angr_proof.py
Exits non-zero unless BOTH the witness and the prune land — so CI/the gate can
assert angr actually discriminates real from impossible.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import angr

from zeroverse.concolic import AngrConfig, check_reachability

HERE = Path(__file__).resolve().parent


def main() -> int:
    src = HERE / "guarded.c"
    with tempfile.TemporaryDirectory() as td:
        binary = Path(td) / "guarded"
        subprocess.run(
            ["gcc", "-O0", "-no-pie", "-fno-stack-protector", "-o", str(binary), str(src)],
            check=True,
        )
        proj = angr.Project(str(binary), auto_load_libs=False)

        def sym(name: str) -> int:
            s = proj.loader.find_symbol(name)
            if s is None:
                raise SystemExit(f"symbol {name} not found")
            return int(s.rebased_addr)

        vuln = sym("vuln")
        cfg = AngrConfig(timeout_s=60.0, sym_arg_count=2)

        print("== reachable_path (expect WITNESS) ==")
        good = check_reachability(binary, sym("reachable_path"), vuln, config=cfg)
        print(f"  outcome={good.outcome} note={good.note!r}")
        print(f"  arg_values={[hex(v) for v in good.arg_values]} steps={good.steps}"
              f" elapsed={good.elapsed_s:.1f}s")

        print("== dead_path (expect UNSAT / prune) ==")
        dead = check_reachability(binary, sym("dead_path"), vuln, config=cfg)
        print(f"  outcome={dead.outcome} note={dead.note!r} steps={dead.steps}"
              f" elapsed={dead.elapsed_s:.1f}s")

    witness_ok = good.outcome == "witness" and 0xDEADBEEF in good.arg_values
    prune_ok = dead.outcome == "unsat"
    print("\n== verdict ==")
    print(f"  witness concretized x==0xdeadbeef: {witness_ok}")
    print(f"  dead hypothesis pruned (UNSAT):    {prune_ok}")
    ok = witness_ok and prune_ok
    print("PROOF: PASS" if ok else "PROOF: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
