#!/usr/bin/env python3
"""M5 #27 proof — the engine slices + confirms with Ghidra DISABLED.

Compiles benchmarks/overflow.c, runs the full pipeline with
``ZEROVERSE_BACKEND=rizin`` and ``GHIDRA_HOME`` unset, and shows the rizin/r2ghidra
backend recover the IL, slice read->strcpy, and (where the host can run the
target) confirm a reproducing PoV via the differential oracle.

    make proof-m5      # or: python benchmarks/m5_backend_proof.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    os.environ.pop("GHIDRA_HOME", None)
    os.environ.pop("GHIDRA_INSTALL_DIR", None)
    os.environ["ZEROVERSE_BACKEND"] = "rizin"

    from zeroverse.backends.rizin import r2_available

    if not r2_available():
        print("SKIP: r2 + r2pipe not installed (needed for the rizin fallback)")
        return 0

    src = ROOT / "benchmarks" / "overflow.c"
    with tempfile.TemporaryDirectory() as td:
        binary = Path(td) / "overflow"
        subprocess.run(
            ["gcc", "-no-pie", "-fno-stack-protector", "-o", str(binary), str(src)],
            check=True,
        )

        from zeroverse.backends import contract
        from zeroverse.pipeline import run

        print(f"available backends (no GHIDRA_HOME): {contract.available_backends()}")
        adapter = contract.analyze(binary)
        assert adapter is not None, "no backend available"
        print(f"backend used: {getattr(adapter, '_backend', '?')}")
        meta = adapter.meta  # type: ignore[attr-defined]
        print(f"arch={meta.arch} bits={meta.bits} "
              f"functions={len(meta.decompiled_c)} imports={meta.imports[:6]}")

        r = run(binary)
        print(f"\nstages run: {', '.join(r.stages_run)}")
        print(f"note: {r.note}\n")

        ok = False
        for tf in r.findings:
            f = tf.finding
            confirmed = bool(tf.pov and tf.pov.reproduced)
            mark = "CONFIRMED" if confirmed else ("REAL?" if tf.verdict.is_real else "fp")
            print(f"  [{mark}] {f.source} -> {f.sink} in {f.function} ({tf.verdict.bug_class})")
            if f.source == "read" and f.sink == "strcpy":
                ok = True
                if confirmed:
                    print(f"      PoV class={tf.pov.crash_class} "
                          f"capability={tf.pov.capability}")

        print()
        if not ok:
            print("FAIL: rizin backend did not recover the read->strcpy slice")
            return 1
        print("PROOF OK: Ghidra disabled, rizin backend sliced read->strcpy"
              + (" and CONFIRMED a PoV" if any(
                  tf.pov and tf.pov.reproduced for tf in r.findings) else
                 " (PoV degraded honestly on this host)"))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
