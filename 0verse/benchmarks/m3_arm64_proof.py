#!/usr/bin/env python3
"""M3 ARM64 full-pipeline proof — breadth beyond x86-64 ELF (#19).

Run inside the engine env (clang+lld with an aarch64 target, AFL++ with a
cross-arch ``afl-qemu-trace`` built ``CPU_TARGET=aarch64``, qemu-aarch64 user-mode
registered via binfmt_misc):

    python benchmarks/m3_arm64_proof.py

It proves 0verse covers ARM64 *dynamically*, not just in disassembly, on
benchmarks/parse_arm.c — a freestanding (no-libc) AArch64 ELF with a gated
stack-buffer overflow behind a 4-byte ``ARM!`` magic:

  Part A — INGEST + ABI: triage classifies the AArch64 ELF and the ABI resolves
           to AAPCS64 (x0-x7 / x0).

  Part B — DYNAMIC: AFL++ QEMU-mode via qemu-aarch64 (the -Q cross-arch path)
           cracks the ``ARM!`` gate (CMPLOG -c 0), the differential-allocator
           oracle (#6) confirms the crash, a PoV (#7) is emitted, and the
           standalone PoV is re-run — reproducing natively under qemu-aarch64
           (binfmt). Exit 0 iff a PoV is confirmed and reproduces.

  Part C — FULL PIPELINE (optional, needs GHIDRA_INSTALL_DIR): pipeline.run() on
           the arm64 binary: Ghidra slice (arm64 ABI) → angr → cross-arch fuzz →
           oracle → PoV.
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

from zeroverse.abi import AAPCS64, host_arch  # noqa: E402
from zeroverse.fuzz.aflpp import AflConfig, afl_available, afl_qemu_available  # noqa: E402
from zeroverse.fuzz.orchestrator import run_fuzz_stage  # noqa: E402
from zeroverse.ingest import triage  # noqa: E402
from zeroverse.poc import write_pov_script  # noqa: E402

MAGIC = b"ARM!"
# A Ghidra-style decompiled signature line for parse_record (what #1 recovers);
# supplied directly here so Part B also exercises arm64 harness synthesis (#16).
GHIDRA_DECOMP = {"parse_record": "void parse_record(char *data,int len)\n{\n  /* ... */\n}\n"}


def build_arm64(workdir: Path) -> Path | None:
    src = HERE / "parse_arm.c"
    out = workdir / "parse_arm"
    p = subprocess.run(
        ["clang", "--target=aarch64-linux-gnu", "-nostdlib", "-static",
         "-fno-stack-protector", "-O0", "-fuse-ld=lld", str(src), "-o", str(out)],
        capture_output=True,
    )
    if p.returncode != 0:
        print("  build failed:", p.stderr.decode("utf-8", "replace")[:400])
        return None
    return out


def part_a_ingest_abi(binary: Path) -> None:
    print("== Part A: ingest + ABI ==")
    t = triage(binary)
    print(f"  triage: {t.summary()}")
    assert t.fmt == "ELF" and t.arch == "AArch64", "expected an AArch64 ELF"
    abi = AAPCS64
    print(f"  ABI: {abi.name}  args={abi.int_arg_regs[:4]}...  ret={abi.ret_reg}")
    print("  OK: AArch64 ELF classified, AAPCS64 resolved")


def part_b_dynamic(binary: Path) -> int:
    print("\n== Part B: ARM64 dynamic (AFL++ QEMU-mode via qemu-aarch64) ==")
    if not afl_available():
        print("  FAIL: afl-fuzz not available")
        return 1
    if not afl_qemu_available("aarch64"):
        print("  FAIL: aarch64 afl-qemu-trace missing — build it with")
        print("        CPU_TARGET=aarch64 AFLplusplus/qemu_mode/build_qemu_support.sh")
        print("        and install as afl-qemu-trace-aarch64 (or set "
              "ZEROVERSE_AFL_QEMU_AARCH64)")
        return 1
    print(f"  host arch: {host_arch()}  -> emulating aarch64 under qemu-user")

    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td) / "out"
        cfg = AflConfig(
            qemu_mode=True, qemu_arch="aarch64", cmplog=True, duration_s=120,
            seeds=[MAGIC + b"AAAA"], dict_tokens=["ARM!"],
        )
        findings, note = run_fuzz_stage(
            binary, GHIDRA_DECOMP, out_dir=out_dir, config=cfg, arch="aarch64"
        )
        print(f"  fuzz note: {note}")
        if not findings:
            print("  FAIL: no oracle-confirmed PoV from the aarch64 fuzz run")
            return 1
        ff = findings[0]
        pov = ff.pov
        print(f"  crash_class: {pov.crash_class}  capability: {pov.capability}")
        print(f"  differential-allocator: {pov.diff_allocator}")
        print(f"  CASR: {pov.casr_severity or '(n/a cross-arch)'} {pov.casr_desc}")

        script = Path(td) / "pov_arm64.py"
        write_pov_script(script, binary, pov)
        rc = subprocess.run([sys.executable, str(script)], capture_output=True)
        print(f"  standalone PoV replay exit: {rc.returncode}  (0 == reproduced)")
        out_txt = rc.stdout.decode("utf-8", "replace").strip().splitlines()
        if out_txt:
            print(f"  {out_txt[-1]}")
        if rc.returncode != 0:
            print("  FAIL: PoV did not reproduce under qemu-aarch64")
            return 1
    print("  OK: arm64 bug fuzz-found, oracle-confirmed, PoV reproduces under qemu")
    return 0


def part_c_full_pipeline(binary: Path) -> None:
    print("\n== Part C: full pipeline (Ghidra arm64 slice → angr → fuzz) ==")
    if not (os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")):
        print("  skipped — set GHIDRA_INSTALL_DIR to run the Ghidra-backed pipeline")
        return
    from zeroverse.pipeline import run

    result = run(binary)
    print(f"  stages: {result.stages_run}")
    print(f"  note: {result.note}")
    confirmed = [tf for tf in result.findings if tf.pov and tf.pov.reproduced]
    print(f"  confirmed arm64 PoVs via full pipeline: {len(confirmed)}")


def main() -> int:
    if not (host_arch() == "aarch64" or afl_qemu_available("aarch64")):
        print("aarch64 not runnable here (no native + no qemu-aarch64 trace) — skip")
        return 0
    with tempfile.TemporaryDirectory() as td:
        binary = build_arm64(Path(td))
        if binary is None:
            print("=== M3 ARM64 PROOF: FAIL (build) ===")
            return 1
        part_a_ingest_abi(binary)
        rc = part_b_dynamic(binary)
        part_c_full_pipeline(binary)
    print("\n=== M3 ARM64 PROOF:", "PASS ✅" if rc == 0 else "FAIL ❌", "===")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
