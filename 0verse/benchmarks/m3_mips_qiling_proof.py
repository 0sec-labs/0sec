#!/usr/bin/env python3
"""M3 wave-2 MIPS/Qiling proof — firmware lane breadth beyond x86/ARM ELF (#21).

    python benchmarks/m3_mips_qiling_proof.py

Proves 0verse covers the MIPS *firmware* surface with Qiling emulation — the
reusable engine piece that qemu-user alone can't give you for firmware (no
rootfs/loader). It does NOT fake a router image: it proves the engine on a
freestanding MIPS o32 ELF and documents the binwalk firmware-unpack step.

  Part A — INGEST + ABI: triage classifies the big-endian MIPS ELF and the ABI
           resolves to MIPS o32 ($a0-$a3 / $v0, $ra return-address).

  Part B — QILING REACHABILITY/CRASH: emulate parse_record directly (args + $ra
           seeded from the o32 ABI). A control input returns cleanly to the
           sentinel; the gated overflow corrupts the saved $ra and faults. The
           differential is confirmed into a PoV via the M1 oracle dedup.

  Part C — BINWALK firmware-unpack (documented): run a real binwalk signature
           scan over the MIPS ELF treated as a blob (proving the carve step is
           wired); a genuine squashfs image is out of scope on the bench, so the
           rootfs-carve is noted, never fabricated.

  Part D — FULL PIPELINE (optional, needs GHIDRA_INSTALL_DIR): pipeline.run()
           routes the MIPS ELF, slices it, and the firmware lane Qiling-confirms.
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

from zeroverse import firmware  # noqa: E402
from zeroverse.abi import MIPS_O32  # noqa: E402
from zeroverse.analyze import Finding  # noqa: E402
from zeroverse.ingest import triage  # noqa: E402

MAGIC = b"MIP!"
FIXTURE = ROOT / "tests" / "fixtures" / "mips_parse_o32.elf"


def build_mips(workdir: Path) -> Path | None:
    """Cross-compile the MIPS benchmark with clang (committed fixture is the
    fallback so the proof runs without a toolchain)."""
    src = HERE / "parse_mips.c"
    if not src.exists():
        return FIXTURE if FIXTURE.exists() else None
    out = workdir / "parse_mips"
    p = subprocess.run(
        ["clang", "--target=mips-linux-gnu", "-nostdlib", "-static",
         "-fno-stack-protector", "-O0", "-fuse-ld=lld", str(src), "-o", str(out)],
        capture_output=True,
    )
    if p.returncode != 0:
        print("  build failed, using committed fixture:",
              p.stderr.decode("utf-8", "replace")[:200])
        return FIXTURE if FIXTURE.exists() else None
    return out


def part_a_ingest_abi(binary: Path) -> int:
    print("== Part A: ingest + ABI ==")
    t = triage(binary)
    print(f"  triage: {t.summary()}")
    if not (t.fmt == "ELF" and t.arch == "MIPS" and t.endian == "big"):
        print("  FAIL: expected a big-endian MIPS ELF")
        return 1
    abi = MIPS_O32
    print(f"  ABI: {abi.name}  args={abi.int_arg_regs}  ret={abi.ret_reg}  ra={abi.ra_reg}")
    print("  OK: MIPS ELF classified, o32 ABI resolved")
    return 0


def part_b_qiling(binary: Path) -> int:
    print("\n== Part B: Qiling-emulated reachability/crash ==")
    if not firmware.qiling_available():
        print("  FAIL: qiling not installed (pip install qiling)")
        return 1
    addr = firmware.elf_function_addr(binary, "parse_record")
    if addr is None:
        print("  FAIL: could not resolve parse_record symbol")
        return 1
    print(f"  parse_record @ {hex(addr)}")

    # Direct differential emulation through the reusable engine.
    control = firmware.emulate_call(binary, addr, MAGIC, abi=MIPS_O32)
    trigger = firmware.emulate_call(binary, addr, MAGIC + b"A" * 512, abi=MIPS_O32)
    print(f"  control(len=4):   crashed={control.crashed} reached_end={control.reached_end}")
    print(f"  trigger(len=516): crashed={trigger.crashed}  exc={trigger.exception}")
    if not (control.reached_end and not control.crashed):
        print("  FAIL: control input did not return cleanly to the sentinel")
        return 1
    if not trigger.crashed:
        print("  FAIL: oversized input did not fault under emulation")
        return 1

    f = Finding(source="read", sink="memcpy", function="parse_record",
                source_addr=0, sink_addr=addr, path_len=0)
    pov = firmware.qiling_confirm(f, binary, MIPS_O32, addr, seeds=[MAGIC])
    if pov is None or not pov.reproduced:
        print("  FAIL: qiling_confirm did not emit a reproduced PoV")
        return 1
    print(f"  crash_class: {pov.crash_class}")
    print(f"  differential: {pov.diff_allocator}")
    print(f"  dedup_bucket: {pov.dedup_bucket}")
    print("  OK: MIPS overflow Qiling-emulated, differential-confirmed into a PoV")
    return 0


def part_c_binwalk(binary: Path) -> int:
    print("\n== Part C: binwalk firmware-unpack (documented) ==")
    if not firmware.binwalk_available():
        print("  note: binwalk not installed (apt-get install -y binwalk) — carve "
              "step documented only")
        return 0
    with tempfile.TemporaryDirectory() as td:
        res = firmware.unpack_firmware(binary, td, extract=True)
        print(f"  {res.note}")
        for s in res.signatures[:4]:
            print(f"    sig: {s}")
    print("  note: a real router image's squashfs/cramfs rootfs is carved the same "
          "way (binwalk -e) then each carved ELF feeds the Qiling lane; sourcing a "
          "genuine firmware image is out of scope on the bench — not faked")
    return 0


def part_d_pipeline(binary: Path) -> None:
    print("\n== Part D: full pipeline (Ghidra MIPS slice → firmware Qiling lane) ==")
    if not (os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")):
        print("  skipped — set GHIDRA_INSTALL_DIR to run the Ghidra-backed pipeline")
        return
    from zeroverse.pipeline import run

    result = run(binary)
    print(f"  stages: {result.stages_run}")
    print(f"  note: {result.note}")
    confirmed = [tf for tf in result.findings if tf.pov and tf.pov.reproduced]
    print(f"  Qiling-confirmed MIPS PoVs via full pipeline: {len(confirmed)}")


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        binary = build_mips(Path(td))
        if binary is None:
            print("=== M3 MIPS/QILING PROOF: FAIL (no binary) ===")
            return 1
        rc = part_a_ingest_abi(binary) or part_b_qiling(binary) or part_c_binwalk(binary)
        part_d_pipeline(binary)
    print("\n=== M3 MIPS/QILING PROOF:", "PASS ✅" if rc == 0 else "FAIL ❌", "===")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
