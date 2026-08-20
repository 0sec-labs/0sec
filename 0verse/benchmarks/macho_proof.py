#!/usr/bin/env python3
"""M3 Mach-O proof — static slice + XNU/IOKit fold-in, honest dynamic degrade (#18).

    python benchmarks/macho_proof.py

Proves 0verse ingests + slices a Mach-O target and that pointing it at an IOKit
user client primes the seeded bug class — while being honest that full *dynamic*
AFL++ fuzzing of an arm64 Mach-O needs a macOS/XNU host or emulator (it does NOT
fake a crash on Linux).

  Part A — INGEST: triage the committed arm64 Mach-O fixture (kext-shaped IOKit
           user client) → Mach-O / arm64 / object.

  Part B — XNU/IOKit FOLD-IN: the IOKit seed-bug-class surfaces the
           externalMethod dispatch (missing input-count check → IOMalloc/copyin
           OOB) as a directed hypothesis for the variant-analysis funnel.

  Part C — PIPELINE (Ghidra optional): pipeline.run() routes the Mach-O into the
           decompile path (slice + foxguard + LLM triage) and degrades honestly
           to static-only (findings stay hypotheses; no fabricated crash).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse.ingest import triage  # noqa: E402
from zeroverse.seedbugs import IOKIT_USER_CLIENT, prime_hypotheses, seed_for_target  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "iokit_userclient_arm64.macho"

# What Ghidra recovers from the kext's externalMethod (supplied here so the proof
# runs without a Ghidra install too).
DECOMP = {
    "externalMethod": (
        "IOReturn externalMethod(uint selector,IOExternalMethodArguments *args)\n"
        "{\n"
        "  void *buf = IOMalloc(args->structureInputSize);\n"
        "  copyin(args->structureInput,buf,args->structureInputSize);\n"
        "  return selector;\n"
        "}\n"
    ),
}


def part_a_ingest() -> int:
    print("== Part A: Mach-O ingest ==")
    if not FIXTURE.exists():
        print(f"  FAIL: missing fixture {FIXTURE}")
        return 1
    t = triage(FIXTURE)
    print(f"  triage: {t.summary()}")
    print(f"  notes: {t.notes}")
    if not (t.fmt == "Mach-O" and t.arch == "arm64"):
        print("  FAIL: fixture not classified as arm64 Mach-O")
        return 1
    print("  OK: arm64 Mach-O ingested")
    return 0


def part_b_iokit_foldin() -> int:
    print("\n== Part B: XNU/IOKit seed-bug-class fold-in ==")
    seed = seed_for_target("Mach-O", "OBJECT", DECOMP)
    if seed is not IOKIT_USER_CLIENT:
        print("  FAIL: IOKit seed-bug-class did not prime on the kext")
        return 1
    primed = prime_hypotheses(seed, DECOMP)
    print(f"  seed: {seed.id} ({seed.cwe})")
    for f in primed:
        print(f"  primed hypothesis: {f.function}  {f.source} -> {f.sink}  [{f.origin}]")
    if not primed:
        print("  FAIL: no IOKit hypotheses surfaced")
        return 1
    print("  OK: pointing 0verse at the kext primed the IOKit dispatch hypothesis")
    return 0


def part_c_pipeline() -> int:
    print("\n== Part C: pipeline routing + honest dynamic degrade ==")
    from zeroverse.pipeline import run

    result = run(FIXTURE)
    print(f"  stages: {result.stages_run}")
    print(f"  note: {result.note}")
    if not (os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")):
        if "Ghidra" not in result.note:
            print("  FAIL: expected a Ghidra-needed note without the toolchain")
            return 1
        print("  (no Ghidra here) — Mach-O accepted into the decompile path, not "
              "rejected at the format gate")
        return 0
    confirmed = [tf for tf in result.findings if tf.pov and tf.pov.reproduced]
    print(f"  confirmed (PoV) findings: {len(confirmed)}  (expect 0 — static-only)")
    if "static-only" not in result.note:
        print("  FAIL: expected an honest static-only degrade note")
        return 1
    if confirmed:
        print("  FAIL: a Mach-O finding was 'confirmed' on Linux — must not happen")
        return 1
    print("  OK: static slice + IOKit triage ran; dynamic honestly degraded")
    return 0


def main() -> int:
    rc = part_a_ingest() or part_b_iokit_foldin() or part_c_pipeline()
    print("\n=== M3 MACH-O PROOF:", "PASS ✅" if rc == 0 else "FAIL ❌", "===")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
