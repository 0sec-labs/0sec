#!/usr/bin/env python3
"""M6 #33 — honest, bounded 0verse-lane vs baseline-AFL++ comparison harness.

Representative subset (NOT a multi-day FuzzBench/Magma sweep). For each target it
runs two lanes on the **same** #16-synthesized harness, changing only what 0verse
adds on top of plain AFL++:

  * **0verse lane**   — CMPLOG/redqueen + a dictionary *mined from the decompiled
    slice* (``tokens_from_context``), i.e. exactly what the engine surfaces.
  * **baseline lane** — default AFL++: no CMPLOG, no dictionary.

Both lanes start from the **identical** single ``\\x00`` seed and the identical
synthesized harness — only {dictionary + CMPLOG} varies, so the delta is purely
0verse's slice-derived value-add.

Headline metric: does the lane find + oracle-confirm a crash within the budget,
and the wall-clock to do so (``AFL_BENCH_UNTIL_CRASH`` stops at first crash). The
ablation isolates 0verse's seed/dict/CMPLOG contribution; the shared harness-synth
is held constant on purpose (plain AFL++ cannot fuzz an internal function without
*some* harness — see the caveats in docs/BENCHMARKS.md).

No cherry-picking: results (incl. ties / baseline wins) are emitted verbatim to
NDJSON and tallied by ``zeroverse.benchmark``.

    python benchmarks/fuzzbench/compare.py --budget 60 --out results.ndjson
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse.benchmark import (  # noqa: E402
    BENCHMARK_SCHEMA_VERSION,
    BenchTrial,
    format_table,
    parse_results,
    summarize,
)
from zeroverse.fuzz import fuzz_function  # noqa: E402
from zeroverse.fuzz.aflpp import AflConfig, afl_available, tokens_from_context  # noqa: E402
from zeroverse.fuzz.harness import HarnessSpec, recover_signature  # noqa: E402

TARGETS_DIR = HERE / "targets"

# Each target: (name, function, Ghidra-style decompiled decl for signature recovery).
# All take a (const unsigned char *data, int len) channel — a fuzzable buffer.
TARGETS = [
    ("ungated", "crash_ungated",
     "int crash_ungated(byte *data,int len)\n{\n  char buf[16]; /* ... */\n}\n"),
    ("magic_gated", "parse_gated",
     "int parse_gated(byte *data,int len)\n{\n  /* memcmp REC0 ... */\n}\n"),
    ("nested_gated", "parse_nested",
     "int parse_nested(byte *data,int len)\n{\n  /* FMW1 then u32==0xcafebabe ... */\n}\n"),
]


def _source_text(name: str) -> str:
    return (TARGETS_DIR / f"{name}.c").read_text()


def run_lane(name: str, func: str, decl: str, lane: str, budget: int) -> BenchTrial:
    src = TARGETS_DIR / f"{name}.c"
    sig = recover_signature(func, decl)
    if sig is None:
        return BenchTrial(BENCHMARK_SCHEMA_VERSION, name, lane, False, False, None,
                          budget, 0, 0.0, note="signature recovery failed")

    # Clean ablation: BOTH lanes start from the identical single \x00 seed and the
    # identical #16-synthesized harness. Only what 0verse adds on top of plain
    # AFL++ varies — a dictionary mined from the (decompiled) slice + CMPLOG.
    if lane == "0verse":
        mined = tokens_from_context(_source_text(name))   # what the engine surfaces
        config = AflConfig(duration_s=budget, cmplog=True, use_asan=True,
                           stop_on_crash=True, seeds=[b"\x00"], dict_tokens=mined)
    else:
        config = AflConfig(duration_s=budget, cmplog=False, use_asan=True,
                           stop_on_crash=True, seeds=[b"\x00"], dict_tokens=[])

    spec = HarnessSpec(func=func, signature=sig, decompiled_c=decl, constants=[])
    with tempfile.TemporaryDirectory() as td:
        t0 = time.monotonic()
        outcome = fuzz_function(spec, [src], config=config, workdir=Path(td))
        elapsed = round(time.monotonic() - t0, 2)
    ttc = elapsed if outcome.crash_found else None
    return BenchTrial(
        schema_version=BENCHMARK_SCHEMA_VERSION, target=name, lane=lane,
        crash_found=outcome.crash_found, confirmed_pov=bool(outcome.pov),
        time_to_crash_s=ttc, budget_s=budget, execs=outcome.execs, execs_per_sec=0.0,
        note=outcome.note,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="0verse vs baseline AFL++ comparison")
    ap.add_argument("--budget", type=int, default=60, help="per-lane time budget (s)")
    ap.add_argument("--out", default=str(HERE / "results.ndjson"))
    ap.add_argument("--targets", nargs="*", help="subset of target names")
    args = ap.parse_args(argv)

    if not afl_available():
        print("FAIL: afl-fuzz not on PATH", file=sys.stderr)
        return 2

    chosen = [t for t in TARGETS if not args.targets or t[0] in args.targets]
    out = Path(args.out)
    lines: list[str] = []
    for name, func, decl in chosen:
        for lane in ("0verse", "baseline"):
            print(f"== {name} [{lane}] budget={args.budget}s ==", file=sys.stderr)
            trial = run_lane(name, func, decl, lane, args.budget)
            print(f"   crash={trial.crash_found} ttc={trial.time_to_crash_s} "
                  f"confirmed={trial.confirmed_pov} note={trial.note}", file=sys.stderr)
            lines.append(json.dumps(trial.to_dict()))
    out.write_text("\n".join(lines) + "\n")

    comps = summarize(parse_results("\n".join(lines)))
    print("\n" + format_table(comps))
    print(f"\nresults -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
