#!/usr/bin/env python3
"""M7 #44 milestone proof — the strategy scheduler + per-lane LLM budget gives the
SAME confirmed findings as the sequential pipeline while spending LESS on a
no-signal target, and the content-hash LLM cache dedups identical prompts.

Run inside the engine env (a decompiler backend — rizin/Ghidra — + cc; AFL++
qemu-user for the fuzz complement):

    python benchmarks/m7_scheduler_proof.py

Three honest measurements, all real (no fabricated numbers):

  A. **Same findings (no capability regression).** ``benchmarks/overflow.c`` (a
     slice-confirmable read→strcpy). Sequential vs scheduler (generous budget) must
     produce the IDENTICAL confirmed-PoV set — PoV-is-truth is untouched.

  B. **Less spend on a no-signal target.** ``benchmarks/clean_no_signal.c`` has zero
     static signal. Sequential burns the full no-signal fuzz complement (~30s,
     QEMU-mode); the scheduler under a tight time budget SKIPS that lane. Same
     (empty) finding set, a fraction of the wall-clock. This is the eval's measured
     waste, fixed.

  C. **Content-hash LLM cache dedup.** Re-triaging the same findings through one
     session's cache: the second pass is 100% cache hits — zero backend calls,
     tokens saved — proving identical-prompt dedup.

Exit 0 iff: (A) confirmed sets are identical AND non-empty, (B) the scheduler
skipped the no-signal fuzz lane and ran strictly faster with the same finding
count, and (C) the second triage pass made zero backend calls."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from zeroverse import api  # noqa: E402
from zeroverse.agent import MockLLM, TriageFunnel  # noqa: E402
from zeroverse.analyze import Finding  # noqa: E402
from zeroverse.api import ScanOptions  # noqa: E402
from zeroverse.schedule import SchedulerSession, SessionConfig  # noqa: E402

BACKEND = os.environ.get("ZEROVERSE_BACKEND", "rizin")


def _build(src: Path, workdir: Path) -> Path:
    binp = workdir / src.stem
    subprocess.run(
        ["gcc", "-O0", "-fno-stack-protector", "-no-pie", "-o", str(binp), str(src)],
        check=True, capture_output=True,
    )
    return binp


def _scan(binp: Path, env: dict[str, str]) -> tuple[object, float]:
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        t = time.time()
        r = api.scan(binp, ScanOptions(backend=BACKEND))
        dt = time.time() - t
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return r, dt


def _confirmed(r: object) -> list[tuple[str, str, str]]:
    return sorted((f.function, f.sink, f.capability) for f in r.findings if f.confirmed)  # type: ignore[attr-defined]


def main() -> int:
    ok = True
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        vuln = _build(HERE / "overflow.c", work)
        clean = _build(HERE / "clean_no_signal.c", work)

        print("=" * 78)
        print("A. SAME FINDINGS — sequential vs scheduler (generous budget), vuln target")
        print("=" * 78)
        seq_v, t_seq_v = _scan(vuln, {"ZEROVERSE_SCHEDULER": ""})
        sch_v, t_sch_v = _scan(
            vuln, {"ZEROVERSE_SCHEDULER": "1"}  # generous budget (no time cap)
        )
        cs, cv = _confirmed(seq_v), _confirmed(sch_v)
        print(f"  sequential : confirmed={seq_v.confirmed_count} {cs}  t={t_seq_v:.2f}s")  # type: ignore[attr-defined]
        print(f"  scheduler  : confirmed={sch_v.confirmed_count} {cv}  t={t_sch_v:.2f}s")  # type: ignore[attr-defined]
        print(f"  scheduler stats: {sch_v.scheduler}")  # type: ignore[attr-defined]
        same = cs == cv and len(cs) >= 1
        print(f"  => identical confirmed set & non-empty: {same}")
        ok = ok and same

        print()
        print("=" * 78)
        print("B. LESS SPEND ON NO-SIGNAL — sequential (full fuzz) vs scheduler (tight)")
        print("=" * 78)
        seq_c, t_seq_c = _scan(clean, {"ZEROVERSE_SCHEDULER": ""})
        sch_c, t_sch_c = _scan(
            clean,
            {"ZEROVERSE_SCHEDULER": "1", "ZEROVERSE_SCHED_TIME_BUDGET": "5"},
        )
        print(f"  sequential : confirmed={seq_c.confirmed_count} "  # type: ignore[attr-defined]
              f"findings={len(seq_c.findings)} t={t_seq_c:.2f}s "  # type: ignore[attr-defined]
              f"stages={seq_c.stages_run[-3:]}")  # type: ignore[attr-defined]
        print(f"  scheduler  : confirmed={sch_c.confirmed_count} "  # type: ignore[attr-defined]
              f"findings={len(sch_c.findings)} t={t_sch_c:.2f}s "  # type: ignore[attr-defined]
              f"fuzz_skipped={sch_c.scheduler['fuzz_skipped']}")  # type: ignore[index]
        speedup = t_seq_c / t_sch_c if t_sch_c else 0.0
        same_clean = seq_c.confirmed_count == sch_c.confirmed_count  # type: ignore[attr-defined]
        skipped = bool(sch_c.scheduler["fuzz_skipped"])  # type: ignore[index]
        faster = t_sch_c < t_seq_c
        print(f"  => same findings={same_clean}  fuzz_skipped={skipped}  "
              f"faster={faster}  speedup={speedup:.1f}x  saved={t_seq_c - t_sch_c:.1f}s")
        ok = ok and same_clean and skipped and faster

        print()
        print("=" * 78)
        print("C. CONTENT-HASH LLM CACHE — identical-prompt dedup across a re-triage")
        print("=" * 78)
        sess = SchedulerSession(SessionConfig())

        class _Counter(MockLLM):
            calls = 0

            def complete_json(self, system, prompt, schema):  # type: ignore[no-untyped-def]
                _Counter.calls += 1
                return super().complete_json(system, prompt, schema)

        counter = _Counter()
        llm = sess.wrap_llm(counter)
        findings: list[Finding] = [
            Finding("getenv", "system", "main", 0x10, 0x20, 2, origin="slice"),
            Finding("read", "strcpy", "parse", 0x30, 0x40, 3, origin="slice"),
        ]
        funnel = TriageFunnel(llm)
        funnel.run(findings, lambda f: f"ctx for {f.function}")
        after_first = _Counter.calls
        funnel.run(findings, lambda f: f"ctx for {f.function}")  # identical prompts
        after_second = _Counter.calls
        rep = sess.report()
        print(f"  backend calls after 1st triage pass : {after_first}")
        print(f"  backend calls after 2nd (identical) : {after_second}  (delta="
              f"{after_second - after_first})")
        print(f"  cache: hits={rep['cache']['hits']} misses={rep['cache']['misses']} "
              f"hit_rate={rep['cache']['hit_rate']} saved_tokens={rep['cache']['saved_tokens']}")
        print(f"  per-lane budget (triage): {rep['budget']['lanes'].get('triage')}")
        dedup = after_second == after_first and rep["cache"]["hits"] >= 1
        print(f"  => 2nd pass made ZERO backend calls (full dedup): {dedup}")
        ok = ok and dedup

    print()
    print("=" * 78)
    print(f"RESULT: {'PASS' if ok else 'FAIL'} — same findings, less no-signal spend, "
          "cache dedup")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
