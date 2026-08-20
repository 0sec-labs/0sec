"""Directed trigger construction — the coverage-guided confirm channel.

``confirm_by_synthesis`` (one-shot generate-and-test) hits a wall on gated input
formats: the LLM cannot hand-write a byte string that passes a magic/length/checksum
+ tag-table gate AND reaches the sink. On lcms 64166 it produced 8x NO_CRASH. This
module is the second confirm channel for exactly that case.

THE INSIGHT (validated). The binarygym / OSS-Fuzz ``vuln`` binaries are libFuzzer
harnesses built with SanitizerCoverage + ASan (:func:`oracle.is_asan_file_target`),
so a coverage signal toward the sink is *already compiled in*. Directed trigger
construction reduces to: run the harness in coverage-guided mode from a LEGITIMATE
non-poc seed corpus, let coverage feedback climb the format gates, and hand every
crash artifact to the SAME deterministic oracle that adjudicates everything else.

PoV-IS-TRUTH. The fuzzer only *proposes* inputs; a finding is confirmed ONLY when
the deterministic oracle reproduces a crash — the vuln binary crashes under ASan and
(when a fixed build is supplied) the fixed binary runs the same input CLEAN. The
reported ``crash_function`` is where the input ACTUALLY crashes, which may differ from
the LLM's hypothesized sink — we surface that honestly as ``matches_hypothesis``
rather than forcing the crash to fit the hypothesis. Directed fuzzing thus confirms a
REAL bug in the target even when the LLM mislocalized to a sibling function.

HONEST LIMITS. (1) The exact fault is STOCHASTIC within a bounded budget — the
coverage ladder (baseline vs directed edges) is the reproducible signal, the crash is
variance; we mitigate with parallel jobs (first confirmed wins) + value-profile. (2)
It needs a libFuzzer harness (``applicable=False`` otherwise — a non-harness binary
would need an external instrumented build). (3) It needs a format-relevant non-poc
seed corpus; a bare/empty corpus rarely clears a deep gate in a short budget.
"""

from __future__ import annotations

import glob
import os

# The libFuzzer coverage line, e.g. ``#1234 NEW cov: 1450 ft: 3201 ...``. We take the
# peak ``cov`` value across a run's stderr as the edge-coverage the run reached.
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import oracle
from .adjudicate import (
    _norm_func,  # honest reuse: same normalization the oracle uses
    func_matches,
    parse_asan_crash,
)
from .sandbox_exec import LocalExecutor, current_executor

_COV_RE = re.compile(rb"cov:\s*(\d+)\s+ft:\s*(\d+)")

# ASan/LSan noise these fuzzer builds carry on the patched path — irrelevant to the
# spatial-safety differential, and LSan leaks would otherwise mask the real signal.
_FUZZ_ASAN_ENV = {"ASAN_OPTIONS": "detect_leaks=0", "UBSAN_OPTIONS": "halt_on_error=0"}


@dataclass
class DirectedFuzzResult:
    """Outcome of a directed trigger-construction attempt.

    ``confirmed`` is the only authority claim — the oracle reproduced a crash (vuln
    crashes under ASan, fixed clean when supplied). ``crash_function``/``crash_cwe``
    are where the input ACTUALLY crashed (PoV-is-truth), and ``matches_hypothesis``
    says whether that matches the LLM's sink. ``applicable`` is False when the target
    is not a libFuzzer harness. The coverage ladder (``baseline_cov`` vs
    ``directed_cov``) is the reproducible progress signal even when no crash landed."""

    confirmed: bool = False
    applicable: bool = True
    crash_function: str = ""
    crash_cwe: str = ""
    matches_hypothesis: bool = False
    winning_input: bytes | None = None
    winning_path: str = ""
    baseline_cov: int = 0
    directed_cov: int = 0
    reached_hypothesis_sink: bool = False
    jobs: int = 0
    budget_s: float = 0.0
    seed_count: int = 0        # generic-corpus seeds
    synth_seed_count: int = 0  # LLM-synthesized format-valid seeds added
    seed_source: str = ""
    reason: str = ""
    notes: list[str] = field(default_factory=list)


def _peak_cov(stderr: bytes) -> int:
    peak = 0
    for m in _COV_RE.finditer(stderr):
        peak = max(peak, int(m.group(1)))
    return peak


def _collect_seeds(seed_globs: list[str], dest: Path, *, exclude: set[bytes]) -> tuple[int, str]:
    """Copy corpus seeds into ``dest``, skipping any whose bytes are in ``exclude``
    (the caller passes the poc bytes here — seeding with the poc would be cheating
    for a recall measurement). The module never reads the poc itself."""
    dest.mkdir(parents=True, exist_ok=True)
    n, srcs = 0, set()
    for pat in seed_globs:
        # Campaign configs intentionally supply absolute recursive patterns.
        for p in glob.glob(pat, recursive=True):  # noqa: PTH207
            try:
                b = Path(p).read_bytes()
            except OSError:
                continue
            if b in exclude:
                continue
            (dest / f"seed_{n:04d}").write_bytes(b)
            srcs.add(str(Path(p).parent))
            n += 1
    return n, ", ".join(sorted(srcs)) or "(none)"


def _synthesize_seeds(
    meta: Any, verdict: Any, llm: Any, n: int, dest: Path, *, exclude: set[bytes]
) -> tuple[int, str]:
    """Generate up to ``n`` LLM-synthesized format-valid seeds into ``dest``. Returns
    ``(count, note)`` — ``note`` records WHY a run got few/zero seeds (an LLM error vs
    genuinely-empty synthesis) so a 0 is never silently ambiguous.

    This is the LLM-seeding lever: :func:`synthesize.synthesize_povs` reverse-engineers
    the input format and constructs candidate inputs of the RIGHT sub-type (a CFF2
    font, a Fuji RAF, an ICC with the suspected field cranked). Those candidates often
    fail as DIRECT triggers (they clear the outer gate but miss the exact fault) — but
    that makes them ideal SEEDS: directed fuzzing mutates around them to find the fault,
    solving the corpus/format-mismatch that sinks a generic corpus (TrueType != CFF2).
    Honest: these come from the LLM's own reverse-engineering, never the poc."""
    from .synthesize import synthesize_povs

    try:
        cands = synthesize_povs(meta, verdict, llm, n=n, structural=True)
    except Exception as e:  # surfaced, not swallowed — an LLM/synth error must be visible
        return 0, f"synthesis ERROR: {type(e).__name__}: {e}"[:200]
    dest.mkdir(parents=True, exist_ok=True)
    added, skipped = 0, 0
    for c in cands:
        if not c or c in exclude:
            skipped += 1
            continue
        (dest / f"synth_{added:04d}").write_bytes(c)
        added += 1
    if added == 0:
        return 0, f"synthesis produced 0 usable seeds ({len(cands)} candidates, {skipped} skipped)"
    return added, f"synthesized {added} format-valid seeds"


def _fuzz_argv(
    vuln: str,
    corp: Path,
    art: Path,
    budget_s: float,
    *,
    value_profile: bool,
    focus_function: str | None,
    max_len: int,
) -> list[str]:
    argv = [
        vuln,
        f"-max_total_time={int(budget_s)}",
        f"-max_len={max_len}",
        "-print_final_stats=1",
        f"-artifact_prefix={art}/",
    ]
    if value_profile:
        argv.append("-use_value_profile=1")
    if focus_function:
        argv.append(f"-focus_function={focus_function}")
    argv.append(str(corp))
    return argv


def _run_jobs(
    vuln: str,
    corp: Path,
    art: Path,
    budget_s: float,
    *,
    jobs: int,
    value_profile: bool,
    focus_function: str | None,
    max_len: int,
) -> int:
    """Launch ``jobs`` parallel libFuzzer processes over the same seed corpus, each an
    independent PRNG trajectory writing crashes to the shared ``art`` dir. Each stops
    on its first crash (libFuzzer default) or at the budget. Returns peak edge cov
    seen across all jobs. First-crash-wins is realized downstream: the caller
    adjudicates whatever landed in ``art``."""
    art.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, **_FUZZ_ASAN_ENV}
    procs: list[subprocess.Popen[bytes]] = []
    for _ in range(max(1, jobs)):
        argv = _fuzz_argv(
            vuln,
            corp,
            art,
            budget_s,
            value_profile=value_profile,
            focus_function=focus_function,
            max_len=max_len,
        )
        # ``argv`` is an argument vector produced internally by ``_fuzz_argv``;
        # no shell parses target paths or fuzzer options.
        procs.append(
            subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
            )
        )
    peak = 0
    deadline = time.monotonic() + budget_s + 120
    for p in procs:
        remaining = max(1.0, deadline - time.monotonic())
        try:
            _out, err = p.communicate(timeout=remaining)
            peak = max(peak, _peak_cov(err or b""))
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                _out, err = p.communicate(timeout=10)
                peak = max(peak, _peak_cov(err or b""))
            except Exception:
                pass
    return peak


def _adjudicate_artifact(
    artifact: bytes,
    verdict: Any,
    vuln: str,
    fixed: str | None,
    timeout: float,
) -> tuple[bool, str, str, bool, str]:
    """Differential oracle on one crash artifact. Returns
    ``(confirmed, crash_function, crash_cwe, matches_hypothesis, detail)``.

    confirmed := vuln crashes under ASan AND (no fixed OR fixed runs it clean).
    The crash function/CWE come from the ACTUAL ASan report (PoV-is-truth)."""
    run = oracle.run_sanitizer(vuln, artifact, vector="file", env=_FUZZ_ASAN_ENV, timeout=timeout)
    if not run.valid:
        return False, "", "", False, "vuln execution produced no valid verdict"
    if not run.crashed:
        return False, "", "", False, "vuln did not crash on artifact"
    # parse_asan_crash returns an Adjudication with crash_function + crash_cwe already
    # derived from the ASan report kind + READ/WRITE access.
    info = parse_asan_crash(run.stderr, kind_hint=run.sanitizer or "")
    crash_fn = info.crash_function or ""
    crash_cwe = info.cwe or ""
    # Differential: a real fix must make the SAME input safe.
    if fixed:
        fx = oracle.run_sanitizer(
            fixed, artifact, vector="file", env=_FUZZ_ASAN_ENV, timeout=timeout
        )
        if not fx.valid or fx.crashed:
            return (
                False,
                crash_fn,
                crash_cwe,
                False,
                f"crash at {crash_fn} but FIXED build also crashed — not a differential",
            )
    sink = getattr(verdict, "sink", "") or ""
    source = getattr(verdict, "source", "") or ""
    matches = func_matches(crash_fn, sink) or func_matches(crash_fn, source)
    kind = crash_cwe or run.sanitizer or "crash"
    detail = (
        f"CONFIRMED differential: vuln crashes at {crash_fn} ({kind}), fixed clean"
        if fixed
        else f"vuln crashes at {crash_fn} ({kind}) under ASan"
    )
    return True, crash_fn, crash_cwe, matches, detail


def confirm_by_directed_fuzz(
    verdict: Any,
    vuln_binary: str | Path,
    *,
    seed_globs: list[str],
    fixed_binary: str | Path | None = None,
    budget_s: float = 180.0,
    jobs: int = 2,
    value_profile: bool = True,
    focus_function: str | None = None,
    exclude_inputs: list[bytes] | tuple[bytes, ...] = (),
    max_len: int = 65536,
    timeout: float = 20.0,
    run_baseline: bool = False,
    synth_seeds: int = 0,
    meta: Any = None,
    llm: Any = None,
) -> DirectedFuzzResult:
    """Confirm a finding by directed coverage-guided fuzzing of a libFuzzer harness.

    Runs ``jobs`` parallel harness instances from a non-poc seed corpus for
    ``budget_s`` seconds; adjudicates each crash artifact with the differential ASan
    oracle. Returns a :class:`DirectedFuzzResult` — ``confirmed`` iff the oracle
    reproduced a crash (fixed clean when ``fixed_binary`` is given).

    ``seed_globs`` is the caller-supplied generic corpus; ``exclude_inputs`` (e.g. the
    poc bytes) are skipped so a recall measurement stays honest. When ``synth_seeds`` >
    0 and ``meta``/``llm`` are given, that many LLM-synthesized format-valid seeds are
    added to the corpus (:func:`_synthesize_seeds`) — the lever that beats a
    format-mismatched generic corpus (TrueType seeds can't reach a CFF2 bug; an
    LLM-built CFF2 seed can). ``focus_function`` defaults OFF: the LLM's hypothesized
    sink is often a wrong sibling (validated on lcms — it named ReadCLUT while the bug
    is WriteCLUT), so focusing on it would aim the fuzzer AWAY from the real fault.
    ``value_profile`` defaults ON to turn memcmp/CMP gate comparisons into coverage."""
    vuln = str(vuln_binary)
    fixed = str(fixed_binary) if fixed_binary else None
    res = DirectedFuzzResult(jobs=jobs, budget_s=budget_s)

    if not isinstance(current_executor(), LocalExecutor):
        res.applicable = False
        res.reason = (
            "directed fuzzing needs an explicitly authorized native high-throughput "
            "runner; the selected confirmation executor cannot launch local fuzz jobs"
        )
        return res

    if not oracle.is_asan_file_target(vuln):
        res.applicable = False
        res.reason = (
            "target is not an ASan libFuzzer harness — the free-coverage path does "
            "not apply (would need an external instrumented build; see "
            "DIRECTED_TRIGGER.md)."
        )
        return res

    work = Path(tempfile.mkdtemp(prefix="dfuzz_"))
    try:
        corp, art = work / "corp", work / "art"
        exclude = set(exclude_inputs)
        n, src = _collect_seeds(seed_globs, corp, exclude=exclude)
        res.seed_count, res.seed_source = n, src
        # LLM-seeding lever: add format-valid synthesized seeds of the right sub-type.
        if synth_seeds > 0 and meta is not None and llm is not None:
            res.synth_seed_count, synth_note = _synthesize_seeds(
                meta, verdict, llm, synth_seeds, corp, exclude=exclude
            )
            res.notes.append(synth_note)
        total_seeds = res.seed_count + res.synth_seed_count
        if total_seeds == 0:
            res.reason = (
                "no usable non-poc seeds (generic corpus empty and synthesis produced "
                "no seeds)."
            )
            return res

        if run_baseline:
            base_corp = work / "base_corp"
            base_corp.mkdir(parents=True, exist_ok=True)
            (base_corp / "junk").write_bytes(b"\x00" * 16)
            res.baseline_cov = _run_jobs(
                vuln,
                base_corp,
                work / "base_art",
                min(budget_s, 40),
                jobs=1,
                value_profile=False,
                focus_function=None,
                max_len=max_len,
            )

        res.directed_cov = _run_jobs(
            vuln,
            corp,
            art,
            budget_s,
            jobs=jobs,
            value_profile=value_profile,
            focus_function=focus_function,
            max_len=max_len,
        )

        sink = getattr(verdict, "sink", "") or ""
        for cp in sorted(art.glob("crash-*")) + sorted(art.glob("oom-*")):
            cb = cp.read_bytes()
            confirmed, crash_fn, crash_cwe, matches, detail = _adjudicate_artifact(
                cb, verdict, vuln, fixed, timeout
            )
            if crash_fn and _norm_func(sink).find(_norm_func(crash_fn)) >= 0:
                res.reached_hypothesis_sink = True
            if confirmed:
                res.confirmed = True
                res.crash_function = crash_fn
                res.crash_cwe = crash_cwe
                res.matches_hypothesis = matches
                res.winning_input = cb
                keep = work.parent / f"dfuzz_win_{cp.name}"
                try:
                    keep.write_bytes(cb)
                    res.winning_path = str(keep)
                except OSError:
                    res.winning_path = str(cp)
                res.reason = detail
                return res
            res.notes.append(f"{cp.name}: {detail}")

        res.reason = (
            f"no confirmed crash within budget "
            f"({res.seed_count} generic + {res.synth_seed_count} synth seeds, "
            f"directed cov {res.directed_cov} edges vs baseline {res.baseline_cov}); "
            f"the coverage ladder is the reproducible signal, the fault is stochastic."
        )
        return res
    finally:
        shutil.rmtree(work, ignore_errors=True)
