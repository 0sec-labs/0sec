"""Fuzzing stage orchestration — ties #16 (harness synthesis) → #15 (AFL++ driver)
→ #17 (Driller assist) → #6 oracle → #7 PoV into one callable.

Two entry points:

  * ``fuzz_function`` — the full source-available loop (the OSS-Fuzz-Gen setting,
    used by the M2 benchmark): synthesize + build a harness for one recovered
    function, fuzz it with AFL++/CMPLOG, optionally Driller-assist on a stall,
    and confirm each crash through the M1 oracle into a PoV. This is the path that
    finds bugs a static slice misses.

  * ``run_fuzz_stage`` — the in-pipeline complement: when the #2 slice yields no
    confirmed PoV, synthesize harnesses for the recovered functions and (when
    ``afl-qemu-trace`` is present) QEMU-mode fuzz the stripped binary directly,
    confirming crashes through the same oracle. Honest no-PoV-no-finding: a
    synthesized-but-unfuzzed harness is an artifact + note, never a finding.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..agent import LLM, Verdict
from ..agentic import _signature_params
from ..analyze import Finding
from ..backends._noise import attack_surface_priority, is_noise_name
from ..concolic import AngrConfig, function_entry
from ..il import Inst
from ..ingest import triage
from ..localize import find_entry, parse_signal, propagate_taint
from ..oracle import (
    CrashFeedbackReceipt,
    CrashSet,
    casr_available,
    classify_crash,
    crash_feedback_receipt,
    dedup_key,
    minimize_file_input,
    run_casr_gdb,
    run_sanitizer,
)
from ..poc import write_pov_script
from ..preflight import BudgetTracker
from ..report import PoV
from ..sandbox_exec import Executor
from .aflpp import (
    AflBackend,
    AflConfig,
    SubprocessAfl,
    afl_qemu_available,
    build_fuzz_binaries,
    format_field_tokens,
    has_afl_instrumentation,
    initial_seeds,
    is_instrumented_fuzz_target,
    tokens_from_context,
)
from .confirm import confirm_crash
from .coverage import AddressIndex, CoverageProbe
from .directed import (
    DirectedScheduler,
    DirectedTargets,
    SchedulerConfig,
    collect_targets,
    inst_ranges_for_slice,
)
from .driller import (
    AngrCfgDistance,
    AngrConcolicSolver,
    DistanceDriller,
    DistanceModel,
    DrillerConfig,
    DrillerHybrid,
    NullDistance,
    Solver,
)
from .harness import (
    GccCompiler,
    HarnessSpec,
    HarnessSynthesizer,
    TargetSignature,
    build_harness,
    exported_symbol,
    recover_signature,
)
from .lastmile import (
    LastMileContext,
    last_mile_candidates,
    last_mile_enabled,
    normalized_last_mile_candidates,
    probe_reaching_inputs,
)


@dataclass
class FuzzFinding:
    """A fuzz-confirmed finding, mapped to a pipeline ``TriagedFinding`` by the
    caller. ``pov`` is always reproduced (the gate)."""

    finding: Finding
    verdict: Verdict
    pov: PoV
    feedback_receipt: CrashFeedbackReceipt | None = None


@dataclass
class FuzzOutcome:
    func: str
    harness_built: bool
    crash_found: bool
    pov: PoV | None = None
    harness_path: str = ""
    note: str = ""
    execs: int = 0
    fuzz_findings: list[FuzzFinding] = field(default_factory=list)


_IDENT_RE: re.Pattern[str] = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CALLSITE_RE: re.Pattern[str] = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def _callgraph_from_bodies(decompiled_c: dict[str, str]) -> dict[str, list[str]]:
    """Recover a direct-call graph from the decompiled bodies themselves: an edge
    ``caller -> callee`` for every call-site identifier that names another recovered
    function. Self-calls are dropped. Namespaced C++ callees whose decompiler keeps
    the ``::`` qualification are missed (the regex captures only the last token) —
    a conservative under-approximation, which is exactly what the taint ranking
    tolerates (a missing edge demotes, never excludes)."""
    known = set(decompiled_c)
    return {
        func: sorted(
            {m.group(1) for m in _CALLSITE_RE.finditer(src)} & (known - {func})
        )
        for func, src in decompiled_c.items()
    }


def fuzzable_specs(
    decompiled_c: dict[str, str],
    *,
    limit: int = 12,
    skip: frozenset[str] = frozenset({"main", "_start", "frame_dummy"}),
    priority: Sequence[str] = (),
    callgraph: dict[str, list[str]] | None = None,
) -> list[HarnessSpec]:
    """Build harness specs for the recovered functions worth fuzzing — those with a
    recovered signature that takes a buffer (a fuzzable input channel) — RANKED so
    the real parser/attack-surface sinks are harnessed first instead of whichever
    functions the decompiler happened to emit earliest. Ranking key (best first):

      1. functions the slice / LLM triage already flagged as sinks (``priority``);
      2. attacker-reachability: when an input entry (``main`` /
         ``LLVMFuzzerTestOneInput``) exists, functions the entry's taint actually
         FLOWS to outrank functions no input path reaches (e.g. ``ErrFatal``);
      3. the taint-free parse signal of the body (``parse_signal``) — byte
         assembly, param indexing, param-bounded loops, param-to-sink feeds;
      4. attacker-input boundary names (parse/decode/... — ``attack_surface_priority``),
         a name-only guess, now strictly a tiebreak below the body evidence;
      5. larger bodies (more likely to inline a parser).

    libc / ASan / compiler-runtime shims (``is_noise_name``) are dropped up front so
    the fuzzer never spends its budget on ErrFatal / __asan_* utility functions —
    the exact mistargets that left the fuzz path fuzzing junk.

    ``callgraph`` is the backend-recovered edge set when the caller has one; when
    omitted, a conservative graph is derived from the decompiled bodies
    (``_callgraph_from_bodies``). The name-token heuristic alone picked jhead's
    utility functions (``ParseCmdDate`` — a "parse" *name*) over the real EXIF
    parser; the reachability + parse-evidence tiers exist to fix that."""
    priority_rank: dict[str, int] = {}
    for func in priority:
        priority_rank.setdefault(func, len(priority_rank))
    cg = callgraph if callgraph is not None else _callgraph_from_bodies(decompiled_c)
    params_of = {fn: _signature_params(src) for fn, src in decompiled_c.items()}
    entry = find_entry(decompiled_c, cg)
    taint = propagate_taint(decompiled_c, cg, entry, params_of)
    ranked: list[
        tuple[tuple[int, int, float, int, int], str, str, TargetSignature]
    ] = []
    for func, src in decompiled_c.items():
        if func in skip or is_noise_name(func):
            continue
        sig = recover_signature(func, src)
        if sig is None or not sig.is_fuzzable:
            continue
        params = params_of.get(func, frozenset())
        # An untainted function under a KNOWN input entry sits below every tainted
        # one; with no entry the graph can't speak, so nothing is demoted.
        unreachable = 1 if entry is not None and taint.get(func, 0.0) <= 0.0 else 0
        key = (
            priority_rank.get(func, len(priority_rank)),
            unreachable,
            -parse_signal(src, params),
            attack_surface_priority(func),
            -len(src),
        )
        ranked.append((key, func, src, sig))
    ranked.sort(key=lambda c: (c[0], c[1]))
    return [
        HarnessSpec(func=func, signature=sig, decompiled_c=src,
                    constants=tokens_from_context(src))
        for _key, func, src, sig in ranked[:limit]
    ]


def _native_last_mile_specs(
    decompiled_c: dict[str, str],
    priority: Sequence[str],
    fallback: Sequence[HarnessSpec],
    *,
    limit: int = 12,
    skip: frozenset[str] = frozenset({"main", "_start", "frame_dummy"}),
) -> list[HarnessSpec]:
    """Select whole-program GDB targets without applying harness constraints.

    A native file-input target already owns the driver and parser state. GDB can
    therefore probe a recovered function even when its signature contains opaque
    library structs that a standalone raw-buffer harness cannot construct.
    """
    out: list[HarnessSpec] = []
    seen: set[str] = set()
    for func in priority:
        src = decompiled_c.get(func)
        if not src or func in seen or func in skip or is_noise_name(func):
            continue
        seen.add(func)
        out.append(
            HarnessSpec(
                func=func,
                signature=recover_signature(func, src),
                decompiled_c=src,
                constants=tokens_from_context(src),
            )
        )
        if len(out) >= limit:
            return out
    for spec in fallback:
        if spec.func in seen:
            continue
        seen.add(spec.func)
        out.append(spec)
        if len(out) >= limit:
            break
    return out


def _verdict_for(pov: PoV, func: str) -> Verdict:
    sev = "high"
    if pov.casr_severity == "EXPLOITABLE":
        sev = "critical"
    elif pov.casr_severity in ("NOT_EXPLOITABLE", ""):
        sev = "high"
    return Verdict(
        is_real=True,
        bug_class=pov.casr_desc or "memory-safety (fuzz-confirmed)",
        severity=sev,
        explanation=f"fuzz-discovered crash in {func}, oracle-confirmed",
        input_example="",
    )


def _finding_for(func: str, vector: str) -> Finding:
    return Finding(
        source=f"fuzz:{vector}", sink=func, function=func,
        source_addr=0, sink_addr=0, path_len=0, origin="fuzz",
    )


# The crash-DELIVERY chain is not the bug site. A fatal-canary target (Magma) fires
# the bug by calling its reporter (``magma_log``), which ``abort()``s down the libc
# ``raise``/``kill`` path — so the top backtrace frames name the delivery mechanism,
# and the REAL sink sits just below them. Skip these frames so a PNG003 crash is
# credited to ``png_handle_PLTE``, not to ``magma_log`` or the ``signal`` stub the
# abort frame's ``at ./signal/...`` path token collides with.
_CRASH_DELIVERY_FRAMES: frozenset[str] = frozenset({
    "magma_log", "magma_alert", "magma_canary", "abort", "raise", "gsignal",
    "signal", "kill", "__GI_kill", "__GI_raise", "__GI_abort", "__assert_fail",
    "__stack_chk_fail", "__libc_message", "__pthread_kill", "__chk_fail",
})


def _crash_function(pov: PoV, known: frozenset[str], fallback: str) -> str:
    """Attribute a whole-program / directed fuzz crash to the REAL target function
    named in its own symbolicated backtrace, instead of a synthetic placeholder.

    The confirmed PoV carries ``frames`` (a CASR/gdb backtrace); targets built with
    symbols (e.g. Magma at -O0) name the crashing function in that trace. Walk the
    frames top-down and return the first frame whose function is a recovered target
    function (``known``) and not a libc/ASan/runtime shim or a crash-delivery/canary
    frame. This is honest attribution — the same crash, correctly labelled — so a
    real crash in ``png_check_chunk_length`` is credited to that site instead of
    scoring as an unmatched confirmation. Falls back to ``fallback`` when the trace
    has no recognizable target frame (e.g. a stripped binary)."""
    if not known:
        return fallback
    for frame in pov.frames:
        # A gdb/CASR frame is "#N 0x.. in FUNC (args) at PATH:line". The PATH can
        # carry tokens that collide with a recovered symbol — the abort frame's
        # ``at ./signal/../sysdeps/...`` yields ``signal``, which is a real (weak)
        # stub in the decompiled set. Tokenize only the function field (before
        # " at "), where FUNC leads, so a path component never wins.
        head = frame.split(" at ", 1)[0]
        for tok in _IDENT_RE.findall(head):
            if tok in _CRASH_DELIVERY_FRAMES or is_noise_name(tok):
                break  # crash-delivery/canary frame — its sink is deeper, skip it
            if tok in known:
                return str(tok)
    return fallback


def _fuzz_duration(default: int) -> int:
    """Per-window fuzz budget in seconds. ``ZEROVERSE_FUZZ_DURATION`` overrides the
    default (the magma capability lane needs ~300s to reach a parser sink; the
    30s CI default is too short). Non-positive / non-numeric values are ignored."""
    v = os.environ.get("ZEROVERSE_FUZZ_DURATION", "").strip()
    return int(v) if v.isdigit() and int(v) > 0 else default


_ASAN_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S")


def _asan_backtrace_frames(stderr: str) -> list[str]:
    """The symbolicated backtrace lines from a sanitizer report (``#N 0x.. in fn``)."""
    return [ln.strip() for ln in stderr.splitlines() if _ASAN_FRAME_RE.search(ln)]


def _confirm_instrumented_file_crash(
    binary: str,
    crash: bytes,
    known: frozenset[str],
    *,
    timeout: float | None = None,
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
) -> tuple[PoV, str, CrashFeedbackReceipt] | None:
    """Confirm a fuzzer crash on an instrumented, file-input target and attribute
    it to the real crashing function. The differential ``confirm_crash`` needs a
    non-AFL/non-ASan replay build these magma/ARVO targets are not; the
    instrumented build IS the oracle. When ``casr-gdb`` is available it re-runs the
    crash (delivered as argv[1] file) under gdb and yields a symbolicated backtrace
    (magma is -O0 with symbols) — that gives both the confirmation and the frame to
    attribute. Otherwise fall back to the sanitizer-report oracle
    (``run_sanitizer`` vector=file), whose ASan/UBSan text still confirms and, when
    present, names the frame. Returns the reproduced PoV + attributed function, or
    ``None`` when it does not reproduce."""
    original_crash = crash

    def additional_replay_timeout(default: float) -> float | None:
        if budget is None:
            return default if timeout is None else timeout
        reserved, _reason = budget.reserve_attempt(fuzz=True)
        if not reserved:
            return None
        remaining = budget.remaining_seconds()
        if remaining <= 0:
            budget.reservation_failures += 1
            return None
        return min(default, remaining)

    def minimization_run_cap() -> int:
        if budget is None:
            return 24
        # Minimization is a nicety; the final confirmation is not. Cap it by what
        # is left in the protected fuzz pool and always keep one replay back.
        return min(24, max(0, budget.fuzz_attempts_remaining - 1))

    if casr_available():
        with tempfile.NamedTemporaryFile(prefix="zv_crash_", delete=False) as tf:
            tf.write(crash)
            poc_path = tf.name
        try:
            casr = run_casr_gdb(
                binary,
                argv=[poc_path],
                timeout=60.0 if timeout is None else timeout,
                executor=executor,
            )
        finally:
            with contextlib.suppress(OSError):
                Path(poc_path).unlink()
        if casr is not None:
            # Preserve the same CASR crash class while reducing only contiguous
            # byte ranges. The cap bounds extra target executions per finding.
            expected_kind = casr.short_desc or casr.signal or "crash"

            def casr_confirms(candidate: bytes) -> bool:
                replay_timeout = additional_replay_timeout(60.0)
                if replay_timeout is None:
                    return False
                with tempfile.NamedTemporaryFile(prefix="zv_min_", delete=False) as tf:
                    tf.write(candidate)
                    candidate_path = tf.name
                try:
                    result = run_casr_gdb(
                        binary,
                        argv=[candidate_path],
                        timeout=replay_timeout,
                        executor=executor,
                    )
                finally:
                    with contextlib.suppress(OSError):
                        Path(candidate_path).unlink()
                return (
                    result is not None
                    and (result.short_desc or result.signal or "crash") == expected_kind
                )

            minimized = minimize_file_input(
                crash, casr_confirms, max_runs=minimization_run_cap()
            )
            crash = minimized.candidate
            # Re-read metadata from the accepted minimized input, never from a
            # rejected trial. A flaky final re-run fails closed.
            replay_timeout = additional_replay_timeout(60.0)
            if replay_timeout is None:
                return None
            with tempfile.NamedTemporaryFile(prefix="zv_crash_", delete=False) as tf:
                tf.write(crash)
                poc_path = tf.name
            try:
                casr = run_casr_gdb(
                    binary,
                    argv=[poc_path],
                    timeout=replay_timeout,
                    executor=executor,
                )
            finally:
                with contextlib.suppress(OSError):
                    Path(poc_path).unlink()
            if casr is None or (casr.short_desc or casr.signal or "crash") != expected_kind:
                return None
            kind = casr.short_desc or casr.signal or "crash"
            pov = PoV(
                input_bytes=crash,
                file_input=True,
                crash_class=kind,
                crash_trace=(casr.description or "")[-400:],
                frames=list(casr.frames),
                reproduced=True,
                capability="crash",
            )
            pov.casr_severity = casr.severity
            pov.casr_desc = f"{casr.short_desc}: {casr.description}".strip(": ")
            func = _crash_function(pov, known, "<whole-program>")
            pov.dedup_bucket = dedup_key(casr.severity, list(casr.frames) or [func])
            receipt = crash_feedback_receipt(
                target=binary, original_input=original_crash, minimized_input=crash,
                oracle="casr-gdb", crash_class=kind, signal=casr.signal,
                dedup_bucket=pov.dedup_bucket, oracle_runs=minimized.oracle_runs,
                max_runs=minimized.max_runs,
            )
            return pov, func, receipt
        return None

    # No casr-gdb: sanitizer-report oracle (ASan/UBSan text) confirms + names frames.
    r = run_sanitizer(
        binary,
        crash,
        vector="file",
        timeout=10.0 if timeout is None else timeout,
        executor=executor,
    )
    if not (r.valid and r.crashed and (r.sanitizer or r.signal)):
        return None
    expected_kind = r.sanitizer or r.signal

    def sanitizer_confirms(candidate: bytes) -> bool:
        replay_timeout = additional_replay_timeout(10.0)
        if replay_timeout is None:
            return False
        result = run_sanitizer(
            binary,
            candidate,
            vector="file",
            timeout=replay_timeout,
            executor=executor,
        )
        return (
            result.valid and result.crashed
            and (result.sanitizer or result.signal) == expected_kind
        )

    minimized = minimize_file_input(
        crash, sanitizer_confirms, max_runs=minimization_run_cap()
    )
    crash = minimized.candidate
    replay_timeout = additional_replay_timeout(10.0)
    if replay_timeout is None:
        return None
    r = run_sanitizer(
        binary,
        crash,
        vector="file",
        timeout=replay_timeout,
        executor=executor,
    )
    if not (r.valid and r.crashed and (r.sanitizer or r.signal) == expected_kind):
        return None
    frames = _asan_backtrace_frames(r.stderr)
    kind = r.sanitizer or r.signal or "sanitizer-error"
    cap = classify_crash(r.stderr)
    pov = PoV(
        input_bytes=crash,
        file_input=True,
        crash_class=kind,
        crash_trace=r.stderr[-400:],
        frames=frames,
        reproduced=True,
        capability=cap if cap != "unknown" else "crash",
        execution_provenance=dict(getattr(r, "provenance", {}) or {}),
    )
    func = _crash_function(pov, known, "<whole-program>")
    pov.dedup_bucket = dedup_key(kind, frames or [func])
    receipt = crash_feedback_receipt(
        target=binary, original_input=original_crash, minimized_input=crash,
        oracle="sanitizer-report", crash_class=kind, sanitizer=r.sanitizer,
        signal=r.signal, dedup_bucket=pov.dedup_bucket, provenance=r.provenance,
        oracle_runs=minimized.oracle_runs, max_runs=minimized.max_runs,
    )
    return pov, func, receipt


def fuzz_function(
    spec: HarnessSpec,
    target_sources: list[Path],
    *,
    llm: LLM | None = None,
    backend: AflBackend | None = None,
    config: AflConfig | None = None,
    workdir: Path,
    driller: DrillerHybrid | None = None,
    driller_addrs: tuple[int, int] | None = None,
    max_repair: int = 3,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    native_compiler_path: str | None = None,
    capabilities_resolved: bool = False,
    executor: Executor | None = None,
) -> FuzzOutcome:
    """Full source-available fuzz loop for one function. Returns a FuzzOutcome with
    a confirmed PoV when a crash is found and oracle-confirmed."""
    backend = backend or SubprocessAfl()
    config = config or AflConfig()
    workdir.mkdir(parents=True, exist_ok=True)

    def reserve(count: int = 1) -> tuple[bool, str]:
        if budget is None:
            return True, ""
        return budget.reserve_attempts(count)

    def remaining(default: float) -> float:
        if budget is None:
            return default
        return min(default, budget.remaining_seconds())

    deadline = budget.deadline_monotonic if budget is not None else None

    # #16 — synthesize + reach-validate the harness (compile→repair→reach loop).
    synth = HarnessSynthesizer(llm)
    # Binary shared-library harnesses resolve their target through dlopen/dlsym;
    # source-mode harnesses retain the existing object-link flow.
    link_libs = ("-ldl",) if spec.is_dlsym else ()
    if capabilities_resolved and compiler_path is None:
        return FuzzOutcome(
            func=spec.func,
            harness_built=False,
            crash_found=False,
            note="planned harness compiler unavailable",
        )
    if capabilities_resolved and native_compiler_path is None:
        return FuzzOutcome(
            func=spec.func,
            harness_built=False,
            crash_found=False,
            note="planned native replay compiler unavailable",
        )
    if len(target_sources) > 32:
        return FuzzOutcome(
            func=spec.func,
            harness_built=False,
            crash_found=False,
            note="source object count exceeds bounded compile limit (32)",
        )
    objs: list[Path] = []
    if not spec.is_dlsym:
        for source in target_sources:
            reserved, reason = reserve()
            if not reserved:
                return FuzzOutcome(
                    func=spec.func,
                    harness_built=False,
                    crash_found=False,
                    note=f"source object compile budget skipped: {reason}",
                )
            compile_timeout = remaining(60.0)
            if compile_timeout <= 0:
                if budget is not None:
                    budget.reservation_failures += 1
                return FuzzOutcome(
                    func=spec.func,
                    harness_built=False,
                    crash_found=False,
                    note="source object compile deadline exhausted",
                )
            if budget is None and compiler_path is None and not capabilities_resolved:
                compiled_obj = _compile_plain_object(source, workdir)
            else:
                compiled_obj = _compile_plain_object(
                    source,
                    workdir,
                    compiler_path=native_compiler_path,
                    compiler_resolved=capabilities_resolved,
                    timeout=compile_timeout,
                )
            if compiled_obj is not None:
                objs.append(compiled_obj)
    reserved, reason = reserve(2 if spec.is_dlsym or objs else 1)
    if not reserved:
        return FuzzOutcome(
            func=spec.func,
            harness_built=False,
            crash_found=False,
            note=f"harness build budget skipped: {reason}",
        )
    phase_timeout = remaining(60.0)
    if phase_timeout <= 0:
        if budget is not None:
            budget.reservation_failures += 1
        return FuzzOutcome(
            func=spec.func,
            harness_built=False,
            crash_found=False,
            note="harness build deadline exhausted",
        )
    hb = build_harness(
        spec,
        synthesizer=synth,
        compiler=GccCompiler(
            cc=native_compiler_path or "cc",
            link_libs=link_libs,
            timeout=phase_timeout,
            deadline_monotonic=deadline,
        ),
        objects=objs,
        workdir=workdir,
        max_repair=0 if budget is not None else max_repair,
        reach_timeout=remaining(10.0),
        deadline_monotonic=deadline,
    )
    if not hb.ok:
        return FuzzOutcome(
            func=spec.func, harness_built=False, crash_found=False,
            note=f"harness build failed: {hb.reason}",
        )
    harness_path = workdir / "harness.c"
    harness_path.write_text(hb.harness.source)

    # #15 — build the instrumented + CMPLOG + replay binaries and fuzz.
    if not config.dict_tokens:
        config.dict_tokens = list(spec.constants)
    if not config.seeds:
        config.seeds = initial_seeds(spec.constants)
    compile_runs = 3 if config.cmplog else 2
    reserved, reason = reserve(compile_runs)
    if not reserved:
        return FuzzOutcome(
            func=spec.func,
            harness_built=True,
            harness_path=str(harness_path),
            crash_found=False,
            note=f"fuzz-binary build budget skipped: {reason}",
        )
    compiled = build_fuzz_binaries(
        hb.harness.source,
        target_sources,
        workdir / "build",
        config=config,
        link_libs=link_libs,
        compiler_path=compiler_path,
        native_compiler_path=native_compiler_path,
        compiler_resolved=capabilities_resolved,
        deadline_monotonic=deadline,
    )
    if compiled is None:
        return FuzzOutcome(
            func=spec.func, harness_built=True, harness_path=str(harness_path),
            crash_found=False, note="fuzz-binary build failed (afl-clang-fast?)",
        )

    if spec.is_dlsym:
        # Do not interpret a constructor/dependency failure or an ABI-wiring crash as
        # an AFL discovery. The shared target must accept a benign nonempty control
        # before we spend fuzz budget or submit any crash to the oracle.
        reserved, reason = reserve()
        if not reserved:
            return FuzzOutcome(
                func=spec.func,
                harness_built=True,
                harness_path=str(harness_path),
                crash_found=False,
                note=f"shared-library control budget skipped: {reason}",
            )
        control_timeout = remaining(10.0)
        if control_timeout <= 0:
            if budget is not None:
                budget.reservation_failures += 1
            return FuzzOutcome(
                func=spec.func,
                harness_built=True,
                harness_path=str(harness_path),
                crash_found=False,
                note="shared-library control deadline exhausted",
            )
        if executor is not None:
            control_result = executor.run(
                [str(compiled.replay_bin)],
                stdin=b"A",
                timeout=control_timeout,
            )
            control_returncode = (
                -1
                if control_result.error or control_result.timed_out
                else control_result.returncode
            )
        elif budget is not None:
            return FuzzOutcome(
                func=spec.func,
                harness_built=True,
                harness_path=str(harness_path),
                crash_found=False,
                note="shared-library control lacks planned executor",
            )
        else:
            try:
                control = subprocess.run(  # foxguard: ignore[py/no-command-injection]
                    [str(compiled.replay_bin)], input=b"A", capture_output=True,
                    timeout=control_timeout, check=False,
                )
                control_returncode = control.returncode
            except (OSError, subprocess.TimeoutExpired) as e:
                return FuzzOutcome(
                    func=spec.func, harness_built=True, harness_path=str(harness_path),
                    crash_found=False, note=f"shared-library control unavailable: {e}",
                )
        if control_returncode != 0:
            return FuzzOutcome(
                func=spec.func, harness_built=True, harness_path=str(harness_path),
                crash_found=False,
                note=f"shared-library control failed (exit {control_returncode})",
            )

    in_dir, out_dir = workdir / "in", workdir / "out"
    reserved, reason = reserve()
    if not reserved:
        return FuzzOutcome(
            func=spec.func,
            harness_built=True,
            harness_path=str(harness_path),
            crash_found=False,
            note=f"shared-library AFL budget skipped: {reason}",
        )
    fuzz_timeout = remaining(float(config.duration_s))
    if fuzz_timeout <= 0:
        if budget is not None:
            budget.reservation_failures += 1
        return FuzzOutcome(
            func=spec.func,
            harness_built=True,
            harness_path=str(harness_path),
            crash_found=False,
            note="shared-library AFL deadline exhausted",
        )
    if budget is not None:
        config.hard_timeout_s = fuzz_timeout
        config.duration_s = min(config.duration_s, max(0, int(fuzz_timeout)))
    result = backend.fuzz(
        compiled.fuzz_bin, in_dir=in_dir, out_dir=out_dir,
        config=config, cmplog_bin=compiled.cmplog_bin,
    )

    # #17 — Driller assist on a stall: solve the gate, re-seed, fuzz again.
    if (
        not result.found_crash
        and driller is not None
        and driller_addrs is not None
        and driller.note_progress(result.execs)
    ):
        stuck = _queue_inputs(out_dir)
        new_seeds = driller.assist(
            compiled.replay_bin, stuck or config.seeds,
            func_addr=driller_addrs[0], target_addr=driller_addrs[1],
        )
        if new_seeds:
            config.seeds = [*config.seeds, *new_seeds]
            reserved, reason = reserve()
            if not reserved:
                return FuzzOutcome(
                    func=spec.func,
                    harness_built=True,
                    harness_path=str(harness_path),
                    crash_found=False,
                    execs=result.execs,
                    note=f"driller AFL budget skipped: {reason}",
                )
            fuzz_timeout = remaining(float(config.duration_s))
            if fuzz_timeout <= 0:
                if budget is not None:
                    budget.reservation_failures += 1
                return FuzzOutcome(
                    func=spec.func,
                    harness_built=True,
                    harness_path=str(harness_path),
                    crash_found=False,
                    execs=result.execs,
                    note="driller AFL deadline exhausted",
                )
            if budget is not None:
                config.hard_timeout_s = fuzz_timeout
                config.duration_s = min(config.duration_s, max(0, int(fuzz_timeout)))
            result = backend.fuzz(
                compiled.fuzz_bin, in_dir=in_dir, out_dir=out_dir,
                config=config, cmplog_bin=compiled.cmplog_bin,
            )

    if not result.found_crash:
        return FuzzOutcome(
            func=spec.func, harness_built=True, harness_path=str(harness_path),
            crash_found=False, execs=result.execs,
            note=f"no crash in {config.duration_s}s ({result.note})",
        )

    # #6/#7 — confirm each unique crash through the oracle, emit a PoV.
    seen = CrashSet()
    findings: list[FuzzFinding] = []
    first_pov: PoV | None = None
    for crash in result.crashes:
        pov = confirm_crash(
            compiled.replay_bin,
            crash,
            vector="stdin",
            function=spec.func,
            sink=spec.func,
            budget=budget,
            executor=executor,
            native_compiler_path=native_compiler_path,
            compiler_resolved=capabilities_resolved,
        )
        if pov is None:
            continue
        if not seen.add(pov.dedup_bucket, pov.frames):
            continue
        with contextlib.suppress(OSError):
            script = workdir / f"pov_{spec.func}.py"
            pov.pov_script = str(
                write_pov_script(script, compiled.replay_bin, pov)
            )
        findings.append(
            FuzzFinding(
                _finding_for(spec.func, "stdin"), _verdict_for(pov, spec.func), pov
            )
        )
        first_pov = first_pov or pov

    return FuzzOutcome(
        func=spec.func, harness_built=True, harness_path=str(harness_path),
        crash_found=bool(findings), pov=first_pov, execs=result.execs,
        note=f"confirmed {len(findings)} PoV(s)" if findings else
        "crash found but oracle did not confirm (stock/guard differential clean)",
        fuzz_findings=findings,
    )


def _synth_structured_seeds(
    binary: str,
    specs: list[HarnessSpec],
    tokens: list[str],
    llm: LLM | None,
) -> list[bytes]:
    """Opt-in (``ZEROVERSE_SYNTH_INPUTS``, issues #52 / #224 sub-gap (b)):
    LLM-synthesized FORMAT-VALID starter seeds for the AFL corpus. Token-derived
    seeds build a magic header at best, so coverage-guided AFL stalls at the
    container gate and never reaches a format-specific parser sink (the magma
    0/53 confirm gap); a handful of format-valid synthesized containers give it a
    foothold deep in the parser. Conditioned on the binary name, the recovered
    strings, and the top-ranked fuzz target's body — the same context the #52
    confirm path uses. These are seed HYPOTHESES: the crash oracle remains the
    sole arbiter of any crash they lead to. Any failure degrades to no seeds."""
    if llm is None or not os.environ.get("ZEROVERSE_SYNTH_INPUTS"):
        return []
    try:
        from ..inputsynth import context_from_finding, synthesize_candidates

        top = specs[0] if specs else None
        ctx = context_from_finding(
            harness_name=Path(binary).name,
            sink_function=top.func if top else "",
            sink_decompiled=top.decompiled_c if top else "",
            strings=tokens,
        )
        return synthesize_candidates(ctx, llm)
    except Exception:
        return []


def _native_last_mile_queue(
    out_dir: Path,
    seeds: Sequence[bytes],
    *,
    limit: int = 16,
) -> list[bytes]:
    """A bounded, order-stable mix of recent AFL discoveries and starter seeds."""
    if limit <= 0:
        return []
    recent_limit = max(1, limit // 2)
    seed_limit = max(1, limit // 4)
    candidates = [
        *_queue_inputs(out_dir, limit=recent_limit, newest=True),
        *seeds[:seed_limit],
        *_queue_inputs(out_dir, limit=limit),
    ]
    out: list[bytes] = []
    seen: set[bytes] = set()
    for data in candidates:
        if data in seen:
            continue
        seen.add(data)
        out.append(data)
        if len(out) >= limit:
            break
    return out


def _promote_native_last_mile_inputs(
    queue: Sequence[bytes], candidates: Sequence[bytes], *, limit: int
) -> list[bytes]:
    """Keep verified mutations first in the bounded next-sink probe corpus."""
    if limit <= 0:
        return []
    promoted: list[bytes] = []
    seen: set[bytes] = set()
    for group in (candidates, queue):
        for data in group:
            if data in seen:
                continue
            seen.add(data)
            promoted.append(data)
            if len(promoted) >= limit:
                return promoted
    return promoted


def _native_last_mile_attempt(
    binary: str,
    specs: Sequence[HarnessSpec],
    queue: list[bytes],
    llm: LLM,
    known: frozenset[str],
    seen: CrashSet,
    confirmed_functions: set[str],
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
) -> tuple[list[FuzzFinding], str]:
    """Run last-mile mutation over runtime-proven native file-input corpus."""
    from ..inputsynth import infer_format

    if not queue:
        return [], "last-mile skipped: no AFL queue inputs"

    # Runtime reachability, not static rank, decides which sinks receive an LLM
    # spend. Search beyond the first two ranked hypotheses: mature parsers often
    # expose many plausible static sinks, while only a later one is on the
    # concrete path exercised by the current AFL queue.
    eligible = [
        spec for spec in specs if spec.func not in confirmed_functions
    ][:12]
    if not eligible:
        return [], "last-mile skipped: prioritized sinks already confirmed"

    findings: list[FuzzFinding] = []
    base_probes = candidate_probes = 0
    proposed = format_valid = malformed = unsupported = 0
    sink_preserving = reach_lost = 0
    probed_functions: list[str] = []
    reached_functions: list[str] = []
    probe_failure = ""
    active_queue = list(queue)
    queue_limit = len(queue)
    for spec in eligible:
        probe = (
            probe_reaching_inputs(binary, spec.func, active_queue)
            if budget is None
            else probe_reaching_inputs(
                binary, spec.func, active_queue, budget=budget
            )
        )
        if not probe.available:
            if not probed_functions:
                return [], f"last-mile skipped: {probe.note} (sink={spec.func})"
            probe_failure = probe.note
            break
        probed_functions.append(spec.func)
        base_probes += probe.attempted
        if not probe.inputs:
            continue
        reached_functions.append(spec.func)
        ctx = LastMileContext(
            sink_function=spec.func,
            sink_decompiled=spec.decompiled_c,
            reaching_inputs=probe.inputs,
            file_format=infer_format(binary, spec.constants),
        )
        batch = normalized_last_mile_candidates(ctx, llm)
        proposed += batch.proposed
        format_valid += batch.format_valid
        malformed += batch.malformed
        unsupported += batch.unsupported
        if batch.candidates:
            candidate_inputs = [candidate.data for candidate in batch.candidates]
            candidate_probe = (
                probe_reaching_inputs(
                    binary,
                    spec.func,
                    candidate_inputs,
                    max_inputs=len(candidate_inputs),
                    max_reaching=len(candidate_inputs),
                )
                if budget is None
                else probe_reaching_inputs(
                    binary,
                    spec.func,
                    candidate_inputs,
                    max_inputs=len(candidate_inputs),
                    max_reaching=len(candidate_inputs),
                    budget=budget,
                )
            )
            candidate_probes += candidate_probe.attempted
            if not candidate_probe.available:
                probe_failure = f"candidate re-probe unavailable: {candidate_probe.note}"
                break
            sink_preserving += len(candidate_probe.inputs)
            reach_lost += len(batch.candidates) - len(candidate_probe.inputs)
            promoted: list[bytes] = []
            for candidate in candidate_probe.inputs:
                if budget is not None and not budget.reserve_attempt()[0]:
                    probe_failure = "attempt budget exhausted during last-mile replay"
                    break
                timeout = budget.remaining_seconds() if budget is not None else None
                if timeout is not None and timeout <= 0:
                    probe_failure = "deadline exhausted during last-mile replay"
                    break
                if timeout is None and executor is None:
                    confirmed = _confirm_instrumented_file_crash(
                        binary, candidate, known
                    )
                else:
                    confirmed = _confirm_instrumented_file_crash(
                        binary,
                        candidate,
                        known,
                        timeout=timeout,
                        executor=executor,
                        budget=budget,
                    )
                if confirmed is None:
                    promoted.append(candidate)
                    continue
                pov, func, receipt = confirmed
                if not seen.add(pov.dedup_bucket, pov.frames):
                    continue
                findings.append(
                    FuzzFinding(
                        _finding_for(func, "file"),
                        _verdict_for(pov, func),
                        pov,
                        feedback_receipt=receipt,
                    )
                )
            active_queue = _promote_native_last_mile_inputs(
                active_queue, promoted, limit=queue_limit
            )
        if len(reached_functions) >= 2:
            break

    note = (
        f"last-mile: {base_probes} base input probe(s), "
        f"{candidate_probes} candidate re-probe(s), "
        f"{len(reached_functions)}/{len(probed_functions)} sink(s) reached, "
        f"proposed={proposed}, format-valid={format_valid}, "
        f"sink-preserving={sink_preserving}, oracle-confirmed={len(findings)}"
    )
    note += f"; unsupported={unsupported}, malformed={malformed}, reach-lost={reach_lost}"
    note += f"; probed={','.join(probed_functions) or 'none'}"
    note += f"; reached={','.join(reached_functions) or 'none'}"
    if probe_failure:
        note = f"{note}; later probe unavailable: {probe_failure}"
    return findings, note



def _shared_library_abi_safe(spec: HarnessSpec) -> bool:
    """Accept only a plainly buffer-and-length ABI without manual wiring.

    Recovered signatures can contain opaque context pointers. Calling those with a
    byte buffer is capable of producing an authentic-looking crash that is really a
    harness ABI error. More elaborate APIs need explicit parameter-role provenance
    before this opt-in lane can execute them.
    """
    signature = spec.signature
    if signature is None or len(signature.params) != 2:
        return False
    pointer_count = len(signature.pointer_params)
    return pointer_count == 1 and any("*" not in ctype for ctype, _ in signature.params)


def _shared_library_harness_specs(
    binary: str | Path, specs: Sequence[HarnessSpec]
) -> tuple[list[HarnessSpec], str]:
    """Return safely callable generated-harness targets for an explicit .so lane.

    Loading a shared object executes its constructors and dependency initializers, so
    this is deliberately opt-in. The first implementation accepts only exported
    code symbols from Linux ELF DSOs; guessed offsets and internal functions remain
    artifact-only until their ABI/offset provenance can be independently validated.
    """
    if os.environ.get("ZEROVERSE_FUZZ_SHARED_LIB") != "1":
        return [], ""
    if not sys.platform.startswith("linux"):
        return [], "shared-library harness fuzz skipped: Linux host required"
    try:
        target = triage(binary)
    except OSError as e:
        return [], f"shared-library harness fuzz skipped: cannot triage target: {e}"
    if target.fmt != "ELF" or target.kind != "DYN" or target.mitigations.get("pie"):
        return [], "shared-library harness fuzz skipped: ELF shared object required"
    lib = Path(binary)
    exported = [
        replace(spec, lib=lib)
        for spec in specs
        if _shared_library_abi_safe(spec) and exported_symbol(lib, spec.func)
    ]
    if not exported:
        return [], "shared-library harness fuzz skipped: no exported buffer-length functions"
    return exported, f"shared-library harness fuzz: {len(exported)} exported target(s)"


def _run_shared_library_harnesses(
    binary: str | Path,
    specs: Sequence[HarnessSpec],
    *,
    llm: LLM | None,
    out_dir: Path,
    config: AflConfig,
    backend: AflBackend,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    native_compiler_path: str | None = None,
    capabilities_resolved: bool = False,
    executor: Executor | None = None,
) -> tuple[list[FuzzFinding], str]:
    """Fuzz generated dlsym harnesses and retain only oracle-confirmed findings."""
    shared_specs, note = _shared_library_harness_specs(binary, specs)
    if not shared_specs:
        return [], note
    findings: list[FuzzFinding] = []
    outcomes: list[FuzzOutcome] = []
    for spec in shared_specs:
        target_config = replace(
            config,
            qemu_mode=False,
            file_input=False,
            dict_tokens=list(config.dict_tokens),
            seeds=list(config.seeds),
            extra_env=dict(config.extra_env),
        )
        outcome = fuzz_function(
            spec,
            [],
            llm=llm,
            backend=backend,
            config=target_config,
            workdir=out_dir / f"shared_harness_{spec.func}",
            budget=budget,
            compiler_path=compiler_path,
            native_compiler_path=native_compiler_path,
            capabilities_resolved=capabilities_resolved,
            executor=executor,
        )
        outcomes.append(outcome)
        findings.extend(outcome.fuzz_findings)
    built = sum(outcome.harness_built for outcome in outcomes)
    return findings, (
        f"{note}; built {built}/{len(outcomes)} harness(es); "
        f"{len(findings)} confirmed PoV(s)"
    )


def run_fuzz_stage(
    binary: str | Path,
    decompiled_c: dict[str, str],
    *,
    llm: LLM | None = None,
    out_dir: Path,
    config: AflConfig | None = None,
    backend: AflBackend | None = None,
    arch: str = "",
    priority: Sequence[str] = (),
    callgraph: dict[str, list[str]] | None = None,
    budget: BudgetTracker | None = None,
    target_instrumented: bool | None = None,
    afl_path: str | None = None,
    qemu_path: str | None = None,
    compiler_path: str | None = None,
    native_compiler_path: str | None = None,
    capabilities_resolved: bool = False,
    execution_authorized: bool | None = None,
    executor: Executor | None = None,
) -> tuple[list[FuzzFinding], str]:
    """In-pipeline binary-only fuzzing complement. Synthesizes harnesses for the
    recovered functions (proving #16 in-pipeline) and, when ``afl-qemu-trace`` is
    present, QEMU-mode fuzzes the stripped binary directly, confirming crashes via
    the oracle. ``arch`` (canonical, e.g. ``aarch64``) selects the cross-arch
    QEMU-mode trace (#19) so a non-host ELF is fuzzed under qemu-user. ``priority``
    are functions the slice/LLM already flagged as sinks — harnessed first.
    ``callgraph`` is the backend-recovered edge set, used to rank fuzz targets by
    attacker-reachability (derived from the decompiled bodies when omitted).
    Returns confirmed findings + an honest note. Never fabricates a finding without
    a reproduced PoV."""
    config = config or AflConfig(qemu_mode=True, duration_s=_fuzz_duration(30))
    if arch:
        config.qemu_arch = arch
    # A natively AFL/ASan-instrumented libFuzzer-style target (magma/ARVO shape)
    # must NOT be forced through QEMU: it already carries fast native coverage, and
    # -Q on top is 10-100x slower for no gain. Fuzz it natively with file-arg input,
    # exactly like the source lane (``-- $BIN @@``) that confirms these in seconds.
    native_fuzz = (
        is_instrumented_fuzz_target(binary)
        if target_instrumented is None
        else target_instrumented
    )
    # #315 third case — INSTRUMENTED BUT DRIVERLESS. magma `lua` carries the AFL
    # instrumentation (`__afl_sharedmem_fuzzing`, `__afl_area_ptr`) but has no
    # `LLVMFuzzerTestOneInput`/`AFL_DRIVER` entry: it is an interpreter that reads
    # STDIN. Both of the existing lanes are wrong for it. The driver lane would
    # hand it `@@` (a file path it treats as a script argument, never reading the
    # testcase), and QEMU-mode makes afl-fuzz hard-abort before the first exec:
    #   PROGRAM ABORT : Instrumentation found in -Q mode
    # So: NATIVE lane (never -Q), STDIN input.
    driverless_native = not native_fuzz and has_afl_instrumentation(binary)
    # Both instrumented lanes share everything except how the testcase is delivered.
    instrumented_lane = native_fuzz or driverless_native
    input_vector = "file" if native_fuzz else "stdin"
    if instrumented_lane:
        config.qemu_mode = False
        # Routing (#315/#317): a driverless-but-instrumented target reads STDIN,
        # so file_input must follow native_fuzz rather than being forced True.
        config.file_input = native_fuzz
        # Fuzz the WHOLE window, never stop at the first crash (#313). This lane
        # scores bug SITES, so the second and third crash are the point; AFL's
        # ``AFL_BENCH_UNTIL_CRASH`` is a time-to-first-crash instrument and is
        # wrong here. It is also not even cheaper: the run used to stop fuzzing at
        # the first crash and then sit wedged until the hard timeout anyway.
        # Measured on bench (magma libpng driver, 90s window, same seeds): stopping
        # at the first crash gave 3,334 execs / 1 crash and burned the rest of the
        # window; fuzzing through gives 46,133 execs / 2 crashes and exits on time.
        # Last-mile additionally needs the grown queue for its reach probe. All
        # crashes are collected and adjudicated either way.
        config.stop_on_crash = False
        # An instrumented driver reports the bug through ASan/UBSan, but AFL only
        # SAVES a crash if the sanitizer ABORTS the process. UBSan defaults to
        # log-and-continue, so a UBSan-class bug (e.g. libpng png_check_chunk_length)
        # is executed but never recorded — the fuzzer spins for the whole budget and
        # reports "no crash". Force the sanitizers to abort. ``symbolize=0`` is
        # mandatory: afl-fuzz refuses to start with a custom ASAN_OPTIONS that omits
        # it. (setdefault keeps an operator override authoritative.)
        config.extra_env.setdefault(
            "ASAN_OPTIONS", "abort_on_error=1:symbolize=0:detect_leaks=0")
        config.extra_env.setdefault(
            "UBSAN_OPTIONS", "halt_on_error=1:abort_on_error=1:symbolize=0")
    backend = backend or SubprocessAfl(
        afl_path=afl_path,
        qemu_path=qemu_path,
        resolved=capabilities_resolved,
        execution_authorized=execution_authorized,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    specs = fuzzable_specs(decompiled_c, priority=priority, callgraph=callgraph)
    notes: list[str] = []

    if os.environ.get("ZEROVERSE_FUZZ_SHARED_LIB") == "1":
        shared_findings, shared_note = _run_shared_library_harnesses(
            binary,
            specs,
            llm=llm,
            out_dir=out_dir,
            config=config,
            backend=backend,
            budget=budget,
            compiler_path=compiler_path,
            native_compiler_path=native_compiler_path,
            capabilities_resolved=capabilities_resolved,
            executor=executor,
        )
        # A valid shared-object request is handled exclusively by generated native
        # harnesses. Ineligible inputs retain the existing whole-program fallback.
        if shared_note.startswith("shared-library harness fuzz:"):
            return shared_findings, shared_note
        if shared_note:
            notes.append(shared_note)
    if instrumented_lane:
        # Magma/OSS-Fuzz-style binaries already contain the driver AFL executes
        # (or, driverless, ARE the program AFL executes). Per-function harness
        # artifacts are neither compiled nor invoked in this lane, so asking the
        # LLM to synthesize them only adds cost and latency.
        notes.append(
            "reused native instrumented harness" if native_fuzz
            else "reused native instrumented binary (driverless, stdin)"
        )
    else:
        synth = HarnessSynthesizer(llm)
        artifacts = 0
        for spec in specs:
            h = synth.synthesize(spec)
            (out_dir / f"harness_{spec.func}.c").write_text(h.source)
            artifacts += 1
        if artifacts:
            notes.append(f"synthesized {artifacts} harness(es)")

    qemu_available = (
        qemu_path is not None
        if capabilities_resolved
        else afl_qemu_available(config.qemu_arch)
    )
    if config.qemu_mode and not qemu_available:
        which = config.qemu_arch or "host"
        notes.append(
            f"QEMU-mode fuzz skipped: afl-qemu-trace ({which}) not built "
            "(harnesses emitted as artifacts; CPU_TARGET=<cpu> build_qemu_support.sh)"
        )
        return [], "; ".join(notes)

    # Whole-program fuzz: native+file-input for an instrumented libFuzzer target,
    # else QEMU whole-program of the stripped binary (reads stdin).
    tokens = tokens_from_context(*decompiled_c.values())
    fmt_tokens = format_field_tokens(*decompiled_c.values())
    config.dict_tokens = config.dict_tokens or (tokens + fmt_tokens)
    binary_str = str(binary)
    if not config.seeds:
        # in the parser), then the structured file/token starter corpus.
        synth_seeds = _synth_structured_seeds(binary_str, specs, tokens, llm)
        config.seeds = synth_seeds + initial_seeds(tokens)
    if budget is not None:
        reserved, reason = budget.reserve_attempt(fuzz=True)
        if not reserved:
            notes.append(f"fuzz budget skipped: {reason}")
            return [], "; ".join(notes)
        remaining = budget.remaining_seconds()
        if remaining <= 0:
            notes.append("fuzz budget skipped: wall-clock budget exhausted")
            return [], "; ".join(notes)
        config.duration_s = min(config.duration_s, max(0, int(remaining)))
        # `-V` is what bounds afl-fuzz; the subprocess timeout is only the backstop
        # for an AFL that cannot honour it. Handing it the ENTIRE remaining wall
        # clock means one wedged forkserver (a piped `core_pattern` hangs the child
        # on the first crash) eats the whole run and starves replay/confirmation.
        # Cap it at the requested window plus slack instead.
        config.hard_timeout_s = min(remaining, config.duration_s + 60)
    result = backend.fuzz(
        Path(binary), in_dir=out_dir / "in", out_dir=out_dir / "out", config=config
    )
    findings: list[FuzzFinding] = []
    seen = CrashSet()
    known = frozenset(decompiled_c)
    # For the instrumented lanes, a benign control input must stay clean, else the
    # target is unstable and no crash can be trusted as a differential.
    control_ok = True
    ctrl = None
    if instrumented_lane:
        if budget is not None and not budget.reserve_attempt(fuzz=True)[0]:
            notes.append("instrumented control check budget-skipped")
            control_ok = False
        else:
            remaining = budget.remaining_seconds() if budget is not None else 10.0
            ctrl = run_sanitizer(
                binary_str,
                b"A" * 64,
                vector=input_vector,
                timeout=remaining,
                executor=executor,
            )
            control_ok = bool(
                ctrl.valid and not ctrl.crashed and not _loader_failure(ctrl.stderr)
            )
        if not control_ok:
            # Surface an oracle INFRASTRUCTURE failure loudly — a disabled
            # executor / missing runtime lib reads identically to "no crashes"
            # otherwise, silently zeroing the lane (the exact #224 diagnosis
            # trap). A genuinely unstable target reports the same way.
            reason = (
                "attempt budget exhausted"
                if ctrl is None
                else ctrl.infrastructure_error
                or (ctrl.stderr or "")[:160]
                or "benign control crashed"
            )
            notes.append(f"instrumented control check FAILED: {reason}")
    for crash in result.crashes:
        if (
            instrumented_lane
            and budget is not None
            and not budget.reserve_attempt(fuzz=True)[0]
        ):
            notes.append("crash replay budget exhausted")
            break
        replay_timeout = budget.remaining_seconds() if budget is not None else None
        if replay_timeout is not None and replay_timeout <= 0:
            notes.append("crash replay deadline exhausted")
            break
        if instrumented_lane and not control_ok:
            break
        if native_fuzz:
            if replay_timeout is None and executor is None:
                conf = _confirm_instrumented_file_crash(binary_str, crash, known)
            else:
                conf = _confirm_instrumented_file_crash(
                    binary_str,
                    crash,
                    known,
                    timeout=replay_timeout,
                    executor=executor,
                    budget=budget,
                )
            if conf is None:
                continue
            confirmed_pov, func, receipt = conf
            if not seen.add(confirmed_pov.dedup_bucket, confirmed_pov.frames):
                continue
            findings.append(
                FuzzFinding(
                    _finding_for(func, "file"),
                    _verdict_for(confirmed_pov, func),
                    confirmed_pov,
                    feedback_receipt=receipt,
                )
            )
            continue
        pov = confirm_crash(
            binary_str,
            crash,
            vector="stdin",
            function="<whole-program>",
            budget=budget,
            executor=executor,
            native_compiler_path=native_compiler_path,
            compiler_resolved=capabilities_resolved,
        )
        if pov is None or not seen.add(pov.dedup_bucket, pov.frames):
            continue
        func = _crash_function(pov, known, "<whole-program>")
        findings.append(
            FuzzFinding(_finding_for(func, "stdin"), _verdict_for(pov, func), pov)
        )
    if (
        native_fuzz
        and control_ok
        and last_mile_enabled()
        and llm is not None
    ):
        queue = _native_last_mile_queue(out_dir / "out", config.seeds)
        native_specs = _native_last_mile_specs(decompiled_c, priority, specs)
        last_mile_findings, last_mile_note = _native_last_mile_attempt(
            binary_str,
            native_specs,
            queue,
            llm,
            known,
            seen,
            {finding.finding.function for finding in findings},
            budget=budget,
            executor=executor,
        )
        findings.extend(last_mile_findings)
        notes.append(last_mile_note)
    if native_fuzz:
        lane = "native-instrumented fuzz (file-input)"
    elif driverless_native:
        lane = "native-instrumented fuzz (driverless, stdin)"
    else:
        lane = "qemu-mode fuzz"
    notes.append(
        f"{lane}: {len(findings)} confirmed PoV(s)" if findings
        else f"{lane}: no confirmed crash ({result.note})"
    )
    return findings, "; ".join(notes)


# --- small helpers ----------------------------------------------------------

# The dynamic loader's failure text. A binary extracted from its build container
# and run on a host that lacks one of its (possibly TRANSITIVE) shared libraries
# exits 127 with this on stderr — it never executes a single instruction of the
# target. That is an INFRASTRUCTURE failure, but a plain non-zero exit with no
# sanitizer report otherwise classifies as "ran fine, did not crash", which is
# exactly how a broken lane emits a clean-looking zero (#262/#315).
_LOADER_FAILURES: tuple[str, ...] = (
    "error while loading shared libraries",
    "cannot open shared object file",
)


def _loader_failure(stderr: str) -> bool:
    """True when ``stderr`` shows the target never loaded (missing shared lib)."""
    return any(m in stderr for m in _LOADER_FAILURES)


def _compile_plain_object(
    src: Path,
    workdir: Path,
    *,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
    timeout: float = 60.0,
) -> Path | None:
    obj = workdir / (src.stem + "_plain.o")
    compiler = compiler_path if compiler_resolved else (compiler_path or "cc")
    if compiler is None:
        return None
    try:
        p = subprocess.run(
            [compiler, "-O0", "-c", str(src), "-o", str(obj)],
            capture_output=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return obj if p.returncode == 0 else None


def _queue_inputs(
    out_dir: Path,
    limit: int = 8,
    *,
    newest: bool = False,
) -> list[bytes]:
    qdir = out_dir / "default" / "queue"
    if not qdir.is_dir():
        return []
    out: list[bytes] = []
    files = sorted(qdir.glob("id:*"))
    selected = files[-limit:] if newest else files[:limit]
    for f in selected:
        try:
            out.append(f.read_bytes())
        except OSError:
            continue
    return out


def fuzz_enabled(force_env: str = "ZEROVERSE_FORCE_FUZZ") -> bool:
    """Fuzzing runs as a complement when the slice found nothing; this also lets an
    operator force it on (``ZEROVERSE_FORCE_FUZZ=1``) even when the slice confirmed."""
    return bool(os.environ.get(force_env))


# === #39/#40/#41 — the directed fuzzing lane ================================
#
# Wires the three M7 pieces into one stage that drives AFL++ *toward* the sinks
# the engine already flagged instead of fuzzing for blind coverage:
#
#   * #40 ``CoverageProbe`` — per-seed key-address-near-sink energy + the
#     reached-but-uncrashed last-mile signal.
#   * #39 ``DirectedScheduler`` — UniAFL 25/25/50 corpus re-prioritisation between
#     windows, dropping sinks the oracle already confirmed.
#   * #41 ``DistanceDriller`` — on a distance plateau toward the nearest sink,
#     concolic-solve the next gate and re-seed AFL++.
#
# PoV-is-truth is unchanged: every crash is still adjudicated by the M1 oracle in
# ``confirm_crash``. Directed fuzzing only changes *where* the fuzzer spends
# energy. Empty target set ⇒ this degrades to a plain windowed coverage run (and
# ``directed_fuzz_stage`` falls all the way back to ``run_fuzz_stage``), so it is
# an honest no-op when the archetype/slice layer gave us no sink.


def _probe_union(probe: CoverageProbe | None, seeds: list[bytes]) -> frozenset[int]:
    """Union of executed block addresses across ``seeds`` (empty when no probe)."""
    if probe is None or not seeds:
        return frozenset()
    out: set[int] = set()
    for s in seeds:
        out |= probe.trace(s).addrs
    return frozenset(out)


def _last_mile_attempt(
    spec: HarnessSpec,
    targets: DirectedTargets,
    probe: CoverageProbe,
    queue: list[bytes],
    replay_bin: Path,
    llm: LLM,
) -> list[FuzzFinding]:
    """Last-mile assist (ROADMAP M2, #224): the fuzz windows reached a sink but
    never crashed it. Spend LLM reasoning on the reached-but-uncrashed sinks —
    targeted mutations of the corpus inputs that REACH the sink, conditioned on
    the sink's decompiled body — and adjudicate every candidate through the
    same oracle as an AFL-found crash. Opt-in (``ZEROVERSE_LAST_MILE``); the
    candidates are hypotheses, the oracle is the sole arbiter."""
    from ..inputsynth import infer_format

    findings: list[FuzzFinding] = []
    seen = CrashSet()
    hot = probe.uncrashed_but_reached(queue, targets.active)
    for t in hot[:2]:  # the deepest reached sinks first; bounded LLM spend
        reaching = [s for s in queue[:64] if probe.reached_sinks(s, [t])]
        if not reaching:
            continue
        ctx = LastMileContext(
            sink_function=t.function or spec.func,
            sink_decompiled=spec.decompiled_c,
            reaching_inputs=reaching,
            file_format=infer_format(str(replay_bin), spec.constants),
        )
        for cand in last_mile_candidates(ctx, llm):
            pov = confirm_crash(
                replay_bin, cand, vector="stdin", function=spec.func, sink=spec.func,
            )
            if pov is None or not seen.add(pov.dedup_bucket, pov.frames):
                continue
            findings.append(
                FuzzFinding(
                    _finding_for(spec.func, "stdin"), _verdict_for(pov, spec.func), pov,
                )
            )
    return findings


def directed_fuzz_function(
    spec: HarnessSpec,
    target_sources: list[Path],
    *,
    targets: DirectedTargets,
    distance: DistanceModel | None = None,
    probe: CoverageProbe | None = None,
    solver: Solver | None = None,
    harness_src: str | None = None,
    llm: LLM | None = None,
    backend: AflBackend | None = None,
    config: AflConfig | None = None,
    workdir: Path,
    solve_bin: Path | None = None,
    scheduler_config: SchedulerConfig | None = None,
    max_windows: int = 4,
    max_repair: int = 3,
) -> FuzzOutcome:
    """Directed fuzz loop for one function (the source-available / benchmark
    setting). Runs AFL++ in bounded windows; between windows it (a) re-prioritises
    the corpus toward the sinks with the #39 scheduler and (b) fires the #41
    DistanceDriller when the corpus has not reached a sink, concolic-solving the
    gate and re-seeding. When the budget ends with a sink REACHED but uncrashed,
    the opt-in last-mile assist (``ZEROVERSE_LAST_MILE``, #224) spends LLM
    reasoning on targeted mutations of the sink-reaching inputs. Confirms every
    crash — AFL-found or last-mile — through the same M1 oracle.

    With an **empty** ``targets`` set this is just a plain windowed coverage run —
    the honest ablation baseline (identical harness/binaries, only the directed
    machinery removed)."""
    backend = backend or SubprocessAfl()
    config = config or AflConfig()
    workdir.mkdir(parents=True, exist_ok=True)

    # Harness: a caller-fixed source (so an injected probe/trace-bin shares the
    # exact same harness) or the #16 synthesizer.
    if harness_src is None:
        synth = HarnessSynthesizer(llm)
        compiled_objs = (_compile_plain_object(s, workdir) for s in target_sources)
        objs: list[Path] = [o for o in compiled_objs if o is not None]
        hb = build_harness(
            spec, synthesizer=synth, compiler=GccCompiler(), objects=objs,
            workdir=workdir, max_repair=max_repair,
        )
        if not hb.ok:
            return FuzzOutcome(
                func=spec.func, harness_built=False, crash_found=False,
                note=f"harness build failed: {hb.reason}",
            )
        harness_src = hb.harness.source
    harness_path = workdir / "harness.c"
    harness_path.write_text(harness_src)

    if not config.dict_tokens:
        config.dict_tokens = list(spec.constants)
    if not config.seeds:
        config.seeds = initial_seeds(spec.constants)
    compiled = build_fuzz_binaries(
        harness_src, target_sources, workdir / "build", config=config
    )
    if compiled is None:
        return FuzzOutcome(
            func=spec.func, harness_built=True, harness_path=str(harness_path),
            crash_found=False, note="fuzz-binary build failed (afl-clang-fast?)",
        )

    # Steering machinery (only when we have sinks to drive to).
    driller: DistanceDriller | None = None
    scheduler: DirectedScheduler | None = None
    if targets:
        dist = distance or NullDistance([(t.func_entry, t.sink_addr) for t in targets.active])
        driller = DistanceDriller(
            solver or AngrConcolicSolver(),
            dist,
            DrillerConfig(stall_rounds=1, max_assists=4),
        )
        if probe is not None:
            scheduler = DirectedScheduler(probe, targets, scheduler_config)
        if config.qemu_mode:
            ranges = inst_ranges_for_slice(targets.active, probe.index) if probe else ""
            if ranges:
                config.extra_env.setdefault("AFL_QEMU_INST_RANGES", ranges)

    in_dir = workdir / "in"
    result = None
    assisted = False
    queue: list[bytes] = []
    windows = max_windows if targets else 1
    for w in range(windows):
        out_dir = workdir / f"out_w{w}"
        result = backend.fuzz(
            compiled.fuzz_bin, in_dir=in_dir, out_dir=out_dir,
            config=config, cmplog_bin=compiled.cmplog_bin,
        )
        if result.found_crash or driller is None:
            break
        queue = _queue_inputs(out_dir) or list(config.seeds)
        executed = _probe_union(probe, queue)
        # #41 distance-directed assist: drive to the next gate when the corpus has
        # not reached a sink (or the graded CfgDistance has plateaued).
        plateaued = driller.note_distance(executed)
        reached = bool(
            probe.reached_sinks(queue[0], targets.active)
        ) if (probe and queue) else False
        if not reached and (plateaued or not assisted):
            new_seeds = driller.assist_distance(
                solve_bin or compiled.replay_bin, queue, executed
            )
            if new_seeds:
                config.seeds = [*config.seeds, *new_seeds]
                assisted = True
        # #39 re-prioritise the corpus toward the sinks for the next window.
        if scheduler is not None:
            ranked = scheduler.reprioritize([*queue, *config.seeds])
            if ranked:
                config.seeds = ranked

    assert result is not None
    if not result.found_crash:
        # Last-mile assist (#224, opt-in): the corpus REACHED a sink but never
        # crashed it — spend LLM reasoning on targeted mutations of the
        # reaching inputs before declaring the budget exhausted.
        if (
            last_mile_enabled() and llm is not None
            and probe is not None and targets and queue
        ):
            lm = _last_mile_attempt(spec, targets, probe, queue,
                                    compiled.replay_bin, llm)
            if lm:
                first = lm[0]
                return FuzzOutcome(
                    func=spec.func, harness_built=True,
                    harness_path=str(harness_path), crash_found=True,
                    pov=first.pov, execs=result.execs,
                    note=f"last-mile: confirmed {len(lm)} PoV(s) via LLM-targeted "
                    "mutation of sink-reaching inputs",
                    fuzz_findings=lm,
                )
        return FuzzOutcome(
            func=spec.func, harness_built=True, harness_path=str(harness_path),
            crash_found=False, execs=result.execs,
            note=f"no crash in {config.duration_s * windows}s budget "
            f"({'directed' if targets else 'coverage'}, {result.note})",
        )

    # #6/#7 — confirm each unique crash through the oracle, emit a PoV.
    seen = CrashSet()
    findings: list[FuzzFinding] = []
    first_pov: PoV | None = None
    for crash in result.crashes:
        pov = confirm_crash(
            compiled.replay_bin, crash, vector="stdin", function=spec.func,
            sink=spec.func,
        )
        if pov is None or not seen.add(pov.dedup_bucket, pov.frames):
            continue
        with contextlib.suppress(OSError):
            script = workdir / f"pov_{spec.func}.py"
            pov.pov_script = str(write_pov_script(script, compiled.replay_bin, pov))
        findings.append(
            FuzzFinding(_finding_for(spec.func, "stdin"), _verdict_for(pov, spec.func), pov)
        )
        first_pov = first_pov or pov
    # directed-target bookkeeping: drop every confirmed sink from the live set.
    if findings:
        for t in targets.active:
            targets.confirm(t.sink_addr)

    return FuzzOutcome(
        func=spec.func, harness_built=True, harness_path=str(harness_path),
        crash_found=bool(findings), pov=first_pov, execs=result.execs,
        note=(f"{'directed' if targets else 'coverage'}: "
              f"confirmed {len(findings)} PoV(s)"
              + (" [concolic-assisted]" if assisted else "")) if findings else
        "crash found but oracle did not confirm",
        fuzz_findings=findings,
    )


def directed_fuzz_stage(
    binary: str | Path,
    decompiled_c: dict[str, str],
    findings: list[Finding],
    insts: list[Inst],
    *,
    seed_matches: list[tuple[str, str, int]] | None = None,
    disasm: str = "",
    llm: LLM | None = None,
    out_dir: Path,
    config: AflConfig | None = None,
    backend: AflBackend | None = None,
    arch: str = "",
    budget: BudgetTracker | None = None,
    target_instrumented: bool | None = None,
    afl_path: str | None = None,
    qemu_path: str | None = None,
    coverage_qemu_path: str | None = None,
    compiler_path: str | None = None,
    native_compiler_path: str | None = None,
    capabilities_resolved: bool = False,
    execution_authorized: bool | None = None,
    executor: Executor | None = None,
) -> tuple[list[FuzzFinding], str]:
    """In-pipeline directed entry: collect sink targets from the slice findings +
    seed-archetype matches; if there are none, fall straight back to the plain
    coverage lane (``run_fuzz_stage``). Otherwise build the address index / probe /
    distance model over the stripped binary and QEMU-mode fuzz it toward the sinks.

    This is the default fuzzing strategy when the slice/seeds provide targets, and
    a transparent no-op (delegating to the coverage lane) when they don't —
    directedness never *reduces* the engine's reach."""
    entries = {f: e for f in {i.func for i in insts}
               if (e := function_entry(insts, f)) is not None}
    targets = collect_targets(
        findings, seed_matches=seed_matches or (), disasm=disasm, func_entries=entries,
    )
    if not targets:
        return run_fuzz_stage(
            binary,
            decompiled_c,
            llm=llm,
            out_dir=out_dir,
            config=config,
            backend=backend,
            arch=arch,
            budget=budget,
            target_instrumented=target_instrumented,
            afl_path=afl_path,
            qemu_path=qemu_path,
            compiler_path=compiler_path,
            native_compiler_path=native_compiler_path,
            capabilities_resolved=capabilities_resolved,
            execution_authorized=execution_authorized,
            executor=executor,
        )

    # The directed lane is QEMU-mode by construction (it steers with
    # AFL_QEMU_INST_RANGES). afl-fuzz refuses `-Q` on ANY binary carrying AFL
    # instrumentation, not just on driver targets, so a driverless instrumented
    # binary (magma `lua`, #315) has to fall back to the coverage lane too —
    # otherwise afl-fuzz aborts before the first exec and the target scores a
    # structural zero.
    if target_instrumented or has_afl_instrumentation(binary):
        return run_fuzz_stage(
            binary,
            decompiled_c,
            llm=llm,
            out_dir=out_dir,
            config=config,
            backend=backend,
            arch=arch,
            budget=budget,
            target_instrumented=target_instrumented,
            afl_path=afl_path,
            qemu_path=qemu_path,
            compiler_path=compiler_path,
            native_compiler_path=native_compiler_path,
            capabilities_resolved=capabilities_resolved,
            execution_authorized=execution_authorized,
            executor=executor,
        )

    config = config or AflConfig(qemu_mode=True, duration_s=_fuzz_duration(30))
    if arch:
        config.qemu_arch = arch
    index = AddressIndex.from_insts(insts)
    probe = CoverageProbe(
        binary,
        index,
        qemu_arch=config.qemu_arch,
        budget=budget,
        qemu_path=coverage_qemu_path,
        qemu_resolved=capabilities_resolved,
    )
    if not probe.available():
        # no address-level coverage (no qemu) → degrade to the coverage lane.
        return run_fuzz_stage(
            binary,
            decompiled_c,
            llm=llm,
            out_dir=out_dir,
            config=config,
            backend=backend,
            arch=arch,
            budget=budget,
            target_instrumented=target_instrumented,
            afl_path=afl_path,
            qemu_path=qemu_path,
            compiler_path=compiler_path,
            native_compiler_path=native_compiler_path,
            capabilities_resolved=capabilities_resolved,
            execution_authorized=execution_authorized,
            executor=executor,
        )
    budget_notes: list[str] = []
    cfg_timeout = 30.0
    if budget is not None:
        reserved, reason = budget.reserve_attempt()
        if not reserved:
            return [], f"directed fuzz skipped: CFG distance budget-skipped: {reason}"
        remaining = budget.remaining_seconds()
        if remaining <= 0:
            budget.reservation_failures += 1
            return [], (
                "directed fuzz skipped: CFG distance budget-skipped: "
                "wall-clock budget exhausted"
            )
        cfg_timeout = min(cfg_timeout, remaining)
    cfg_dist = AngrCfgDistance(
        Path(binary),
        [(t.func_entry, t.sink_addr) for t in targets.active],
        timeout_s=cfg_timeout,
    )
    distance: DistanceModel = cfg_dist if cfg_dist.ok else NullDistance(
        [(t.func_entry, t.sink_addr) for t in targets.active]
    )

    tokens = tokens_from_context(*decompiled_c.values())
    config.dict_tokens = config.dict_tokens or tokens
    config.seeds = config.seeds or initial_seeds(tokens)
    ranges = inst_ranges_for_slice(targets.active, index)
    if ranges:
        config.extra_env.setdefault("AFL_QEMU_INST_RANGES", ranges)

    concolic_solver = AngrConcolicSolver(AngrConfig(timeout_s=cfg_timeout))
    driller = DistanceDriller(
        concolic_solver, distance, DrillerConfig(stall_rounds=1, max_assists=4)
    )

    def reserve_concolic_solve() -> bool:
        if budget is None:
            return True
        reserved, reason = budget.reserve_attempt()
        if not reserved:
            budget_notes.append(f"concolic assist budget-skipped: {reason}")
            return False
        remaining = budget.remaining_seconds()
        if remaining <= 0:
            budget.reservation_failures += 1
            budget_notes.append(
                "concolic assist budget-skipped: wall-clock budget exhausted"
            )
            return False
        concolic_solver.config.timeout_s = min(30.0, remaining)
        return True

    scheduler = DirectedScheduler(probe, targets)
    backend = backend or SubprocessAfl(
        afl_path=afl_path,
        qemu_path=qemu_path,
        resolved=capabilities_resolved,
        execution_authorized=execution_authorized,
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    in_dir = out_dir / "in"
    fuzz_findings: list[FuzzFinding] = []
    seen = CrashSet()
    result = None
    for w in range(4):
        if budget is not None:
            if not budget.reserve_attempt()[0]:
                break
            remaining = budget.remaining_seconds()
            if remaining <= 0:
                break
            config.hard_timeout_s = remaining
            config.duration_s = min(config.duration_s, max(0, int(remaining)))
        result = backend.fuzz(
            Path(binary), in_dir=in_dir, out_dir=out_dir / f"w{w}", config=config
        )
        if result.found_crash:
            break
        queue = _queue_inputs(out_dir / f"w{w}") or list(config.seeds)
        executed = _probe_union(probe, queue)
        if (
            driller.note_distance(executed)
            or not probe.reached_sinks(queue[0], targets.active)
        ):
            new_seeds = driller.assist_distance(
                Path(binary),
                queue,
                executed,
                before_solve=reserve_concolic_solve,
            )
            if new_seeds:
                config.seeds = [*config.seeds, *new_seeds]
        ranked = scheduler.reprioritize([*queue, *config.seeds])
        if ranked:
            config.seeds = ranked

    if result is None:
        return [], "directed fuzz skipped: attempt/deadline budget exhausted"
    known = frozenset(decompiled_c)
    for crash in result.crashes:
        pov = confirm_crash(
            binary,
            crash,
            vector="stdin",
            function="<directed>",
            budget=budget,
            executor=executor,
            native_compiler_path=native_compiler_path,
            compiler_resolved=capabilities_resolved,
        )
        if pov is None or not seen.add(pov.dedup_bucket, pov.frames):
            continue
        func = _crash_function(pov, known, "<directed>")
        fuzz_findings.append(
            FuzzFinding(_finding_for(func, "stdin"),
                        _verdict_for(pov, func), pov)
        )
    note = (f"directed qemu-mode fuzz ({len(targets)} sink target(s)): "
            f"{len(fuzz_findings)} confirmed PoV(s)" if fuzz_findings
            else f"directed qemu-mode fuzz: no confirmed crash ({result.note})")
    if budget_notes:
        note = f"{note}; {'; '.join(dict.fromkeys(budget_notes))}"
    return fuzz_findings, note
