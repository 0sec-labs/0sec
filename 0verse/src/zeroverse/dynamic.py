"""Stage 6 — dynamic confirmation: turn a triage hypothesis into a reproducing PoV.

The LLM proposes a triggering input; this stage *executes* it against the real
binary and lets a deterministic oracle decide (DESIGN-NOTES Decision 6, oracle.py):

  * command injection (system/popen/exec*): inject a unique-canary command via the
    source vector, run, and confirm the marker appears in output — proof that
    attacker-controlled input reached command execution.
  * memory safety (memcpy/strcpy/sprintf/gets): drive an oversized input through
    the source vector and confirm a native crash (differential: the control input
    does NOT crash).

No LLM here — only the canary-marker and differential-crash oracles adjudicate.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from . import oracle
from .agent import Verdict
from .analyze import Finding
from .execution.contract import ExecutionBackend, ExecutionEvidence, ExecutionRequest
from .payloads import memsafe_candidates
from .preflight import BudgetTracker
from .report import PoV
from .sandbox_exec import Executor, current_executor

CMDI_SINKS = {"system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execvpe"}
MEMSAFE_SINKS = {"memcpy", "strcpy", "strcat", "sprintf", "gets", "stpcpy"}


@dataclass
class ExecResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    valid: bool = True
    provenance: dict[str, str] = field(default_factory=dict)

    @property
    def crashed(self) -> bool:
        return self.returncode < 0  # killed by a signal

    @property
    def signal(self) -> str:
        return {-11: "SIGSEGV", -6: "SIGABRT", -4: "SIGILL", -8: "SIGFPE"}.get(
            self.returncode, ""
        )


CandidateProvenance = Literal["structure-aware-synthesis", "generic-boundary"]
_CANDIDATE_PROVENANCE = frozenset({"structure-aware-synthesis", "generic-boundary"})
MAX_CONFIRMATION_CANDIDATE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ConfirmationCandidate:
    """One proposed input and its non-adjudicative generation provenance."""

    payload: bytes
    provenance: CandidateProvenance

    def __post_init__(self) -> None:
        if not self.payload:
            raise ValueError("confirmation candidate must not be empty")
        if len(self.payload) > MAX_CONFIRMATION_CANDIDATE_BYTES:
            raise ValueError("confirmation candidate exceeds the 1 MiB pipeline limit")
        if self.provenance not in _CANDIDATE_PROVENANCE:
            raise ValueError("confirmation candidate has invalid provenance")


class Runner(Protocol):
    def run(
        self,
        binary: str,
        *,
        env: dict[str, str] | None = None,
        argv: list[str] | None = None,
        stdin: bytes = b"",
        timeout: float = 5.0,
    ) -> ExecResult: ...


def _reserve_execution(
    budget: BudgetTracker | None,
    *,
    count: int = 1,
    unknown_sink: bool = False,
) -> bool:
    return budget is None or budget.reserve_attempts(
        count, unknown_sink=unknown_sink
    )[0]


def _execution_timeout(
    budget: BudgetTracker | None,
    configured: float,
) -> float:
    if budget is None:
        return configured
    remaining = budget.remaining_seconds()
    if remaining <= 0:
        budget.reservation_failures += 1
        return 0.0
    return min(configured, remaining)


class SubprocessRunner:
    """Compatibility runner backed by one selected execution boundary."""

    def __init__(self, executor: Executor | None = None) -> None:
        self._executor = executor

    @property
    def executor(self) -> Executor:
        return self._executor or current_executor()

    def run(
        self,
        binary: str,
        *,
        env: dict[str, str] | None = None,
        argv: list[str] | None = None,
        stdin: bytes = b"",
        timeout: float = 5.0,
    ) -> ExecResult:
        result = self.executor.run(
            [binary, *(argv or [])], stdin=stdin, env=env, timeout=timeout
        )
        valid = not result.error and not result.timed_out
        return ExecResult(
            result.returncode if valid else (124 if result.timed_out else -99),
            result.stdout.encode(),
            result.stderr.encode(),
            valid=valid,
            provenance=dict(result.provenance),
        )


def _env_name(hint: str, default: str = "CMD") -> str:
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", hint)
    return m.group(1) if m else default


def confirm(
    finding: Finding,
    verdict: Verdict,
    binary: str | Path,
    runner: Runner | None = None,
    *,
    executor: ExecutionBackend | None = None,
    target_format: str = "ELF",
    candidate_inputs: Sequence[ConfirmationCandidate] = (),
    allow_unknown_sink: bool = False,
    timeout: float | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> PoV | None:
    """Execute the LLM-proposed trigger and return a reproducing PoV, or None."""
    if executor is not None:
        return _confirm_with_executor(
            finding,
            verdict,
            str(binary),
            executor,
            target_format=target_format,
            candidate_inputs=candidate_inputs,
            allow_unknown_sink=allow_unknown_sink,
            timeout=timeout,
            budget=budget,
        )
    runner = runner or SubprocessRunner()
    oracle_executor = runner.executor if isinstance(runner, SubprocessRunner) else None
    binary = str(binary)
    runner_limit = 5.0 if timeout is None else min(5.0, timeout)
    diff_limit = 10.0 if timeout is None else min(10.0, timeout)

    if finding.sink in CMDI_SINKS and finding.source == "getenv":
        canary = oracle.new_canary()
        name = _env_name(verdict.input_example)
        marker = oracle.marker_line(canary, "reached-sink")
        env = {name: f"echo {marker}"}
        if not _reserve_execution(budget, unknown_sink=allow_unknown_sink):
            return None
        run_timeout = _execution_timeout(budget, runner_limit)
        if run_timeout <= 0:
            return None
        r = runner.run(
            binary,
            env=env,
            timeout=run_timeout,
        )
        output = r.stdout + r.stderr
        if r.valid and oracle.adjudicate_capability(output, canary).proven:
            return PoV(
                env=env,
                crash_class="command-injection",
                crash_trace=output.decode("utf-8", "replace").strip(),
                reproduced=True,
                execution_provenance=dict(r.provenance),
            )
        return None

    if finding.sink in MEMSAFE_SINKS or allow_unknown_sink:
        vector = "argv" if finding.source in ("argv", "getenv") else "stdin"

        # Drive an ordered family of trigger payloads through the oracle and stop
        # at the first that reproduces. `b"A"*4096` (first) confirms a flat copy
        # in one shot; integer-boundary header probes — seeded with any sizes the
        # LLM named in `verdict.input_example` — follow, so size/count-driven
        # corruption a flat payload can't reach (CWE-190 -> OOB, the shape of most
        # real parser CVEs) still confirms. The deterministic oracle, not the
        # payload source, decides truth.
        payload = None
        loud = guard_only = False
        target = diff = None
        if not _reserve_execution(budget, unknown_sink=allow_unknown_sink):
            return None
        run_timeout = _execution_timeout(budget, runner_limit)
        if run_timeout <= 0:
            return None
        control = _drive(
            runner,
            binary,
            finding.source,
            b"A",
            timeout=run_timeout,
        )
        if not control.valid:
            return None
        control_rr = oracle.RunResult(crashed=control.crashed, valid=control.valid)
        for cand in memsafe_candidates(verdict.input_example):
            # (1) loud path: a native crash under the stock allocator (e.g. a
            #     stack smash) that a benign control input does NOT trigger.
            if not _reserve_execution(budget, unknown_sink=allow_unknown_sink):
                break
            run_timeout = _execution_timeout(budget, runner_limit)
            if run_timeout <= 0:
                break
            cand_target = _drive(
                runner,
                binary,
                finding.source,
                cand,
                timeout=run_timeout,
            )
            target_rr = oracle.RunResult(
                crashed=cand_target.crashed,
                signal=cand_target.signal,
                valid=cand_target.valid,
            )
            cand_loud = oracle.differential_confirmed(target_rr, control_rr)

            # (2) silent path: the differential-allocator oracle re-runs the input
            #     under a guard allocator. `clean -> crash` confirms a *silent*
            #     heap OOB write that stock glibc never notices (no-sanitizer win).
            if not _reserve_execution(
                budget,
                count=2,
                unknown_sink=allow_unknown_sink,
            ):
                break
            cand_diff = oracle.differential_allocator(
                binary,
                cand,
                vector=vector,
                timeout=_execution_timeout(budget, diff_limit),
                deadline_monotonic=(
                    budget.deadline_monotonic if budget is not None else None
                ),
                executor=oracle_executor,
                budget=budget,
                compiler_path=compiler_path,
                compiler_resolved=compiler_resolved,
            )
            cand_guard_only = (not cand_loud) and cand_diff.real_heap_bug
            if cand_loud or cand_guard_only:
                payload = cand
                target, diff = cand_target, cand_diff
                loud, guard_only = cand_loud, cand_guard_only
                break

        if payload is None:
            return None
        assert target is not None and diff is not None  # set together with payload
        argv = [payload.decode("latin-1")] if vector == "argv" else []

        # A silent heap bug only reproduces under the guard env, so the PoV (and
        # its standalone replay) must carry the SAME (deterministic quarantine)
        # guard the differential oracle confirmed under.
        repro_env = (
            oracle.confirm_guard_env(
                executor=oracle_executor,
                budget=budget,
                compiler_path=compiler_path,
                compiler_resolved=compiler_resolved,
            )
            if guard_only
            else {}
        )
        crash_signal = target.signal if loud else diff.guard.signal
        pov = PoV(
            input_bytes=payload,
            argv=argv,
            env=repro_env,
            crash_class=crash_signal or "SIGSEGV",
            crash_trace=(target.stderr or diff.guard.stderr.encode())
            .decode("utf-8", "replace")[-400:],
            reproduced=True,
            capability="crash",
            execution_provenance=dict(
                target.provenance if loud else diff.guard.provenance
            ),
        )
        pov.diff_allocator = (
            f"stock={'crash' if diff.stock.crashed else 'clean'}"
            f"({diff.stock.signal or '-'}) "
            f"guard={'crash' if diff.guard.crashed else 'clean'}"
            f"({diff.guard.signal or '-'})"
            + (" [clean->crash: real silent heap OOB]" if diff.real_heap_bug else "")
        )

        # CASR: native exploitability classification + dedup bucket (run under the
        # guard env when the crash is guard-only, so CASR captures the fault).
        casr = None
        if _reserve_execution(budget, unknown_sink=allow_unknown_sink):
            casr_timeout = _execution_timeout(
                budget,
                60.0 if timeout is None else min(60.0, timeout),
            )
            if casr_timeout > 0:
                casr = oracle.run_casr_gdb(
                    binary,
                    stdin_bytes=payload if vector == "stdin" else None,
                    argv=argv if vector == "argv" else None,
                    env=repro_env or None,
                    timeout=casr_timeout,
                    executor=oracle_executor,
                )
        if casr is not None:
            pov.casr_severity = casr.severity
            pov.casr_desc = f"{casr.short_desc}: {casr.description}".strip(": ")
            pov.capability = casr.capability
            pov.frames = casr.frames
            pov.dedup_bucket = oracle.dedup_key(casr.severity, casr.frames)
        else:
            pov.dedup_bucket = oracle.dedup_key(
                pov.crash_class, [f"{finding.function}+{hex(finding.sink_addr)}"]
            )
        return pov

    return None


def supports_local_confirmation(
    finding: Finding, *, allow_unknown_sink: bool = False
) -> bool:
    if finding.sink in CMDI_SINKS:
        return finding.source == "getenv"
    return finding.sink in MEMSAFE_SINKS or allow_unknown_sink


def supports_confirmation(
    finding: Finding,
    executor: ExecutionBackend,
    *,
    target_format: str,
    allow_unknown_sink: bool = False,
) -> bool:
    """Whether an adapter can faithfully deliver this finding's input shape."""
    caps = executor.capabilities
    if finding.sink in CMDI_SINKS and finding.source == "getenv":
        return any(
            caps.supports(target_format, "env", oracle)
            for oracle in caps.oracles
        )
    if finding.sink not in MEMSAFE_SINKS and not allow_unknown_sink:
        return False
    native_vector = "argv" if finding.source in ("argv", "getenv") else "stdin"
    return any(
        caps.supports(target_format, vector, oracle)
        for vector in (native_vector, "file")
        for oracle in caps.oracles
    )


def _confirm_with_executor(
    finding: Finding,
    verdict: Verdict,
    binary: str,
    executor: ExecutionBackend,
    *,
    target_format: str,
    candidate_inputs: Sequence[ConfirmationCandidate] = (),
    allow_unknown_sink: bool = False,
    timeout: float | None = None,
    budget: BudgetTracker | None = None,
) -> PoV | None:
    """Adapter-neutral deterministic confirmation.

    Unlike the local-only path above, this does not run a host guard allocator or
    CASR beside a remote target.  It instead requires normalized, hash-bound
    adapter evidence and a clean-control/crashing-candidate differential.
    """
    if not supports_confirmation(
        finding,
        executor,
        target_format=target_format,
        allow_unknown_sink=allow_unknown_sink,
    ):
        return None
    executor_limit = executor.capabilities.default_timeout
    if timeout is not None:
        executor_limit = min(executor_limit, timeout)

    if finding.sink in CMDI_SINKS and finding.source == "getenv":
        canary = oracle.new_canary()
        name = _env_name(verdict.input_example)
        marker = oracle.marker_line(canary, "reached-sink")
        command = f"echo {marker}"
        if not _reserve_execution(budget, unknown_sink=allow_unknown_sink):
            return None
        request_timeout = _execution_timeout(budget, executor_limit)
        if request_timeout <= 0:
            return None
        request = ExecutionRequest(
            target=binary,
            target_format=target_format,
            payload=command.encode(),
            vector="env",
            oracle=_select_oracle(executor, preferred="marker"),
            timeout=request_timeout,
            env={name: command},
        )
        evidence = _execute_checked(executor, request, budget=budget)
        if evidence is not None and oracle.adjudicate_capability(
            evidence.stdout, canary
        ).proven:
            return PoV(
                env={name: command},
                crash_class="command-injection",
                crash_trace=evidence.stdout.strip(),
                reproduced=True,
                capability="command-exec",
            )
        return None

    native_vector = "argv" if finding.source in ("argv", "getenv") else "stdin"
    vector = _select_vector(executor, target_format, native_vector)
    selected_oracle = _select_oracle(executor, preferred="native-crash")
    if not _reserve_execution(budget, unknown_sink=allow_unknown_sink):
        return None
    request_timeout = _execution_timeout(budget, executor_limit)
    if request_timeout <= 0:
        return None
    control_request = ExecutionRequest(
        target=binary,
        target_format=target_format,
        payload=b"A",
        vector=vector,  # type: ignore[arg-type]
        oracle=selected_oracle,
        timeout=request_timeout,
    )
    control = _execute_checked(executor, control_request, budget=budget)
    if control is None or control.status != "CLEAN":
        return None

    for proposed in _confirmation_candidates(verdict, candidate_inputs):
        payload = proposed.payload
        if not _reserve_execution(budget, unknown_sink=allow_unknown_sink):
            return None
        request_timeout = _execution_timeout(budget, executor_limit)
        if request_timeout <= 0:
            return None
        request = ExecutionRequest(
            target=binary,
            target_format=target_format,
            payload=payload,
            vector=vector,  # type: ignore[arg-type]
            oracle=selected_oracle,
            timeout=request_timeout,
        )
        evidence = _execute_checked(executor, request, budget=budget)
        if evidence is None or not evidence.confirmed_crash:
            continue
        capability = oracle.classify_crash(evidence.stderr)
        crash_class = evidence.signal or evidence.crash_signature or evidence.oracle
        pov = PoV(
            input_bytes=payload,
            argv=[payload.decode("latin-1")] if vector == "argv" else [],
            file_input=vector == "file",
            crash_class=crash_class,
            crash_trace=(evidence.stderr or evidence.stdout)[-400:],
            reproduced=True,
            capability=capability if capability != "unknown" else "crash",
        )
        pov.diff_allocator = (
            f"execution-adapter={executor.name} vector={vector} "
            f"candidate_source={proposed.provenance} "
            f"control=CLEAN candidate=CRASH oracle={evidence.oracle} "
            f"target_sha256={evidence.target_sha256} "
            f"input_sha256={evidence.input_sha256}"
        )
        pov.dedup_bucket = oracle.dedup_key(
            crash_class, [f"{finding.function}+{hex(finding.sink_addr)}"]
        )
        return pov
    return None


def _confirmation_candidates(
    verdict: Verdict,
    supplied: Sequence[ConfirmationCandidate],
) -> tuple[ConfirmationCandidate, ...]:
    """Prefer structure-aware inputs, then retain the deterministic fallback family."""
    ordered = [
        *supplied,
        *(
            ConfirmationCandidate(payload, "generic-boundary")
            for payload in memsafe_candidates(verdict.input_example)
        ),
    ]
    unique: list[ConfirmationCandidate] = []
    seen: set[bytes] = set()
    for candidate in ordered:
        if candidate.payload in seen:
            continue
        seen.add(candidate.payload)
        unique.append(candidate)
    return tuple(unique)


def _execute_checked(
    executor: ExecutionBackend,
    request: ExecutionRequest,
    *,
    budget: BudgetTracker | None = None,
) -> ExecutionEvidence | None:
    """Reject late or mismatched adapter evidence under the clipped provider timeout.

    Explicit execution adapters are cooperative by contract; the pipeline applies
    hard, run-local process boundaries to native and decompiler providers.
    """
    try:
        evidence = executor.run(request)
    except Exception:  # adapter failures are fail-closed infrastructure
        _mark_executor_failure(executor, "execution adapter failed before evidence")
        return None
    if budget is not None and budget.expired():
        budget.reservation_failures += 1
        _mark_executor_failure(executor, "execution evidence arrived after run deadline")
        return None
    valid = (
        evidence.matches(request)
        and evidence.backend == executor.name
        and evidence.oracle == request.oracle
    )
    if not valid:
        _mark_executor_failure(executor, "execution adapter returned mismatched evidence")
        return None
    return evidence


def _mark_executor_failure(executor: ExecutionBackend, reason: str) -> None:
    """Set observed-wrapper failure state without requiring it in the public protocol."""
    observed: Any = executor
    if hasattr(observed, "failure_reason"):
        observed.failure_reason = reason
    if hasattr(observed, "failure_state"):
        observed.failure_state = "infra-failed"


def _select_vector(
    executor: ExecutionBackend, target_format: str, native_vector: str
) -> str:
    for vector in (native_vector, "file"):
        if any(
            executor.capabilities.supports(target_format, vector, oracle_name)
            for oracle_name in executor.capabilities.oracles
        ):
            return vector
    raise ValueError("execution adapter has no compatible input vector")


def _select_oracle(executor: ExecutionBackend, *, preferred: str) -> str:
    choices = executor.capabilities.oracles
    if preferred in choices:
        return preferred
    if "auto" in choices:
        return "auto"
    return sorted(choices)[0]


def confirm_asan_file(
    finding: Finding,
    verdict: Verdict,
    binary: str | Path,
    *,
    fixed: str | Path | None = None,
    timeout: float = 10.0,
    synth_candidates: Sequence[bytes] | None = None,
    budget: BudgetTracker | None = None,
    unknown_sink: bool = False,
    executor: Executor | None = None,
) -> PoV | None:
    """Confirm a bug on an ASan-instrumented, file-input (libFuzzer/ARVO) target.

    Candidate inputs — the deterministic integer-boundary probes plus any size the
    LLM named in ``verdict.input_example`` — are written to a temp file, passed as
    argv[1], and run under AddressSanitizer. Confirmation is differential and
    LLM-free (the sanitizer report is the oracle):

      * a benign control input must NOT trip the sanitizer (native-clean control);
      * a candidate must produce an ASan/UBSan report while the control stays clean;
      * when a paired ``fixed`` build is supplied, the SAME report must be ABSENT on
        the patched build (crash-on-vuln / clean-on-fixed) — else it is a false
        positive on already-correct code.

    Returns a reproduced ``PoV`` (``file_input=True``) or ``None``. Note: the
    boundary probes are target-independent, so they confirm flat/size-driven OOB
    but will not craft a valid container header for a format-specific parser bug —
    which stays an honest hypothesis, never a fabricated crash.

    ISSUE #52 HOOK (LLM-driven structured-input synthesis): ``synth_candidates``,
    when supplied by the caller (from ``zeroverse.inputsynth.synthesize_inputs``),
    are FORMAT-VALID inputs the LLM crafted for this target's parser. They are
    tried FIRST — before the format-blind boundary probes — because they are the
    only way to reach a format-specific parser sink. They are candidates only:
    the SAME differential sanitizer oracle below (crash-on-vuln / clean-on-fixed)
    adjudicates them, so a synthesized input can never be over-claimed."""
    binary = str(binary)
    # native-clean control: a benign input must not already trip the sanitizer,
    # else the target is unstable and no differential can be drawn.
    if not _reserve_execution(budget, unknown_sink=unknown_sink):
        return None
    run_timeout = _execution_timeout(budget, timeout)
    if run_timeout <= 0:
        return None
    control = oracle.run_sanitizer(
        binary,
        b"A" * 64,
        vector="file",
        timeout=run_timeout,
        executor=executor,
    )
    if not control.valid or control.crashed:
        return None
    candidates = [*(synth_candidates or []), *memsafe_candidates(verdict.input_example)]
    for cand in candidates:
        if not _reserve_execution(budget, unknown_sink=unknown_sink):
            break
        run_timeout = _execution_timeout(budget, timeout)
        if run_timeout <= 0:
            break
        r = oracle.run_sanitizer(
            binary,
            cand,
            vector="file",
            timeout=run_timeout,
            executor=executor,
        )
        if not r.valid or not r.crashed:
            continue
        if fixed is not None:
            if not _reserve_execution(budget, unknown_sink=unknown_sink):
                break
            run_timeout = _execution_timeout(budget, timeout)
            if run_timeout <= 0:
                break
            fr = oracle.run_sanitizer(
                str(fixed),
                cand,
                vector="file",
                timeout=run_timeout,
                executor=executor,
            )
            if not fr.valid:
                continue
            if fr.crashed and fr.sanitizer == r.sanitizer:
                continue  # patched build ALSO reports it -> false positive, skip
        kind = r.sanitizer or "sanitizer-error"
        capability = oracle.classify_crash(r.stderr)
        pov = PoV(
            input_bytes=cand,
            file_input=True,
            crash_class=kind,
            crash_trace=r.stderr[-400:],
            reproduced=True,
            capability=capability if capability != "unknown" else "crash",
            diff_allocator=(
                f"asan={kind} on file input (exit-code crash); benign control clean"
                + ("; fixed build clean" if fixed is not None else "")
            ),
            execution_provenance=dict(r.provenance),
        )
        pov.dedup_bucket = oracle.dedup_key(
            kind, [f"{finding.function}+{hex(finding.sink_addr)}"]
        )
        return pov
    return None


def _drive(
    runner: Runner,
    binary: str,
    source: str,
    payload: bytes,
    *,
    timeout: float = 5.0,
) -> ExecResult:
    """Feed `payload` through the input vector implied by the source function."""
    if source in ("argv", "getenv"):
        return runner.run(binary, argv=[payload.decode("latin-1")], timeout=timeout)
    # read/recv/fgets/gets/scanf -> stdin
    return runner.run(binary, stdin=payload, timeout=timeout)
