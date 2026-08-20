"""Stage orchestration — deterministic scheduler (DESIGN-NOTES Decision 1).

The full loop, wired end to end:

    ingest → Ghidra decompile/lift → #2 slice analyze → #3 foxguard pre-pass →
    #4 cheap→expensive LLM triage funnel → #5 angr concolic prune → #6 crash
    oracle → #7 PoV emit → #8 report,  then the M2 fuzzing complement:
    #16 harness synthesis → #15 AFL++ driver → #17 Driller assist → #6 oracle → #7.

When the Ghidra toolchain is present (the Docker image / a host Ghidra), it
decompiles, slices, unions foxguard hypotheses, ranks+triages, discharges with
angr, and confirms with the oracle; otherwise it cleanly reports stage 1 only.
Every engine stage is best-effort and falls through on choke — the spine never
blocks on an optional consult.

Breadth (M3): ingest classifies + routes ELF, Mach-O, and PE/PE32+ (#20). Dynamic
confirmation chooses its vector by arch/format: native or qemu-user for runnable
ELF, the **Qiling firmware lane** (#21) for MIPS/ARM ELF the host can't run, or an
explicit versioned execution adapter for a compatible remote/platform target.
Without such an adapter, PE and non-native Mach-O degrade honestly to static-only.

The M2 fuzzing stage runs as a COMPLEMENT to the static slice: when the slice
yields no confirmed PoV (or always, with ``ZEROVERSE_FORCE_FUZZ``), it synthesizes
harnesses for the recovered functions and fuzzes — finding bugs (guarded /
hand-rolled, no libc sink) that slice-then-intersect structurally misses. A
synthesized harness without a reproduced crash is an artifact, never a finding:
the no-PoV-no-finding gate holds.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from . import bugclasses, firmware
from .abi import normalize_arch
from .agent import LLM, MockLLM, TriageFunnel, Verdict
from .agentic import AgentVerdict
from .analyze import Finding, filter_findings, foxguard_union, scan
from .atomic_store import canonical_json_bytes, sha256_file
from .bugclasses import prime_bugclasses
from .cancellation import CancelledError
from .concolic import AngrConfig, AngrVerdict, angr_available, check_reachability, function_entry
from .dynamic import (
    CMDI_SINKS,
    MAX_CONFIRMATION_CANDIDATE_BYTES,
    MEMSAFE_SINKS,
    ConfirmationCandidate,
    SubprocessRunner,
    confirm,
    confirm_asan_file,
    supports_confirmation,
    supports_local_confirmation,
)
from .execution.contract import (
    EXECUTION_CONTRACT_VERSION,
    ExecutionBackend,
    ExecutionCapabilities,
    ExecutionEvidence,
    ExecutionRequest,
)
from .grounding import callgraph_from_meta, ground_verdict, grounding_enabled
from .ingest import Triage, triage
from .poc import write_pov_script
from .preflight import (
    BudgetTracker,
    RunBudget,
    RunPlan,
    RunProfile,
    probe_capabilities,
)
from .receipts import (
    ReceiptStore,
    StageIdentity,
    backend_toolchain_identity,
    dependency_tree_identity,
    engine_source_identity,
)
from .report import PoV
from .seedbugs import firmware_seeds_for_arch, prime_hypotheses, seeds_for_target
from .synthesize import synthesize_povs_diagnostic
from .taint import load_model

# Container formats whose decompile pipeline (slice + foxguard + triage + angr) is
# wired today. Dynamic confirmation additionally depends on the host being able to
# *run* (native/qemu-user) or *emulate* (Qiling firmware lane) the target —
# Mach-O and PE degrade to static-only (see ``abi.can_execute`` / the degrade note).
SUPPORTED_FORMATS: tuple[str, ...] = ("ELF", "Mach-O", "PE")

# Every M1 issue (#1-#9) plus the M2 fuzzing backbone (#15/#16/#17) is wired into
# the spine. Optional engines (foxguard, angr, AFL++) degrade gracefully when
# absent, but nothing is left stubbed-as-pending.
PENDING_STAGES: tuple[str, ...] = ()

TerminalState = Literal[
    "confirmed",
    "no-findings",
    "unsupported",
    "skipped",
    "infra-failed",
    "cancelled",
]
StageStatus = Literal["completed", "skipped", "unavailable", "failed", "cancelled"]
CandidateOutcomeStatus = Literal[
    "attempted",
    "rejected",
    "budget-skipped",
    "oracle-confirmed",
]
REQUIRED_STAGES: tuple[str, ...] = ("ingest", "decompile", "lift", "analyze", "reason")

MAX_ADAPTER_SYNTHESIS_CANDIDATES = 6
MAX_ADAPTER_SYNTHESIS_FINDINGS = 8
STRONG_UNKNOWN_SINK_MIN_SCORE = 0.6
_FUZZ_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class TriagedFinding:
    finding: Finding
    verdict: Verdict
    pov: PoV | None = None
    score: float = 0.0                 # #4 cheap-classifier rank score
    escalated: bool = False            # did it reach the expensive LLM agent?
    angr: AngrVerdict | None = None    # #5 concolic reachability verdict (if run)
    grounding: dict[str, Any] | None = None  # G1 structural-grounding verdict (opt-in)
    # CVE-KB novelty gate: {verdict, cve_ids, ...} — is this a KNOWN-CVE
    # re-discovery or NO-PUBLIC-RECORD? Populated when a KB mirror is configured
    # (ZEROVERSE_CVE_KB_DIR); None when no KB is available. Never "novel".
    novelty: dict[str, Any] | None = None


@dataclass
class StageOutcome:
    """One pipeline stage's outcome and the component that produced it."""

    stage: str
    status: StageStatus
    required: bool
    reason: str = ""
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass
class _ObservedExecutionBackend:
    """Preserve the execution contract while retaining failures it already degrades."""

    backend: ExecutionBackend
    failure_reason: str = ""
    failure_state: TerminalState | None = None
    name: str = field(init=False)
    capabilities: ExecutionCapabilities = field(init=False)

    def __post_init__(self) -> None:
        self.name = self.backend.name
        self.capabilities = self.backend.capabilities

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        try:
            evidence = self.backend.run(request)
        except (OSError, RuntimeError, ValueError) as exc:
            self.failure_reason = f"{self.name} executor raised {type(exc).__name__}"
            self.failure_state = "infra-failed"
            raise
        if evidence.status == "UNSUPPORTED":
            self.failure_reason = evidence.error or f"{self.name} returned UNSUPPORTED"
            self.failure_state = "unsupported"
        elif evidence.status in {"ERROR", "TIMEOUT"}:
            self.failure_reason = evidence.error or f"{self.name} returned {evidence.status}"
            self.failure_state = "infra-failed"
        elif not evidence.matches(request):
            self.failure_reason = f"{self.name} returned invalid or stale execution evidence"
            self.failure_state = "infra-failed"
        return evidence


@dataclass
class RunResult:
    triage: Triage
    stages_run: list[str] = field(default_factory=list)
    findings: list[TriagedFinding] = field(default_factory=list)
    note: str = ""
    # A RunResult is fail-closed until ``run`` terminalizes it. This default also
    # keeps direct construction backward-compatible while never implying a clean run.
    terminal_state: TerminalState = "infra-failed"
    status_reason: str = "scan did not complete"
    stage_outcomes: list[StageOutcome] = field(default_factory=list)
    # M7 #44: opt-in scheduler stats (per-lane LLM budget + cache + epoch
    # plan), populated only when ZEROVERSE_SCHEDULER=1; None on default path.
    scheduler: dict[str, Any] | None = None
    # Present only when the caller explicitly injected an execution adapter.
    # This is descriptive metadata, never an implicit authorization selector.
    execution: dict[str, Any] | None = None
    candidate_outcome_stage_index: int | None = None


def _stage_outcome(
    result: RunResult,
    stage: str,
    status: StageStatus,
    *,
    reason: str = "",
    provenance: dict[str, str] | None = None,
    required: bool | None = None,
) -> None:
    """Record one current outcome per stage without changing ``stages_run``."""
    outcome = StageOutcome(
        stage=stage,
        status=status,
        required=stage in REQUIRED_STAGES if required is None else required,
        reason=reason,
        provenance=dict(provenance or {}),
    )
    for index, current in enumerate(result.stage_outcomes):
        if current.stage == stage:
            result.stage_outcomes[index] = outcome
            return
    result.stage_outcomes.append(outcome)


def _record_preflight(result: RunResult, report: RunPlan) -> None:
    """Project typed capability evidence into the existing v1.5 stage contract."""
    result.stages_run.append("preflight")
    for name, capability in report.named_capabilities():
        _stage_outcome(
            result,
            f"preflight:{name}",
            "completed" if capability.available else "unavailable",
            required=capability.mandatory,
            reason=capability.detail,
            provenance={
                "component": "zeroverse.preflight",
                "capability": name,
                "profile": report.profile,
                "provider": capability.provider,
                "failure_disposition": capability.failure_disposition,
            },
        )
    _stage_outcome(
        result,
        "preflight",
        "completed" if not report.mandatory_failures else "failed",
        required=True,
        reason=(
            "all mandatory capabilities available"
            if not report.mandatory_failures
            else "mandatory capabilities unavailable: "
            + ", ".join(name for name, _ in report.mandatory_failures)
        ),
        provenance={
            "component": "zeroverse.preflight",
            "profile": report.profile,
            "selected_backend": report.selected_backend,
        },
    )


def _record_candidate(
    result: RunResult,
    index: int,
    finding: Finding,
    status: CandidateOutcomeStatus,
    reason: str,
    *,
    unknown_sink: bool = False,
    oracle_name: str = "",
) -> None:
    """Update one bounded aggregate candidate ledger in O(1)."""
    del index  # rank is deliberately excluded from stable v1.5 evidence identity
    outcome_index = result.candidate_outcome_stage_index
    if outcome_index is None:
        outcome_index = len(result.stage_outcomes)
        result.candidate_outcome_stage_index = outcome_index
        result.stage_outcomes.append(
            StageOutcome(
                stage="candidate-oracle",
                status="completed",
                required=False,
                reason="bounded candidate outcome ledger",
                provenance={
                    "component": "zeroverse.pipeline.candidate-oracle",
                    "attempted": "0",
                    "rejected": "0",
                    "budget-skipped": "0",
                    "oracle-confirmed": "0",
                    "sample_count": "0",
                },
            )
        )
    outcome = result.stage_outcomes[outcome_index]
    outcome.provenance[status] = str(int(outcome.provenance[status]) + 1)
    stable_key = (
        f"{finding.function}|{finding.source}|{finding.sink}|"
        f"{finding.sink_addr}|{finding.origin}"
    )
    stable_id = hashlib.sha256(stable_key.encode()).hexdigest()[:16]
    sample = {
        "id": stable_id,
        "outcome": status,
        "unknown_sink": unknown_sink,
        "oracle": oracle_name,
        "reason": reason,
    }
    samples: dict[str, dict[str, object]] = {}
    for key, value in tuple(outcome.provenance.items()):
        if not key.startswith("sample_") or key == "sample_count":
            continue
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            current = json.loads(value)
            if isinstance(current, dict) and isinstance(current.get("id"), str):
                samples[current["id"]] = current
        del outcome.provenance[key]
    samples.setdefault(stable_id, sample)
    for sample_index, sample_id in enumerate(sorted(samples)[:16]):
        outcome.provenance[f"sample_{sample_index:02d}"] = json.dumps(
            samples[sample_id],
            sort_keys=True,
            separators=(",", ":"),
        )
    outcome.provenance["sample_count"] = str(min(len(samples), 16))


def _strong_unknown_sink(ranked: Any) -> bool:
    finding = ranked.finding
    verdict = ranked.verdict
    return bool(
        finding.origin == "slice"
        and finding.sink not in CMDI_SINKS
        and finding.sink not in MEMSAFE_SINKS
        and verdict.is_real
        and ranked.escalated
        and ranked.score >= STRONG_UNKNOWN_SINK_MIN_SCORE
    )


def _terminalize(result: RunResult) -> None:
    """Assign exactly one fail-closed terminal state after all pipeline work."""
    recorded_stages = {outcome.stage for outcome in result.stage_outcomes}
    for stage in result.stages_run:
        if stage not in recorded_stages:
            result.stage_outcomes.append(
                StageOutcome(
                    stage=stage,
                    status="completed",
                    required=stage in REQUIRED_STAGES,
                    provenance={"component": "zeroverse.pipeline"},
                )
            )
            recorded_stages.add(stage)

    confirmed = sum(
        1
        for finding in result.findings
        if finding.pov is not None and finding.pov.reproduced
    )
    if confirmed:
        result.terminal_state = "confirmed"
        noun = "finding has" if confirmed == 1 else "findings have"
        result.status_reason = f"{confirmed} {noun} a replay-confirmed PoV"
        return

    # These states can only be selected explicitly by the point that knows why the
    # entire scan did not run. They are not inferred from an optional lane skip.
    if result.terminal_state in ("unsupported", "skipped", "cancelled"):
        return
    if result.terminal_state == "infra-failed" and result.status_reason != "scan did not complete":
        return

    required = {
        outcome.stage: outcome
        for outcome in result.stage_outcomes
        if outcome.required
    }
    incomplete = [
        stage for stage in REQUIRED_STAGES
        if stage not in required or required[stage].status != "completed"
    ]
    incomplete.extend(
        stage
        for stage, outcome in required.items()
        if stage not in REQUIRED_STAGES and outcome.status != "completed"
    )
    if incomplete:
        result.terminal_state = "infra-failed"
        if result.status_reason == "scan did not complete":
            first = required.get(incomplete[0])
            result.status_reason = (
                f"{first.stage} {first.status}: {first.reason}"
                if first is not None and first.reason
                else "required stage incomplete: " + ", ".join(incomplete)
            )
        return

    result.terminal_state = "no-findings"
    result.status_reason = "required stages completed; no replay-confirmed PoV"


def _conf_dir() -> Path:
    return Path(os.environ.get("ZEROVERSE_CONF", "conf"))


# --- #224 sub-gap (c): incremental stage-progress mirror ----------------------
#
# A driver that wraps the pipeline in a hard wall-clock timeout (the magma eval
# child, ``benchmarks/magma/run.py --scan-one``) gets its result JSON only when
# the pipeline RETURNS — a timeout SIGKILL left no output and no log,
# indistinguishable from a hang. With ``ZEROVERSE_PROGRESS_PATH`` set, every
# stage transition appends one NDJSON record (stage, stages so far,
# findings/confirmed counts) so the parent can report WHERE a killed scan
# stood. Opt-in; a progress write never raises into the pipeline.


def _progress_path() -> Path | None:
    v = os.environ.get("ZEROVERSE_PROGRESS_PATH", "").strip()
    return Path(v) if v else None


class _ProgressStages(list[str]):
    """``stages_run`` list that mirrors every stage transition to the opt-in
    progress file. Hooking the list (instead of each append site) covers every
    current and future stage, including the ones appended from helper functions
    (``_run_fuzz_complement``). Emission happens on ``append``/``extend`` — use
    those, not ``+=`` (the inherited C-level ``__iadd__`` bypasses the hook)."""

    def __init__(self, result: RunResult) -> None:
        super().__init__()
        self._result = result

    def _emit(self, stage: str) -> None:
        p = _progress_path()
        if p is None:
            return
        try:
            confirmed = sum(
                1 for tf in self._result.findings
                if tf.pov is not None and tf.pov.reproduced
            )
            rec = {
                "ts": round(time.monotonic(), 1),
                "stage": stage,
                "stages_run": list(self),
                "findings": len(self._result.findings),
                "confirmed": confirmed,
            }
            with p.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        except (OSError, TypeError, ValueError):
            pass

    def append(self, stage: str) -> None:
        super().append(stage)
        self._emit(stage)

    def extend(self, stages: Iterable[str]) -> None:
        for s in stages:
            self.append(s)


def _decompile_receipt_identity(
    path: str | Path,
    *,
    plan: RunPlan,
    profile: RunProfile,
    bug_class: str,
    timeout: int,
) -> StageIdentity:
    from .backends import contract

    backend_sources: list[str | Path] = [__file__, contract.__file__]
    resolved = plan.resolved_backend
    concrete = getattr(resolved, "backend", resolved)
    module = __import__(type(concrete).__module__, fromlist=["__name__"])
    module_file = getattr(module, "__file__", None)
    if module_file:
        backend_sources.append(module_file)
    return StageIdentity(
        stage="decompile",
        stage_schema="zeroverse.pipeline.decompile/v1",
        input_sha256=sha256_file(path),
        options={
            "profile": profile,
            "bug_class": bug_class,
            "selected_backend": plan.selected_backend,
            "timeout": timeout,
        },
        engine=engine_source_identity(*backend_sources),
        backend=backend_toolchain_identity(
            plan.selected_backend,
            plan.backend.provider,
        ),
        dependencies={"configuration": dependency_tree_identity(_conf_dir())},
    )


def _adapter_json(adapter: object) -> bytes | None:
    serializer = getattr(adapter, "to_json", None)
    if callable(serializer):
        try:
            value = serializer()
            return value.encode() if isinstance(value, str) else None
        except (TypeError, ValueError):
            return None
    try:
        from .backends.ghidra import GhidraAdapter

        compatible = GhidraAdapter(
            list(adapter.all_insts()),  # type: ignore[attr-defined]
            dict(adapter._defs),  # type: ignore[attr-defined]
            dict(adapter._mem),  # type: ignore[attr-defined]
            dict(adapter._callers),  # type: ignore[attr-defined]
            dict(adapter._returns),  # type: ignore[attr-defined]
            meta=adapter.meta,  # type: ignore[attr-defined]
        )
        return compatible.to_json().encode()
    except (AttributeError, TypeError, ValueError):
        return None


def _resume_decompile(
    store: ReceiptStore,
    identity: StageIdentity,
    backend_name: str,
) -> object | None:
    receipt = store.load(identity)
    if receipt is None:
        return None
    try:
        from .backends.ghidra import GhidraAdapter

        payload = json.loads(receipt.sidecars["adapter.json"])
        if not isinstance(payload, dict):
            return None
        adapter = GhidraAdapter.from_json(payload)
        adapter._backend = backend_name  # type: ignore[attr-defined]
        return adapter
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _record_decompile_receipt(
    store: ReceiptStore,
    identity: StageIdentity,
    adapter: object,
    *,
    backend_name: str,
    budget: BudgetTracker,
) -> None:
    serialized = _adapter_json(adapter)
    if serialized is None or budget.expired():
        return
    with contextlib.suppress(OSError, TypeError, ValueError):
        store.write_completed(
            identity,
            {"backend": backend_name, "adapter_schema": "ghidra-export/v1"},
            sidecars={"adapter.json": serialized},
            provenance={
                "component": "zeroverse.pipeline",
                "backend": backend_name,
                "resumable": "true",
            },
            context=budget.run_context,
        )


def _try_ghidra(
    path: str | Path,
    *,
    backend: Any = None,
    timeout: int = 120,
) -> object | None:
    """Analyze with a resolved backend, retaining string selection compatibility."""
    from .backends import contract

    if backend is not None and not isinstance(backend, str):
        return contract.analyze_selected(backend, path, timeout=timeout)
    return contract.analyze(path, name=backend, timeout=timeout)


def _local_execution_unavailable() -> str:
    """Return the configured local execution boundary's fail-closed reason, if any."""
    from .sandbox_exec import DisabledExecutor, current_executor

    executor = current_executor()
    return executor.reason if isinstance(executor, DisabledExecutor) else ""


def _angr_cfg() -> AngrConfig:
    cfg = AngrConfig()
    env = os.environ.get("ZEROVERSE_ANGR_TIMEOUT")
    if env:
        with contextlib.suppress(ValueError):
            cfg.timeout_s = float(env)
    return cfg


def _flywheel_priming(
    findings: list[Finding], features: dict[str, Any], bug_class: str
) -> tuple[Any, bool] | None:
    """M7 #43 — build the opt-in flywheel priming for this run, or None when the
    flywheel is disabled. Returns ``(Priming, downgrade_to_cheap)`` where the second
    flag is the cost-router's verdict: only downgrade (skip the expensive LLM) when a
    *non-empty* corpus confidently saw nothing similar — never on an empty store.
    Best-effort: any failure degrades to None (the cold funnel runs unchanged)."""
    from . import flywheel

    if not flywheel.flywheel_enabled():
        return None
    try:
        fw = flywheel.Flywheel(dataset_path=os.environ.get("ZEROVERSE_DATASET_PATH"))
        query = flywheel.query_from_findings(features, findings, bug_class=bug_class)
        prm = fw.prime(query)
        downgrade = (not prm.active) and fw.episodic_loaded > 0
        return prm, downgrade
    except Exception:
        return None


def run(
    path: str | Path,
    *,
    bug_class: str = "memory-safety",
    llm: LLM | None = None,
    backend: str | None = None,
    confirm_binary: str | Path | None = None,
    execution_backend: ExecutionBackend | None = None,
    profile: RunProfile = "analysis",
    budget: RunBudget | None = None,
    output_dir: str | Path | None = None,
) -> RunResult:
    """M7 #48 — public entrypoint: run the spine, then collapse same-bug findings
    so a unique bug is reported once (a slice-confirmed and a fuzz-confirmed
    crash of the SAME root cause no longer double-count). PoV-is-truth is
    untouched: dedup only groups already-confirmed crashes; a distinct or
    frameless finding always survives.

    LOCATE/CONFIRM split (binarygym #51): ``path`` is the binary the pipeline
    *decompiles and analyzes* (LOCATE); ``confirm_binary``, when given, is a
    *behaviourally equivalent* build the dynamic oracle *executes* to confirm a
    PoV (CONFIRM). This exists because an ASan-instrumented libFuzzer target
    decompiles to pseudo-C buried in ``__asan_stack_malloc`` / shadow-memory
    scaffolding (WriteCLUT: ~300 lines vs ~36 for a clean build), so LOCATE runs
    on a clean (non-ASan) rebuild while CONFIRM keeps the ASan build's precise
    crash oracle. ``confirm_binary=None`` (default) points both at ``path`` — the
    existing single-binary behaviour, byte-for-byte."""
    if profile not in {"analysis", "confirmation", "fuzz"}:
        raise ValueError(f"unsupported run profile: {profile}")
    tracker = BudgetTracker.start(budget or RunBudget())
    result = _run_pipeline(
        path,
        bug_class=bug_class,
        llm=llm,
        backend=backend,
        confirm_binary=confirm_binary,
        execution_backend=execution_backend,
        profile=profile,
        budget=tracker,
        output_dir=output_dir,
    )
    _dedup_result(result)
    _annotate_novelty(result)
    _terminalize(result)
    _record_terminal_receipt(
        path,
        result,
        bug_class=bug_class,
        backend=backend,
        profile=profile,
        budget=tracker,
        output_dir=output_dir,
    )
    return result


def _record_terminal_receipt(
    path: str | Path,
    result: RunResult,
    *,
    bug_class: str,
    backend: str | None,
    profile: RunProfile,
    budget: BudgetTracker,
    output_dir: str | Path | None,
) -> None:
    """Retain terminal/stage/PoV evidence as hash-verified audit sidecars."""
    if result.terminal_state in {"cancelled", "infra-failed"} or budget.expired():
        return
    try:
        input_sha256 = sha256_file(path)
    except OSError:
        return
    selected_backend = next(
        (
            outcome.provenance.get("selected_backend", "")
            for outcome in result.stage_outcomes
            if outcome.stage == "preflight"
        ),
        backend or "auto",
    )
    decompile_key = next(
        (
            outcome.provenance.get("receipt_key", "")
            for outcome in result.stage_outcomes
            if outcome.stage == "decompile"
        ),
        "",
    )
    identity = StageIdentity(
        stage="terminal",
        stage_schema="zeroverse.pipeline.terminal/v1",
        input_sha256=input_sha256,
        options={
            "profile": profile,
            "bug_class": bug_class,
            "backend": backend or "auto",
            "attempt_limit": budget.budget.attempt_limit,
            "unknown_sink_oracle_attempts": (
                budget.budget.unknown_sink_oracle_attempts
            ),
            "fuzz_complement_attempts": budget.budget.fuzz_attempt_limit,
        },
        engine=engine_source_identity(__file__),
        backend=backend_toolchain_identity(selected_backend),
        dependencies={"decompile_receipt": decompile_key},
    )
    stages = [
        {
            "stage": outcome.stage,
            "status": outcome.status,
            "required": outcome.required,
            "reason": outcome.reason,
            "provenance": outcome.provenance,
        }
        for outcome in result.stage_outcomes
    ]
    sidecars: dict[str, bytes] = {
        "terminal.json": canonical_json_bytes(
            {
                "state": result.terminal_state,
                "reason": result.status_reason,
                "note": result.note,
            }
        ),
        "stages.json": canonical_json_bytes(stages),
    }
    pov_count = 0
    for finding in result.findings:
        pov = finding.pov
        if pov is None or not pov.reproduced:
            continue
        prefix = f"pov-{pov_count:03d}"
        if pov.input_bytes is not None:
            sidecars[f"{prefix}.input.bin"] = pov.input_bytes
        sidecars[f"{prefix}.replay.json"] = canonical_json_bytes(
            {
                "argv": pov.argv,
                "env": pov.env,
                "file_input": pov.file_input,
                "reproduced": pov.reproduced,
                "crash_class": pov.crash_class,
                "execution_provenance": pov.execution_provenance,
            }
        )
        sidecars[f"{prefix}.stdout.txt"] = b""
        sidecars[f"{prefix}.stderr.txt"] = b""
        sidecars[f"{prefix}.combined-output.txt"] = pov.crash_trace.encode(
            "utf-8", "replace"
        )
        pov_count += 1
    store = ReceiptStore(
        Path(output_dir or os.environ.get("ZEROVERSE_OUT", "0verse-out"))
        / ".receipts"
    )
    with contextlib.suppress(OSError, TypeError, ValueError):
        store.write_completed(
            identity,
            {
                "terminal_state": result.terminal_state,
                "confirmed_povs": pov_count,
            },
            sidecars=sidecars,
            provenance={
                "component": "zeroverse.pipeline",
                "stdio": "combined output retained; separate streams unavailable",
            },
            context=budget.run_context,
        )


def _annotate_novelty(result: RunResult) -> None:
    """CVE-KB novelty gate (best-effort): flag KNOWN-CVE re-discoveries on every
    finding when a KB mirror is configured (``ZEROVERSE_CVE_KB_DIR``). No-ops
    cleanly when no KB is available; never breaks a scan; never drops a finding."""
    with contextlib.suppress(Exception):
        from .cve_kb.scan_gate import annotate_run

        annotate_run(result)


def _dedup_result(result: RunResult) -> None:
    """Collapse same-bug-different-input findings in place (M7 #48)."""
    from .dedup import CrashKey, dedup_items

    def key_of(tf: TriagedFinding) -> CrashKey:
        pov = tf.pov
        frames = tuple(pov.frames) if (pov is not None and pov.reproduced) else ()
        addr = hex(getattr(tf.finding, "sink_addr", 0) or 0)
        return CrashKey(crash_addr=addr, frames=frames)

    reps, _ = dedup_items(result.findings, key_of=key_of)
    result.findings = reps


def _run_pipeline(
    path: str | Path,
    *,
    budget: BudgetTracker,
    bug_class: str = "memory-safety",
    llm: LLM | None = None,
    backend: str | None = None,
    confirm_binary: str | Path | None = None,
    execution_backend: ExecutionBackend | None = None,
    profile: RunProfile = "analysis",
    output_dir: str | Path | None = None,
) -> RunResult:
    t = triage(path)
    result = RunResult(triage=t)
    result.stages_run = _ProgressStages(result)
    result.stages_run.append("ingest")
    _stage_outcome(
        result,
        "ingest",
        "completed",
        provenance={
            "component": "zeroverse.ingest.triage",
            "format": t.fmt,
            "arch": t.arch,
        },
    )
    if execution_backend is not None:
        result.execution = {
            "contract_version": EXECUTION_CONTRACT_VERSION,
            "backend": execution_backend.name,
            "capabilities": execution_backend.capabilities.to_dict(),
        }

    requested_output_dir = Path(
        output_dir or os.environ.get("ZEROVERSE_OUT", "0verse-out")
    )
    confirmation_path = Path(confirm_binary) if confirm_binary is not None else Path(path)
    confirmation_triage = t if confirmation_path == Path(path) else triage(confirmation_path)
    preflight = probe_capabilities(
        t,
        confirmation_triage=confirmation_triage,
        confirmation_path=confirmation_path,
        profile=profile,
        requested_backend=backend,
        execution_backend=execution_backend,
        output_dir=requested_output_dir,
        budget=budget,
        supported_formats=SUPPORTED_FORMATS,
    )
    _record_preflight(result, preflight)
    disposition = preflight.disposition
    if disposition != "ready":
        if disposition == "unsupported" and not preflight.target_format.available:
            result.note = (
                f"{t.fmt}: the decompile pipeline supports {', '.join(SUPPORTED_FORMATS)}"
            )
            _stage_outcome(
                result,
                "decompile",
                "skipped",
                reason=result.note,
                provenance={"component": "zeroverse.pipeline.format-gate"},
            )
        elif disposition == "infra-failed" and not preflight.backend.available:
            from .backends import contract

            result.note = contract.selection_note(backend)
            _stage_outcome(
                result,
                "decompile",
                "unavailable",
                reason=result.note,
                provenance={
                    "component": "zeroverse.backends.contract",
                    "requested_backend": backend
                    or os.environ.get("ZEROVERSE_BACKEND", "auto"),
                },
            )
        result.terminal_state = disposition
        result.status_reason = result.note or preflight.failure_reason
        return result

    out_dir = preflight.output_dir
    session = _scheduler_session()  # M7 #44 — None unless ZEROVERSE_SCHEDULER=1

    # LOCATE/CONFIRM split (#51): preflight planned the actual confirmation artifact.
    confirm_path: str | Path = preflight.confirmation_path

    remaining = budget.remaining_seconds()
    if remaining < 1.0:
        _stage_outcome(
            result,
            "decompile",
            "cancelled",
            required=True,
            reason="less than one second remained for the selected backend",
            provenance={"component": "zeroverse.backends.contract"},
        )
        result.terminal_state = "cancelled"
        result.status_reason = "wall-clock budget exhausted before decompilation"
        return result
    backend_timeout = min(120, int(remaining))
    receipt_store = ReceiptStore(out_dir / ".receipts")
    receipt_identity = _decompile_receipt_identity(
        path,
        plan=preflight,
        profile=profile,
        bug_class=bug_class,
        timeout=backend_timeout,
    )
    adapter = _resume_decompile(
        receipt_store,
        receipt_identity,
        preflight.selected_backend,
    )
    decompile_resumed = adapter is not None
    if adapter is None:
        try:
            adapter = _try_ghidra(
                path,
                backend=preflight.resolved_backend,
                timeout=backend_timeout,
            )
        except CancelledError:
            _stage_outcome(
                result,
                "decompile",
                "cancelled",
                required=True,
                reason=budget.run_context.reason,
                provenance={"component": "zeroverse.process_boundary"},
            )
            result.terminal_state = "cancelled"
            result.status_reason = budget.run_context.reason
            return result
    if adapter is None:
        from .backends import contract

        result.note = contract.selection_note(preflight.selected_backend)
        _stage_outcome(
            result,
            "decompile",
            "unavailable",
            reason=result.note,
            provenance={
                "component": "zeroverse.backends.contract",
                "requested_backend": preflight.selected_backend,
            },
        )
        result.status_reason = result.note
        return result

    if budget.expired():
        _stage_outcome(
            result,
            "decompile",
            "cancelled",
            required=True,
            reason=budget.exhaustion_reason(),
            provenance={"component": "zeroverse.backends.contract"},
        )
        result.terminal_state = "cancelled"
        result.status_reason = budget.exhaustion_reason()
        return result

    if not decompile_resumed:
        _record_decompile_receipt(
            receipt_store,
            receipt_identity,
            adapter,
            backend_name=preflight.selected_backend,
            budget=budget,
        )

    if t.fmt == "PE" and getattr(adapter, "_backend", "ghidra") == "ghidra":
        from .pe_symbols import enrich_ghidra_symbols

        recovered = enrich_ghidra_symbols(adapter, path)
        if recovered:
            result.note = f"PDB symbols recovered: {recovered} functions"

    insts = adapter.all_insts()  # type: ignore[attr-defined]
    meta = getattr(adapter, "meta", None)
    decompiled = getattr(meta, "decompiled_c", {}) if meta else {}

    # Record which decompiler backend produced the IL (#27). The non-Ghidra
    # backends mine a lower-fidelity IL from pseudo-C — flagged honestly here so a
    # consumer knows the slice degraded (no SSA def-use, no per-sink addresses).
    backend_name = getattr(adapter, "_backend", "ghidra")
    if backend_name != "ghidra":
        bnote = (f"decompiler backend: {backend_name} (non-Ghidra fallback — "
                 "pseudo-C IL, lower fidelity; angr reachability stage skipped)")
        result.note = f"{result.note} | {bnote}" if result.note else bnote

    # Consume the execution route resolved against the actual confirmation artifact.
    abi = preflight.confirmation_abi
    arch = abi.arch if abi else normalize_arch(confirmation_triage.arch, confirmation_triage.bits)
    runnable = preflight.confirmation_runnable
    qiling_lane = preflight.execution_route == "qiling"
    adapter_owns_execution = preflight.adapter_owns_execution
    adapter_compatible = preflight.adapter_compatible
    observed_executor = (
        _ObservedExecutionBackend(execution_backend)
        if adapter_compatible and execution_backend is not None
        else None
    )

    # ASan/libFuzzer file-input lane: an AddressSanitizer-instrumented libFuzzer
    # target takes its PoC as a FILE (argv[1]) and "crashes" via an ASan report at
    # a non-zero *exit* (not a native signal on stdin). Recognize it as runnable —
    # even when ``can_execute`` conservatively says no (e.g. an i386 target the
    # x86-64 host can still exec natively) — so the dynamic confirm stage engages
    # via the sanitizer-report oracle instead of degrading to hypotheses-only. The
    # native-stdin corpus is unaffected: this lane fires only for ASan file targets.
    # ASan-ness is a property of the CONFIRM build (the ASan target the oracle
    # executes), not the LOCATE build — which under the split is a clean rebuild.
    asan_file = preflight.target_instrumented
    # An explicit compatible adapter is an authorization/routing decision. Never
    # bypass it by launching the same browser/PE harness locally merely because
    # this coordinator happens to support its container/architecture.
    asan_runnable = asan_file and preflight.local_executor_available

    findings = scan(adapter, load_model(_conf_dir()), insts)  # type: ignore[arg-type]
    result.stages_run.extend(["decompile", "lift", "analyze"])
    backend_provenance = {
        "component": "zeroverse.backends.contract",
        "backend": backend_name,
        "receipt": "resumed" if decompile_resumed else "recorded",
        "receipt_key": receipt_identity.key,
    }
    for stage in ("decompile", "lift", "analyze"):
        _stage_outcome(result, stage, "completed", provenance=backend_provenance)

    # #3 foxguard static pre-pass — union its hits as hypotheses (graceful stub).
    findings, fox_note = foxguard_union(findings, decompiled)
    result.stages_run.append("foxguard-prepass")
    if fox_note:
        result.note = f"{result.note} | {fox_note}" if result.note else fox_note

    # M3 XNU/IOKit fold-in — point-at-a-kext primes the IOKit seed-bug-class and
    # frames the funnel with variant analysis (seedbugs.py).
    seeds = seeds_for_target(t.fmt, t.kind, decompiled)
    # Firmware lane (#21): a MIPS/ARM firmware ELF (not a .ko) primes the
    # unauth-getter->shell / getter->unbounded-copy firmware seed-classes.
    if t.fmt == "ELF" and t.kind != "KMOD":
        seeds = [*seeds, *firmware_seeds_for_arch(arch)]
    seed_framing: str | None = None
    if seeds:
        primed: list[Finding] = []
        for s in seeds:
            primed += prime_hypotheses(s, decompiled)
        covered = {(f.function, f.origin) for f in findings}
        new_primed = [f for f in primed if (f.function, f.origin) not in covered]
        findings += new_primed
        seed_framing = seeds[0].framing
        result.stages_run.append("seed-prime")
        ids = ", ".join(s.id for s in seeds)
        kindlabel = (
            "IOKit" if t.fmt == "Mach-O"
            else "firmware" if any(sd.id.startswith("firmware:") for sd in seeds)
            else "kernel-module"
        )
        snote = (
            f"seed-bug-class [{ids}]: {len(new_primed)} primed {kindlabel} hypotheses"
        )
        result.note = f"{result.note} | {snote}" if result.note else snote

    # M4 bug-class lenses (#22-#26) — union tagged hypotheses (origin
    # ``bugclass:<id>``) over the decompiled C: intoverflow / fmtstring / uaf /
    # cmdi (confirmable) + logic (honest hypothesis-only). High-recall by design;
    # the funnel ranks them and the confirmable ones route to their oracle below.
    bc_hyps = prime_bugclasses(
        decompiled, callgraph=getattr(meta, "callgraph", None)
    )
    seen_bc = {(f.function, f.sink, f.origin) for f in findings}
    new_bc = [f for f in bc_hyps if (f.function, f.sink, f.origin) not in seen_bc]
    findings += new_bc
    if new_bc:
        result.stages_run.append("bugclass-lens")
        classes = sorted({f.origin.split(":", 1)[1] for f in new_bc})
        bnote = f"M4 bug-class lenses: {len(new_bc)} hypotheses ({', '.join(classes)})"
        result.note = f"{result.note} | {bnote}" if result.note else bnote

    # libFuzzer target focus (feat/reachability-filter): a real ASan+libFuzzer
    # binary statically links the libFuzzer *driver*, which CALLS the target harness
    # (LLVMFuzzerTestOneInput). Findings in driver/runtime functions are false
    # positives — drop them by name (noise) and by reachability from the entry so
    # the queue lands in the target library. Gated to a no-op for small /
    # non-libFuzzer binaries (the toy corpus). See analyze.filter_findings.
    findings, focus_note = filter_findings(findings, meta)
    if focus_note:
        result.stages_run.append("libfuzzer-focus")
        result.note = f"{result.note} | {focus_note}" if result.note else focus_note

    # feat/llm-pseudoc-scan — LLM-driven bug-finding over the decompiled pseudo-C, as
    # a COMPLEMENT to the regex-shape lenses (not a replacement). The decompiler
    # mangles the source shape — cast indices, cursor (`do{}while(cur!=end)`) loops,
    # indirect callbacks — so a raw OOB store with no libc sink (and a function static
    # reachability can't even reach, because the dispatch edge is unresolved) slips
    # past every name/shape lens. Let the model read the semantics of the reachable
    # target functions the lenses did NOT flag and union its positive judgments as
    # hypotheses. Gated to the real-LLM lane (ZEROVERSE_LLM_SCAN) so the deterministic
    # MockLLM CI is untouched; PoV-is-truth still gates confirmation (the LLM proposes,
    # the oracle disposes — nothing here is upgraded to a finding without a crash).
    from . import llm_scan

    findings, ls_note = llm_scan.llm_scan_stage(findings, meta, llm)
    if ls_note:
        result.stages_run.append("llm-pseudoc-scan")
        result.note = _join_note(result.note, ls_note)

    # #4 cheap→expensive triage funnel over the whole #2+#3+seed+bugclass queue.
    base_llm = llm or MockLLM()
    triage_llm = session.wrap_llm(base_llm) if session is not None else base_llm

    # M7 #43 — opt-in flywheel priming (ZEROVERSE_FLYWHEEL=1, default OFF). Recall the
    # most-similar past concepts / PoVs and inject them as a variant-analysis framing
    # + a rank bonus over known-fruitful sinks, plus a cost-router hint. Memory PRIMES
    # ordering/budget only; the oracle below still adjudicates (PoV-is-truth).
    funnel_kwargs: dict[str, Any] = {"seed_bug_class": seed_framing}
    escalate_top = 8
    fly = _flywheel_priming(findings, {"format": t.fmt, "arch": arch, "bits": t.bits},
                            bug_class)
    if fly is not None:
        prm, downgrade = fly
        if prm.active:
            if prm.framing:
                funnel_kwargs["seed_bug_class"] = prm.framing
            funnel_kwargs["rank_bonus"] = prm.rank_bonus
        if downgrade:
            escalate_top = 0   # cost-router: no similar signal -> skip the expensive LLM
        result.stages_run.append("flywheel-prime")
        pnote = f"flywheel: {prm.cost_reason}"
        result.note = f"{result.note} | {pnote}" if result.note else pnote

    funnel = TriageFunnel(triage_llm, escalate_top=escalate_top, **funnel_kwargs)
    ranked = funnel.run(findings, lambda f: _decompiled_context(f, decompiled))
    result.stages_run.append("reason")
    if session is not None:
        _note_scheduler_signal(session, ranked, findings)

    # G1 structural-grounding gate (opt-in, ZEROVERSE_GROUND). Grounds the LLM's
    # STRUCTURAL premises (does this function call the sink? is it reachable from an
    # export? does it free anything?) against the disassembly call graph Ghidra
    # already recovered (meta.callgraph) — never re-runs Ghidra. A refuted premise
    # floors the reported severity; an unverifiable one caps it at low. The PoV
    # oracle below is untouched: a reproducing crash still overrides a static
    # refutation (execution truth beats the call graph). See
    # docs/GROUNDING.md.
    if grounding_enabled():
        cg = callgraph_from_meta(meta)
        for rh in ranked:
            gr = ground_verdict(rh.finding, rh.verdict, cg)
            rh.verdict.severity = gr.final_severity  # cap/floor; never raised
            rh.grounding = gr.to_dict()  # type: ignore[attr-defined]
        result.stages_run.append("grounding")

    use_angr = angr_available() and not os.environ.get("ZEROVERSE_NO_ANGR")
    # angr is a *symbolic* discharge, not native execution — CLE loads ELF and PE,
    # so it runs for both (Mach-O loading is less reliable, so we skip it there).
    # angr reachability (#5) keys on real sink VAs + the function entry. The Ghidra
    # backend recovers those; the rizin/angr pseudo-C backends carry only ordinal
    # addresses (cdecomp), so the stage is disabled for them — slice + oracle still run.
    angr_ok = use_angr and t.fmt in ("ELF", "PE") and backend_name == "ghidra"
    if not use_angr:
        angr_status: StageStatus = (
            "skipped" if os.environ.get("ZEROVERSE_NO_ANGR") else "unavailable"
        )
        angr_reason = (
            "disabled by ZEROVERSE_NO_ANGR"
            if angr_status == "skipped"
            else "angr toolchain unavailable"
        )
        _stage_outcome(
            result,
            "concolic",
            angr_status,
            reason=angr_reason,
            provenance={"component": "zeroverse.concolic"},
        )
    elif not angr_ok:
        _stage_outcome(
            result,
            "concolic",
            "skipped",
            reason="selected format or decompiler backend lacks address-level reachability",
            provenance={"component": "zeroverse.concolic", "backend": backend_name},
        )
    cfg = _angr_cfg()
    angr_ran = dynamic_ran = qiling_ran = adapter_ran = False
    local_execution_unavailable = ""
    adapter_synthesis_attempts = 0
    adapter_synthesis_capped = False
    confirmation_incomplete = False

    # Candidate magic prefixes for the Qiling firmware lane, mined from the slice's
    # string constants (the same dictionary the fuzzer uses to crack gates).
    qseeds = _qiling_seeds(decompiled) if qiling_lane else None
    asan_attempted = False  # drive the (target-level) ASan file probes at most once

    for candidate_index, rh in enumerate(ranked):
        f, verdict = rh.finding, rh.verdict
        angr_v: AngrVerdict | None = None
        pov: PoV | None = None
        unknown_sink = _strong_unknown_sink(rh)

        if not verdict.is_real:
            _record_candidate(
                result,
                candidate_index,
                f,
                "rejected",
                "triage verdict rejected candidate",
            )
            result.findings.append(_tf(f, verdict, None, rh, angr_v))
            continue

        if asan_runnable:
            # The sanitizer oracle is target-level, so only the first real candidate
            # consumes an attempt. Remaining candidates are explicitly rejected as
            # duplicates rather than disappearing from provenance.
            if asan_attempted:
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    "rejected",
                    "target-level ASan oracle already attempted",
                    unknown_sink=unknown_sink,
                    oracle_name="asan-file",
                )
                result.findings.append(_tf(f, verdict, None, rh, angr_v))
                continue
            asan_attempted = True
            local_execution_unavailable = (
                "" if preflight.local_executor_available else preflight.executor.detail
            )
            if local_execution_unavailable:
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    "rejected",
                    local_execution_unavailable,
                    unknown_sink=unknown_sink,
                    oracle_name="asan-file",
                )
                result.findings.append(_tf(f, verdict, None, rh, angr_v))
                continue
            if not budget.can_reserve(unknown_sink=unknown_sink):
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    "budget-skipped",
                    budget.exhaustion_reason(unknown_sink=unknown_sink),
                    unknown_sink=unknown_sink,
                    oracle_name="asan-file",
                )
                result.findings.append(_tf(f, verdict, None, rh, angr_v))
                continue
            attempts_before = budget.attempts_used
            failures_before = budget.reservation_failures
            synth = _synth_asan_candidates(f, verdict, decompiled, path, triage_llm)
            if synth:
                result.stages_run.append("input-synthesis")
            pov = confirm_asan_file(
                f,
                verdict,
                confirm_path,
                synth_candidates=synth,
                timeout=min(10.0, budget.remaining_seconds()),
                budget=budget,
                unknown_sink=unknown_sink,
                executor=preflight.local_executor,
            )
            dynamic_ran = budget.attempts_used > attempts_before
            if pov and pov.reproduced:
                pov.pov_script = _emit_script(out_dir, f, pov, confirm_path)
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    "oracle-confirmed",
                    "sanitizer oracle replayed a PoV",
                    unknown_sink=unknown_sink,
                    oracle_name="asan-file",
                )
            else:
                skipped = budget.reservation_failures > failures_before
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    "budget-skipped" if skipped else "attempted",
                    (
                        budget.exhaustion_reason(unknown_sink=unknown_sink)
                        if skipped
                        else "sanitizer oracle produced no replay-confirmed PoV"
                    ),
                    unknown_sink=unknown_sink,
                    oracle_name="asan-file",
                )
            result.findings.append(_tf(f, verdict, pov, rh, angr_v))
            continue

        if f.origin == "slice":
            if angr_ok and f.sink_addr:
                entry = function_entry(insts, f.function)
                if entry is not None:
                    if not budget.can_reserve(unknown_sink=unknown_sink):
                        _record_candidate(
                            result,
                            candidate_index,
                            f,
                            "budget-skipped",
                            budget.exhaustion_reason(unknown_sink=unknown_sink),
                            unknown_sink=unknown_sink,
                            oracle_name="angr",
                        )
                        result.findings.append(_tf(f, verdict, None, rh, angr_v))
                        continue
                    budget.reserve_attempt(unknown_sink=unknown_sink)
                    cfg.timeout_s = min(cfg.timeout_s, budget.remaining_seconds())
                    angr_v = check_reachability(path, entry, f.sink_addr, config=cfg)
                    angr_ran = True
                    if angr_v.pruned:
                        _record_candidate(
                            result,
                            candidate_index,
                            f,
                            "rejected",
                            "angr proved the sink unreachable",
                            unknown_sink=unknown_sink,
                            oracle_name="angr",
                        )
                        result.findings.append(_tf(f, verdict, None, rh, angr_v))
                        continue

            local_route = supports_local_confirmation(
                f,
                allow_unknown_sink=unknown_sink,
            )
            if not local_route and observed_executor is None:
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    "rejected",
                    "candidate lacks a supported oracle and strong unknown-sink signal",
                )
                result.findings.append(_tf(f, verdict, None, rh, angr_v))
                continue

            if qiling_lane:
                if not budget.can_reserve(unknown_sink=unknown_sink):
                    _record_candidate(
                        result,
                        candidate_index,
                        f,
                        "budget-skipped",
                        budget.exhaustion_reason(unknown_sink=unknown_sink),
                        unknown_sink=unknown_sink,
                        oracle_name="qiling",
                    )
                    result.findings.append(_tf(f, verdict, None, rh, angr_v))
                    continue
                attempts_before = budget.attempts_used
                failures_before = budget.reservation_failures
                entry = function_entry(insts, f.function)
                pov = firmware.qiling_confirm(
                    f,
                    confirm_path,
                    abi,
                    entry,
                    seeds=qseeds,
                    budget=budget,
                    unknown_sink=unknown_sink,
                    capabilities_resolved=True,
                    execution_authorized=preflight.afl_local_authorized,
                )
                qiling_ran = True
                dynamic_ran = dynamic_ran or budget.attempts_used > attempts_before
                if pov and pov.reproduced:
                    pov.pov_script = _emit_script(out_dir, f, pov, confirm_path)
                skipped = budget.reservation_failures > failures_before
                candidate_status: CandidateOutcomeStatus = (
                    "oracle-confirmed"
                    if pov and pov.reproduced
                    else "budget-skipped"
                    if skipped
                    else "attempted"
                )
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    candidate_status,
                    (
                        "Qiling oracle replayed a PoV"
                        if candidate_status == "oracle-confirmed"
                        else budget.exhaustion_reason(unknown_sink=unknown_sink)
                        if candidate_status == "budget-skipped"
                        else "Qiling oracle produced no replay-confirmed PoV"
                    ),
                    unknown_sink=unknown_sink,
                    oracle_name="qiling",
                )
            else:
                selected_executor = (
                    observed_executor
                    if observed_executor is not None
                    and supports_confirmation(
                        f,
                        observed_executor,
                        target_format=confirmation_triage.fmt,
                        allow_unknown_sink=unknown_sink,
                    )
                    else None
                )
                if (
                    not preflight.local_executor_available or not local_route
                ) and selected_executor is None:
                    _record_candidate(
                        result,
                        candidate_index,
                        f,
                        "rejected",
                        "no compatible target executor",
                        unknown_sink=unknown_sink,
                    )
                    result.findings.append(_tf(f, verdict, None, rh, angr_v))
                    continue
                if selected_executor is None:
                    local_execution_unavailable = (
                "" if preflight.local_executor_available else preflight.executor.detail
            )
                if local_execution_unavailable:
                    _record_candidate(
                        result,
                        candidate_index,
                        f,
                        "rejected",
                        local_execution_unavailable,
                        unknown_sink=unknown_sink,
                    )
                    result.findings.append(_tf(f, verdict, None, rh, angr_v))
                    continue
                oracle_name = (
                    selected_executor.name
                    if selected_executor is not None
                    else "local-differential-crash"
                )
                if not budget.can_reserve(unknown_sink=unknown_sink):
                    _record_candidate(
                        result,
                        candidate_index,
                        f,
                        "budget-skipped",
                        budget.exhaustion_reason(unknown_sink=unknown_sink),
                        unknown_sink=unknown_sink,
                        oracle_name=oracle_name,
                    )
                    result.findings.append(_tf(f, verdict, None, rh, angr_v))
                    continue

                attempts_before = budget.attempts_used
                failures_before = budget.reservation_failures
                candidate_inputs: tuple[ConfirmationCandidate, ...] = ()
                if (
                    selected_executor is not None
                    and llm is not None
                    and f.sink in MEMSAFE_SINKS
                ):
                    if adapter_synthesis_attempts < MAX_ADAPTER_SYNTHESIS_FINDINGS:
                        adapter_synthesis_attempts += 1
                        candidate_inputs, synthesis_note = _adapter_synthesis_candidates(
                            meta,
                            f,
                            verdict,
                            triage_llm,
                        )
                        if "structure-synthesis" not in result.stages_run:
                            result.stages_run.append("structure-synthesis")
                        result.note = _join_note(result.note, synthesis_note)
                    else:
                        adapter_synthesis_capped = True
                pov = confirm(
                    f,
                    verdict,
                    confirm_path,
                    runner=(
                        SubprocessRunner(preflight.local_executor)
                        if selected_executor is None
                        and preflight.local_executor is not None
                        else None
                    ),
                    executor=selected_executor,
                    target_format=confirmation_triage.fmt,
                    candidate_inputs=candidate_inputs,
                    allow_unknown_sink=unknown_sink,
                    timeout=budget.remaining_seconds(),
                    budget=budget,
                    compiler_path=preflight.native_compiler_path,
                    compiler_resolved=True,
                )
                dynamic_ran = dynamic_ran or budget.attempts_used > attempts_before
                adapter_ran = adapter_ran or selected_executor is not None
                if pov and pov.reproduced and selected_executor is None:
                    pov.pov_script = _emit_script(out_dir, f, pov, confirm_path)
                skipped = budget.reservation_failures > failures_before
                candidate_status = (
                    "oracle-confirmed"
                    if pov and pov.reproduced
                    else "budget-skipped"
                    if skipped
                    else "attempted"
                )
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    candidate_status,
                    (
                        "deterministic oracle replayed a PoV"
                        if candidate_status == "oracle-confirmed"
                        else budget.exhaustion_reason(unknown_sink=unknown_sink)
                        if candidate_status == "budget-skipped"
                        else "deterministic oracle produced no replay-confirmed PoV"
                    ),
                    unknown_sink=unknown_sink,
                    oracle_name=oracle_name,
                )
        elif (
            preflight.local_executor_available
            and not qiling_lane
            and f.origin in bugclasses.CONFIRMABLE_ORIGINS
        ):
            local_execution_unavailable = (
                "" if preflight.local_executor_available else preflight.executor.detail
            )
            if local_execution_unavailable:
                _record_candidate(
                    result,
                    candidate_index,
                    f,
                    "rejected",
                    local_execution_unavailable,
                    oracle_name="bugclass",
                )
            else:
                if not budget.can_reserve():
                    _record_candidate(
                        result,
                        candidate_index,
                        f,
                        "budget-skipped",
                        budget.exhaustion_reason(),
                        oracle_name="bugclass",
                    )
                else:
                    attempts_before = budget.attempts_used
                    failures_before = budget.reservation_failures
                    pov = bugclasses.confirm(
                        f,
                        verdict,
                        confirm_path,
                        budget=budget,
                        executor=preflight.local_executor,
                        compiler_path=preflight.native_compiler_path,
                        compiler_resolved=True,
                    )
                    dynamic_ran = budget.attempts_used > attempts_before
                    if pov and pov.reproduced:
                        pov.pov_script = _emit_script(out_dir, f, pov, confirm_path)
                    skipped = (
                        not pov and budget.reservation_failures > failures_before
                    )
                    candidate_status = (
                        "oracle-confirmed"
                        if pov and pov.reproduced
                        else "budget-skipped"
                        if skipped
                        else "attempted"
                    )
                    _record_candidate(
                        result,
                        candidate_index,
                        f,
                        candidate_status,
                        (
                            "bug-class oracle replayed a PoV"
                            if candidate_status == "oracle-confirmed"
                            else budget.exhaustion_reason()
                            if candidate_status == "budget-skipped"
                            else "bug-class oracle produced no replay-confirmed PoV"
                        ),
                        oracle_name="bugclass",
                    )
        else:
            _record_candidate(
                result,
                candidate_index,
                f,
                "rejected",
                "candidate has no executable deterministic oracle route",
            )
        result.findings.append(_tf(f, verdict, pov, rh, angr_v))

    if budget.expired():
        _stage_outcome(
            result,
            "deadline",
            "cancelled",
            required=True,
            reason="wall-clock budget exhausted during candidate evaluation",
            provenance={"component": "zeroverse.preflight.BudgetTracker"},
        )
        result.terminal_state = "cancelled"
        result.status_reason = "wall-clock budget exhausted during candidate evaluation"
        _finalize_scheduler(result, session)
        return result

    if profile == "confirmation":
        ledger_index = result.candidate_outcome_stage_index
        budget_skipped = bool(
            ledger_index is not None
            and int(result.stage_outcomes[ledger_index].provenance["budget-skipped"]) > 0
        )
        confirmation_incomplete = not dynamic_ran or budget_skipped
        if confirmation_incomplete:
            _stage_outcome(
                result,
                "dynamic",
                "skipped",
                required=True,
                reason=(
                    "confirmation attempt budget was insufficient"
                    if budget_skipped
                    else "no eligible candidate reached the requested confirmation lane"
                ),
                provenance={"component": "zeroverse.pipeline.candidate-oracle"},
            )
            result.status_reason = "requested confirmation lane did not complete"
            _finalize_scheduler(result, session)
            return result

    # G1 grounding — a reproducing PoV overrides a static refutation (below).
    if grounding_enabled():
        _pov_overrides_grounding(result.findings)

    if adapter_synthesis_capped:
        result.note = _join_note(
            result.note,
            "structure synthesis capped at the "
            f"{MAX_ADAPTER_SYNTHESIS_FINDINGS} highest-ranked compatible findings; "
            "generic boundary candidates retained for the remainder",
        )

    if angr_ran:
        result.stages_run.append("concolic")
        _stage_outcome(
            result,
            "concolic",
            "completed",
            provenance={"component": "zeroverse.concolic", "backend": "angr"},
        )
    elif angr_ok:
        _stage_outcome(
            result,
            "concolic",
            "skipped",
            reason="no eligible address-level finding requested reachability analysis",
            provenance={"component": "zeroverse.concolic", "backend": "angr"},
        )
    if qiling_ran:
        result.stages_run.append("qiling-emulate")
        _stage_outcome(
            result,
            "qiling-emulate",
            "completed",
            provenance={"component": "zeroverse.firmware", "backend": "qiling"},
        )
        if not dynamic_ran:
            _stage_outcome(
                result,
                "dynamic",
                "completed",
                reason="Qiling confirmation completed without a replayed PoV",
                provenance={"component": "zeroverse.firmware", "backend": "qiling"},
            )
    execution_failure = (
        observed_executor.failure_reason
        if adapter_ran and observed_executor is not None
        else ""
    )
    execution_failure_state = (
        observed_executor.failure_state
        if adapter_ran and observed_executor is not None
        else None
    )
    if adapter_ran and execution_failure:
        failed_status: StageStatus = (
            "unavailable" if execution_failure_state == "unsupported" else "failed"
        )
        execution_provenance = {
            "component": "zeroverse.execution",
            "backend": observed_executor.name if observed_executor is not None else "",
        }
        _stage_outcome(
            result,
            "execution-adapter",
            failed_status,
            reason=execution_failure,
            provenance=execution_provenance,
            required=True,
        )
        _stage_outcome(
            result,
            "dynamic",
            failed_status,
            reason=execution_failure,
            provenance=execution_provenance,
            required=True,
        )
        for stage in ("poc", "report"):
            _stage_outcome(
                result,
                stage,
                "skipped",
                reason="execution adapter did not produce valid confirmation evidence",
                provenance=execution_provenance,
            )
        result.terminal_state = execution_failure_state or "infra-failed"
        result.status_reason = f"execution-adapter {failed_status}: {execution_failure}"
    elif dynamic_ran and not confirmation_incomplete:
        if adapter_ran:
            result.stages_run.append("execution-adapter")
            _stage_outcome(
                result,
                "execution-adapter",
                "completed",
                provenance={
                    "component": "zeroverse.execution",
                    "backend": observed_executor.name if observed_executor is not None else "",
                },
                required=True,
            )
        result.stages_run.extend(["dynamic", "poc", "report"])
        _stage_outcome(
            result,
            "dynamic",
            "completed",
            provenance={
                "component": "zeroverse.execution" if adapter_ran else "zeroverse.dynamic",
                **(
                    {"backend": observed_executor.name}
                    if adapter_ran and observed_executor
                    else {}
                ),
            },
            required=adapter_ran,
        )
    elif local_execution_unavailable:
        _stage_outcome(
            result,
            "dynamic",
            "unavailable",
            reason=local_execution_unavailable,
            provenance={"component": "zeroverse.sandbox_exec"},
        )

    # #9 PATCH STAGE (M7 #45/#46) — gated on ZEROVERSE_PATCH=1, iterates ONLY over
    # confirmed PoVs. Best-effort; attaches a Patch (located recommendation always,
    # verified source-diff / binary micro-patch when enabled) to each pov. An
    # explicit adapter owns placement, so local patch verification is unavailable.
    if not adapter_owns_execution and preflight.afl_local_authorized:
        _maybe_patch_budgeted(
            result,
            str(path),
            decompiled,
            llm,
            budget,
            preflight,
        )
    else:
        from .patch import patch_enabled

        if patch_enabled() and any(
            tf.pov is not None and tf.pov.reproduced for tf in result.findings
        ):
            _stage_outcome(
                result,
                "patch",
                "skipped",
                reason="selected execution provider does not authorize local patch verification",
                provenance={"component": "zeroverse.preflight"},
                required=True,
            )

    # The firmware Qiling lane IS the dynamic vector for this arch — it replaces
    # the native AFL complement (which needs arch-matched guard libs / a built
    # cross-arch afl-qemu-trace). Note honestly and return.
    if qiling_lane:
        result.note = _degrade_note(
            result.note,
            confirmation_triage.fmt,
            arch,
            qiling_lane=True,
        )
        _finalize_scheduler(result, session)
        return result

    # An explicit compatible adapter owns every dynamic target-execution lane,
    # even when no supported finding caused it to run. Never bypass its placement
    # and authorization decision by feeding the target into local AFL afterward.
    if adapter_owns_execution:
        assert execution_backend is not None
        adapter_outcome = (
            f"dynamic confirmation failed ({execution_failure})"
            if execution_failure
            else "dynamic confirmation ran"
            if adapter_ran
            else "no compatible finding requested dynamic confirmation"
        )
        if not adapter_ran:
            _stage_outcome(
                result,
                "dynamic",
                "skipped",
                reason=adapter_outcome,
                provenance={
                    "component": "zeroverse.execution",
                    "backend": execution_backend.name,
                },
            )
        result.note = _join_note(
            result.note,
            f"{confirmation_triage.fmt}/{arch}: explicit "
            f"{execution_backend.name} execution adapter "
            f"owns target execution; {adapter_outcome}; local AFL fuzz complement "
            "skipped",
        )
        _finalize_scheduler(result, session)
        return result

    if preflight.execution_route == "none":
        _stage_outcome(
            result,
            "dynamic",
            "unavailable",
            reason=preflight.executor.detail,
            provenance={"component": "zeroverse.preflight"},
        )
        _stage_outcome(
            result,
            "fuzz",
            "unavailable",
            reason="selected execution boundary has no local or remote target executor",
            provenance={"component": "zeroverse.preflight"},
        )
        result.note = _join_note(
            result.note,
            "local dynamic execution and AFL fuzzing unavailable at the selected boundary",
        )
        _finalize_scheduler(result, session)
        return result

    # Honest degrade: a target this host can neither execute nor emulate stays a
    # set of hypotheses (slice + foxguard + LLM triage [+ angr where CLE loads it]).
    if not runnable:
        if not dynamic_ran:
            _stage_outcome(
                result,
                "dynamic",
                "unavailable",
                reason=(
                    f"{confirmation_triage.fmt}/{arch} cannot execute on this host "
                    "without an adapter"
                ),
                provenance={"component": "zeroverse.dynamic"},
            )
        if asan_runnable and dynamic_ran:
            # The host could not run this via the arch/binfmt gate, but the ASan
            # file-input lane DID drive dynamic confirmation (sanitizer-report
            # oracle). Say so honestly rather than claiming static-only.
            result.note = _join_note(
                result.note,
                f"{arch}: ASan/libFuzzer file-input target — dynamic confirmation ran "
                "via the sanitizer-report oracle (file vector); native AFL fuzz "
                "complement skipped (no arch-matched guard/instrumentation libs)",
            )
        else:
            result.note = _degrade_note(
                result.note,
                confirmation_triage.fmt,
                arch,
                qiling_lane=False,
            )
        _finalize_scheduler(result, session)
        return result

    # --- M2 fuzzing complement (#15/#16/#17), arch-aware (#19) ----------------
    # M7 #44: under a tight scheduler time budget, skip this lane on a target
    # with NO slice signal (the eval's measured waste: ~30s fuzzing a clean
    # binary that confirms nothing). Default path / generous budget is unchanged.
    if not preflight.afl_local_authorized:
        if not preflight.local_executor_available:
            _stage_outcome(
                result,
                "dynamic",
                "unavailable",
                reason=preflight.executor.detail,
                provenance={"component": "zeroverse.sandbox_exec"},
            )
        _stage_outcome(
            result,
            "fuzz",
            "unavailable",
            reason="local AFL execution is not authorized by the selected boundary",
            provenance={"component": "zeroverse.sandbox_exec"},
            required=profile == "fuzz",
        )
    elif (
        profile != "fuzz"
        and session is not None
        and not session.should_run_fuzz()
    ):
        result.stages_run.append("scheduler-skip-fuzz")
        _stage_outcome(
            result,
            "fuzz",
            "skipped",
            reason="scheduler skipped the no-signal fuzz lane under a tight time budget",
            provenance={"component": "zeroverse.schedule"},
        )
        result.note = _join_note(
            result.note,
            "scheduler: skipped no-signal fuzz lane under tight time budget",
        )
    else:
        # The AFL complement executes/fuzzes the target — drive the CONFIRM build.
        # The backend-recovered call graph lets the fuzz selector rank targets by
        # attacker-reachability, not name shape (0verse#224 sub-gap (a)).
        _run_fuzz_complement(
            confirm_path,
            decompiled,
            result,
            out_dir,
            llm,
            arch=arch,
            callgraph=getattr(meta, "callgraph", None) if meta else None,
            budget=budget,
            plan=preflight,
            required=profile == "fuzz",
        )
        if result.terminal_state == "cancelled":
            _finalize_scheduler(result, session)
            return result
        # Patch any NEW confirmed PoVs the fuzz complement produced (idempotent
        # — the driver skips findings already carrying a patch).
        _maybe_patch_budgeted(
            result,
            str(path),
            decompiled,
            llm,
            budget,
            preflight,
        )
    _finalize_scheduler(result, session)
    return result


def _adapter_synthesis_candidates(
    meta: Any,
    finding: Finding,
    verdict: Verdict,
    llm: LLM,
) -> tuple[tuple[ConfirmationCandidate, ...], str]:
    """Generate bounded structured inputs for an explicitly selected executor."""
    synthesis_verdict = AgentVerdict(
        is_bug=verdict.is_real,
        cwe=verdict.bug_class,
        sink=finding.sink,
        source=finding.source,
        explanation=verdict.explanation,
    )
    batch = synthesize_povs_diagnostic(
        meta,
        synthesis_verdict,
        llm,
        n=MAX_ADAPTER_SYNTHESIS_CANDIDATES,
        visited=[finding.function],
        structural=True,
        max_candidate_bytes=MAX_CONFIRMATION_CANDIDATE_BYTES,
    )
    if batch.status == "backend-error":
        return (), (
            "structure synthesis backend failed "
            f"({batch.error_type or 'unknown error'}); generic boundary candidates retained"
        )
    if batch.status == "empty":
        return (), (
            "structure synthesis produced no decodable candidates; "
            "generic boundary candidates retained"
        )

    accepted = tuple(
        ConfirmationCandidate(candidate, "structure-aware-synthesis")
        for candidate in batch.candidates
        if len(candidate) <= MAX_CONFIRMATION_CANDIDATE_BYTES
    )
    filtered = len(batch.candidates) - len(accepted)
    if not accepted:
        return (), (
            "structure synthesis candidates exceeded the 1 MiB pipeline limit; "
            "generic boundary candidates retained"
        )
    note = f"structure synthesis supplied {len(accepted)} bounded candidate(s)"
    if filtered:
        note += f"; filtered {filtered} oversized candidate(s)"
    return accepted, note


def _maybe_patch_budgeted(
    result: RunResult,
    path: str,
    decompiled: dict[str, str],
    llm: LLM | None,
    budget: BudgetTracker,
    plan: RunPlan,
) -> None:
    """Run the planned local patch lane with per-operation budget enforcement."""
    from .patch import patch_enabled, run_patch_stage
    from .sandbox_exec import LocalExecutor

    pending = [
        tf
        for tf in result.findings
        if tf.pov is not None and tf.pov.reproduced and tf.pov.patch is None
    ]
    if not patch_enabled() or not pending:
        return
    provenance = {
        "component": "zeroverse.patch",
        "executor_provider": plan.executor.provider,
        "native_compiler": plan.native_compiler.provider,
        "output_dir": str(plan.output_dir),
    }
    if plan.adapter_owns_execution or not isinstance(plan.local_executor, LocalExecutor):
        _stage_outcome(
            result,
            "patch",
            "skipped",
            reason="selected execution provider does not authorize local patch verification",
            provenance=provenance,
            required=True,
        )
        return
    if not budget.can_reserve():
        _stage_outcome(
            result,
            "patch",
            "cancelled" if budget.expired() else "skipped",
            reason=f"patch stage budget exhausted: {budget.exhaustion_reason()}",
            provenance=provenance,
            required=True,
        )
        return

    failures_before = budget.reservation_failures
    attached = run_patch_stage(
        result,
        path,
        decompiled,
        llm=llm,
        output_dir=plan.output_dir,
        budget=budget,
        executor=plan.local_executor,
        executor_provider=plan.executor.provider,
        native_compiler_path=plan.native_compiler_path,
    )
    verified = sum(
        1
        for tf in pending
        if tf.pov is not None
        and tf.pov.patch is not None
        and tf.pov.patch.verified
    )
    exhausted = budget.reservation_failures > failures_before or (
        attached < len(pending) and not budget.can_reserve()
    )
    if exhausted:
        status: StageStatus = "cancelled" if budget.expired() else "skipped"
        reason = (
            f"patch stage stopped on budget exhaustion after attaching {attached} "
            f"result(s), {verified} verified"
        )
    elif attached == 0:
        status = "failed"
        reason = "patch stage produced no result for a replay-confirmed finding"
    else:
        status = "completed"
        reason = f"attached {attached} patch result(s), {verified} verified"
    _stage_outcome(
        result,
        "patch",
        status,
        reason=reason,
        provenance=provenance,
        required=True,
    )


def _degrade_note(note: str, fmt: str, arch: str, *, qiling_lane: bool) -> str:
    if qiling_lane:
        why = (
            f"{arch} firmware lane: dynamic confirmation routes through Qiling "
            "emulation (no arch-matched guard-allocator libs nor AFL cross-trace "
            "needed) — slice-recovered sinks are differential-confirmed by emulating "
            "the function; binwalk carves a real firmware image's rootfs upstream "
            "(firmware.unpack_firmware)"
        )
    elif fmt == "PE":
        why = (
            f"PE/{arch}: static-only on Linux — slice + foxguard + LLM triage "
            "(+ angr reachability where CLE loads the PE) run; full dynamic fuzzing "
            "needs WinAFL on a Windows host or a wine+qemu harness, so findings "
            "remain hypotheses (no fabricated crash)"
        )
    elif fmt == "Mach-O":
        why = (
            f"Mach-O/{arch}: static-only on this host — slice + foxguard + LLM triage"
            " run; dynamic confirmation (oracle/fuzz) needs a macOS/XNU host or "
            "emulator, so findings remain hypotheses"
        )
    else:
        why = f"{arch}: no native or qemu-user execution on this host — static-only"
    return f"{note} | {why}" if note else why


def _qiling_seeds(decompiled: dict[str, str]) -> list[bytes]:
    """Magic-gate prefixes for the Qiling lane, mined from the slice's string
    literals (reusing the fuzzer's dictionary extraction). Empty prefix is always
    tried so an ungated overflow is still reachable."""
    from .fuzz.aflpp import tokens_from_context

    seeds = [t.encode("latin-1", "replace") for t in tokens_from_context(*decompiled.values())]
    return [b"", *seeds][:8]


def _fuzz_priority_functions(findings: list[TriagedFinding]) -> list[str]:
    """Return stable, deduplicated native-probe targets in risk order."""
    candidates = [
        tf for tf in findings if getattr(tf.finding, "function", "")
    ]

    def risk_key(tf: TriagedFinding) -> tuple[int, int]:
        severity = _FUZZ_SEVERITY_RANK.get(tf.verdict.severity.lower(), 4)
        if tf.verdict.is_real and severity <= 1:
            return 0, severity
        if tf.verdict.is_real and severity <= 3:
            return 1, severity
        return 2, 0

    out: list[str] = []
    seen: set[str] = set()
    for tf in sorted(candidates, key=risk_key):
        func = tf.finding.function
        if func in seen:
            continue
        seen.add(func)
        out.append(func)
    return out


def _run_fuzz_complement(
    path: str | Path,
    decompiled: dict[str, str],
    result: RunResult,
    out_dir: Path,
    llm: LLM | None,
    *,
    budget: BudgetTracker,
    plan: RunPlan,
    arch: str = "",
    callgraph: dict[str, list[str]] | None = None,
    required: bool = False,
) -> None:
    """Synthesize harnesses + fuzz when the static slice confirmed nothing (or when
    forced). ``arch`` selects the cross-arch QEMU-mode trace (#19). ``callgraph`` is
    the backend-recovered edge set, used to rank fuzz targets by attacker-
    reachability. Only reproduced PoVs become findings — the gate holds."""
    from .fuzz.aflpp import AflConfig
    from .fuzz.orchestrator import _fuzz_duration, fuzz_enabled, run_fuzz_stage

    slice_confirmed = any(tf.pov and tf.pov.reproduced for tf in result.findings)
    shared_harness_requested = bool(os.environ.get("ZEROVERSE_FUZZ_SHARED_LIB"))
    if not plan.afl_local_authorized:
        _stage_outcome(
            result,
            "fuzz",
            "unavailable",
            reason="AFL execution disabled by selected execution boundary",
            provenance={"component": "zeroverse.sandbox_exec"},
            required=required,
        )
        return
    if plan.afl_path is None:
        _stage_outcome(
            result,
            "fuzz",
            "unavailable",
            reason="AFL++ toolchain unavailable",
            provenance={"component": "zeroverse.fuzz.aflpp"},
            required=required,
        )
        return
    if (
        not required
        and slice_confirmed
        and not fuzz_enabled()
        and not shared_harness_requested
    ):
        _stage_outcome(
            result,
            "fuzz",
            "skipped",
            reason="a replay-confirmed slice PoV made the fuzz complement optional",
            provenance={"component": "zeroverse.fuzz.orchestrator"},
            required=required,
        )
        return
    if not decompiled:
        _stage_outcome(
            result,
            "fuzz",
            "skipped",
            reason="no decompiled functions were available for harness synthesis",
            provenance={"component": "zeroverse.fuzz.orchestrator"},
            required=required,
        )
        return

    # Directed lane (#39/#40/#41) is the default fuzzing strategy WHEN the slice
    # gave us sink targets — gated behind ZEROVERSE_DIRECTED until the M7 benchmark
    # promotes it. ``directed_fuzz_stage`` itself falls back to ``run_fuzz_stage``
    # when there are no targets or no address-level coverage, so this never reduces
    # the engine's reach.
    directed = [
        tf.finding for tf in result.findings if getattr(tf.finding, "sink_addr", 0)
    ]
    # Functions the slice / LLM triage already flagged — the fuzz selector harnesses
    # these real sinks first instead of whatever the decompiler emitted earliest.
    priority = _fuzz_priority_functions(result.findings)
    remaining = budget.remaining_seconds()
    if remaining <= 0:
        _stage_outcome(
            result,
            "fuzz",
            "skipped",
            reason="wall-clock budget exhausted before fuzz execution",
            provenance={"component": "zeroverse.preflight.BudgetTracker"},
            required=required,
        )
        return
    # Honour ZEROVERSE_FUZZ_DURATION here. `run_fuzz_stage` only consults
    # `_fuzz_duration` when it builds its own config (`config or AflConfig(...)`),
    # so supplying one from the pipeline previously pinned every run to the 30s CI
    # default and made --fuzz-seconds a silent no-op — the capability lane needs
    # ~300s to reach a parser sink, which is why magma confirmed nothing (#304).
    fuzz_config = AflConfig(
        qemu_mode=not plan.target_instrumented,
        duration_s=min(_fuzz_duration(30), int(remaining)),
        hard_timeout_s=remaining,
    )
    failures_before = budget.reservation_failures
    if (
        os.environ.get("ZEROVERSE_DIRECTED")
        and not shared_harness_requested
        and directed
    ):
        from .fuzz.orchestrator import directed_fuzz_stage
        fuzz_findings, fnote = directed_fuzz_stage(
            path,
            decompiled,
            directed,
            [],
            out_dir=out_dir / "fuzz",
            arch=arch,
            config=fuzz_config,
            budget=budget,
            target_instrumented=plan.target_instrumented,
            afl_path=plan.afl_path,
            qemu_path=plan.qemu_path,
            coverage_qemu_path=plan.coverage_qemu_path,
            compiler_path=plan.compiler_path,
            native_compiler_path=plan.native_compiler_path,
            capabilities_resolved=True,
            execution_authorized=plan.afl_local_authorized,
            executor=plan.local_executor,
        )
    else:
        fuzz_findings, fnote = run_fuzz_stage(
            path,
            decompiled,
            llm=llm,
            out_dir=out_dir / "fuzz",
            arch=arch,
            priority=priority,
            callgraph=callgraph,
            config=fuzz_config,
            budget=budget,
            target_instrumented=plan.target_instrumented,
            afl_path=plan.afl_path,
            qemu_path=plan.qemu_path,
            compiler_path=plan.compiler_path,
            native_compiler_path=plan.native_compiler_path,
            capabilities_resolved=True,
            execution_authorized=plan.afl_local_authorized,
            executor=plan.local_executor,
        )
    # Attach the stage's own account of what it did BEFORE any early return. The
    # two returns below used to drop `fnote` on the floor, so a stage that declined
    # to run reported no artifacts AND no explanation — which is why #304 took five
    # rounds to localize. A return that produces neither work nor a reason is the
    # defect (#297 family), not just an inconvenience.
    _attach_fuzz_note(result, fnote)
    if budget.expired():
        _stage_outcome(
            result,
            "fuzz",
            "cancelled",
            reason=_fuzz_reason(
                "wall-clock budget exhausted during fuzz stage", fnote
            ),
            provenance={"component": "zeroverse.fuzz.orchestrator"},
            required=required,
        )
        result.terminal_state = "cancelled"
        result.status_reason = "wall-clock budget exhausted during fuzz stage"
        return
    if budget.reservation_failures > failures_before and not fuzz_findings:
        _stage_outcome(
            result,
            "fuzz",
            "skipped",
            reason=_fuzz_reason(
                "fuzz or replay attempt budget was insufficient", fnote
            ),
            provenance={
                "component": "zeroverse.fuzz.orchestrator",
                "candidate_outcome": "budget-skipped",
            },
            required=required,
        )
        return
    result.stages_run.append("fuzz")
    _stage_outcome(
        result,
        "fuzz",
        "completed",
        provenance={"component": "zeroverse.fuzz.orchestrator", "backend": "afl++"},
        required=required,
    )
    for ff in fuzz_findings:
        if ff.pov and ff.pov.reproduced and not ff.pov.pov_script:
            with contextlib.suppress(OSError):
                name = f"pov_fuzz_{ff.finding.function}.py"
                ff.pov.pov_script = str(write_pov_script(out_dir / name, path, ff.pov))
        result.findings.append(
            TriagedFinding(finding=ff.finding, verdict=ff.verdict, pov=ff.pov,
                           score=1.0, escalated=False)
        )
    if fuzz_findings:
        result.stages_run.append("fuzz-poc")


def _fuzz_reason(reason: str, fnote: str) -> str:
    """Fold the fuzz stage's own note into the stage-outcome reason."""
    return f"{reason}: {fnote}" if fnote else reason


def _attach_fuzz_note(result: RunResult, fnote: str) -> None:
    """Publish the fuzz stage's note exactly once, on every exit path."""
    if not fnote:
        return
    stamped = f"M2-fuzz: {fnote}"
    if stamped in result.note:
        return
    result.note = f"{result.note} | {stamped}" if result.note else stamped


def _synth_asan_candidates(
    f: Finding, v: Verdict, decompiled: dict[str, str] | None,
    path: str | Path, llm: LLM | None,
) -> list[bytes] | None:
    """Issue #52 (opt-in ``ZEROVERSE_SYNTH_INPUTS``): ask the LLM for format-valid
    candidate inputs aimed at this finding's parser sink, to feed
    ``confirm_asan_file(synth_candidates=...)``. Format is inferred from the
    binary name + the decompiled string constants; the sink body + the LLM's own
    overflow reasoning condition the synthesis. Degrades to None (generic boundary
    probes) on any failure — never crashes confirm. Input path only; does not
    touch the ASan-report parsing (output) path."""
    if not os.environ.get("ZEROVERSE_SYNTH_INPUTS") or llm is None:
        return None
    try:
        from .fuzz.aflpp import tokens_from_context
        from .inputsynth import context_from_finding, synthesize_candidates

        dc = decompiled or {}
        ctx = context_from_finding(
            harness_name=Path(path).name,
            sink_function=f.function,
            sink_decompiled=dc.get(f.function, ""),
            overflow_reason=v.explanation or "",
            strings=tokens_from_context(*dc.values()),
        )
        return synthesize_candidates(ctx, llm) or None
    except Exception:
        return None


def _pov_overrides_grounding(findings: list[TriagedFinding]) -> None:
    """G1 grounding reconciliation: a finding the call-graph gate floored/capped
    but that then produced a REPRODUCING crash is proven by execution — restore
    its pre-grounding severity (the crash oracle is a stronger premise than the
    call graph). The grounding evidence is retained, re-stamped so the report
    shows the override honestly. In-place; only touches overridden findings."""
    for tf in findings:
        g = tf.grounding
        if g and tf.pov and tf.pov.reproduced and g.get("status") in ("refuted", "capped"):
            tf.verdict.severity = g["proposed_severity"]
            g["status"] = f"overridden_by_pov (was {g['status']})"


def _tf(
    f: Finding, v: Verdict, pov: PoV | None, rh: object, angr_v: AngrVerdict | None
) -> TriagedFinding:
    score = getattr(rh, "score", 0.0)
    escalated = getattr(rh, "escalated", False)
    grounding = getattr(rh, "grounding", None)
    return TriagedFinding(
        finding=f, verdict=v, pov=pov, score=score, escalated=escalated,
        angr=angr_v, grounding=grounding,
    )


def _emit_script(out_dir: Path, f: Finding, pov: PoV, binary: str | Path) -> str:
    """Write the standalone pwntools replay script; best-effort (never fail a run)."""
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = f"pov_{f.source}_{f.sink}_{hex(f.sink_addr)}"
        safe = "".join(c if c.isalnum() or c in "_-." else "_" for c in stem)
        return str(write_pov_script(out_dir / f"{safe}.py", binary, pov))
    except OSError:
        return ""


def _decompiled_context(f: Finding, decompiled: dict[str, str] | None = None) -> str:
    """Feed the LLM the *slice* context plus the decompiled function body when the
    Ghidra backend recovered it (DESIGN-NOTES Decision 5 — triage the slice, not
    the raw binary)."""
    head = f"call {f.source} -> ... -> call {f.sink}  (in {f.function})"
    body = (decompiled or {}).get(f.function)
    return f"{head}\n\n--- decompiled {f.function} ---\n{body}" if body else head

def _scheduler_session() -> Any:
    """M7 #44 — build the opt-in scheduler session, or None on the default
    path. Imported lazily so the package loads without touching schedule.py."""
    from .schedule import build_session, scheduler_enabled

    return build_session() if scheduler_enabled() else None


def _note_scheduler_signal(
    session: Any, ranked: list[Any], findings: list[Finding]
) -> None:
    """Feed the static-lane signal (max cheap-rank score, lifted by any
    oracle-confirmable bug-class hypothesis) to the scheduler so it can
    (de)prioritise the expensive fuzz/LLM lanes — the measured-waste fix."""
    from .schedule import signal_from_scores

    scores = [float(getattr(rh, "score", 0.0)) for rh in ranked]
    confirmable = any(
        f.origin in bugclasses.CONFIRMABLE_ORIGINS for f in findings
    )
    session.note_signal(signal_from_scores(scores, confirmable))


def _join_note(note: str, extra: str) -> str:
    return f"{note} | {extra}" if note else extra


def _finalize_scheduler(result: RunResult, session: Any) -> None:
    """Materialise the epoch plan + attach the scheduler report to the run."""
    if session is None:
        return
    plan = session.plan()
    report = session.report()
    report["epochs"] = len(plan.epochs)
    report["fallback_demotions"] = plan.fallback_demotions
    result.scheduler = report
    result.note = _join_note(result.note, session.summary_note())
