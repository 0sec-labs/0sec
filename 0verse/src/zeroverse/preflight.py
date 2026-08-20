"""Typed capability planning and per-run attempt/wall-clock budgets."""

from __future__ import annotations

import ctypes.util
import math
import os
import shutil
import sys
import time
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Literal

from .abi import Abi, abi_for, can_execute, normalize_arch
from .backends.contract import DecompilerBackend
from .cancellation import CancellationToken, RunContext
from .execution.contract import ExecutionBackend
from .ingest import Triage
from .process_boundary import call_isolated
from .sandbox_exec import (
    DisabledExecutor,
    Executor,
    LocalExecutor,
    bind_run_context,
    current_executor,
)

RunProfile = Literal["analysis", "confirmation", "fuzz"]
CapabilityStatus = Literal["available", "unavailable"]
FailureDisposition = Literal["unsupported", "infra-failed", "cancelled"]
PreflightDisposition = Literal["ready", "unsupported", "infra-failed", "cancelled"]
ExecutionRoute = Literal["external-adapter", "qiling", "local", "afl", "none"]


@dataclass(frozen=True)
class RunBudget:
    """Finite execution budget with capacity protected for unknown sinks and for
    the dynamic fuzz complement."""

    attempt_limit: int = 16
    wall_clock_seconds: float = 300.0
    unknown_sink_oracle_attempts: int = 4
    # The fuzz complement runs LAST, after the per-candidate oracle loop, and it
    # competes for the same pool. On a target with many static hypotheses the loop
    # drains every regular attempt, so `run_fuzz_stage` cannot even reserve the one
    # attempt it needs to LAUNCH afl-fuzz — the lane that actually produces PoVs is
    # starved by the lane that mostly does not (#304). This is a small SEPARATE pool
    # (capped by `attempt_limit`, so a zero budget still means zero) that candidate
    # confirmation cannot touch. Sized for one campaign launch, the benign control
    # check, and a few crash replay/confirm rounds.
    fuzz_complement_attempts: int = 8
    deadline_monotonic: float | None = None
    cancellation: CancellationToken | None = None

    @property
    def fuzz_attempt_limit(self) -> int:
        """Effective size of the protected fuzz-complement pool."""
        return min(self.fuzz_complement_attempts, self.attempt_limit)

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_limit, int) or isinstance(self.attempt_limit, bool):
            raise ValueError("attempt_limit must be an integer")
        if (
            not isinstance(self.unknown_sink_oracle_attempts, int)
            or isinstance(self.unknown_sink_oracle_attempts, bool)
        ):
            raise ValueError("unknown_sink_oracle_attempts must be an integer")
        if (
            not isinstance(self.fuzz_complement_attempts, int)
            or isinstance(self.fuzz_complement_attempts, bool)
        ):
            raise ValueError("fuzz_complement_attempts must be an integer")
        if self.attempt_limit < 0:
            raise ValueError("attempt_limit must be non-negative")
        if self.fuzz_complement_attempts < 0:
            raise ValueError("fuzz_complement_attempts must be non-negative")
        if not math.isfinite(self.wall_clock_seconds) or self.wall_clock_seconds <= 0:
            raise ValueError("wall_clock_seconds must be finite and positive")
        if self.deadline_monotonic is not None and not math.isfinite(
            self.deadline_monotonic
        ):
            raise ValueError("deadline_monotonic must be finite")
        if self.cancellation is not None and not isinstance(
            self.cancellation, CancellationToken
        ):
            raise ValueError("cancellation must be a CancellationToken")
        if not 0 <= self.unknown_sink_oracle_attempts <= self.attempt_limit:
            raise ValueError(
                "unknown_sink_oracle_attempts must be between zero and attempt_limit"
            )


@dataclass
class BudgetTracker:
    """Mutable run-local accounting. No state is shared between scans."""

    budget: RunBudget
    started_monotonic: float
    regular_attempts_used: int = 0
    unknown_sink_attempts_used: int = 0
    fuzz_attempts_used: int = 0
    reservation_failures: int = 0
    control: RunContext | None = None

    @classmethod
    def start(cls, budget: RunBudget) -> BudgetTracker:
        started = time.monotonic()
        wall_deadline = started + budget.wall_clock_seconds
        deadline = (
            min(wall_deadline, budget.deadline_monotonic)
            if budget.deadline_monotonic is not None
            else wall_deadline
        )
        return cls(
            budget=budget,
            started_monotonic=started,
            control=RunContext(
                deadline_monotonic=deadline,
                cancellation=budget.cancellation or CancellationToken(),
            ),
        )

    @property
    def deadline_monotonic(self) -> float:
        wall_deadline = self.started_monotonic + self.budget.wall_clock_seconds
        explicit = self.budget.deadline_monotonic
        return min(wall_deadline, explicit) if explicit is not None else wall_deadline

    @property
    def run_context(self) -> RunContext:
        if self.control is None:
            self.control = RunContext(
                deadline_monotonic=self.deadline_monotonic,
                cancellation=self.budget.cancellation or CancellationToken(),
            )
        return self.control

    def remaining_seconds(self) -> float:
        deadline = min(self.deadline_monotonic, self.run_context.deadline_monotonic)
        return max(0.0, deadline - time.monotonic())

    def expired(self) -> bool:
        return self.run_context.cancelled or self.remaining_seconds() <= 0.0

    def cancelled(self) -> bool:
        return self.run_context.cancelled

    @property
    def attempts_used(self) -> int:
        return self.regular_attempts_used + self.unknown_sink_attempts_used

    @property
    def fuzz_attempts_remaining(self) -> int:
        return max(0, self.budget.fuzz_attempt_limit - self.fuzz_attempts_used)

    def can_reserve(
        self, count: int = 1, *, unknown_sink: bool = False, fuzz: bool = False
    ) -> bool:
        if count <= 0 or self.expired():
            return False
        if fuzz:
            # Separate pool: candidate confirmation cannot spend it, and spending it
            # does not shrink the candidate pool.
            return self.fuzz_attempts_used + count <= self.budget.fuzz_attempt_limit
        if self.attempts_used + count > self.budget.attempt_limit:
            return False
        if unknown_sink:
            # The reserve is protected from known candidates, not a ceiling on novel
            # candidates. Unknown candidates may consume unused regular capacity.
            return True
        regular_limit = self.budget.attempt_limit - self.budget.unknown_sink_oracle_attempts
        return self.regular_attempts_used + count <= regular_limit

    def exhaustion_reason(
        self, *, unknown_sink: bool = False, fuzz: bool = False
    ) -> str:
        if self.cancelled():
            return self.run_context.reason
        if self.expired():
            return "wall-clock budget exhausted"
        if fuzz:
            return "protected fuzz-complement attempt budget exhausted"
        if unknown_sink:
            return "candidate attempt budget exhausted after protected unknown-sink capacity"
        return "candidate attempt budget exhausted"

    def reserve_attempt(
        self, *, unknown_sink: bool = False, fuzz: bool = False
    ) -> tuple[bool, str]:
        return self.reserve_attempts(1, unknown_sink=unknown_sink, fuzz=fuzz)

    def reserve_attempts(
        self, count: int, *, unknown_sink: bool = False, fuzz: bool = False
    ) -> tuple[bool, str]:
        if count <= 0:
            raise ValueError("attempt reservation count must be positive")
        if fuzz and unknown_sink:
            raise ValueError("a reservation is either fuzz-lane or unknown-sink")
        if not self.can_reserve(count, unknown_sink=unknown_sink, fuzz=fuzz):
            self.reservation_failures += 1
            return False, self.exhaustion_reason(unknown_sink=unknown_sink, fuzz=fuzz)
        if fuzz:
            self.fuzz_attempts_used += count
        elif unknown_sink:
            self.unknown_sink_attempts_used += count
        else:
            self.regular_attempts_used += count
        return True, ""


@dataclass(frozen=True)
class Capability:
    status: CapabilityStatus
    mandatory: bool
    failure_disposition: FailureDisposition
    detail: str
    provider: str = ""

    @property
    def available(self) -> bool:
        return self.status == "available"


@dataclass
class CancellableDecompilerBackend:
    """Run one uninterruptible provider inside a cancellable child boundary."""

    backend: DecompilerBackend
    context: RunContext
    name: str = field(init=False)

    def __post_init__(self) -> None:
        self.name = self.backend.name

    def available(self) -> bool:
        return self.backend.available()

    def analyze(self, binary: str | Path, *, timeout: int = 120) -> object:
        return call_isolated(
            self.backend.analyze,
            binary,
            timeout=timeout,
            context=self.context,
        )


@dataclass(frozen=True)
class RunPlan:
    """Typed preflight snapshot plus concrete decisions consumed by the pipeline."""

    profile: RunProfile
    target_format: Capability
    target_arch: Capability
    confirmation_format: Capability
    confirmation_arch: Capability
    backend: Capability
    compiler: Capability
    native_compiler: Capability
    libdl: Capability
    afl: Capability
    qemu: Capability
    coverage_qemu: Capability
    qiling: Capability
    executor: Capability
    oracle: Capability
    artifact_store: Capability
    deadline: Capability
    resolved_backend: DecompilerBackend | None
    selected_backend: str
    compiler_path: str | None
    native_compiler_path: str | None
    afl_path: str | None
    qemu_path: str | None
    coverage_qemu_path: str | None
    target_instrumented: bool
    harness_requested: bool
    adapter_owns_execution: bool
    adapter_compatible: bool
    execution_route: ExecutionRoute
    confirmation_path: Path
    confirmation_abi: Abi | None
    confirmation_runnable: bool
    local_executor_available: bool
    afl_local_authorized: bool
    local_executor: Executor | None
    output_dir: Path

    def named_capabilities(self) -> tuple[tuple[str, Capability], ...]:
        return tuple(
            (item.name, getattr(self, item.name))
            for item in fields(self)
            if isinstance(getattr(self, item.name), Capability)
        )

    @property
    def mandatory_failures(self) -> tuple[tuple[str, Capability], ...]:
        return tuple(
            (name, capability)
            for name, capability in self.named_capabilities()
            if capability.mandatory and not capability.available
        )

    @property
    def disposition(self) -> PreflightDisposition:
        failures = {capability.failure_disposition for _, capability in self.mandatory_failures}
        if not failures:
            return "ready"
        if "cancelled" in failures:
            return "cancelled"
        if "unsupported" in failures:
            return "unsupported"
        return "infra-failed"

    @property
    def failure_reason(self) -> str:
        if self.disposition == "ready":
            return "all mandatory capabilities available"
        failed = self.mandatory_failures
        if self.disposition == "cancelled":
            return "caller deadline or wall-clock budget expired in preflight"
        if self.disposition == "unsupported":
            return next(
                capability.detail
                for _, capability in failed
                if capability.failure_disposition == "unsupported"
            )
        return "mandatory preflight capability unavailable: " + ", ".join(
            name for name, _ in failed
        )


def _mandatory(
    profile: RunProfile,
    *,
    route: ExecutionRoute,
    instrumented: bool,
    harness_requested: bool,
) -> set[str]:
    required = {"target_format", "backend", "deadline"}
    if profile in {"confirmation", "fuzz"}:
        required |= {
            "confirmation_format",
            "confirmation_arch",
            "executor",
            "oracle",
            "artifact_store",
        }
    if route == "qiling" and profile in {"confirmation", "fuzz"}:
        required.add("qiling")
    if profile == "fuzz" and route not in {"external-adapter", "qiling"}:
        required.add("afl")
        if not instrumented and not harness_requested:
            required.add("qemu")
        if harness_requested:
            required |= {"compiler", "native_compiler", "libdl"}
    return required


def _capability(
    name: str,
    available: bool,
    detail: str,
    required: set[str],
    *,
    failure_disposition: FailureDisposition = "infra-failed",
    provider: str = "",
) -> Capability:
    return Capability(
        status="available" if available else "unavailable",
        mandatory=name in required,
        failure_disposition=failure_disposition,
        detail=detail,
        provider=provider,
    )


def _system_compiler() -> str | None:
    """Resolve the native compiler once for guard/exec-trap helper builds."""
    configured = os.environ.get("CC", "").strip()
    if configured:
        return shutil.which(configured) or (
            str(Path(configured).resolve()) if Path(configured).is_file() else None
        )
    for name in ("cc", "clang", "gcc"):
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return None


def _artifact_store_available(path: Path) -> tuple[bool, str]:
    if path.exists():
        ok = path.is_dir() and os.access(path, os.W_OK | os.X_OK)
        return ok, f"{path} is {'writable' if ok else 'not a writable directory'}"
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    ok = parent.is_dir() and os.access(parent, os.W_OK | os.X_OK)
    return ok, f"{path} can be created under {parent}" if ok else f"no writable parent for {path}"


def _adapter_supports_format(
    execution_backend: ExecutionBackend | None,
    target_format: str,
) -> bool:
    if execution_backend is None or execution_backend.capabilities.stateful:
        return False
    caps = execution_backend.capabilities
    return any(
        caps.supports(target_format, vector, oracle)
        for vector in caps.vectors
        for oracle in caps.oracles
    )


def probe_capabilities(
    triage: Triage,
    *,
    confirmation_triage: Triage,
    confirmation_path: Path,
    profile: RunProfile,
    requested_backend: str | None,
    execution_backend: ExecutionBackend | None,
    output_dir: Path,
    budget: BudgetTracker,
    supported_formats: tuple[str, ...],
) -> RunPlan:
    """Resolve one immutable run plan before decompilation or target execution."""
    from . import firmware
    from .backends import contract
    from .fuzz.aflpp import afl_cc, afl_fuzz_path, afl_qemu_trace_path, is_instrumented_fuzz_target
    from .fuzz.coverage import qemu_user_bin

    normalized_output = output_dir.expanduser().resolve(strict=False)
    expired = budget.expired()
    selected_backend = None if expired else contract.select(requested_backend)
    selected_name = selected_backend.name if selected_backend is not None else ""
    resolved_backend = (
        CancellableDecompilerBackend(selected_backend, budget.run_context)
        if selected_backend is not None
        and type(selected_backend).__module__.startswith("zeroverse.backends.")
        else selected_backend
    )

    locate_abi = abi_for(triage.arch, triage.bits, fmt=triage.fmt)
    confirm_abi = abi_for(
        confirmation_triage.arch,
        confirmation_triage.bits,
        fmt=confirmation_triage.fmt,
    )
    locate_arch = (
        locate_abi.arch
        if locate_abi is not None
        else normalize_arch(triage.arch, triage.bits)
    )
    confirm_arch = (
        confirm_abi.arch
        if confirm_abi is not None
        else normalize_arch(confirmation_triage.arch, confirmation_triage.bits)
    )
    runnable = can_execute(confirm_abi, fmt=confirmation_triage.fmt)
    adapter_requested = execution_backend is not None
    adapter_compatible = _adapter_supports_format(
        execution_backend, confirmation_triage.fmt
    )
    prefers_qiling = (
        not adapter_requested
        and confirmation_triage.fmt == "ELF"
        and firmware.prefers_qiling(confirm_abi, runnable=runnable)
    )

    instrumented = bool(
        not expired
        and not adapter_requested
        and not prefers_qiling
        and is_instrumented_fuzz_target(confirmation_path)
    )
    host_runnable = runnable or instrumented

    # Select the route before probing route-specific tools. An explicit adapter is
    # adapter is an authorization boundary even when incompatible: it fails closed
    # instead of silently falling back to local/Qiling/AFL execution.
    if adapter_requested:
        route: ExecutionRoute = "external-adapter"
    elif prefers_qiling:
        route = "qiling"
    elif profile == "fuzz":
        route = "afl"
    elif host_runnable:
        route = "local"
    else:
        route = "none"

    harness_requested = bool(
        route == "afl"
        and os.environ.get("ZEROVERSE_FUZZ_SHARED_LIB") == "1"
        and sys.platform.startswith("linux")
        and confirmation_triage.fmt == "ELF"
        and confirmation_triage.kind == "DYN"
        and not confirmation_triage.mitigations.get("pie")
    )

    qiling_ok = bool(
        not expired and route == "qiling" and firmware.qiling_available()
    )
    needs_local_boundary = route in {"local", "afl", "qiling"}
    raw_local_executor = (
        current_executor() if not expired and needs_local_boundary else None
    )
    local_executor = (
        bind_run_context(raw_local_executor, budget.run_context)
        if raw_local_executor is not None
        else None
    )
    executor_available = bool(
        local_executor is not None and not isinstance(local_executor, DisabledExecutor)
    )
    afl_local_authorized = isinstance(local_executor, LocalExecutor)

    # Tool discovery is route-scoped. Do each at most once and never probe an
    # irrelevant local stack for an adapter- or Qiling-owned run.
    probe_afl = route == "afl" or (profile == "analysis" and route == "local")
    afl_path = afl_fuzz_path() if not expired and probe_afl else None
    qemu_path = (
        afl_qemu_trace_path(confirm_arch)
        if (
            not expired
            and probe_afl
            and not instrumented
            and not harness_requested
        )
        else None
    )
    directed_requested = bool(os.environ.get("ZEROVERSE_DIRECTED"))
    coverage_qemu_path = (
        qemu_user_bin(confirm_arch)
        if (
            not expired
            and probe_afl
            and directed_requested
            and not instrumented
            and not harness_requested
            and afl_local_authorized
        )
        else None
    )
    compiler = (
        afl_cc()
        if not expired and probe_afl and not instrumented
        else None
    )
    native_compiler = (
        _system_compiler()
        if not expired and afl_local_authorized and route in {"local", "afl"}
        else None
    )
    libdl = (
        ctypes.util.find_library("dl")
        if not expired and probe_afl and not instrumented
        else None
    )
    libdl_ok = bool(libdl) or (
        not expired and probe_afl and not instrumented and sys.platform == "darwin"
    )

    local_ok = host_runnable and executor_available
    required = _mandatory(
        profile,
        route=route,
        instrumented=instrumented,
        harness_requested=harness_requested,
    )
    executor_ok = bool(
        adapter_compatible
        or (route == "qiling" and qiling_ok and afl_local_authorized)
        or (route == "afl" and afl_path and afl_local_authorized)
        or (route == "local" and local_ok)
    )
    placement_mismatch = (
        route in {"afl", "qiling"}
        and executor_available
        and not afl_local_authorized
    )
    executor_failure: FailureDisposition = (
        "unsupported"
        if (adapter_requested and not adapter_compatible) or placement_mismatch
        else "infra-failed"
    )
    executor_provider = (
        execution_backend.name
        if adapter_requested and execution_backend is not None
        else "qiling"
        if route == "qiling"
        else "afl++"
        if route == "afl"
        else type(local_executor).__name__
    )
    executor_detail = (
        f"executor={executor_provider}"
        if executor_ok
        else local_executor.reason
        if isinstance(local_executor, DisabledExecutor) and not adapter_requested
        else "selected remote executor cannot authorize in-process target execution"
        if placement_mismatch
        else "no compatible target executor"
    )
    artifact_ok, artifact_detail = (
        (False, "not probed after deadline expiry")
        if expired
        else _artifact_store_available(normalized_output)
    )
    remaining = budget.remaining_seconds()

    return RunPlan(
        profile=profile,
        target_format=_capability(
            "target_format",
            triage.fmt in supported_formats,
            f"format={triage.fmt}; supported={','.join(supported_formats)}",
            required,
            failure_disposition="unsupported",
            provider="zeroverse.ingest",
        ),
        target_arch=_capability(
            "target_arch",
            locate_abi is not None,
            f"arch={locate_arch or 'unknown'}; bits={triage.bits}",
            required,
            failure_disposition="unsupported",
            provider="zeroverse.abi",
        ),
        confirmation_format=_capability(
            "confirmation_format",
            confirmation_triage.fmt in supported_formats,
            f"format={confirmation_triage.fmt}; supported={','.join(supported_formats)}",
            required,
            failure_disposition="unsupported",
            provider="zeroverse.ingest",
        ),
        confirmation_arch=_capability(
            "confirmation_arch",
            confirm_abi is not None,
            f"arch={confirm_arch or 'unknown'}; bits={confirmation_triage.bits}",
            required,
            failure_disposition="unsupported",
            provider="zeroverse.abi",
        ),
        backend=_capability(
            "backend",
            resolved_backend is not None,
            (
                f"selected={selected_name}"
                if resolved_backend
                else f"requested={requested_backend or 'auto'}; no backend available"
            ),
            required,
            provider="zeroverse.backends.contract",
        ),
        compiler=_capability(
            "compiler", compiler is not None, compiler or "no AFL C compiler found", required,
            provider=compiler or "",
        ),
        native_compiler=_capability(
            "native_compiler",
            native_compiler is not None,
            native_compiler or "no native C compiler found for runtime helpers",
            required,
            provider=native_compiler or "",
        ),
        libdl=_capability(
            "libdl", libdl_ok,
            libdl or ("provided by libSystem" if libdl_ok else "libdl unavailable"),
            required, provider=libdl or "",
        ),
        afl=_capability(
            "afl", afl_path is not None,
            afl_path or "afl-fuzz unavailable", required,
            provider=afl_path or "",
        ),
        qemu=_capability(
            "qemu", qemu_path is not None,
            qemu_path or f"afl-qemu-trace unavailable for {confirm_arch}", required,
            provider=qemu_path or "",
        ),
        coverage_qemu=_capability(
            "coverage_qemu",
            coverage_qemu_path is not None,
            coverage_qemu_path or f"qemu-user unavailable for {confirm_arch}",
            required,
            provider=coverage_qemu_path or "",
        ),
        qiling=_capability(
            "qiling", qiling_ok,
            "Qiling available" if qiling_ok else "Qiling unavailable", required,
            provider="qiling" if qiling_ok else "",
        ),
        executor=_capability(
            "executor", executor_ok,
            executor_detail,
            required,
            failure_disposition=executor_failure,
            provider=executor_provider if executor_ok else "",
        ),
        oracle=_capability(
            "oracle", executor_ok,
            "deterministic oracle available" if executor_ok else "no compatible oracle",
            required,
            failure_disposition=executor_failure,
            provider=executor_provider if executor_ok else "",
        ),
        artifact_store=_capability(
            "artifact_store", artifact_ok, artifact_detail, required,
            provider=str(normalized_output),
        ),
        deadline=_capability(
            "deadline", remaining > 0, f"{remaining:.3f}s remaining", required,
            failure_disposition="cancelled",
            provider="zeroverse.preflight.BudgetTracker",
        ),
        resolved_backend=resolved_backend,
        selected_backend=selected_name,
        compiler_path=compiler,
        native_compiler_path=native_compiler,
        afl_path=afl_path,
        qemu_path=qemu_path,
        coverage_qemu_path=coverage_qemu_path,
        target_instrumented=instrumented,
        harness_requested=harness_requested,
        adapter_owns_execution=adapter_requested,
        adapter_compatible=adapter_compatible,
        execution_route=route,
        confirmation_path=confirmation_path,
        confirmation_abi=confirm_abi,
        confirmation_runnable=runnable,
        local_executor_available=local_ok and not adapter_requested,
        afl_local_authorized=afl_local_authorized and not adapter_requested,
        local_executor=(
            local_executor
            if executor_available and not adapter_requested
            else None
        ),
        output_dir=normalized_output,
    )
