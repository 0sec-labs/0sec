"""Dynamic PoV confirmation — with mock runners simulating a vulnerable binary,
so it runs with no real target."""

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.dynamic import (
    MAX_CONFIRMATION_CANDIDATE_BYTES,
    ConfirmationCandidate,
    ExecResult,
    SubprocessRunner,
    _env_name,
    confirm,
)
from zeroverse.execution import ExecutionCapabilities, ExecutionEvidence, ExecutionRequest
from zeroverse.preflight import BudgetTracker, RunBudget

CMDI = Finding("getenv", "system", "main", 0x1000, 0x1010, 4)
OVERFLOW = Finding("read", "strcpy", "f", 0x2000, 0x2010, 6)
V = Verdict(
    is_real=True, bug_class="x", severity="high", explanation="", input_example='CMD="; id"'
)


class EchoVulnRunner:
    """Simulates system(getenv(NAME)): runs the injected `echo <x>` command."""

    def run(self, binary: str, *, env=None, argv=None, stdin=b"", timeout=5.0) -> ExecResult:  # type: ignore[no-untyped-def]
        for v in (env or {}).values():
            if v.startswith("echo "):
                return ExecResult(0, (v[len("echo "):] + "\n").encode())
        return ExecResult(0)


class OverflowRunner:
    """Crashes (SIGSEGV) on a large stdin, runs clean on a small one."""

    def run(self, binary: str, *, env=None, argv=None, stdin=b"", timeout=5.0) -> ExecResult:  # type: ignore[no-untyped-def]
        return ExecResult(-11) if len(stdin) > 64 else ExecResult(0)


class CleanRunner:
    def run(self, binary: str, *, env=None, argv=None, stdin=b"", timeout=5.0) -> ExecResult:  # type: ignore[no-untyped-def]
        return ExecResult(0)


class InvalidRunner:
    def run(self, binary: str, *, env=None, argv=None, stdin=b"", timeout=5.0) -> ExecResult:  # type: ignore[no-untyped-def]
        return ExecResult(-99, stderr=b"transport failed", valid=False)


def test_confirm_command_injection() -> None:
    pov = confirm(CMDI, V, "/bin/vuln", EchoVulnRunner())
    assert pov is not None and pov.reproduced
    assert pov.crash_class == "command-injection"
    assert pov.env and "CMD" in pov.env  # canary injected via the env var the LLM named


def test_confirm_memory_safety_differential() -> None:
    pov = confirm(OVERFLOW, V, "/bin/vuln", OverflowRunner())
    assert pov is not None and pov.reproduced
    assert pov.crash_class == "SIGSEGV"
    assert pov.input_bytes and len(pov.input_bytes) == 4096


def test_default_unknown_sink_can_use_unspent_regular_capacity(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from zeroverse import dynamic
    from zeroverse.oracle import RunResult

    finding = Finding("read", "custom_copy", "f", 0x2000, 0x2010, 0)
    budget = BudgetTracker.start(RunBudget())
    clean = RunResult(crashed=False)
    monkeypatch.setattr(
        dynamic.oracle,
        "differential_allocator",
        lambda *args, **kwargs: SimpleNamespace(
            real_heap_bug=False,
            stock=clean,
            guard=clean,
        ),
    )
    monkeypatch.setattr(dynamic.oracle, "run_casr_gdb", lambda *args, **kwargs: None)

    pov = confirm(
        finding,
        V,
        "/bin/vuln",
        OverflowRunner(),
        allow_unknown_sink=True,
        budget=budget,
    )

    assert pov is not None and pov.reproduced
    assert budget.unknown_sink_attempts_used > budget.budget.unknown_sink_oracle_attempts
    assert budget.attempts_used <= budget.budget.attempt_limit


def test_protected_unknown_sink_capacity_completes_real_local_transaction(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    from zeroverse import dynamic
    from zeroverse.oracle import RunResult

    finding = Finding("read", "custom_copy", "f", 0x2000, 0x2010, 0)
    budget = BudgetTracker.start(RunBudget())
    assert budget.reserve_attempts(12) == (True, "")
    clean = RunResult(crashed=False)
    monkeypatch.setattr(
        dynamic.oracle,
        "differential_allocator",
        lambda *args, **kwargs: SimpleNamespace(
            real_heap_bug=False,
            stock=clean,
            guard=clean,
        ),
    )
    monkeypatch.setattr(dynamic.oracle, "run_casr_gdb", lambda *args, **kwargs: None)

    pov = confirm(
        finding,
        V,
        "/bin/vuln",
        OverflowRunner(),
        allow_unknown_sink=True,
        budget=budget,
    )

    assert pov is not None and pov.reproduced
    assert budget.attempts_used == budget.budget.attempt_limit
    assert budget.reservation_failures == 1  # optional CASR was explicitly skipped


def test_local_differential_consumes_one_planned_executor() -> None:
    from zeroverse.sandbox_exec import (
        DisabledExecutor,
        reset_executor,
        set_executor,
    )
    from zeroverse.sandbox_exec import (
        ExecResult as SandboxExecResult,
    )

    class PlannedExecutor:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, argv, *, stdin=b"", env=None, timeout=10.0):  # type: ignore[no-untyped-def]
            self.calls += 1
            return SandboxExecResult(returncode=-11 if len(stdin) > 64 else 0)

    planned = PlannedExecutor()
    set_executor(DisabledExecutor("global executor must not be re-selected"))
    try:
        pov = confirm(
            OVERFLOW,
            V,
            "/bin/vuln",
            SubprocessRunner(planned),
        )
    finally:
        reset_executor()

    assert pov is not None and pov.reproduced
    assert planned.calls >= 4  # control, candidate, stock, guard


def test_asan_control_candidate_and_fixed_use_planned_executor(tmp_path) -> None:
    from zeroverse.dynamic import confirm_asan_file
    from zeroverse.sandbox_exec import (
        DisabledExecutor,
        reset_executor,
        set_executor,
    )
    from zeroverse.sandbox_exec import (
        ExecResult as SandboxExecResult,
    )

    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    vulnerable.write_bytes(b"binary")
    fixed.write_bytes(b"binary")

    class PlannedExecutor:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def run(self, argv, *, stdin=b"", env=None, timeout=10.0):  # type: ignore[no-untyped-def]
            self.calls.append(argv[0])
            payload = Path(argv[1]).read_bytes() if len(argv) > 1 else stdin
            if argv[0] == str(vulnerable) and len(payload) > 64:
                return SandboxExecResult(
                    returncode=1,
                    stderr=(
                        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
                        "SUMMARY: AddressSanitizer: heap-buffer-overflow test.c:1 in parse\n"
                    ),
                )
            return SandboxExecResult(returncode=0)

    planned = PlannedExecutor()
    set_executor(DisabledExecutor("global executor trap"))
    try:
        pov = confirm_asan_file(
            OVERFLOW,
            V,
            vulnerable,
            fixed=fixed,
            executor=planned,
        )
    finally:
        reset_executor()

    assert pov is not None and pov.reproduced
    assert planned.calls == [str(vulnerable), str(vulnerable), str(fixed)]


def test_no_pov_when_clean() -> None:
    assert confirm(CMDI, V, "/bin/vuln", CleanRunner()) is None
    assert confirm(OVERFLOW, V, "/bin/vuln", CleanRunner()) is None


def test_no_pov_when_execution_is_invalid() -> None:
    assert confirm(CMDI, V, "/bin/vuln", InvalidRunner()) is None
    assert confirm(OVERFLOW, V, "/bin/vuln", InvalidRunner()) is None


def test_exec_result_signal() -> None:
    assert ExecResult(-11).crashed and ExecResult(-11).signal == "SIGSEGV"
    assert not ExecResult(0).crashed


def test_env_name_parse() -> None:
    assert _env_name('CMD="; id"') == "CMD"
    assert _env_name("no equals here") == "CMD"  # default
    assert _env_name("PATH=/x") == "PATH"


class FileExecutionBackend:
    name = "fake-file-worker"
    capabilities = ExecutionCapabilities(
        formats=frozenset({"PE"}),
        vectors=frozenset({"file"}),
        oracles=frozenset({"test-oracle"}),
    )

    def __init__(self, *, fail_transport: bool = False) -> None:
        self.fail_transport = fail_transport

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        if self.fail_transport:
            return ExecutionEvidence(
                backend=self.name,
                status="ERROR",
                oracle=request.oracle,
                target_sha256=request.target_sha256,
                input_sha256=request.input_sha256,
                environment={"host": "lab"},
                stderr="crash marker arrived beside transport failure",
                error="SSH exited 255",
            )
        crashed = len(request.payload) > 64
        return ExecutionEvidence(
            backend=self.name,
            status="CRASH" if crashed else "CLEAN",
            oracle=request.oracle,
            target_sha256=request.target_sha256,
            input_sha256=request.input_sha256,
            environment={"host": "lab"},
            crash_signature="test-crash" if crashed else "",
            stderr="test crash" if crashed else "",
        )


class ExactPayloadBackend(FileExecutionBackend):
    def __init__(self, crashing_payload: bytes) -> None:
        super().__init__()
        self.crashing_payload = crashing_payload
        self.payloads: list[bytes] = []

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        self.payloads.append(request.payload)
        crashed = request.payload == self.crashing_payload
        return ExecutionEvidence(
            backend=self.name,
            status="CRASH" if crashed else "CLEAN",
            oracle=request.oracle,
            target_sha256=request.target_sha256,
            input_sha256=request.input_sha256,
            environment={"host": "lab"},
            crash_signature="structured-crash" if crashed else "",
        )


def test_remote_adapter_prefers_structure_aware_candidate(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    structured = b"VALID-HEADER\x00POISONED-COUNT"
    backend = ExactPayloadBackend(structured)

    pov = confirm(
        OVERFLOW,
        V,
        binary,
        executor=backend,
        target_format="PE",
        candidate_inputs=(
            ConfirmationCandidate(structured, "structure-aware-synthesis"),
        ),
    )

    assert pov is not None and pov.input_bytes == structured
    assert backend.payloads == [b"A", structured]
    assert "candidate_source=structure-aware-synthesis" in pov.diff_allocator


def test_remote_adapter_deduplicates_supplied_candidate_before_generic_family(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    duplicate = b"A" * 4096
    backend = ExactPayloadBackend(b"never-crashes")

    assert confirm(
        OVERFLOW,
        V,
        binary,
        executor=backend,
        target_format="PE",
        candidate_inputs=(
            ConfirmationCandidate(duplicate, "structure-aware-synthesis"),
        ),
    ) is None
    assert backend.payloads.count(duplicate) == 1


def test_executor_confirmation_stops_at_attempt_budget(tmp_path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    backend = ExactPayloadBackend(b"never-crashes")
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=2, unknown_sink_oracle_attempts=0)
    )

    assert confirm(
        OVERFLOW,
        V,
        binary,
        executor=backend,
        target_format="PE",
        budget=budget,
    ) is None

    assert backend.payloads == [b"A", b"A" * 4096]
    assert budget.attempts_used == 2


def test_executor_confirmation_does_not_run_after_deadline(tmp_path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    backend = ExactPayloadBackend(b"never-crashes")
    budget = BudgetTracker.start(
        RunBudget(
            attempt_limit=2,
            unknown_sink_oracle_attempts=0,
            deadline_monotonic=time.monotonic() - 1,
        )
    )

    assert confirm(
        OVERFLOW,
        V,
        binary,
        executor=backend,
        target_format="PE",
        budget=budget,
    ) is None

    assert backend.payloads == []
    assert budget.attempts_used == 0


class TimeoutCaptureBackend(ExactPayloadBackend):
    def __init__(self) -> None:
        super().__init__(b"never-crashes")
        self.timeouts: list[float] = []

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        self.timeouts.append(request.timeout)
        return super().run(request)


def test_adapter_control_uses_remaining_deadline_not_default(tmp_path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    backend = TimeoutCaptureBackend()
    budget = BudgetTracker.start(
        RunBudget(
            attempt_limit=2,
            unknown_sink_oracle_attempts=0,
            deadline_monotonic=time.monotonic() + 0.1,
        )
    )

    confirm(
        OVERFLOW,
        V,
        binary,
        executor=backend,
        target_format="PE",
        budget=budget,
    )

    assert backend.timeouts
    assert 0 < backend.timeouts[0] <= 0.1


class MismatchedEvidenceBackend(FileExecutionBackend):
    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        evidence = super().run(request)
        return ExecutionEvidence(
            backend="different-backend",
            status=evidence.status,
            oracle="different-oracle",
            target_sha256=evidence.target_sha256,
            input_sha256=evidence.input_sha256,
            environment=evidence.environment,
            crash_signature=evidence.crash_signature,
        )


def test_adapter_evidence_binds_backend_and_oracle_identity(tmp_path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")

    assert confirm(
        OVERFLOW,
        V,
        binary,
        executor=MismatchedEvidenceBackend(),
        target_format="PE",
    ) is None


class SleepingBackend(FileExecutionBackend):
    capabilities = ExecutionCapabilities(
        formats=frozenset({"PE"}),
        vectors=frozenset({"file"}),
        oracles=frozenset({"test-oracle"}),
        default_timeout=1.0,
    )

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        time.sleep(0.2)
        return super().run(request)


def test_late_adapter_evidence_is_rejected_after_cooperative_timeout(tmp_path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    budget = BudgetTracker.start(
        RunBudget(
            attempt_limit=2,
            unknown_sink_oracle_attempts=0,
            deadline_monotonic=time.monotonic() + 0.03,
        )
    )
    started = time.monotonic()

    pov = confirm(
        OVERFLOW,
        V,
        binary,
        executor=SleepingBackend(),
        target_format="PE",
        budget=budget,
    )

    assert pov is None
    assert time.monotonic() - started >= 0.18
    assert budget.reservation_failures >= 1


def test_confirmation_candidate_rejects_oversize_and_untrusted_provenance() -> None:
    with pytest.raises(ValueError, match="1 MiB pipeline limit"):
        ConfirmationCandidate(
            b"X" * (MAX_CONFIRMATION_CANDIDATE_BYTES + 1),
            "structure-aware-synthesis",
        )
    with pytest.raises(ValueError, match="invalid provenance"):
        ConfirmationCandidate(b"valid", "forged\ncontrol=CRASH")  # type: ignore[arg-type]


def test_remote_file_adapter_confirms_same_candidate_family(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    pov = confirm(
        OVERFLOW,
        V,
        binary,
        executor=FileExecutionBackend(),
        target_format="PE",
    )
    assert pov is not None and pov.reproduced and pov.file_input
    assert len(pov.input_bytes) == 4096
    assert "fake-file-worker" in pov.diff_allocator
    assert "candidate_source=generic-boundary" in pov.diff_allocator


def test_transport_failure_cannot_become_adapter_crash(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    assert confirm(
        OVERFLOW,
        V,
        binary,
        executor=FileExecutionBackend(fail_transport=True),
        target_format="PE",
    ) is None
