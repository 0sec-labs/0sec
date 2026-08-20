"""Truthful terminal scan states, stage evidence, and backend isolation."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Lock
from types import SimpleNamespace

import pytest

from zeroverse import api
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.api import ScanOptions
from zeroverse.execution import ExecutionCapabilities, ExecutionEvidence, ExecutionRequest
from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, StageOutcome, TriagedFinding, _terminalize
from zeroverse.preflight import RunBudget
from zeroverse.report import PoV

_REQUIRED = ["ingest", "decompile", "lift", "analyze", "reason"]
_TERMINAL_STATES = {
    "confirmed",
    "no-findings",
    "unsupported",
    "skipped",
    "infra-failed",
    "cancelled",
}


def _triage(path: str = "/bin/target") -> Triage:
    return Triage(
        path=path,
        fmt="ELF",
        arch="x86-64",
        bits=64,
        endian="little",
        kind="EXEC",
    )


def _install_backend_preflight(monkeypatch, name: str = "ghidra") -> None:  # type: ignore[no-untyped-def]
    from zeroverse.backends import contract

    monkeypatch.setattr(contract, "select", lambda requested=None: SimpleNamespace(name=name))


def _completed_run() -> RunResult:
    return RunResult(triage=_triage(), stages_run=list(_REQUIRED))


def _confirmed_finding() -> TriagedFinding:
    finding = Finding("read", "memcpy", "parse", 0x1000, 0x1100, 1)
    verdict = Verdict(True, "CWE-787", "high", "replayed overflow", "")
    pov = PoV(
        input_bytes=b"A" * 128,
        crash_class="heap-buffer-overflow",
        capability="oob-write",
        crash_trace="AddressSanitizer",
        reproduced=True,
    )
    return TriagedFinding(finding=finding, verdict=verdict, pov=pov)


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        ("unsupported", "unsupported container"),
        ("skipped", "scan declined by policy"),
        ("cancelled", "caller deadline expired"),
    ],
)
def test_explicit_whole_scan_terminal_states_are_preserved(state: str, reason: str) -> None:
    result = RunResult(triage=_triage(), terminal_state=state, status_reason=reason)  # type: ignore[arg-type]

    _terminalize(result)

    assert result.terminal_state == state
    assert result.status_reason == reason
    assert result.terminal_state in _TERMINAL_STATES


def test_explicit_infra_failure_is_not_reclassified_as_clean() -> None:
    result = _completed_run()
    result.terminal_state = "infra-failed"
    result.status_reason = "required artifact upload failed"

    _terminalize(result)

    assert result.terminal_state == "infra-failed"
    assert result.status_reason == "required artifact upload failed"


def test_required_stage_failure_is_not_a_clean_result() -> None:
    result = RunResult(triage=_triage(), stages_run=["ingest"])

    _terminalize(result)

    assert result.terminal_state == "infra-failed"
    assert "required stage incomplete" in result.status_reason


def test_completed_required_stages_are_no_findings() -> None:
    result = _completed_run()

    _terminalize(result)

    assert result.terminal_state == "no-findings"
    assert result.status_reason == "required stages completed; no replay-confirmed PoV"
    assert all(outcome.status == "completed" for outcome in result.stage_outcomes)


def test_optional_lane_unavailability_does_not_invalidate_clean_result() -> None:
    result = _completed_run()
    result.stage_outcomes.append(
        StageOutcome(
            stage="fuzz",
            status="unavailable",
            required=False,
            reason="AFL++ toolchain unavailable",
        )
    )

    _terminalize(result)

    assert result.terminal_state == "no-findings"
    assert result.stage_outcomes[0].status == "unavailable"


def test_replay_confirmed_pov_has_precedence_over_other_terminal_states() -> None:
    result = RunResult(
        triage=_triage(),
        stages_run=["ingest"],
        findings=[_confirmed_finding()],
        terminal_state="infra-failed",
        status_reason="backend later became unavailable",
    )

    _terminalize(result)

    assert result.terminal_state == "confirmed"
    assert result.status_reason == "1 finding has a replay-confirmed PoV"


def test_terminal_metadata_is_additive_in_all_serializers() -> None:
    result = api._result_from_run("/bin/target", _completed_run(), backend="ghidra")

    json_result = json.loads(api.result_to_json(result))
    ndjson_meta = json.loads(api.result_to_ndjson(result).splitlines()[0])["_meta"]
    sarif_run = json.loads(api.result_to_sarif(result))["runs"][0]

    assert json_result["terminal_state"] == "no-findings"
    assert json_result["stage_outcomes"][0]["provenance"]["component"] == "zeroverse.pipeline"
    assert ndjson_meta["terminal_state"] == "no-findings"
    assert ndjson_meta["status_reason"] == result.status_reason
    assert ndjson_meta["stage_outcomes"] == json_result["stage_outcomes"]
    assert sarif_run["properties"]["terminal_state"] == "no-findings"
    assert sarif_run["properties"]["stage_outcomes"] == json_result["stage_outcomes"]


def test_v1_4_fields_remain_present_in_v1_5_result() -> None:
    result = api._result_from_run("/bin/target", _completed_run()).to_dict()
    legacy_fields = {
        "contract_version",
        "tool",
        "binary",
        "format",
        "arch",
        "backend",
        "triage",
        "stages_run",
        "findings",
        "note",
        "scheduler",
        "execution",
        "confirmed_count",
    }

    assert legacy_fields <= result.keys()
    assert result["contract_version"] == "1.5"


def test_v1_5_fields_do_not_shift_pre_v1_5_positional_arguments() -> None:
    scheduler = {"budget": "legacy-scheduler"}
    execution = {"backend": "legacy-executor"}

    result = api.ScanResult(
        "1.4",
        {"name": "0verse", "version": "legacy"},
        "/bin/target",
        "ELF",
        "x86-64",
        "ghidra",
        "ELF x86-64",
        ["ingest"],
        [],
        "legacy note",
        scheduler,
        execution,
    )

    assert result.scheduler is scheduler
    assert result.execution is execution
    assert result.terminal_state == "infra-failed"
    assert result.status_reason == "scan did not complete"
    assert result.stage_outcomes == []


def test_scan_threads_backend_without_mutating_process_environment(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    barrier = Barrier(2)
    lock = Lock()
    observed: list[tuple[str | None, str | None]] = []
    monkeypatch.setenv("ZEROVERSE_BACKEND", "environment-default")
    monkeypatch.setattr(api, "_maybe_capture", lambda *args: None)

    def fake_run(path: str, **kwargs: object) -> RunResult:
        barrier.wait(timeout=5)
        with lock:
            observed.append(
                (kwargs.get("backend"), os.environ.get("ZEROVERSE_BACKEND"))  # type: ignore[arg-type]
            )
        return _completed_run()

    monkeypatch.setattr(api, "run", fake_run)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(api.scan, "/bin/a", ScanOptions(backend="ghidra")),
            pool.submit(api.scan, "/bin/b", ScanOptions(backend="rizin")),
        ]
        results = [future.result(timeout=5) for future in futures]

    assert sorted(observed) == [
        ("ghidra", "environment-default"),
        ("rizin", "environment-default"),
    ]
    assert {result.backend for result in results} == {"ghidra", "rizin"}
    assert os.environ["ZEROVERSE_BACKEND"] == "environment-default"


def test_scan_threads_profile_and_budget_without_global_mutation(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}
    budget = RunBudget(
        attempt_limit=7,
        wall_clock_seconds=12.5,
        unknown_sink_oracle_attempts=2,
    )
    monkeypatch.setattr(api, "_maybe_capture", lambda *args: None)

    def fake_run(path: str, **kwargs: object) -> RunResult:
        captured.update(kwargs)
        return _completed_run()

    monkeypatch.setattr(api, "run", fake_run)
    before = dict(os.environ)

    api.scan(
        "/bin/target",
        ScanOptions(
            profile="fuzz",
            budget=budget,
            output_dir=str(tmp_path),
        ),
    )

    assert captured["profile"] == "fuzz"
    assert captured["budget"] is budget
    assert captured["output_dir"] == str(tmp_path)
    assert dict(os.environ) == before


def test_pipeline_passes_explicit_backend_to_registry(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from zeroverse import pipeline
    from zeroverse.backends import contract

    captured: dict[str, object] = {}

    def fake_analyze(path: str | Path, *, name: str | None, timeout: int = 120) -> None:
        captured.update(path=path, name=name, timeout=timeout)

    monkeypatch.setattr(contract, "analyze", fake_analyze)

    assert pipeline._try_ghidra("/bin/target", backend="angr") is None
    assert captured == {"path": "/bin/target", "name": "angr", "timeout": 120}


class _FailingExecutor:
    name = "failing-worker"
    capabilities = ExecutionCapabilities(
        formats=frozenset({"ELF"}),
        vectors=frozenset({"file"}),
        oracles=frozenset({"native-crash"}),
    )

    def __init__(self, status: str = "ERROR") -> None:
        self.status = status

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        return ExecutionEvidence(
            backend=self.name,
            status=self.status,  # type: ignore[arg-type]
            oracle=request.oracle,
            target_sha256=request.target_sha256,
            input_sha256=request.input_sha256,
            environment={"worker": "test"},
            error=(
                "worker does not support this profile"
                if self.status == "UNSUPPORTED"
                else "worker deadline expired"
            ),
        )


@pytest.mark.parametrize(
    ("executor_status", "terminal_state", "stage_status", "reason"),
    [
        ("ERROR", "infra-failed", "failed", "worker deadline expired"),
        ("TIMEOUT", "infra-failed", "failed", "worker deadline expired"),
        (
            "UNSUPPORTED",
            "unsupported",
            "unavailable",
            "worker does not support this profile",
        ),
    ],
)
def test_required_execution_backend_failure_is_terminal_failure(
    tmp_path: Path,
    monkeypatch,
    executor_status: str,
    terminal_state: str,
    stage_status: str,
    reason: str,
) -> None:  # type: ignore[no-untyped-def]
    from zeroverse import pipeline

    binary = tmp_path / "target.elf"
    binary.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 57 + b".symtab\x00")
    finding = Finding("read", "memcpy", "parse", 0x1000, 0x1100, 1)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={"parse": "memcpy(dst, src, n);"}, callgraph={}),
        all_insts=lambda: [],
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, *, backend=None, timeout=120: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [finding])
    monkeypatch.setattr(pipeline, "foxguard_union", lambda findings, decompiled: (findings, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda findings, meta: (findings, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)

    result = pipeline.run(
        binary,
        backend="ghidra",
        execution_backend=_FailingExecutor(executor_status),
    )

    outcomes = {outcome.stage: outcome for outcome in result.stage_outcomes}
    assert result.terminal_state == terminal_state
    assert result.status_reason == f"execution-adapter {stage_status}: {reason}"
    assert outcomes["execution-adapter"].status == stage_status
    assert outcomes["execution-adapter"].required is True
    assert outcomes["dynamic"].status == stage_status
    assert outcomes["dynamic"].required is True
    assert outcomes["dynamic"].reason == reason
    assert outcomes["poc"].status == "skipped"
    assert outcomes["report"].status == "skipped"
    assert "execution-adapter" not in result.stages_run
    assert "dynamic" not in result.stages_run
    assert "poc" not in result.stages_run
    assert "report" not in result.stages_run


def test_disabled_local_executor_is_recorded_as_optional_unavailable(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    from zeroverse import pipeline
    from zeroverse.sandbox_exec import DisabledExecutor, reset_executor, set_executor

    binary = tmp_path / "target.elf"
    header = bytearray(64)
    header[0:7] = b"\x7fELF\x02\x01\x01"
    header[16:20] = b"\x03\x00\x3e\x00"
    binary.write_bytes(bytes(header) + b".symtab\x00")
    finding = Finding("read", "memcpy", "parse", 0x1000, 0x1100, 1)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={"parse": "memcpy(dst, src, n);"}, callgraph={}),
        all_insts=lambda: [],
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, *, backend=None, timeout=120: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [finding])
    monkeypatch.setattr(pipeline, "foxguard_union", lambda findings, decompiled: (findings, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda findings, meta: (findings, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: True)
    monkeypatch.setattr(
        pipeline,
        "_run_fuzz_complement",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("DisabledExecutor reached raw AFL execution")
        ),
    )
    reason = "dynamic execution disabled for test"
    set_executor(DisabledExecutor(reason))
    try:
        result = pipeline.run(binary, backend="ghidra")
    finally:
        reset_executor()

    dynamic = next(outcome for outcome in result.stage_outcomes if outcome.stage == "dynamic")
    assert result.terminal_state == "no-findings"
    assert dynamic.status == "unavailable"
    assert dynamic.required is False
    assert dynamic.reason == reason
    assert "dynamic" not in result.stages_run


def test_missing_required_backend_differs_from_completed_clean_scan(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    from zeroverse import pipeline

    binary = tmp_path / "target.elf"
    binary.write_bytes(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 57 + b".symtab\x00"
    )
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, *, backend=None, timeout=120: None)

    failed = pipeline.run(binary, backend="ghidra")

    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={}, callgraph={}),
        all_insts=lambda: [],
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, *, backend=None, timeout=120: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "foxguard_union", lambda findings, decompiled: (findings, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda findings, meta: (findings, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)
    monkeypatch.setattr(pipeline, "_run_fuzz_complement", lambda *args, **kwargs: None)

    clean = pipeline.run(binary, backend="ghidra")

    assert failed.terminal_state == "infra-failed"
    assert failed.stage_outcomes[-1].stage == "decompile"
    assert failed.stage_outcomes[-1].status == "unavailable"
    assert clean.terminal_state == "no-findings"
    assert set(_REQUIRED) <= set(clean.stages_run)
