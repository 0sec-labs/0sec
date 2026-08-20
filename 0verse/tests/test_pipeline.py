"""Pipeline orchestration — the engine-free paths (no Ghidra on the test host)."""

import json
import struct
import time
from pathlib import Path
from types import SimpleNamespace

import zeroverse.pipeline as pipeline
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.execution import ExecutionCapabilities, ExecutionEvidence, ExecutionRequest
from zeroverse.ingest import Triage
from zeroverse.pipeline import run
from zeroverse.preflight import BudgetTracker, RunBudget, probe_capabilities
from zeroverse.report import Patch, PoV
from zeroverse.sandbox_exec import LocalExecutor
from zeroverse.synthesize import SynthesisBatch


def _make_elf(tmp_path: Path) -> Path:
    end = "<"
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 1, 1
    struct.pack_into(end + "H", hdr, 16, 3)      # ET_DYN
    struct.pack_into(end + "H", hdr, 18, 0x3E)   # x86-64
    p = tmp_path / "t.elf"
    p.write_bytes(bytes(hdr) + b".symtab\x00")
    return p


def _triaged(function: str, *, severity: str, is_real: bool) -> pipeline.TriagedFinding:
    return pipeline.TriagedFinding(
        finding=Finding("fread", "memcpy", function, 0x1000, 0x1100, 1),
        verdict=Verdict(is_real, "CWE-787", severity, "test", ""),
    )


def test_budgeted_patch_stage_reports_result_without_overriding_confirmation(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    import zeroverse.patch as patch_module

    finding = _triaged("parse", severity="high", is_real=True)
    finding.pov = PoV(reproduced=True, dedup_bucket="bucket")
    result = pipeline.RunResult(
        triage=pipeline.triage(Path(__file__)), findings=[finding]
    )
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=0)
    )
    executor = LocalExecutor()
    plan = SimpleNamespace(
        adapter_owns_execution=False,
        local_executor=executor,
        executor=SimpleNamespace(provider="planned-local"),
        native_compiler=SimpleNamespace(provider="/planned/native-cc"),
        native_compiler_path="/planned/native-cc",
        output_dir=tmp_path,
    )
    calls: list[dict[str, object]] = []
    monkeypatch.setenv("ZEROVERSE_PATCH", "1")

    def fake_stage(run_result, path, decompiled, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(kwargs)
        run_result.findings[0].pov.patch = Patch(  # type: ignore[union-attr]
            mode="binary-micropatch",
            verified=True,
        )
        return 1

    monkeypatch.setattr(patch_module, "run_patch_stage", fake_stage)
    pipeline._maybe_patch_budgeted(
        result,
        "/target",
        {},
        None,
        budget,
        plan,
    )
    pipeline._terminalize(result)

    outcome = next(item for item in result.stage_outcomes if item.stage == "patch")
    assert outcome.status == "completed"
    assert outcome.reason == "attached 1 patch result(s), 1 verified"
    assert calls[0]["budget"] is budget
    assert calls[0]["executor"] is executor
    assert calls[0]["executor_provider"] == "planned-local"
    assert calls[0]["native_compiler_path"] == "/planned/native-cc"
    assert calls[0]["output_dir"] == tmp_path
    assert result.terminal_state == "confirmed"


def test_budgeted_patch_stage_reports_exhaustion_and_preserves_confirmation(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    import zeroverse.patch as patch_module

    finding = _triaged("parse", severity="high", is_real=True)
    finding.pov = PoV(reproduced=True, dedup_bucket="bucket")
    result = pipeline.RunResult(
        triage=pipeline.triage(Path(__file__)), findings=[finding]
    )
    plan = SimpleNamespace(
        adapter_owns_execution=False,
        local_executor=LocalExecutor(),
        executor=SimpleNamespace(provider="planned-local"),
        native_compiler=SimpleNamespace(provider="/planned/native-cc"),
        native_compiler_path="/planned/native-cc",
        output_dir=tmp_path,
    )
    monkeypatch.setenv("ZEROVERSE_PATCH", "1")
    monkeypatch.setattr(
        patch_module,
        "run_patch_stage",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("patch ran after attempt exhaustion")
        ),
    )

    pipeline._maybe_patch_budgeted(
        result,
        "/target",
        {},
        None,
        BudgetTracker.start(
            RunBudget(attempt_limit=0, unknown_sink_oracle_attempts=0)
        ),
        plan,
    )
    pipeline._terminalize(result)

    outcome = next(item for item in result.stage_outcomes if item.stage == "patch")
    assert outcome.status == "skipped"
    assert "budget exhausted" in outcome.reason
    assert result.terminal_state == "confirmed"


def test_fuzz_priority_functions_orders_risk_and_deduplicates() -> None:
    findings = [
        _triaged("false_first", severity="critical", is_real=False),
        _triaged("medium_sink", severity="medium", is_real=True),
        _triaged("high_sink", severity="high", is_real=True),
        _triaged("high_sink", severity="low", is_real=True),
        _triaged("info_sink", severity="info", is_real=True),
    ]

    assert pipeline._fuzz_priority_functions(findings) == [
        "high_sink",
        "medium_sink",
        "false_first",
        "info_sink",
    ]


def test_run_unsupported_format_is_reported(tmp_path: Path) -> None:
    p = tmp_path / "junk.bin"
    p.write_bytes(b"not a binary")
    r = run(p)
    assert r.stages_run == ["ingest", "preflight"]
    # unsupported container → bounced at the format gate (ELF + Mach-O supported)
    assert "the decompile pipeline supports" in r.note
    assert r.findings == []


def test_run_elf_without_ghidra(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    # Pin the Ghidra backend so the rizin/angr fallback (M5 #27), which may be
    # installed on this host, does not engage: this test asserts the *Ghidra*
    # toolchain-absence degrade specifically.
    monkeypatch.setenv("ZEROVERSE_BACKEND", "ghidra")
    r = run(_make_elf(tmp_path))
    assert r.triage.fmt == "ELF"
    assert r.stages_run == ["ingest", "preflight"]
    assert "Ghidra" in r.note


class _PEFileBackend:
    name = "test-windows-worker"
    capabilities = ExecutionCapabilities(
        formats=frozenset({"PE"}),
        vectors=frozenset({"file"}),
        oracles=frozenset({"test-oracle"}),
    )

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        crashed = len(request.payload) > 64
        return ExecutionEvidence(
            backend=self.name,
            status="CRASH" if crashed else "CLEAN",
            oracle=request.oracle,
            target_sha256=request.target_sha256,
            input_sha256=request.input_sha256,
            environment={"host": "owned-lab"},
            crash_signature="pageheap" if crashed else "",
            stderr="VERIFIER STOP" if crashed else "",
        )


class _ELFFileBackend(_PEFileBackend):
    name = "test-browser-worker"
    capabilities = ExecutionCapabilities(
        formats=frozenset({"ELF"}),
        vectors=frozenset({"file"}),
        oracles=frozenset({"test-oracle"}),
    )


class _ExactPEBackend(_PEFileBackend):
    def __init__(self, crashing_payload: bytes) -> None:
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
            environment={"host": "owned-lab"},
            crash_signature="structured-pageheap" if crashed else "",
        )


class _StructureAwareLLM:
    def __init__(self, candidate: bytes | Exception) -> None:
        self.candidate = candidate
        self.synthesis_prompt = ""

    def complete_json(self, system, prompt, schema):  # type: ignore[no-untyped-def]
        properties = schema.get("properties", {})
        if "invariants" in properties:
            self.synthesis_prompt = prompt
            if isinstance(self.candidate, Exception):
                raise self.candidate
            return {"invariants": [], "candidates": [{"bytes_hex": self.candidate.hex()}]}
        return {
            "is_real": True,
            "bug_class": "CWE-787",
            "severity": "high",
            "explanation": "record count reaches an unbounded copy",
            "input_example": "",
        }


def _install_backend_preflight(monkeypatch, name: str = "ghidra") -> None:  # type: ignore[no-untyped-def]
    from zeroverse.backends import contract

    monkeypatch.setattr(contract, "select", lambda requested=None: SimpleNamespace(name=name))


def _install_single_pe_finding(monkeypatch, finding: Finding) -> None:  # type: ignore[no-untyped-def]
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(
            decompiled_c={
                finding.function: (
                    "void parse(unsigned char *p) { unsigned n = p[4]; "
                    "memcpy(dst, p + 8, n); }"
                )
            },
            callgraph={},
        ),
        all_insts=lambda: [],
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, **kwargs: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [finding])
    monkeypatch.setattr(
        pipeline, "foxguard_union", lambda findings, decompiled: (findings, "")
    )
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        pipeline, "filter_findings", lambda findings, meta: (findings, "")
    )
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)


def test_explicit_adapter_receives_structure_aware_synthesis(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    pe = Path(__file__).parent / "fixtures" / "pe_overflow_x64.exe"
    finding = Finding("fread", "strcpy", "parse", 0x1000, 0x1100, 1)
    _install_single_pe_finding(monkeypatch, finding)
    structured = b"SPK1\x01\x00\xff\xffVALID-RECORD"
    backend = _ExactPEBackend(structured)
    llm = _StructureAwareLLM(structured)

    result = run(pe, llm=llm, execution_backend=backend)

    assert backend.payloads == [b"A", structured]
    assert result.findings[0].pov is not None
    assert result.findings[0].pov.input_bytes == structured
    assert "candidate_source=structure-aware-synthesis" in result.findings[0].pov.diff_allocator
    assert "structure-synthesis" in result.stages_run
    assert "structure synthesis supplied 1 bounded candidate" in result.note
    assert "source (where input enters): fread" in llm.synthesis_prompt
    assert "sink (where the overflow happens): strcpy" in llm.synthesis_prompt
    assert "void parse" in llm.synthesis_prompt


def test_adapter_synthesis_empty_and_backend_failure_keep_generic_fallback(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    pe = Path(__file__).parent / "fixtures" / "pe_overflow_x64.exe"
    finding = Finding("fread", "strcpy", "parse", 0x1000, 0x1100, 1)
    _install_single_pe_finding(monkeypatch, finding)

    empty = run(pe, llm=_StructureAwareLLM(b""), execution_backend=_PEFileBackend())
    failed = run(
        pe,
        llm=_StructureAwareLLM(TimeoutError("provider detail must not leak")),
        execution_backend=_PEFileBackend(),
    )

    assert empty.findings[0].pov is not None  # generic boundary family still runs
    assert "produced no decodable candidates" in empty.note
    assert failed.findings[0].pov is not None
    assert "backend failed (TimeoutError)" in failed.note
    assert "provider detail" not in failed.note


def test_adapter_synthesis_filters_oversized_candidate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    oversized = b"X" * (pipeline.MAX_CONFIRMATION_CANDIDATE_BYTES + 1)
    monkeypatch.setattr(
        pipeline,
        "synthesize_povs_diagnostic",
        lambda *args, **kwargs: SynthesisBatch((oversized,), "ok"),
    )
    finding = Finding("fread", "strcpy", "parse", 0x1000, 0x1100, 1)
    verdict = Verdict(True, "CWE-787", "high", "unbounded count", "")

    candidates, note = pipeline._adapter_synthesis_candidates(
        SimpleNamespace(decompiled_c={}),
        finding,
        verdict,
        _StructureAwareLLM(b"ignored"),
    )

    assert candidates == ()
    assert "exceeded the 1 MiB pipeline limit" in note


def test_injected_pe_backend_advances_through_dynamic_confirmation(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    pe = Path(__file__).parent / "fixtures" / "pe_overflow_x64.exe"
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={}, callgraph={}),
        all_insts=lambda: [],
    )
    finding = Finding("fread", "strcpy", "parse", 0x1000, 0x1100, 1)
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, **kwargs: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [finding])
    monkeypatch.setattr(
        pipeline, "foxguard_union", lambda findings, decompiled: (findings, "")
    )
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        pipeline, "filter_findings", lambda findings, meta: (findings, "")
    )
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)
    monkeypatch.setattr(
        pipeline,
        "synthesize_povs_diagnostic",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("llm=None must not invoke structure synthesis")
        ),
    )

    monkeypatch.setenv("ZEROVERSE_PATCH", "1")
    monkeypatch.setenv("ZEROVERSE_BINPATCH", "1")
    monkeypatch.setattr(
        pipeline,
        "_maybe_patch_budgeted",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("explicit adapter PoV drifted into local patch verification")
        ),
    )
    result = run(pe, execution_backend=_PEFileBackend())
    assert "execution-adapter" in result.stages_run
    assert "dynamic" in result.stages_run and "report" in result.stages_run
    assert result.findings[0].pov is not None
    assert result.findings[0].pov.reproduced
    assert result.findings[0].pov.file_input
    assert result.findings[0].pov.pov_script == ""
    patch_stage = next(
        outcome for outcome in result.stage_outcomes if outcome.stage == "patch"
    )
    assert patch_stage.status == "skipped"
    assert "does not authorize" in patch_stage.reason
    assert result.execution is not None
    assert result.execution["backend"] == "test-windows-worker"
    assert "local AFL fuzz complement skipped" in result.note


def test_explicit_adapter_preempts_local_asan_launch(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    binary = _make_elf(tmp_path)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={}, callgraph={}),
        all_insts=lambda: [],
    )
    finding = Finding("fread", "strcpy", "parse", 0x1000, 0x1100, 1)
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, **kwargs: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [finding])
    monkeypatch.setattr(
        pipeline, "foxguard_union", lambda findings, decompiled: (findings, "")
    )
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        pipeline, "filter_findings", lambda findings, meta: (findings, "")
    )
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)
    monkeypatch.setattr(
        pipeline,
        "confirm_asan_file",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("explicit adapter was bypassed")
        ),
    )

    result = run(binary, execution_backend=_ELFFileBackend())
    assert "execution-adapter" in result.stages_run
    assert result.findings[0].pov is not None
    assert result.findings[0].pov.reproduced
    assert "adapter owns target execution" in result.note


def test_explicit_adapter_preempts_local_fuzz_without_supported_finding(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    binary = _make_elf(tmp_path)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={}, callgraph={}),
        all_insts=lambda: [],
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, **kwargs: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        pipeline, "foxguard_union", lambda findings, decompiled: (findings, "")
    )
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        pipeline, "filter_findings", lambda findings, meta: (findings, "")
    )
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)
    monkeypatch.setattr(
        pipeline,
        "_run_fuzz_complement",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("explicit adapter placement was bypassed")
        ),
    )

    result = run(binary, execution_backend=_ELFFileBackend())

    assert "execution-adapter" not in result.stages_run
    assert "no compatible finding requested dynamic confirmation" in result.note
    assert "local AFL fuzz complement skipped" in result.note


def test_budget_reserves_unknown_sink_attempts_from_known_candidates() -> None:
    tracker = BudgetTracker.start(
        RunBudget(attempt_limit=3, unknown_sink_oracle_attempts=1)
    )

    assert tracker.reserve_attempt() == (True, "")
    assert tracker.reserve_attempt() == (True, "")
    assert tracker.reserve_attempt() == (False, "candidate attempt budget exhausted")
    assert tracker.reserve_attempt(unknown_sink=True) == (True, "")
    assert tracker.reserve_attempt(unknown_sink=True) == (
        False,
        "candidate attempt budget exhausted after protected unknown-sink capacity",
    )
    assert tracker.attempts_used == 3


def test_candidate_loop_cannot_starve_the_fuzz_complement() -> None:
    """#304: the fuzz complement runs LAST and used to draw on the same pool as the
    per-candidate oracle loop. On a target with many static hypotheses the loop
    drained it, so `run_fuzz_stage` could not reserve the single attempt it needs to
    LAUNCH afl-fuzz — no fuzzing, no PoV, a well-formed zero."""
    tracker = BudgetTracker.start(RunBudget())

    assert tracker.reserve_attempts(12) == (True, "")
    assert tracker.reserve_attempt() == (False, "candidate attempt budget exhausted")

    assert tracker.reserve_attempt(fuzz=True) == (True, "")
    assert tracker.fuzz_attempts_used == 1
    # Spending the fuzz pool does not shrink candidate accounting, and vice versa.
    assert tracker.attempts_used == 12


def test_fuzz_complement_pool_is_bounded_by_its_own_limit() -> None:
    tracker = BudgetTracker.start(RunBudget(fuzz_complement_attempts=2))

    assert tracker.reserve_attempts(2, fuzz=True) == (True, "")
    assert tracker.reserve_attempt(fuzz=True) == (
        False,
        "protected fuzz-complement attempt budget exhausted",
    )
    assert tracker.fuzz_attempts_remaining == 0


def test_zero_attempt_budget_grants_no_protected_fuzz_capacity() -> None:
    tracker = BudgetTracker.start(
        RunBudget(attempt_limit=0, unknown_sink_oracle_attempts=0)
    )

    assert tracker.budget.fuzz_attempt_limit == 0
    assert tracker.reserve_attempt(fuzz=True)[0] is False


def test_fuzz_stage_note_survives_a_budget_early_return(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """A stage that declines to do work must SAY why on EVERY exit path. Both
    post-fuzz early returns used to drop the orchestrator's note, so the run
    reported no AFL artifacts and no explanation (#304, #297 family)."""
    from zeroverse.fuzz import orchestrator as fuzz_orchestrator

    budget = BudgetTracker.start(RunBudget())
    result = pipeline.RunResult(triage=pipeline.triage(Path(__file__)))

    def fake_stage(*_args, **kwargs):  # type: ignore[no-untyped-def]
        tracker = kwargs["budget"]
        tracker.reserve_attempts(tracker.budget.fuzz_attempt_limit, fuzz=True)
        assert tracker.reserve_attempt(fuzz=True)[0] is False
        return [], "reused native instrumented harness; fuzz budget skipped: no room"

    monkeypatch.setattr(fuzz_orchestrator, "run_fuzz_stage", fake_stage)
    plan = SimpleNamespace(
        afl_local_authorized=True,
        afl_path="/tools/afl-fuzz",
        qemu_path=None,
        target_instrumented=True,
        compiler_path=None,
        native_compiler_path=None,
        local_executor=None,
    )

    pipeline._run_fuzz_complement(
        _make_elf(tmp_path),
        {"parse": "void parse(void) {}"},
        result,
        tmp_path,
        None,
        budget=budget,
        plan=plan,
        required=True,
    )

    assert "M2-fuzz: reused native instrumented harness" in result.note
    outcome = next(o for o in result.stage_outcomes if o.stage == "fuzz")
    assert outcome.status == "skipped"
    assert "fuzz budget skipped: no room" in outcome.reason


def test_unknown_sink_reserve_is_minimum_not_hard_ceiling() -> None:
    tracker = BudgetTracker.start(
        RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=2)
    )

    assert tracker.reserve_attempts(4, unknown_sink=True) == (True, "")
    assert tracker.unknown_sink_attempts_used == 4
    assert tracker.attempts_used == 4


def test_unknown_first_reservations_cannot_exceed_global_attempt_limit() -> None:
    tracker = BudgetTracker.start(
        RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=2)
    )

    assert tracker.reserve_attempts(8, unknown_sink=True) == (True, "")
    assert tracker.reserve_attempt() == (
        False,
        "candidate attempt budget exhausted",
    )
    assert tracker.attempts_used == 8


def test_non_finite_budgets_and_invalid_profiles_fail_closed(tmp_path: Path) -> None:
    import pytest

    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="finite"):
            RunBudget(wall_clock_seconds=value)
        with pytest.raises(ValueError, match="finite"):
            RunBudget(deadline_monotonic=value)
    with pytest.raises(ValueError, match="attempt_limit must be an integer"):
        RunBudget(attempt_limit=1.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown_sink_oracle_attempts must be an integer"):
        RunBudget(unknown_sink_oracle_attempts=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unsupported run profile"):
        run(_make_elf(tmp_path), profile="invalid")  # type: ignore[arg-type]


def test_confirmation_profile_fails_preflight_before_decompilation(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    from zeroverse.sandbox_exec import DisabledExecutor, reset_executor, set_executor

    binary = _make_elf(tmp_path)
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(
        pipeline,
        "_try_ghidra",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("decompilation ran before mandatory preflight passed")
        ),
    )
    set_executor(DisabledExecutor("confirmation executor unavailable"))
    try:
        result = run(binary, profile="confirmation", output_dir=tmp_path)
    finally:
        reset_executor()

    assert result.terminal_state == "infra-failed"
    assert "executor" in result.status_reason
    assert "oracle" in result.status_reason
    outcomes = {outcome.stage: outcome for outcome in result.stage_outcomes}
    assert outcomes["preflight:executor"].required is True
    assert outcomes["preflight:executor"].status == "unavailable"
    assert outcomes["preflight:oracle"].required is True
    assert "decompile" not in result.stages_run


def test_fuzz_profile_requires_afl_and_qemu_not_unused_compiler(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    binary = _make_elf(tmp_path)
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_cc", lambda: None)
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_available", lambda: False)
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_qemu_available", lambda arch="": False)
    monkeypatch.setattr(
        pipeline,
        "_try_ghidra",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("fuzz profile reached decompilation with missing tools")
        ),
    )

    result = run(binary, profile="fuzz", output_dir=tmp_path)

    assert result.terminal_state == "infra-failed"
    assert "compiler" not in result.status_reason
    assert "afl" in result.status_reason
    assert "qemu" in result.status_reason
    outcomes = {outcome.stage: outcome for outcome in result.stage_outcomes}
    assert outcomes["preflight:compiler"].required is False
    assert outcomes["preflight:afl"].required is True
    assert outcomes["preflight:qemu"].required is True


def test_expired_deadline_cancels_before_decompilation(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    from zeroverse.backends import contract

    binary = _make_elf(tmp_path)
    monkeypatch.setattr(
        contract,
        "select",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("backend probe ran after the caller deadline")
        ),
    )
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_available",
        lambda: (_ for _ in ()).throw(
            AssertionError("AFL probe ran after the caller deadline")
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "_try_ghidra",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("decompilation ran after the caller deadline")
        ),
    )

    result = run(
        binary,
        budget=RunBudget(deadline_monotonic=time.monotonic() - 1),
        output_dir=tmp_path,
    )

    assert result.terminal_state == "cancelled"
    assert "deadline" in result.status_reason
    deadline = next(
        outcome for outcome in result.stage_outcomes if outcome.stage == "preflight:deadline"
    )
    assert deadline.required is True
    assert deadline.status == "unavailable"
    assert deadline.provenance["failure_disposition"] == "cancelled"


def test_analysis_profile_keeps_missing_optional_capability_non_terminal(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    binary = _make_elf(tmp_path)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={}, callgraph={}),
        all_insts=lambda: [],
    )
    _install_backend_preflight(monkeypatch)
    backend_call: dict[str, object] = {}

    def fake_backend(path, **kwargs):  # type: ignore[no-untyped-def]
        backend_call.update(kwargs)
        return adapter

    monkeypatch.setattr(pipeline, "_try_ghidra", fake_backend)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "foxguard_union", lambda findings, decompiled: (findings, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda findings, meta: (findings, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)
    monkeypatch.setattr(pipeline, "_run_fuzz_complement", lambda *args, **kwargs: None)
    monkeypatch.setattr("zeroverse.preflight._system_compiler", lambda: None)
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_available", lambda: False)
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_qemu_available", lambda arch="": False)

    result = run(binary, output_dir=tmp_path)

    outcomes = {outcome.stage: outcome for outcome in result.stage_outcomes}
    assert result.terminal_state == "no-findings"
    assert outcomes["preflight:compiler"].status == "unavailable"
    assert outcomes["preflight:compiler"].required is False
    assert outcomes["preflight:afl"].status == "unavailable"
    assert outcomes["preflight:afl"].required is False
    assert backend_call["backend"].name == "ghidra"
    assert 1 <= backend_call["timeout"] <= 120


def test_unknown_sink_reserve_records_all_candidate_outcomes(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    binary = _make_elf(tmp_path)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={}, callgraph={}),
        all_insts=lambda: [],
    )
    candidates = [
        Finding("recv", "memcpy", "known", 0x1000, 0x1100, 0),
        Finding("recv", "custom_a", "novel_a", 0x1200, 0x1300, 0),
        Finding("recv", "custom_b", "novel_b", 0x1400, 0x1500, 0),
        Finding("recv", "custom_c", "rejected", 0x1600, 0x1700, 0, origin="foxguard"),
    ]
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, **kwargs: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: candidates)
    monkeypatch.setattr(pipeline, "foxguard_union", lambda findings, decompiled: (findings, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda findings, meta: (findings, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: True)
    monkeypatch.setattr(pipeline, "_run_fuzz_complement", lambda *args, **kwargs: None)
    monkeypatch.setattr(pipeline, "_emit_script", lambda *args, **kwargs: "pov.py")
    confirmations: list[str] = []

    def fake_confirm(finding, *args, **kwargs):  # type: ignore[no-untyped-def]
        assert kwargs["allow_unknown_sink"] is True
        assert kwargs["budget"].reserve_attempt(unknown_sink=True) == (True, "")
        confirmations.append(finding.sink)
        if finding.sink == "custom_b":
            return PoV(crash_class="SIGSEGV", reproduced=True)
        return None

    monkeypatch.setattr(pipeline, "confirm", fake_confirm)

    result = run(
        binary,
        llm=_StructureAwareLLM(b"candidate"),
        budget=RunBudget(attempt_limit=2, unknown_sink_oracle_attempts=2),
        output_dir=tmp_path,
    )

    assert confirmations == ["custom_a", "custom_b"]
    assert result.terminal_state == "confirmed"
    ledger = next(
        outcome for outcome in result.stage_outcomes if outcome.stage == "candidate-oracle"
    )
    assert {
        key: ledger.provenance[key]
        for key in ("budget-skipped", "attempted", "oracle-confirmed", "rejected")
    } == {
        "budget-skipped": "1",
        "attempted": "1",
        "oracle-confirmed": "1",
        "rejected": "1",
    }


def test_pipeline_consumes_resolved_backend_without_reselection(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    from zeroverse.backends import contract

    target = _make_elf(tmp_path)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={}, callgraph={}),
        all_insts=lambda: [],
    )

    class ResolvedBackend:
        name = "ghidra"

        def __init__(self) -> None:
            self.calls = 0

        def available(self) -> bool:
            return True

        def analyze(self, binary, *, timeout=120):  # type: ignore[no-untyped-def]
            self.calls += 1
            return adapter

    resolved = ResolvedBackend()
    monkeypatch.setattr(contract, "select", lambda requested=None: resolved)
    monkeypatch.setattr(
        contract,
        "analyze",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("resolved backend was re-selected")
        ),
    )
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "foxguard_union", lambda findings, decompiled: (findings, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda findings, meta: (findings, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)

    result = run(target, output_dir=tmp_path)

    assert result.terminal_state == "no-findings"
    assert resolved.calls == 1


def test_fuzz_plan_uses_instrumented_confirm_binary_not_clean_locate(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    locate = _make_elf(tmp_path)
    confirm_target = tmp_path / "confirm-asan"
    confirm_target.write_bytes(locate.read_bytes())
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(
        "zeroverse.oracle.host_can_launch",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("preflight executed the confirmation target")
        ),
    )
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.is_instrumented_fuzz_target",
        lambda path: Path(path) == confirm_target,
    )
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_fuzz_path", lambda: "/tools/afl-fuzz")
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_qemu_trace_path", lambda arch="": None)

    plan = probe_capabilities(
        pipeline.triage(locate),
        confirmation_triage=pipeline.triage(confirm_target),
        confirmation_path=confirm_target,
        profile="fuzz",
        requested_backend=None,
        execution_backend=None,
        output_dir=tmp_path / "out",
        budget=BudgetTracker.start(RunBudget()),
        supported_formats=pipeline.SUPPORTED_FORMATS,
    )

    assert plan.confirmation_path == confirm_target
    assert plan.target_instrumented is True
    assert plan.qemu.mandatory is False
    assert plan.compiler.mandatory is False
    assert plan.libdl.mandatory is False


def test_shared_library_harness_fuzz_plan_does_not_require_qemu(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "libtarget.so"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target_triage = Triage(
        path=str(target),
        fmt="ELF",
        arch="x86-64",
        bits=64,
        endian="little",
        kind="DYN",
        mitigations={"pie": False},
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setenv("ZEROVERSE_FUZZ_SHARED_LIB", "1")
    monkeypatch.setattr("zeroverse.preflight.sys.platform", "linux")
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: True)
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.is_instrumented_fuzz_target", lambda path: False
    )
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_fuzz_path", lambda: "/tools/afl-fuzz")
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_qemu_trace_path",
        lambda arch="": (_ for _ in ()).throw(
            AssertionError("native shared-library harness probed AFL QEMU")
        ),
    )
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_cc", lambda: "/tools/afl-clang-fast")
    monkeypatch.setattr("zeroverse.preflight._system_compiler", lambda: "/tools/cc")
    monkeypatch.setattr(
        "zeroverse.preflight.ctypes.util.find_library", lambda name: "libdl.so.2"
    )
    monkeypatch.setattr("zeroverse.preflight.current_executor", lambda: LocalExecutor())

    plan = probe_capabilities(
        target_triage,
        confirmation_triage=target_triage,
        confirmation_path=target,
        profile="fuzz",
        requested_backend=None,
        execution_backend=None,
        output_dir=tmp_path / "out",
        budget=BudgetTracker.start(RunBudget()),
        supported_formats=pipeline.SUPPORTED_FORMATS,
    )

    assert plan.disposition == "ready"
    assert plan.execution_route == "afl"
    assert plan.harness_requested is True
    assert plan.target_instrumented is False
    assert plan.afl_local_authorized is True
    assert plan.qemu.mandatory is False
    assert plan.qemu_path is None


def test_noninstrumented_binary_fuzz_plan_still_requires_qemu(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "target"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target_triage = Triage(
        path=str(target),
        fmt="ELF",
        arch="x86-64",
        bits=64,
        endian="little",
        kind="EXEC",
        mitigations={"pie": False},
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setenv("ZEROVERSE_FUZZ_SHARED_LIB", "1")
    monkeypatch.setattr("zeroverse.preflight.sys.platform", "linux")
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: True)
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.is_instrumented_fuzz_target", lambda path: False
    )
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_fuzz_path", lambda: "/tools/afl-fuzz")
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_qemu_trace_path", lambda arch="": None
    )
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_cc", lambda: "/tools/afl-clang-fast")
    monkeypatch.setattr("zeroverse.preflight._system_compiler", lambda: "/tools/cc")
    monkeypatch.setattr("zeroverse.preflight.current_executor", lambda: LocalExecutor())

    plan = probe_capabilities(
        target_triage,
        confirmation_triage=target_triage,
        confirmation_path=target,
        profile="fuzz",
        requested_backend=None,
        execution_backend=None,
        output_dir=tmp_path / "out",
        budget=BudgetTracker.start(RunBudget()),
        supported_formats=pipeline.SUPPORTED_FORMATS,
    )

    assert plan.harness_requested is False
    assert plan.qemu.mandatory is True
    assert plan.qemu.available is False
    assert plan.disposition == "infra-failed"
    assert [name for name, _ in plan.mandatory_failures] == ["qemu"]


def test_external_adapter_plan_does_not_require_local_fuzz_stack(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = _make_elf(tmp_path)
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_fuzz_path",
        lambda: (_ for _ in ()).throw(AssertionError("external route probed AFL")),
    )
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_cc",
        lambda: (_ for _ in ()).throw(AssertionError("external route probed compiler")),
    )
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_qemu_trace_path",
        lambda arch="": (_ for _ in ()).throw(AssertionError("external route probed QEMU")),
    )

    plan = probe_capabilities(
        pipeline.triage(target),
        confirmation_triage=pipeline.triage(target),
        confirmation_path=target,
        profile="fuzz",
        requested_backend=None,
        execution_backend=_ELFFileBackend(),
        output_dir=tmp_path / "out",
        budget=BudgetTracker.start(RunBudget()),
        supported_formats=pipeline.SUPPORTED_FORMATS,
    )

    assert plan.disposition == "ready"
    assert plan.execution_route == "external-adapter"
    assert plan.adapter_owns_execution is True
    assert plan.afl.mandatory is False
    assert plan.compiler.mandatory is False
    assert plan.qemu.mandatory is False


def test_qiling_requires_explicit_local_execution_authorization(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    from zeroverse.sandbox_exec import DisabledExecutor, reset_executor, set_executor

    target = tmp_path / "firmware.elf"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target_triage = Triage(
        path=str(target),
        fmt="ELF",
        arch="MIPS",
        bits=32,
        endian="big",
        kind="EXEC",
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(pipeline, "triage", lambda path: target_triage)
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: False)
    monkeypatch.setattr("zeroverse.firmware.qiling_available", lambda: True)
    monkeypatch.setattr(
        pipeline,
        "_try_ghidra",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Qiling target reached decompilation without authorization")
        ),
    )
    set_executor(DisabledExecutor("execution disabled for test"))
    try:
        result = run(target, profile="confirmation", output_dir=tmp_path / "out")
    finally:
        reset_executor()

    assert result.terminal_state == "infra-failed"
    executor_stage = next(
        outcome
        for outcome in result.stage_outcomes
        if outcome.stage == "preflight:executor"
    )
    assert "execution disabled" in executor_stage.reason
    assert "qiling-emulate" not in result.stages_run


def test_nonnative_fuzz_plan_selects_qiling_without_afl(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "firmware.elf"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    triage_result = Triage(
        path=str(target),
        fmt="ELF",
        arch="MIPS",
        bits=32,
        endian="big",
        kind="EXEC",
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: False)
    monkeypatch.setattr("zeroverse.firmware.qiling_available", lambda: True)
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_fuzz_path",
        lambda: (_ for _ in ()).throw(AssertionError("Qiling route probed AFL")),
    )
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_cc",
        lambda: (_ for _ in ()).throw(AssertionError("Qiling route probed compiler")),
    )
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.afl_qemu_trace_path",
        lambda arch="": (_ for _ in ()).throw(AssertionError("Qiling route probed QEMU")),
    )

    plan = probe_capabilities(
        triage_result,
        confirmation_triage=triage_result,
        confirmation_path=target,
        profile="fuzz",
        requested_backend=None,
        execution_backend=None,
        output_dir=tmp_path / "out",
        budget=BudgetTracker.start(RunBudget()),
        supported_formats=pipeline.SUPPORTED_FORMATS,
    )

    assert plan.disposition == "ready"
    assert plan.execution_route == "qiling"
    assert plan.qiling.mandatory is True
    assert plan.afl.mandatory is False


class _StatefulELFBackend(_ELFFileBackend):
    capabilities = ExecutionCapabilities(
        formats=frozenset({"ELF"}),
        vectors=frozenset({"file"}),
        oracles=frozenset({"test-oracle"}),
        stateful=True,
    )


class _DenyingCapabilities:
    formats = frozenset({"ELF"})
    vectors = frozenset({"file"})
    oracles = frozenset({"test-oracle"})
    stateful = False
    default_timeout = 1.0

    def supports(self, fmt: str, vector: str, oracle: str | None = None) -> bool:
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "formats": ["ELF"],
            "vectors": ["file"],
            "oracles": ["test-oracle"],
            "stateful": False,
            "default_timeout": 1.0,
        }


class _DenyingBackend(_ELFFileBackend):
    capabilities = _DenyingCapabilities()  # type: ignore[assignment]


def test_adapter_ownership_uses_capability_supports_not_format_membership(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = _make_elf(tmp_path)
    _install_backend_preflight(monkeypatch)

    plan = probe_capabilities(
        pipeline.triage(target),
        confirmation_triage=pipeline.triage(target),
        confirmation_path=target,
        profile="confirmation",
        requested_backend=None,
        execution_backend=_DenyingBackend(),
        output_dir=tmp_path / "out",
        budget=BudgetTracker.start(RunBudget()),
        supported_formats=pipeline.SUPPORTED_FORMATS,
    )

    assert plan.adapter_owns_execution is True
    assert plan.adapter_compatible is False
    assert plan.disposition == "unsupported"


class _RemoteExecutor:
    def run(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("remote executor should not authorize local target execution")


def test_remote_executor_cannot_authorize_local_afl(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = _make_elf(tmp_path)
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: True)
    monkeypatch.setattr("zeroverse.preflight.current_executor", lambda: _RemoteExecutor())
    monkeypatch.setattr("zeroverse.fuzz.aflpp.afl_fuzz_path", lambda: "/tools/afl-fuzz")
    monkeypatch.setattr(
        "zeroverse.fuzz.aflpp.is_instrumented_fuzz_target", lambda path: True
    )

    plan = probe_capabilities(
        pipeline.triage(target),
        confirmation_triage=pipeline.triage(target),
        confirmation_path=target,
        profile="fuzz",
        requested_backend=None,
        execution_backend=None,
        output_dir=tmp_path / "out",
        budget=BudgetTracker.start(RunBudget()),
        supported_formats=pipeline.SUPPORTED_FORMATS,
    )

    assert plan.execution_route == "afl"
    assert plan.afl_local_authorized is False
    assert plan.disposition == "unsupported"
    assert "remote" in plan.failure_reason


def test_incompatible_explicit_adapter_never_falls_back_local(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = _make_elf(tmp_path)
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr(
        pipeline,
        "_try_ghidra",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unsupported adapter fell through to decompile/local execution")
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "_run_fuzz_complement",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unsupported adapter fell through to AFL")
        ),
    )

    result = run(
        target,
        profile="confirmation",
        execution_backend=_StatefulELFBackend(),
        output_dir=tmp_path,
    )

    assert result.terminal_state == "unsupported"
    assert result.findings == []


def test_output_dir_is_expanded_once_into_run_plan(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = _make_elf(tmp_path)
    _install_backend_preflight(monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path))

    plan = probe_capabilities(
        pipeline.triage(target),
        confirmation_triage=pipeline.triage(target),
        confirmation_path=target,
        profile="analysis",
        requested_backend=None,
        execution_backend=None,
        output_dir=Path("~/evidence"),
        budget=BudgetTracker.start(RunBudget()),
        supported_formats=pipeline.SUPPORTED_FORMATS,
    )

    assert plan.output_dir == (tmp_path / "evidence").resolve()
    assert plan.artifact_store.provider == str(plan.output_dir)


def test_candidate_ledger_is_bounded_and_constant_size() -> None:
    result = pipeline.RunResult(triage=pipeline.triage(Path(__file__)))
    finding = Finding("recv", "custom", "parse", 1, 2, 0)

    for index in range(1_000):
        pipeline._record_candidate(result, index, finding, "rejected", "test")

    ledger = [outcome for outcome in result.stage_outcomes if outcome.stage == "candidate-oracle"]
    assert len(ledger) == 1
    assert ledger[0].provenance["rejected"] == "1000"
    assert ledger[0].provenance["sample_count"] == "1"
    sample = json.loads(ledger[0].provenance["sample_00"])
    assert "rank" not in sample
    assert len(ledger[0].provenance) <= 22


def test_candidate_ledger_identity_is_stable_across_reordering() -> None:
    findings = [
        Finding("recv", "custom_a", "parse_a", 1, 2, 0),
        Finding("read", "custom_b", "parse_b", 3, 4, 0),
    ]
    ledgers = []
    for ordered in (findings, list(reversed(findings))):
        result = pipeline.RunResult(triage=pipeline.triage(Path(__file__)))
        for index, finding in enumerate(ordered):
            pipeline._record_candidate(result, index, finding, "rejected", "test")
        ledger = next(
            outcome
            for outcome in result.stage_outcomes
            if outcome.stage == "candidate-oracle"
        )
        ledgers.append(
            tuple(
                value
                for key, value in sorted(ledger.provenance.items())
                if key.startswith("sample_") and key != "sample_count"
            )
        )

    assert ledgers[0] == ledgers[1]


def test_deadline_cancellation_prevents_patch_and_fuzz(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = _make_elf(tmp_path)
    finding = Finding("recv", "memcpy", "parse", 1, 2, 0)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={"parse": "memcpy(dst, src, n);"}, callgraph={}),
        all_insts=lambda: [],
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: True)
    monkeypatch.setattr("zeroverse.preflight.current_executor", lambda: object())
    monkeypatch.setattr(pipeline, "_local_execution_unavailable", lambda: "")
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, **kwargs: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [finding])
    monkeypatch.setattr(pipeline, "foxguard_union", lambda findings, decompiled: (findings, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda findings, meta: (findings, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)

    def expire_during_confirmation(*args, **kwargs):  # type: ignore[no-untyped-def]
        tracker = kwargs["budget"]
        tracker.started_monotonic -= tracker.budget.wall_clock_seconds + 1

    monkeypatch.setattr(pipeline, "confirm", expire_during_confirmation)
    monkeypatch.setattr(
        pipeline,
        "_maybe_patch_budgeted",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("patch ran after deadline cancellation")
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "_run_fuzz_complement",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("fuzz ran after deadline cancellation")
        ),
    )

    result = run(target, llm=_StructureAwareLLM(b"candidate"), output_dir=tmp_path)

    assert result.terminal_state == "cancelled"


def test_zero_attempt_confirmation_is_not_no_findings(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = _make_elf(tmp_path)
    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={}, callgraph={}),
        all_insts=lambda: [],
    )
    _install_backend_preflight(monkeypatch)
    monkeypatch.setattr("zeroverse.preflight.can_execute", lambda abi, *, fmt: True)
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, **kwargs: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "foxguard_union", lambda findings, decompiled: (findings, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda findings, meta: (findings, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)
    monkeypatch.setattr(
        pipeline,
        "_run_fuzz_complement",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("confirmation profile fell through to fuzz")
        ),
    )

    result = run(
        target,
        profile="confirmation",
        budget=RunBudget(attempt_limit=0, unknown_sink_oracle_attempts=0),
        output_dir=tmp_path,
    )

    assert result.terminal_state == "infra-failed"
    dynamic = next(outcome for outcome in result.stage_outcomes if outcome.stage == "dynamic")
    assert dynamic.required is True
    assert dynamic.status == "skipped"
