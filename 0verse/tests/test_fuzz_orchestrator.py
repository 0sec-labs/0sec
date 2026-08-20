"""Fuzz stage orchestration — spec selection, qemu-skip note, synth→crash→PoV wiring."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from zeroverse.fuzz import orchestrator
from zeroverse.fuzz.aflpp import AflConfig, CompiledTarget, FakeAfl
from zeroverse.fuzz.directed import DirectedTargets, SinkTarget
from zeroverse.fuzz.harness import Harness, HarnessBuild, HarnessSpec
from zeroverse.preflight import BudgetTracker, RunBudget
from zeroverse.report import PoV

DECOMP = {
    "main": "undefined8 main(void)\n{\n}\n",
    "parse_record": "int parse_record(byte *data,int len)\n{\n  char buf[32];\n}\n",
    "helper": "void helper(void)\n{\n}\n",
}



def test_shared_library_harness_specs_require_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = orchestrator.fuzzable_specs(DECOMP)[0]
    selected, note = orchestrator._shared_library_harness_specs("/tmp/libx.so", [spec])
    assert selected == [] and note == ""

    monkeypatch.setenv("ZEROVERSE_FUZZ_SHARED_LIB", "1")
    monkeypatch.setattr(orchestrator.sys, "platform", "linux")
    monkeypatch.setattr(
        orchestrator, "triage",
        lambda _path: SimpleNamespace(fmt="ELF", kind="DYN", mitigations={"pie": False}),
    )
    monkeypatch.setattr(orchestrator, "exported_symbol", lambda _lib, name: name == spec.func)
    selected, note = orchestrator._shared_library_harness_specs("/tmp/libx.so", [spec])
    assert [candidate.func for candidate in selected] == [spec.func]
    assert selected[0].lib == Path("/tmp/libx.so")
    assert note.startswith("shared-library harness fuzz:")


def test_shared_library_harness_specs_reject_unexported(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = orchestrator.fuzzable_specs(DECOMP)[0]
    monkeypatch.setenv("ZEROVERSE_FUZZ_SHARED_LIB", "1")
    monkeypatch.setattr(orchestrator.sys, "platform", "linux")
    monkeypatch.setattr(
        orchestrator, "triage",
        lambda _path: SimpleNamespace(fmt="ELF", kind="DYN", mitigations={"pie": False}),
    )
    monkeypatch.setattr(orchestrator, "exported_symbol", lambda *_args: False)
    selected, note = orchestrator._shared_library_harness_specs("/tmp/libx.so", [spec])
    assert selected == []
    assert "no exported buffer-length functions" in note


    specs = orchestrator.fuzzable_specs(DECOMP)
    names = {s.func for s in specs}
    assert "parse_record" in names      # has a byte* buffer param
    assert "main" not in names          # void params / skip list
    assert "helper" not in names        # void params, not fuzzable


RANK_DECOMP = {
    "__asan_memcpy": "void __asan_memcpy(byte *dst,int len)\n{\n  char b[8];\n}\n",
    "zzz_read": "int zzz_read(byte *data,int len)\n{\n  char buf[16];\n}\n",
    "aaa_parse": "int aaa_parse(byte *data,int len)\n{\n  char buf[16];\n}\n",
}


def test_shared_harness_fuzz_reserves_before_build_and_uses_native_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = HarnessSpec(
        func="parse_record",
        decompiled_c=DECOMP["parse_record"],
        lib=Path("/tmp/libtarget.so"),
    )
    compilers: list[str] = []

    def failed_build(*args, compiler, **kwargs):  # type: ignore[no-untyped-def]
        compilers.append(compiler.cc)
        return HarnessBuild(
            ok=False,
            harness=Harness(
                spec.func,
                "int main(void) { return 0; }",
                spec,
            ),
            reason="test-stop",
        )

    monkeypatch.setattr(orchestrator, "build_harness", failed_build)
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=0)
    )
    outcome = orchestrator.fuzz_function(
        spec,
        [],
        backend=FakeAfl([]),
        config=AflConfig(),
        workdir=tmp_path,
        budget=budget,
        compiler_path="/planned/afl-clang-fast",
        native_compiler_path="/planned/native-cc",
        capabilities_resolved=True,
    )

    assert outcome.harness_built is False
    assert compilers == ["/planned/native-cc"]
    assert budget.attempts_used == 2

    exhausted = BudgetTracker.start(
        RunBudget(attempt_limit=0, unknown_sink_oracle_attempts=0)
    )
    monkeypatch.setattr(
        orchestrator,
        "build_harness",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("shared harness built without budget")
        ),
    )
    skipped = orchestrator.fuzz_function(
        spec,
        [],
        backend=FakeAfl([]),
        config=AflConfig(),
        workdir=tmp_path / "exhausted",
        budget=exhausted,
        compiler_path="/planned/afl-clang-fast",
        native_compiler_path="/planned/native-cc",
        capabilities_resolved=True,
    )
    assert "budget skipped" in skipped.note


def test_source_objects_and_reach_probe_use_planned_native_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = HarnessSpec(func="parse_record", decompiled_c=DECOMP["parse_record"])
    source = tmp_path / "target.c"
    source.write_text("int parse_record(void) { return 0; }")
    plain_compilers: list[tuple[str | None, bool]] = []
    harness_compilers: list[str] = []

    def fake_plain_compile(
        _source: Path,
        _workdir: Path,
        *,
        compiler_path: str | None = None,
        compiler_resolved: bool = False,
        timeout: float = 60.0,
    ) -> Path:
        _ = timeout
        plain_compilers.append((compiler_path, compiler_resolved))
        return tmp_path / "target.o"

    def failed_build(*args, compiler, **kwargs):  # type: ignore[no-untyped-def]
        harness_compilers.append(compiler.cc)
        return HarnessBuild(
            ok=False,
            harness=Harness(spec.func, "int main(void) { return 0; }", spec),
            reason="test-stop",
        )

    monkeypatch.setattr(orchestrator, "_compile_plain_object", fake_plain_compile)
    monkeypatch.setattr(orchestrator, "build_harness", failed_build)
    outcome = orchestrator.fuzz_function(
        spec,
        [source],
        backend=FakeAfl([]),
        config=AflConfig(),
        workdir=tmp_path / "work",
        budget=BudgetTracker.start(
            RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=0)
        ),
        compiler_path="/planned/afl-clang-fast",
        native_compiler_path="/planned/native-cc",
        capabilities_resolved=True,
    )

    assert outcome.harness_built is False
    assert plain_compilers == [("/planned/native-cc", True)]
    assert harness_compilers == ["/planned/native-cc"]


def test_fuzz_build_and_confirmation_use_distinct_planned_compilers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = HarnessSpec(func="parse_record", decompiled_c=DECOMP["parse_record"])
    harness = Harness(spec.func, "int main(void) { return 0; }", spec)
    compiled = CompiledTarget(
        fuzz_bin=tmp_path / "afl",
        replay_bin=tmp_path / "replay",
        cmplog_bin=tmp_path / "cmplog",
    )
    build_kwargs: list[dict[str, object]] = []
    confirm_kwargs: list[dict[str, object]] = []
    monkeypatch.setattr(
        orchestrator,
        "build_harness",
        lambda *args, **kwargs: HarnessBuild(ok=True, harness=harness),
    )

    def fake_build(*args, **kwargs):  # type: ignore[no-untyped-def]
        build_kwargs.append(kwargs)
        return compiled

    def fake_confirm(*args, **kwargs):  # type: ignore[no-untyped-def]
        confirm_kwargs.append(kwargs)
        return PoV(reproduced=True, dedup_bucket="bucket")

    monkeypatch.setattr(orchestrator, "build_fuzz_binaries", fake_build)
    monkeypatch.setattr(orchestrator, "confirm_crash", fake_confirm)

    outcome = orchestrator.fuzz_function(
        spec,
        [],
        backend=FakeAfl([b"boom"]),
        config=AflConfig(cmplog=True),
        workdir=tmp_path / "work",
        budget=BudgetTracker.start(
            RunBudget(attempt_limit=32, unknown_sink_oracle_attempts=0)
        ),
        compiler_path="/planned/afl-clang-fast",
        native_compiler_path="/planned/native-cc",
        capabilities_resolved=True,
        executor=SimpleNamespace(),
    )

    assert outcome.crash_found is True
    assert build_kwargs[0]["compiler_path"] == "/planned/afl-clang-fast"
    assert build_kwargs[0]["native_compiler_path"] == "/planned/native-cc"
    assert confirm_kwargs[0]["native_compiler_path"] == "/planned/native-cc"
    assert "compiler_path" not in confirm_kwargs[0]


def test_shared_harness_control_uses_planned_executor_not_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.sandbox_exec import ExecResult as SandboxExecResult

    spec = HarnessSpec(
        func="parse_record",
        decompiled_c=DECOMP["parse_record"],
        lib=Path("/tmp/libtarget.so"),
    )
    harness = Harness(spec.func, "int main(void) { return 0; }", spec)
    replay = tmp_path / "replay"
    replay.write_bytes(b"binary")
    compiled = CompiledTarget(
        fuzz_bin=tmp_path / "afl",
        replay_bin=replay,
        cmplog_bin=tmp_path / "cmplog",
    )
    monkeypatch.setattr(
        orchestrator,
        "build_harness",
        lambda *args, **kwargs: HarnessBuild(ok=True, harness=harness),
    )
    monkeypatch.setattr(
        orchestrator,
        "build_fuzz_binaries",
        lambda *args, **kwargs: compiled,
    )
    monkeypatch.setattr(
        orchestrator.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("shared control bypassed planned executor")
        ),
    )

    class PlannedExecutor:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, argv, *, stdin=b"", env=None, timeout=10.0):  # type: ignore[no-untyped-def]
            self.calls += 1
            return SandboxExecResult(returncode=0)

    planned = PlannedExecutor()
    outcome = orchestrator.fuzz_function(
        spec,
        [],
        backend=FakeAfl([]),
        config=AflConfig(),
        workdir=tmp_path / "work",
        budget=BudgetTracker.start(
            RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=0)
        ),
        compiler_path="/planned/afl-clang-fast",
        native_compiler_path="/planned/native-cc",
        capabilities_resolved=True,
        executor=planned,
    )

    assert outcome.crash_found is False
    assert planned.calls == 1


def test_source_object_compile_is_budgeted_and_uses_native_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = HarnessSpec(func="parse_record", decompiled_c=DECOMP["parse_record"])
    source = tmp_path / "target.c"
    source.write_text("int parse_record(void) { return 0; }")
    commands: list[list[str]] = []
    monkeypatch.setattr(
        orchestrator.subprocess,
        "run",
        lambda cmd, **kwargs: commands.append(cmd) or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        orchestrator,
        "build_harness",
        lambda *args, **kwargs: HarnessBuild(
            ok=False,
            harness=Harness(spec.func, "", spec),
            reason="test-stop",
        ),
    )

    orchestrator.fuzz_function(
        spec,
        [source],
        backend=FakeAfl([]),
        workdir=tmp_path / "work",
        budget=BudgetTracker.start(
            RunBudget(attempt_limit=4, unknown_sink_oracle_attempts=0)
        ),
        compiler_path="/planned/afl-clang-fast",
        native_compiler_path="/planned/native-cc",
        capabilities_resolved=True,
    )

    assert commands[0][0] == "/planned/native-cc"

    commands.clear()
    skipped = orchestrator.fuzz_function(
        spec,
        [source],
        backend=FakeAfl([]),
        workdir=tmp_path / "exhausted",
        budget=BudgetTracker.start(
            RunBudget(attempt_limit=0, unknown_sink_oracle_attempts=0)
        ),
        compiler_path="/planned/afl-clang-fast",
        native_compiler_path="/planned/native-cc",
        capabilities_resolved=True,
    )
    assert "budget skipped" in skipped.note
    assert commands == []


def test_fuzzable_specs_drops_runtime_shims_and_ranks() -> None:
    names = [s.func for s in orchestrator.fuzzable_specs(RANK_DECOMP)]
    assert "__asan_memcpy" not in names          # is_noise_name shim dropped
    # attack-surface name ("parse") outranks a plain one by default
    assert names.index("aaa_parse") < names.index("zzz_read")


def test_fuzzable_specs_priority_floats_slice_sinks_first() -> None:
    specs = orchestrator.fuzzable_specs(RANK_DECOMP, priority=["zzz_read"])
    # a slice/LLM-flagged sink is harnessed first even without a parser-y name
    assert specs[0].func == "zzz_read"


def test_fuzzable_specs_respects_priority_order() -> None:
    specs = orchestrator.fuzzable_specs(
        RANK_DECOMP, priority=["zzz_read", "aaa_parse"]
    )
    assert [spec.func for spec in specs[:2]] == ["zzz_read", "aaa_parse"]


def test_native_last_mile_specs_include_non_harnessable_priority() -> None:
    decompiled = {
        "png_parser": (
            "void png_parser(png_structrp png_ptr,png_inforp info_ptr)\n{\n}\n"
        ),
        **RANK_DECOMP,
    }
    fallback = orchestrator.fuzzable_specs(decompiled)

    specs = orchestrator._native_last_mile_specs(
        decompiled, ["png_parser"], fallback
    )

    assert specs[0].func == "png_parser"
    assert specs[0].signature is not None
    assert not specs[0].is_fuzzable
    assert "aaa_parse" in [spec.func for spec in specs]


# jhead-shaped regression for 0verse#224 sub-gap (a): the name-token heuristic
# alone harnessed the *utility* functions (``ParseCmdDate`` — a "parse" NAME —
# and ``ErrFatal``) over the real attacker-reachable EXIF parser.
JHEAD_DECOMP = {
    "main": "int main(int argc,char **argv)\n{\n"
            "  ParseCmdDate(argv[1], argc);\n"
            "  ReadJpegSections(argv[2], argc);\n"
            "}\n",
    "ParseCmdDate": "int ParseCmdDate(char *str,int len)\n{\n"
                    "  int y = 0;\n  sscanf(str, \"%d\", &y);\n  return y;\n}\n",
    "ReadJpegSections": "int ReadJpegSections(char *f,int n)\n{\n"
                        "  char buf[16];\n  ProcessExifDir(buf, n);\n}\n",
    "ProcessExifDir": "int ProcessExifDir(byte *data,int len)\n{\n"
                      "  return process_EXIF(data, len);\n}\n",
    "process_EXIF": "int process_EXIF(byte *data,int len)\n{\n"
                    "  int i;\n"
                    "  unsigned v = data[0] << 8 | data[1];\n"
                    "  for (i = 0; i < len; i++) {\n"
                    "    char b[8];\n    memcpy(b, data + i, 4);\n  }\n"
                    "  return v;\n}\n",
    "ErrFatal": "void ErrFatal(char *msg,int code)\n{\n  exit(code);\n}\n",
}


def test_fuzzable_specs_ranks_real_parser_over_utility_names() -> None:
    names = [s.func for s in orchestrator.fuzzable_specs(JHEAD_DECOMP)]
    # the real parser (byte assembly + param-bounded loop + param-to-sink)
    # outranks the *name*-parse-y utility that used to win on the token alone
    assert names[0] == "process_EXIF"
    assert names.index("process_EXIF") < names.index("ParseCmdDate")
    # nothing calls ErrFatal: under a known input entry the unreachable utility
    # sinks below every tainted candidate
    assert names[-1] == "ErrFatal"


GRAPH_DECOMP = {
    "main": "int main(int argc,char **argv)\n{\n  via_graph(argv[1], argc);\n}\n",
    "via_graph": "int via_graph(byte *data,int len)\n{\n  char b[8];\n}\n",
    "parse_unreached": "int parse_unreached(byte *data,int len)\n{\n  char b[8];\n}\n",
}


def test_fuzzable_specs_reachability_tier_from_body_graph() -> None:
    names = [s.func for s in orchestrator.fuzzable_specs(GRAPH_DECOMP)]
    # the body-derived call graph taints via_graph from main; the parse-NAMED but
    # unreached function loses despite the attack-surface token
    assert names.index("via_graph") < names.index("parse_unreached")


def test_fuzzable_specs_explicit_callgraph_overrides_body_graph() -> None:
    # a backend-recovered graph that wires main -> parse_unreached flips the order
    names = [
        s.func for s in orchestrator.fuzzable_specs(
            GRAPH_DECOMP, callgraph={"main": ["parse_unreached"]}
        )
    ]
    assert names.index("parse_unreached") < names.index("via_graph")


class _SynthSeedLLM:
    """Answers harness synthesis with junk (template fallback) and the #52 input
    synthesis with one format-valid candidate."""

    PAYLOAD = b"\xff\xd8\xff\xe1" + b"A" * 32  # minimal JPEG/SOI+APP1 container

    def complete_json(self, system: str, prompt: str, schema: dict) -> dict:
        if "candidates" in schema.get("properties", {}):
            return {"candidates": [{"hex": self.PAYLOAD.hex(), "note": "poc"}]}
        return {}


def test_attempt_limit_one_stops_after_afl_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = FakeAfl(crashes=[b"boom"])
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=1, unknown_sink_oracle_attempts=0)
    )
    monkeypatch.setattr(
        orchestrator,
        "run_sanitizer",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("post-AFL control/replay exceeded attempt budget")
        ),
    )

    findings, note = orchestrator.run_fuzz_stage(
        "/bin/true",
        DECOMP,
        out_dir=tmp_path,
        backend=cap,
        budget=budget,
        target_instrumented=True,
    )

    assert findings == []
    assert budget.fuzz_attempts_used == 1
    assert budget.fuzz_attempts_remaining == 0
    assert "budget" in note or "control check FAILED" in note


class _CaptureAfl(FakeAfl):
    """FakeAfl that records the config it was driven with."""

    def __init__(self) -> None:
        super().__init__(crashes=[])
        self.config: AflConfig | None = None

    def fuzz(self, fuzz_bin, *, in_dir, out_dir, config, cmplog_bin=None):
        self.config = config
        return super().fuzz(
            fuzz_bin, in_dir=in_dir, out_dir=out_dir, config=config,
            cmplog_bin=cmplog_bin,
        )


def test_directed_stage_consumes_instrumented_classification_as_file_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.oracle import RunResult

    backend = _CaptureAfl()
    monkeypatch.setattr(
        orchestrator,
        "collect_targets",
        lambda *args, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        orchestrator,
        "run_sanitizer",
        lambda *args, **kwargs: RunResult(crashed=False),
    )

    findings, _ = orchestrator.directed_fuzz_stage(
        "/bin/true",
        DECOMP,
        [],
        [],
        out_dir=tmp_path,
        backend=backend,
        target_instrumented=True,
    )

    assert findings == []
    assert backend.config is not None
    assert backend.config.qemu_mode is False
    assert backend.config.file_input is True


class _DirectedProbe:
    def __init__(self, _binary, index, **_kwargs):  # type: ignore[no-untyped-def]
        self.index = index

    def available(self) -> bool:
        return True

    def reached_sinks(self, _seed, _targets):  # type: ignore[no-untyped-def]
        return []


class _DirectedScheduler:
    def __init__(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
        pass

    def reprioritize(self, seeds):  # type: ignore[no-untyped-def]
        return list(seeds)


def _install_directed_budget_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    targets = DirectedTargets(
        [SinkTarget("parse_record", 0x1000, 0x1010, "slice")]
    )
    monkeypatch.setattr(orchestrator, "collect_targets", lambda *args, **kwargs: targets)
    monkeypatch.setattr(orchestrator, "CoverageProbe", _DirectedProbe)
    monkeypatch.setattr(orchestrator, "DirectedScheduler", _DirectedScheduler)
    monkeypatch.setattr(orchestrator, "inst_ranges_for_slice", lambda *args: "")
    monkeypatch.setattr(orchestrator, "_probe_union", lambda *args: frozenset())
    monkeypatch.setattr(orchestrator, "_queue_inputs", lambda *args: [b"seed"])


def test_directed_budget_limit_one_never_constructs_cfg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_directed_budget_fakes(monkeypatch)
    cfg_calls: list[object] = []
    monkeypatch.setattr(
        orchestrator,
        "AngrCfgDistance",
        lambda *args, **kwargs: cfg_calls.append((args, kwargs)),
    )
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=1, unknown_sink_oracle_attempts=0)
    )
    assert budget.reserve_attempt() == (True, "")

    findings, note = orchestrator.directed_fuzz_stage(
        tmp_path / "target",
        DECOMP,
        [],
        [],
        out_dir=tmp_path / "out",
        budget=budget,
        backend=FakeAfl([]),
    )

    assert findings == []
    assert cfg_calls == []
    assert "CFG distance budget-skipped" in note


def test_directed_budget_limit_two_never_calls_concolic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_directed_budget_fakes(monkeypatch)

    class NoDistance:
        ok = False

        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            pass

    solver_calls: list[bytes] = []

    class NoCallSolver:
        def __init__(self, config):  # type: ignore[no-untyped-def]
            self.config = config

        def solve(self, _binary, stuck, **_kwargs):  # type: ignore[no-untyped-def]
            solver_calls.append(stuck)

    monkeypatch.setattr(orchestrator, "AngrCfgDistance", NoDistance)
    monkeypatch.setattr(orchestrator, "AngrConcolicSolver", NoCallSolver)
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=2, unknown_sink_oracle_attempts=0)
    )

    findings, note = orchestrator.directed_fuzz_stage(
        tmp_path / "target",
        DECOMP,
        [],
        [],
        out_dir=tmp_path / "out",
        budget=budget,
        backend=FakeAfl([]),
    )

    assert findings == []
    assert solver_calls == []
    assert budget.attempts_used == 2
    assert "concolic assist budget-skipped" in note


def test_directed_concolic_reserves_each_solve_and_stops_after_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_directed_budget_fakes(monkeypatch)
    monkeypatch.setattr(
        orchestrator, "_queue_inputs", lambda *args: [b"first", b"second"]
    )

    class NoDistance:
        ok = False

        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            pass

    budget = BudgetTracker.start(
        RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=0)
    )
    solver_calls: list[bytes] = []

    class ExpiringSolver:
        def __init__(self, config):  # type: ignore[no-untyped-def]
            self.config = config

        def solve(self, _binary, stuck, **_kwargs):  # type: ignore[no-untyped-def]
            solver_calls.append(stuck)
            budget.started_monotonic = 0.0

    monkeypatch.setattr(orchestrator, "AngrCfgDistance", NoDistance)
    monkeypatch.setattr(orchestrator, "AngrConcolicSolver", ExpiringSolver)

    findings, note = orchestrator.directed_fuzz_stage(
        tmp_path / "target",
        DECOMP,
        [],
        [],
        out_dir=tmp_path / "out",
        budget=budget,
        backend=FakeAfl([]),
    )

    assert findings == []
    assert solver_calls == [b"first"]
    assert budget.attempts_used == 2 + len(solver_calls)
    assert "concolic assist budget-skipped: wall-clock budget exhausted" in note


def test_directed_angr_uses_live_remaining_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_directed_budget_fakes(monkeypatch)
    cfg_timeouts: list[float] = []
    solve_timeouts: list[float] = []

    class NoDistance:
        ok = False

        def __init__(self, *args, timeout_s, **kwargs):  # type: ignore[no-untyped-def]
            cfg_timeouts.append(timeout_s)

    class CapturingSolver:
        def __init__(self, config):  # type: ignore[no-untyped-def]
            self.config = config

        def solve(self, _binary, _stuck, **_kwargs):  # type: ignore[no-untyped-def]
            solve_timeouts.append(self.config.timeout_s)

    class TwoWindowBackend:
        def __init__(self) -> None:
            self.calls = 0

        def fuzz(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            self.calls += 1
            return SimpleNamespace(
                found_crash=self.calls == 2,
                crashes=[],
                note="test-stop",
            )

    monkeypatch.setattr(orchestrator, "AngrCfgDistance", NoDistance)
    monkeypatch.setattr(orchestrator, "AngrConcolicSolver", CapturingSolver)
    monkeypatch.setattr(BudgetTracker, "remaining_seconds", lambda self: 0.125)

    findings, _ = orchestrator.directed_fuzz_stage(
        tmp_path / "target",
        DECOMP,
        [],
        [],
        out_dir=tmp_path / "out",
        budget=BudgetTracker.start(
            RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=0)
        ),
        backend=TwoWindowBackend(),
    )

    assert findings == []
    assert cfg_timeouts == [pytest.approx(0.125)]
    assert solve_timeouts == [pytest.approx(0.125)]


def test_run_fuzz_stage_prepends_llm_synth_seeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #224 sub-gap (b): with ZEROVERSE_SYNTH_INPUTS + an LLM, format-valid
    # synthesized containers lead the AFL starter corpus (a parser foothold)
    monkeypatch.setenv("ZEROVERSE_SYNTH_INPUTS", "1")
    monkeypatch.setattr(orchestrator, "afl_qemu_available", lambda _a="": True)
    cap = _CaptureAfl()
    orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, llm=_SynthSeedLLM(), out_dir=tmp_path, backend=cap,
    )
    assert cap.config is not None
    assert cap.config.seeds[0] == _SynthSeedLLM.PAYLOAD
    # the token-derived starter corpus still follows the synthesized foothold
    assert len(cap.config.seeds) > 1


def test_run_fuzz_stage_no_synth_seeds_without_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # default path unchanged: no env flag -> pure token/file starter corpus
    monkeypatch.delenv("ZEROVERSE_SYNTH_INPUTS", raising=False)
    monkeypatch.setattr(orchestrator, "afl_qemu_available", lambda _a="": True)
    cap = _CaptureAfl()
    orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, llm=_SynthSeedLLM(), out_dir=tmp_path, backend=cap,
    )
    assert cap.config is not None
    assert _SynthSeedLLM.PAYLOAD not in cap.config.seeds


def test_crash_function_attributes_to_real_backtrace_frame() -> None:
    known = frozenset({"png_check_chunk_length", "png_read_chunk_header"})
    pov = PoV(frames=["__asan_report_load4", "abort",
                      "png_check_chunk_length pngrutil.c:3162"])
    # skips the ASan/abort frames, credits the real sink instead of the fallback
    assert orchestrator._crash_function(pov, known, "<whole-program>") == \
        "png_check_chunk_length"
    # no recognizable target frame -> honest fallback (e.g. a stripped binary)
    assert orchestrator._crash_function(
        PoV(frames=["__asan_memcpy", "abort"]), known, "<whole-program>"
    ) == "<whole-program>"


def test_crash_function_skips_canary_and_path_tokens() -> None:
    # A real Magma libpng PNG003 crash: the fatal canary fires the abort. The abort
    # frame's PATH (`at ./signal/...`) collides with the `signal` stub, and the
    # `magma_log` canary sits above the true sink. Neither may win — the crash is
    # honestly credited to png_handle_PLTE (which the scorer normalizes to match).
    known = frozenset({"MAGMA_png_handle_PLTE", "magma_log", "signal"})
    frames = [
        "#0  0x00007ffff744553b in __GI_kill () at "
        "./signal/../sysdeps/unix/syscall-template.S:120",
        '#1  0x000000000046f153 in magma_log (bug=0x47dbb2 "PNG003", condition=1) '
        "at /magma/magma/src/canary.c:92",
        "#2  0x000000000045b61f in MAGMA_png_handle_PLTE (png_ptr=0x1, length=15) "
        "at /magma/targets/libpng/repo/pngrutil.c:992",
    ]
    assert orchestrator._crash_function(
        PoV(frames=frames), known, "<whole-program>"
    ) == "MAGMA_png_handle_PLTE"


def test_run_fuzz_stage_native_casr_confirms_and_attributes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.fuzz.aflpp import FakeAfl
    from zeroverse.oracle import CasrReport, RunResult

    # instrumented file-input target; casr-gdb yields a symbolicated backtrace
    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(orchestrator, "casr_available", lambda: True)
    monkeypatch.setattr(
        orchestrator, "run_sanitizer",
        lambda *_a, **_k: RunResult(crashed=False),  # benign control stays clean
    )
    monkeypatch.setattr(
        orchestrator, "run_casr_gdb",
        lambda *_a, **_k: CasrReport(
            severity="EXPLOITABLE", short_desc="DestAv", description="oob write",
            frames=["abort", "magma_log", "parse_record pngrutil.c:10"],
        ),
    )
    findings, note = orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path, backend=FakeAfl(crashes=[b"boom"]),
    )
    assert len(findings) == 1
    ff = findings[0]
    # attributed to the real frame, skipping abort + the magma_log canary (noise)
    assert ff.finding.function == "parse_record"
    assert ff.pov.reproduced and ff.pov.file_input
    assert "native-instrumented" in note


def test_native_instrumented_lane_never_stops_at_the_first_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#313 — `stop_on_crash` becomes `AFL_BENCH_UNTIL_CRASH`, a time-to-first-
    crash instrument. This lane scores bug SITES, so ending the campaign on crash
    #1 throws away the rest of the window (measured: 3.3k execs / 1 crash versus
    46.1k execs / 2 crashes over the same 90s on the magma libpng driver). It
    must be off here regardless of whether last-mile is enabled."""
    from zeroverse.oracle import RunResult

    monkeypatch.delenv("ZEROVERSE_LAST_MILE", raising=False)
    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(
        orchestrator, "run_sanitizer",
        lambda *_a, **_k: RunResult(crashed=False),
    )
    config = AflConfig()
    assert config.stop_on_crash, "precondition: the dataclass default is on"

    orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path, backend=FakeAfl(crashes=[]),
        config=config,
    )

    assert not config.stop_on_crash


def test_run_fuzz_stage_native_casr_rejects_post_minimization_class_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.fuzz.aflpp import FakeAfl
    from zeroverse.oracle import CasrReport, FileInputMinimization, RunResult

    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(orchestrator, "casr_available", lambda: True)
    monkeypatch.setattr(
        orchestrator,
        "run_sanitizer",
        lambda *_a, **_k: RunResult(crashed=False),
    )
    reports = iter(
        [
            CasrReport(
                severity="EXPLOITABLE",
                short_desc="DestAv",
                description="original crash",
                frames=["parse_record pngrutil.c:10"],
            ),
            CasrReport(
                severity="EXPLOITABLE",
                short_desc="SourceAv",
                description="class-drifted crash",
                frames=["parse_record pngrutil.c:10"],
            ),
        ]
    )
    monkeypatch.setattr(orchestrator, "run_casr_gdb", lambda *_a, **_k: next(reports))
    monkeypatch.setattr(
        orchestrator,
        "minimize_file_input",
        lambda *_a, **_k: FileInputMinimization(
            candidate=b"minimized", oracle_runs=1, max_runs=24
        ),
    )

    findings, _note = orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path, backend=FakeAfl(crashes=[b"boom"])
    )

    assert findings == []

def test_run_fuzz_stage_native_forces_sanitizer_abort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.oracle import RunResult

    # An instrumented driver reports the bug via ASan/UBSan, but AFL only SAVES a
    # crash if the sanitizer aborts. UBSan defaults to log-and-continue, so the
    # native lane must force the abort (with symbolize=0, which afl-fuzz requires).
    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(
        orchestrator, "run_sanitizer", lambda *_a, **_k: RunResult(crashed=False)
    )
    cfg = AflConfig()
    orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path, backend=FakeAfl(crashes=[]),
        config=cfg,
    )
    assert "abort_on_error=1" in cfg.extra_env["ASAN_OPTIONS"]
    assert "symbolize=0" in cfg.extra_env["ASAN_OPTIONS"]
    assert "halt_on_error=1" in cfg.extra_env["UBSAN_OPTIONS"]

    # An operator-supplied value stays authoritative (setdefault, not overwrite).
    cfg2 = AflConfig(extra_env={"ASAN_OPTIONS": "custom=1:symbolize=0"})
    orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path, backend=FakeAfl(crashes=[]),
        config=cfg2,
    )
    assert cfg2.extra_env["ASAN_OPTIONS"] == "custom=1:symbolize=0"


def test_run_fuzz_stage_native_sanitizer_fallback_when_no_casr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.fuzz.aflpp import FakeAfl
    from zeroverse.oracle import RunResult

    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(orchestrator, "casr_available", lambda: False)

    def fake_run_sanitizer(_binary: str, data: bytes, *, vector: str = "file", **_k):
        if data == b"A" * 64:
            return RunResult(crashed=False)  # benign control stays clean
        return RunResult(
            crashed=True, sanitizer="heap-buffer-overflow",
            stderr=("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                    "    #0 0x1 in __asan_memcpy\n"
                    "    #1 0x2 in parse_record pngrutil.c:10\n"),
        )

    monkeypatch.setattr(orchestrator, "run_sanitizer", fake_run_sanitizer)
    findings, note = orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path, backend=FakeAfl(crashes=[b"boom"]),
    )
    assert len(findings) == 1
    ff = findings[0]
    assert ff.finding.function == "parse_record"  # skips __asan_memcpy frame
    assert ff.pov.reproduced and ff.pov.file_input
    assert ff.feedback_receipt is not None
    assert ff.feedback_receipt.to_dict()["input"]["originalBytes"] == len(b"boom")
    assert "boom" not in str(ff.feedback_receipt.to_dict())
    assert "native-instrumented" in note


def test_run_fuzz_stage_native_unstable_control_drops_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.fuzz.aflpp import FakeAfl
    from zeroverse.oracle import RunResult

    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(orchestrator, "casr_available", lambda: False)
    # control ALSO crashes -> target unstable, no differential -> drop the crash
    monkeypatch.setattr(
        orchestrator, "run_sanitizer",
        lambda *_a, **_k: RunResult(crashed=True, sanitizer="heap-buffer-overflow"),
    )
    findings, note = orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path, backend=FakeAfl(crashes=[b"boom"]),
    )
    assert findings == []
    assert "instrumented control check FAILED: benign control crashed" in note


def test_run_fuzz_stage_native_control_infrastructure_error_is_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.fuzz.aflpp import FakeAfl
    from zeroverse.oracle import RunResult

    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(
        orchestrator,
        "run_sanitizer",
        lambda *_a, **_k: RunResult(
            crashed=False,
            valid=False,
            infrastructure_error="dynamic execution disabled",
        ),
    )

    findings, note = orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path, backend=FakeAfl(crashes=[]),
    )

    assert findings == []
    assert (
        "instrumented control check FAILED: dynamic execution disabled"
        in note
    )


def test_run_fuzz_stage_emits_harnesses_and_notes_qemu_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator, "afl_qemu_available", lambda *_a: False)
    findings, note = orchestrator.run_fuzz_stage(
        "/bin/true", DECOMP, out_dir=tmp_path,
        config=AflConfig(qemu_mode=True),
    )
    assert findings == []
    assert "synthesized" in note
    assert "afl-qemu-trace" in note
    assert (tmp_path / "harness_parse_record.c").exists()


def test_fuzz_function_synth_to_pov(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = HarnessSpec(func="parse_record", constants=["REC0"])

    monkeypatch.setattr(orchestrator, "_compile_plain_object", lambda s, w: tmp_path / "t.o")
    monkeypatch.setattr(
        orchestrator, "build_harness",
        lambda *a, **k: HarnessBuild(
            ok=True, harness=Harness("parse_record", "/* harness */", spec), binary=tmp_path / "p",
        ),
    )
    replay = tmp_path / "replay"
    replay.write_text("x")
    monkeypatch.setattr(
        orchestrator, "build_fuzz_binaries",
        lambda *a, **k: CompiledTarget(
            fuzz_bin=tmp_path / "afl", replay_bin=replay, cmplog_bin=tmp_path / "cl",
        ),
    )
    pov = PoV(input_bytes=b"REC0\xffAAAA", crash_class="SIGSEGV", reproduced=True,
              capability="oob-write", dedup_bucket="b1")
    monkeypatch.setattr(orchestrator, "confirm_crash", lambda *a, **k: pov)

    outcome = orchestrator.fuzz_function(
        spec, [tmp_path / "parser.c"], backend=FakeAfl([b"REC0\xffAAAA"]),
        config=AflConfig(duration_s=1), workdir=tmp_path / "wd",
    )
    assert outcome.crash_found
    assert outcome.pov is pov
    assert len(outcome.fuzz_findings) == 1
    ff = outcome.fuzz_findings[0]
    assert ff.finding.origin == "fuzz"
    assert ff.verdict.is_real
    assert ff.pov.reproduced


def test_fuzz_function_no_crash_is_honest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = HarnessSpec(func="parse_record", constants=["REC0"])
    monkeypatch.setattr(orchestrator, "_compile_plain_object", lambda s, w: tmp_path / "t.o")
    monkeypatch.setattr(
        orchestrator, "build_harness",
        lambda *a, **k: HarnessBuild(ok=True, harness=Harness("parse_record", "x", spec)),
    )
    monkeypatch.setattr(
        orchestrator, "build_fuzz_binaries",
        lambda *a, **k: CompiledTarget(fuzz_bin=tmp_path / "a", replay_bin=tmp_path / "r"),
    )
    outcome = orchestrator.fuzz_function(
        spec, [tmp_path / "p.c"], backend=FakeAfl([]),  # no crashes
        config=AflConfig(duration_s=1), workdir=tmp_path / "wd2",
    )
    assert not outcome.crash_found
    assert outcome.fuzz_findings == []


# --- #315: instrumented-but-driverless is its own lane ----------------------
#
# magma `lua` carries the AFL instrumentation but has no libFuzzer/AFL driver
# entry. Under `-Q` afl-fuzz hard-aborts ("Instrumentation found in -Q mode"), and
# under the driver lane it would be handed `@@` — a path it treats as a script
# argument and never reads the testcase from. It needs native + stdin.

_DRIVERLESS_ELF = (
    b"\x7fELF" + b"\x00" * 32 + b"__AFL_SHM_ID\x00__afl_area_ptr\x00"
    b"__sanitizer_cov_trace_pc\x00"
)


def _driverless_binary(tmp_path: Path) -> Path:
    b = tmp_path / "lua"
    b.write_bytes(_DRIVERLESS_ELF)
    return b


def test_driverless_instrumented_target_fuzzes_native_over_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.oracle import RunResult

    backend = _CaptureAfl()
    vectors: list[str] = []

    def fake_control(*_args: object, **kwargs: object) -> RunResult:
        vectors.append(str(kwargs.get("vector")))
        return RunResult(crashed=False)

    monkeypatch.setattr(orchestrator, "run_sanitizer", fake_control)

    findings, note = orchestrator.run_fuzz_stage(
        _driverless_binary(tmp_path),
        DECOMP,
        out_dir=tmp_path / "fz",
        backend=backend,
        config=AflConfig(qemu_mode=True, duration_s=1),
    )

    assert findings == []
    assert backend.config is not None
    # never -Q: afl-fuzz refuses to run an instrumented binary under QEMU-mode
    assert backend.config.qemu_mode is False
    # ...and never `@@`: this target reads stdin
    assert backend.config.file_input is False
    assert vectors == ["stdin"]
    assert "native-instrumented fuzz (driverless, stdin)" in note


def test_driverless_instrumented_crash_is_confirmed_over_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.oracle import RunResult

    monkeypatch.setattr(
        orchestrator, "run_sanitizer", lambda *a, **k: RunResult(crashed=False)
    )
    monkeypatch.setattr(
        orchestrator,
        "_confirm_instrumented_file_crash",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("driverless target must not use the file-input replay")
        ),
    )
    seen: list[str] = []
    pov = PoV(input_bytes=b"boom", crash_class="SIGSEGV", reproduced=True,
              capability="oob-write", dedup_bucket="b1")

    def fake_confirm(*_args: object, **kwargs: object) -> PoV:
        seen.append(str(kwargs.get("vector")))
        return pov

    monkeypatch.setattr(orchestrator, "confirm_crash", fake_confirm)

    findings, _ = orchestrator.run_fuzz_stage(
        _driverless_binary(tmp_path),
        DECOMP,
        out_dir=tmp_path / "fz",
        backend=FakeAfl([b"boom"]),
        config=AflConfig(qemu_mode=True, duration_s=1),
    )

    assert seen == ["stdin"]
    assert [f.finding.source for f in findings] == ["fuzz:stdin"]


def test_target_that_never_loaded_is_not_a_clean_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing (possibly transitive) shared library means the target never ran.

    The loader exits 127 with no sanitizer report, which otherwise classifies as
    "executed fine, did not crash" — a structural zero wearing a measured zero's
    clothes (#262/#315). The control check has to call it."""
    from zeroverse.oracle import RunResult

    monkeypatch.setattr(
        orchestrator,
        "run_sanitizer",
        lambda *a, **k: RunResult(
            crashed=False,
            stderr="lua: error while loading shared libraries: libtinfo.so.5: "
                   "cannot open shared object file: No such file or directory",
        ),
    )

    findings, note = orchestrator.run_fuzz_stage(
        _driverless_binary(tmp_path),
        DECOMP,
        out_dir=tmp_path / "fz",
        backend=FakeAfl([b"boom"]),
        config=AflConfig(qemu_mode=True, duration_s=1),
    )

    assert findings == []
    assert "control check FAILED" in note
    assert "libtinfo.so.5" in note


def test_directed_stage_keeps_a_driverless_instrumented_target_out_of_qemu(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The directed lane steers with AFL_QEMU_INST_RANGES, i.e. it is -Q by
    construction. An instrumented binary must fall back to the coverage lane even
    when the plan classified it as not-a-driver."""
    from zeroverse.oracle import RunResult

    backend = _CaptureAfl()
    monkeypatch.setattr(
        orchestrator,
        "collect_targets",
        lambda *args, **kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        orchestrator,
        "run_sanitizer",
        lambda *a, **k: RunResult(crashed=False),
    )
    monkeypatch.setattr(
        orchestrator,
        "AngrCfgDistance",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("driverless instrumented target entered the -Q lane")
        ),
    )

    findings, _ = orchestrator.directed_fuzz_stage(
        _driverless_binary(tmp_path),
        DECOMP,
        [],
        [],
        out_dir=tmp_path / "dz",
        backend=backend,
        config=AflConfig(qemu_mode=True, duration_s=1),
        target_instrumented=False,
    )

    assert findings == []
    assert backend.config is not None
    assert backend.config.qemu_mode is False
    assert backend.config.file_input is False
