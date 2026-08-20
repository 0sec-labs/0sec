"""#224 last-mile assist — LLM-targeted mutation of sink-reaching inputs."""

from __future__ import annotations

import zlib
from pathlib import Path

import pytest

from zeroverse.fuzz import lastmile, orchestrator
from zeroverse.fuzz.aflpp import AflConfig, CompiledTarget, FakeAfl
from zeroverse.fuzz.coverage import AddressIndex, BlockTrace, CoverageProbe
from zeroverse.fuzz.directed import DirectedTargets, SinkTarget
from zeroverse.fuzz.harness import HarnessSpec
from zeroverse.il import Inst, Kind
from zeroverse.oracle import CrashFeedbackReceipt, CrashSet, crash_feedback_receipt
from zeroverse.preflight import BudgetTracker, RunBudget
from zeroverse.report import PoV

BASE = b"RIFFdata"
SINK_BODY = (
    "int parse(byte *data,int len)\n{\n"
    "  int flags = data[2];\n"
    "  char correction[8];\n"
    "  if ((flags & 4) == 0) {\n"
    "    for (int i = 0; i < len; i++) correction[i] = data[i];\n"
    "  }\n"
    "  return flags;\n}\n"
)


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(data, zlib.crc32(kind)) & 0xFFFFFFFF
    return len(data).to_bytes(4, "big") + kind + data + crc.to_bytes(4, "big")


def _png() -> bytes:
    ihdr = (
        b"\x00\x00\x00\x01"  # width
        b"\x00\x00\x00\x01"  # height
        b"\x08\x00\x00\x00\x00"  # grayscale, deflate, no filter, no interlace
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00"))
        + _png_chunk(b"IEND", b"")
    )


def _png_chunks(data: bytes) -> list[tuple[bytes, int, int, int]]:
    chunks: list[tuple[bytes, int, int, int]] = []
    pos = 8
    while pos < len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        kind = data[pos + 4:pos + 8]
        data_offset = pos + 8
        end = data_offset + length + 4
        chunks.append((kind, data_offset, data_offset + length, end))
        pos = end
    return chunks


class _LastMileLLM:
    """Proposes one targeted mutation (flip the flag field at offset 2)."""

    def __init__(self, mutations: object = None) -> None:
        self.mutations = mutations
        self.prompts: list[str] = []

    def complete_json(self, system: str, prompt: str, schema: dict) -> dict:
        self.prompts.append(prompt)
        if "mutations" not in schema.get("properties", {}):
            return {}
        if isinstance(self.mutations, Exception):
            raise self.mutations
        if self.mutations is not None:
            return {"mutations": self.mutations}
        return {"mutations": [
            {"input_index": 0, "offset": 2, "value_hex": "ffff",
             "note": "clear the stereo flag -> mono path overflows"},
        ]}


def _ctx(**kw: object) -> lastmile.LastMileContext:
    return lastmile.LastMileContext(
        sink_function="parse", sink_decompiled=SINK_BODY,
        reaching_inputs=[BASE], **kw,  # type: ignore[arg-type]
    )


# --- mutation proposal / application -----------------------------------------

def test_propose_mutations_validates_and_drops_garbage() -> None:
    llm = _LastMileLLM(mutations=[
        {"input_index": 0, "offset": 2, "value_hex": "ff"},      # ok
        {"input_index": 1, "offset": 0, "value_hex": "ff"},      # bad index
        {"input_index": 0, "offset": 99, "value_hex": "ff"},     # offset OOB
        {"input_index": 0, "offset": 0, "value_hex": "zz"},      # bad hex
        {"input_index": 0, "offset": 0, "value_hex": "ff" * 9},  # value too long
        {"input_index": 0, "offset": 0},                         # missing value
        "junk",
    ])
    out = lastmile.propose_mutations(_ctx(), llm)
    assert len(out) == 1
    assert (out[0].input_index, out[0].offset, out[0].value) == (0, 2, b"\xff")


def test_apply_mutation_is_structure_preserving() -> None:
    assert lastmile.apply_mutation(BASE, 2, b"\xff\xff") == b"RI\xff\xffdata"
    # never grows the input: a patch running past the end is rejected, not padded
    assert lastmile.apply_mutation(BASE, 6, b"\xff" * 4) is None
    assert lastmile.apply_mutation(BASE, -1, b"\xff") is None
    assert lastmile.apply_mutation(BASE, 0, b"") is None



def test_normalize_png_repairs_structure_and_chunk_crcs() -> None:
    base = _png()
    ihdr = next(chunk for chunk in _png_chunks(base) if chunk[0] == b"IHDR")
    idat = next(chunk for chunk in _png_chunks(base) if chunk[0] == b"IDAT")
    candidate = bytearray(base)
    candidate[0] = 0
    candidate[ihdr[1]:ihdr[1] + 4] = b"\0" * 4
    candidate[ihdr[1] + 8:ihdr[1] + 13] = b"\x03\x00\x01\x01\x02"
    candidate[idat[1]] ^= 0xFF

    normalized = lastmile.normalize_last_mile_candidate(base, bytes(candidate))

    assert (normalized.container, normalized.status) == ("PNG", "repaired")
    assert normalized.data[:8] == base[:8]
    assert normalized.data[ihdr[1]:ihdr[1] + 13] == base[ihdr[1]:ihdr[1] + 13]
    assert normalized.data[idat[1]] == candidate[idat[1]]
    for kind, data_offset, data_end, end in _png_chunks(normalized.data):
        actual = zlib.crc32(
            normalized.data[data_offset:data_end], zlib.crc32(kind)
        ) & 0xFFFFFFFF
        assert actual == int.from_bytes(normalized.data[data_end:end], "big")


def test_normalize_last_mile_candidate_labels_malformed_and_unsupported() -> None:
    malformed = b"\x89PNG\r\n\x1a\ntruncated"
    malformed_result = lastmile.normalize_last_mile_candidate(malformed, malformed)
    unsupported = lastmile.normalize_last_mile_candidate(BASE, BASE)

    assert (malformed_result.container, malformed_result.status) == ("PNG", "malformed")
    assert malformed_result.data == malformed
    assert (unsupported.container, unsupported.status, unsupported.data) == (
        "",
        "unsupported",
        BASE,
    )


def test_normalized_last_mile_candidates_repair_and_dedupe_png() -> None:
    base = _png()
    idat = next(chunk for chunk in _png_chunks(base) if chunk[0] == b"IDAT")
    ctx = lastmile.LastMileContext(
        sink_function="parse",
        sink_decompiled=SINK_BODY,
        reaching_inputs=[base],
    )
    llm = _LastMileLLM(mutations=[
        {"input_index": 0, "offset": 0, "value_hex": "89"},
        {"input_index": 0, "offset": idat[1], "value_hex": "ff"},
        {"input_index": 0, "offset": idat[1], "value_hex": "ff"},
    ])

    batch = lastmile.normalized_last_mile_candidates(ctx, llm)

    assert (batch.proposed, batch.format_valid, batch.malformed, batch.unsupported) == (
        3,
        3,
        0,
        0,
    )
    assert len(batch.candidates) == 1
    assert batch.candidates[0].status == "repaired"
    assert batch.candidates[0].data != base

def test_last_mile_candidates_apply_and_dedupe() -> None:
    llm = _LastMileLLM(mutations=[
        {"input_index": 0, "offset": 2, "value_hex": "ffff"},
        {"input_index": 0, "offset": 2, "value_hex": "ff ff"},   # same patch, respaced
        {"input_index": 0, "offset": 0, "value_hex": "52494646"},  # rewrites to BASE
    ])
    cands = lastmile.last_mile_candidates(_ctx(), llm)
    assert cands == [b"RI\xff\xffdata"]  # dup + identity both dropped


def test_propose_mutations_degrades_on_llm_failure() -> None:
    assert lastmile.propose_mutations(_ctx(), _LastMileLLM(RuntimeError("boom"))) == []


def test_propose_mutations_needs_inputs_and_body() -> None:
    llm = _LastMileLLM()
    assert lastmile.propose_mutations(
        lastmile.LastMileContext(sink_function="parse", sink_decompiled=SINK_BODY),
        llm,
    ) == []
    assert lastmile.propose_mutations(
        lastmile.LastMileContext(sink_function="parse", reaching_inputs=[BASE]),
        llm,
    ) == []
    assert llm.prompts == []  # no LLM spend without both signals


def test_prompt_carries_sink_and_inputs_but_never_a_reference_poc() -> None:
    llm = _LastMileLLM()
    lastmile.propose_mutations(_ctx(), llm)
    prompt = llm.prompts[0]
    assert SINK_BODY in prompt and BASE.hex() in prompt
    # anti-cheat: the context has no field that could smuggle a known-crashing input
    assert not any("poc" in f or "reference" in f
                   for f in lastmile.LastMileContext.__dataclass_fields__)


def test_gdb_probe_returns_only_runtime_reaching_inputs(tmp_path: Path) -> None:
    calls: list[bytes] = []

    def runner(
        binary: str,
        script: str,
        argv: list[str],
        *,
        timeout: float,
    ) -> tuple[str, int | None, bool]:
        assert binary == "/bin/target"
        assert timeout == 2.0
        data = Path(argv[0]).read_bytes()
        calls.append(data)
        # The randomized marker is embedded in the script. Returning the script
        # simulates GDB printing it only for BASE.
        return (script if data == BASE else "", 0, False)

    result = lastmile.probe_reaching_inputs(
        "/bin/target",
        "parse",
        [BASE, b"miss", BASE],
        timeout_s=2.0,
        runner=runner,
    )

    assert result.available
    assert result.attempted == 2
    assert result.inputs == [BASE]
    assert calls == [BASE, b"miss"]


def test_gdb_probe_degrades_when_runtime_probe_is_unavailable() -> None:
    calls = 0

    def runner(
        _binary: str,
        _script: str,
        _argv: list[str],
        *,
        timeout: float,
    ) -> tuple[str, int | None, bool]:
        nonlocal calls
        calls += 1
        return "runtime GDB requires explicit trusted-local execution", None, False

    result = lastmile.probe_reaching_inputs(
        "/bin/target", "parse", [BASE, b"second"], runner=runner
    )

    assert not result.available
    assert result.inputs == []
    assert calls == 1
    assert "trusted-local" in result.note


def test_gdb_probe_reports_debugger_infrastructure_failures() -> None:
    def runner(
        _binary: str,
        _script: str,
        _argv: list[str],
        *,
        timeout: float,
    ) -> tuple[str, int | None, bool]:
        return "Couldn't get CS register: Input/output error.", 1, False

    result = lastmile.probe_reaching_inputs(
        "/bin/target", "parse", [BASE], runner=runner
    )

    assert not result.available
    assert result.inputs == []
    assert "GDB reach probe failed (exit 1)" in result.note
    assert "Couldn't get CS register" in result.note


def test_native_last_mile_queue_keeps_recent_inputs_and_starter_seeds(
    tmp_path: Path,
) -> None:
    queue = tmp_path / "default" / "queue"
    queue.mkdir(parents=True)
    for index in range(20):
        (queue / f"id:{index:06d},orig:seed").write_bytes(f"queue-{index}".encode())

    inputs = orchestrator._native_last_mile_queue(
        tmp_path, [b"starter-a", b"starter-b"], limit=8
    )

    assert b"queue-19" in inputs
    assert b"queue-0" in inputs
    assert b"starter-a" in inputs
    assert b"starter-b" in inputs
    assert len(inputs) == 8


def test_reach_probe_reserves_each_replay_instead_of_coarse_batch() -> None:
    calls: list[float] = []
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=2, unknown_sink_oracle_attempts=0)
    )

    def runner(
        binary: str,
        script: str,
        argv: list[str],
        *,
        timeout: float,
    ) -> tuple[str, int | None, bool]:
        calls.append(timeout)
        return "", 0, False

    result = lastmile.probe_reaching_inputs(
        "/bin/true",
        "parse",
        [bytes([index]) for index in range(5)],
        runner=runner,
        budget=budget,
    )

    assert result.attempted == 2
    assert len(calls) == 2
    assert "budget skipped" in result.note
    assert budget.reservation_failures == 1


def test_native_last_mile_searches_past_unreached_ranked_sinks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def probe(
        _binary: str, function: str, _queue: list[bytes], **_kwargs: object
    ) -> lastmile.ReachProbeResult:
        calls.append(function)
        return lastmile.ReachProbeResult(
            available=True,
            attempted=1,
            inputs=[BASE] if function == "hot" else [],
        )

    monkeypatch.setattr(orchestrator, "probe_reaching_inputs", probe)
    monkeypatch.setattr(
        orchestrator,
        "normalized_last_mile_candidates",
        lambda *_a, **_k: lastmile.LastMileCandidateBatch(),
    )
    specs = [
        HarnessSpec(func="cold_a", decompiled_c=SINK_BODY),
        HarnessSpec(func="cold_b", decompiled_c=SINK_BODY),
        HarnessSpec(func="hot", decompiled_c=SINK_BODY),
    ]

    findings, note = orchestrator._native_last_mile_attempt(
        "/bin/target",
        specs,
        [BASE],
        _LastMileLLM(),
        frozenset({"cold_a", "cold_b", "hot"}),
        CrashSet(),
        set(),
    )

    assert findings == []
    assert calls == ["cold_a", "cold_b", "hot"]
    assert "1/3 sink(s) reached" in note
    assert "probed=cold_a,cold_b,hot" in note
    assert "reached=hot" in note


def test_native_last_mile_rejects_reach_loss_before_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = b"RI\xff\xffdata"
    oracle_inputs: list[bytes] = []

    def probe(
        _binary: str, _function: str, inputs: list[bytes], **_kwargs: object
    ) -> lastmile.ReachProbeResult:
        if inputs == [BASE]:
            return lastmile.ReachProbeResult(available=True, attempted=1, inputs=[BASE])
        assert inputs == [candidate]
        return lastmile.ReachProbeResult(available=True, attempted=1)

    monkeypatch.setattr(orchestrator, "probe_reaching_inputs", probe)
    monkeypatch.setattr(
        orchestrator,
        "normalized_last_mile_candidates",
        lambda *_a, **_k: lastmile.LastMileCandidateBatch(
            candidates=[lastmile.NormalizedCandidate(candidate, "", "unsupported")],
            proposed=1,
            unsupported=1,
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "_confirm_instrumented_file_crash",
        lambda _binary, data, _known: oracle_inputs.append(data),
    )

    findings, note = orchestrator._native_last_mile_attempt(
        "/bin/target",
        [HarnessSpec(func="parse", decompiled_c=SINK_BODY)],
        [BASE],
        _LastMileLLM(),
        frozenset({"parse"}),
        CrashSet(),
        set(),
    )

    assert findings == []
    assert oracle_inputs == []
    assert "sink-preserving=0" in note
    assert "reach-lost=1" in note


def test_native_last_mile_promotes_noncrashing_sink_preserving_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = b"RI\xff\xffdata"
    second_probe_inputs: list[bytes] = []

    def probe(
        _binary: str, function: str, inputs: list[bytes], **_kwargs: object
    ) -> lastmile.ReachProbeResult:
        if function == "first":
            if inputs == [BASE]:
                return lastmile.ReachProbeResult(
                    available=True, attempted=1, inputs=[BASE]
                )
            assert inputs == [candidate]
            return lastmile.ReachProbeResult(
                available=True, attempted=1, inputs=[candidate]
            )
        second_probe_inputs.extend(inputs)
        return lastmile.ReachProbeResult(
            available=True, attempted=1, inputs=[candidate]
        )

    def candidates(
        ctx: lastmile.LastMileContext, _llm: object
    ) -> lastmile.LastMileCandidateBatch:
        if ctx.sink_function == "first":
            return lastmile.LastMileCandidateBatch(
                candidates=[lastmile.NormalizedCandidate(candidate, "", "unsupported")],
                proposed=1,
                unsupported=1,
            )
        return lastmile.LastMileCandidateBatch()

    monkeypatch.setattr(orchestrator, "probe_reaching_inputs", probe)
    monkeypatch.setattr(orchestrator, "normalized_last_mile_candidates", candidates)
    monkeypatch.setattr(
        orchestrator, "_confirm_instrumented_file_crash", lambda *_a: None
    )

    findings, note = orchestrator._native_last_mile_attempt(
        "/bin/target",
        [
            HarnessSpec(func="first", decompiled_c=SINK_BODY),
            HarnessSpec(func="second", decompiled_c=SINK_BODY),
        ],
        [BASE],
        _LastMileLLM(),
        frozenset({"first", "second"}),
        CrashSet(),
        set(),
    )

    assert findings == []
    assert second_probe_inputs[0] == candidate
    assert "sink-preserving=1" in note
    assert "oracle-confirmed=0" in note


# --- wiring into directed_fuzz_function ---------------------------------------

def _probe(traces: dict[bytes, frozenset[int]]) -> CoverageProbe:
    idx = AddressIndex.from_insts([
        Inst(id=0, func="parse", addr=0x401206, kind=Kind.OTHER),
        Inst(id=1, func="parse", addr=0x401240, kind=Kind.OTHER),
        Inst(id=2, func="parse", addr=0x4012C0, kind=Kind.OTHER),
    ])
    p = CoverageProbe("/bin/true", idx)
    for s, a in traces.items():
        p._cache[s] = BlockTrace(addrs=a, note="fixture")
    return p


def test_directed_fuzz_last_mile_confirms_reached_sink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The fuzz windows find no crash, but the corpus REACHED the sink block; the
    # last-mile pass mutates the reaching input and the oracle confirms it.
    monkeypatch.setenv("ZEROVERSE_LAST_MILE", "1")
    spec = HarnessSpec(func="parse", decompiled_c=SINK_BODY)
    monkeypatch.setattr(
        orchestrator, "build_fuzz_binaries",
        lambda *a, **k: CompiledTarget(fuzz_bin=tmp_path / "a", replay_bin=tmp_path / "r"),
    )
    mutated = b"RI\xff\xffdata"
    pov = PoV(input_bytes=mutated, crash_class="SIGSEGV", reproduced=True,
              capability="oob-write", dedup_bucket="lm1")

    def fake_confirm(_bin: object, data: bytes, **_k: object) -> PoV | None:
        return pov if data == mutated else None

    monkeypatch.setattr(orchestrator, "confirm_crash", fake_confirm)
    targets = DirectedTargets([SinkTarget("parse", 0x401206, 0x4012C0, "slice")])
    probe = _probe({BASE: frozenset({0x401206, 0x401240, 0x4012C0})})
    outcome = orchestrator.directed_fuzz_function(
        spec, [], targets=targets, probe=probe, harness_src="/* h */",
        llm=_LastMileLLM(), backend=FakeAfl([]),
        config=AflConfig(duration_s=1, seeds=[BASE]),
        workdir=tmp_path / "wd", max_windows=1,
    )
    assert outcome.crash_found
    assert outcome.pov is pov
    assert "last-mile" in outcome.note
    assert outcome.fuzz_findings[0].pov.reproduced


def test_directed_fuzz_last_mile_off_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # no ZEROVERSE_LAST_MILE: same setup, no LLM spend, honest no-crash outcome
    monkeypatch.delenv("ZEROVERSE_LAST_MILE", raising=False)
    spec = HarnessSpec(func="parse", decompiled_c=SINK_BODY)
    monkeypatch.setattr(
        orchestrator, "build_fuzz_binaries",
        lambda *a, **k: CompiledTarget(fuzz_bin=tmp_path / "a", replay_bin=tmp_path / "r"),
    )
    llm = _LastMileLLM()
    targets = DirectedTargets([SinkTarget("parse", 0x401206, 0x4012C0, "slice")])
    probe = _probe({BASE: frozenset({0x401206, 0x401240, 0x4012C0})})
    outcome = orchestrator.directed_fuzz_function(
        spec, [], targets=targets, probe=probe, harness_src="/* h */",
        llm=llm, backend=FakeAfl([]),
        config=AflConfig(duration_s=1, seeds=[BASE]),
        workdir=tmp_path / "wd", max_windows=1,
    )
    assert not outcome.crash_found
    assert llm.prompts == []


def test_native_fuzz_last_mile_runs_after_unmatched_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.oracle import RunResult

    monkeypatch.setenv("ZEROVERSE_LAST_MILE", "1")
    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(
        orchestrator,
        "run_sanitizer",
        lambda *_a, **_k: RunResult(crashed=False),
    )
    monkeypatch.setattr(
        orchestrator,
        "_native_last_mile_queue",
        lambda *_a, **_k: [BASE],
    )
    def probe(
        _binary: str, _function: str, inputs: list[bytes], **_kwargs: object
    ) -> lastmile.ReachProbeResult:
        return lastmile.ReachProbeResult(
            available=True, attempted=len(inputs), inputs=list(inputs)
        )

    monkeypatch.setattr(orchestrator, "probe_reaching_inputs", probe)

    unmatched = PoV(
        input_bytes=b"unmatched",
        crash_class="SIGSEGV",
        reproduced=True,
        capability="crash",
        dedup_bucket="unmatched",
        frames=["unknown"],
    )
    mutated = b"RI\xff\xffdata"
    targeted = PoV(
        input_bytes=mutated,
        crash_class="heap-buffer-overflow",
        reproduced=True,
        capability="oob-write",
        dedup_bucket="targeted",
        frames=["parse"],
    )

    def confirm(
        binary: str, data: bytes, _known: frozenset[str]
    ) -> tuple[PoV, str, CrashFeedbackReceipt] | None:
        if data == b"unmatched":
            pov, function = unmatched, "<whole-program>"
        elif data == mutated:
            pov, function = targeted, "parse"
        else:
            return None
        return (
            pov,
            function,
            crash_feedback_receipt(
                target=binary,
                original_input=data,
                minimized_input=data,
                oracle="test-fixture",
                crash_class=pov.crash_class,
                dedup_bucket=pov.dedup_bucket,
            ),
        )

    monkeypatch.setattr(orchestrator, "_confirm_instrumented_file_crash", confirm)
    llm = _LastMileLLM()
    config = AflConfig()
    findings, note = orchestrator.run_fuzz_stage(
        "/bin/target",
        {"parse": SINK_BODY},
        llm=llm,
        out_dir=tmp_path,
        backend=FakeAfl([b"unmatched"]),
        config=config,
    )

    assert {finding.finding.function for finding in findings} == {
        "<whole-program>",
        "parse",
    }
    assert "last-mile: 1 base input probe(s), 1 candidate re-probe(s)" in note
    assert "oracle-confirmed=1" in note
    assert "reused native instrumented harness" in note
    assert not config.stop_on_crash
    assert len(llm.prompts) == 1
    assert "REACHED-BUT-UNCRASHED SINK: parse" in llm.prompts[0]


def test_native_fuzz_last_mile_never_guesses_without_reach_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.oracle import RunResult

    monkeypatch.setenv("ZEROVERSE_LAST_MILE", "1")
    monkeypatch.setattr(orchestrator, "is_instrumented_fuzz_target", lambda _b: True)
    monkeypatch.setattr(
        orchestrator,
        "run_sanitizer",
        lambda *_a, **_k: RunResult(crashed=False),
    )
    monkeypatch.setattr(
        orchestrator,
        "_native_last_mile_queue",
        lambda *_a, **_k: [BASE],
    )
    monkeypatch.setattr(
        orchestrator,
        "probe_reaching_inputs",
        lambda *_a, **_k: lastmile.ReachProbeResult(
            note="GDB unavailable or executor is not trusted-local"
        ),
    )
    llm = _LastMileLLM()

    findings, note = orchestrator.run_fuzz_stage(
        "/bin/target",
        {"parse": SINK_BODY},
        llm=llm,
        out_dir=tmp_path,
        backend=FakeAfl([]),
    )

    assert findings == []
    assert "last-mile skipped: GDB unavailable" in note
    assert not any("REACHED-BUT-UNCRASHED SINK" in prompt for prompt in llm.prompts)
