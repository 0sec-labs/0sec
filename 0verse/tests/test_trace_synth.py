"""Trace-guided structured synthesis — pure unit tests (mock LLM + oracle, no binaries).

Exercises the logic: call-path recovery from decompiled code, envelope parsing,
hex decode, the coverage-feedback refine loop, and the differential-oracle confirm/
partial decision — all deterministic via monkeypatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from zeroverse import adjudicate as adj_mod
from zeroverse import oracle
from zeroverse import trace_synth as ts


def _patch_oracle(monkeypatch, fake):
    """Patch run_sanitizer everywhere it is referenced: the oracle module (used by
    trace_synth's fixed-clean check) AND adjudicate's imported name (used by
    adjudicate_finding for the vuln crash check)."""
    monkeypatch.setattr(ts.oracle, "run_sanitizer", fake)
    monkeypatch.setattr(adj_mod, "run_sanitizer", fake)
    # adjudicate_finding bails UNRUNNABLE unless the host can exec the (fake) binary.
    monkeypatch.setattr(adj_mod, "host_can_launch", lambda b, **kw: True)


@dataclass
class _Verdict:
    sink: str = "libraw_sget4_static"
    source: str = "attacker file"
    cwe: str = "CWE-125"


def _meta(dc: dict[str, str]) -> SimpleNamespace:
    return SimpleNamespace(decompiled_c=dc)


class _LLM:
    """Scripted LLM: returns queued responses for complete_json in order."""

    def __init__(self, envelope, synth_hexes):
        self._envelope = envelope
        self._hexes = list(synth_hexes)

    def complete_json(self, system, prompt, schema):
        if "controlled_field" in str(schema.get("properties", {})):
            return self._envelope
        h = self._hexes.pop(0) if self._hexes else ""
        return {"hex": h}


def _run(crashed, *, sanitizer="", stderr=""):
    return oracle.RunResult(crashed=crashed, sanitizer=sanitizer, stderr=stderr)


# --- call-path recovery -----------------------------------------------------


def test_recover_call_path_walks_callers_to_entry() -> None:
    dc = {
        "LLVMFuzzerTestOneInput": "int LLVMFuzzerTestOneInput(){ identify(); }",
        "identify": "void identify(){ parse_tiff(); }",
        "parse_tiff": "void parse_tiff(){ parse_tiff_ifd(); }",
        "parse_tiff_ifd": "void parse_tiff_ifd(){ parseAdobeRAFMakernote(); }",
        "parseAdobeRAFMakernote": "void parseAdobeRAFMakernote(){ libraw_sget4_static(); }",
        "libraw_sget4_static": "int libraw_sget4_static(){ return oob; }",
        "unrelated": "void unrelated(){ other(); }",
    }
    path = ts.recover_call_path(_meta(dc), _Verdict(sink="libraw_sget4_static"))
    assert path[0] == "LLVMFuzzerTestOneInput"
    assert path[-1] == "libraw_sget4_static"
    assert "parseAdobeRAFMakernote" in path
    assert "unrelated" not in path


def test_recover_call_path_empty_when_no_decompile() -> None:
    assert ts.recover_call_path(_meta({}), _Verdict()) == []


def test_caller_slice_gathers_full_neighborhood_not_a_thin_chain() -> None:
    """The fix for the failed autonomous run: gather ALL transitive callers (the real
    parser functions), ordered outermost-first, not one spurious shortest chain."""
    dc = {
        "LLVMFuzzerTestOneInput": "void LLVMFuzzerTestOneInput(){ identify(); }",
        "identify": "void identify(){ parse_tiff(); }",
        "parse_tiff": "void parse_tiff(){ parse_makernote_0xc634(); }",
        "parse_makernote_0xc634": "void parse_makernote_0xc634(){ parseAdobeRAFMakernote(); }",
        "parseAdobeRAFMakernote": "void parseAdobeRAFMakernote(){ libraw_sget4_static(); }",
        "libraw_sget4_static": "int libraw_sget4_static(){ return oob; }",
        # a spurious function that textually references the sink but isn't the real path
        "LibRaw": "void LibRaw(){ /* vtable mentions libraw_sget4_static */ }",
    }
    sl = ts.caller_slice(_meta(dc), _Verdict(sink="libraw_sget4_static"))
    assert sl[-1] == "libraw_sget4_static"  # sink last
    assert sl[0] == "LLVMFuzzerTestOneInput"  # entry outermost-first
    # the real parser functions are ALL present (the neighborhood, not a 2-hop shortcut)
    for fn in ("parse_tiff", "parse_makernote_0xc634", "parseAdobeRAFMakernote"):
        assert fn in sl


# --- hex decode -------------------------------------------------------------


def test_decode_hex_tolerant() -> None:
    assert ts._decode_hex("4949 2a00") == b"II*\x00"
    assert ts._decode_hex("0x49492a00") == b"II*\x00"
    assert ts._decode_hex("zzz") is None
    assert ts._decode_hex("494") == b"I"  # odd length trimmed


# --- envelope recovery ------------------------------------------------------


def test_recover_envelope_parses_schema() -> None:
    env_json = {
        "format_name": "TIFF/DNG",
        "layers": [
            {"name": "tiff_header", "kind": "magic", "detail": "II*\\0", "bytes_hint": "49492a00"},
            {"name": "tag_0xC634", "kind": "tag", "detail": "DNGPrivateData"},
        ],
        "controlled_field": "sget4(2) offset",
        "fault_constraint": "offset < 0",
        "notes": "one-sided bounds check",
    }
    llm = _LLM(env_json, [])
    env = ts.recover_envelope(
        _meta({"libraw_sget4_static": "x"}),
        _Verdict(),
        ["LLVMFuzzerTestOneInput", "libraw_sget4_static"],
        llm,
    )
    assert env.format_name == "TIFF/DNG"
    assert len(env.layers) == 2
    assert env.layers[0].kind == "magic"
    assert env.fault_constraint == "offset < 0"


# --- end-to-end confirm -----------------------------------------------------

_DC = {
    "LLVMFuzzerTestOneInput": "void LLVMFuzzerTestOneInput(){ identify(); }",
    "identify": "void identify(){ libraw_sget4_static(); }",
    "libraw_sget4_static": "int libraw_sget4_static(){ return oob; }",
}
_ENV = {
    "format_name": "TIFF/DNG",
    "layers": [{"name": "h", "kind": "magic", "detail": "II"}],
    "controlled_field": "offset",
    "fault_constraint": "offset < 0",
}


def test_confirm_end_to_end(monkeypatch) -> None:
    monkeypatch.setattr(ts.oracle, "is_asan_file_target", lambda b: True)
    asan = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow READ\n"
        "    #0 0x1 in libraw_sget4_static /src/read_utils.cpp:63\n"
    )
    # adjudicate_finding -> run_sanitizer on vuln crashes at sink; fixed clean.
    _patch_oracle(
        monkeypatch,
        lambda b, d, **kw: _run(
            "vuln" in str(b), sanitizer="AddressSanitizer", stderr=asan if "vuln" in str(b) else ""
        ),
    )
    llm = _LLM(_ENV, ["4949"])
    res = ts.confirm_by_trace_synthesis(
        _meta(_DC),
        _Verdict(),
        "/t/vuln",
        llm,
        fixed_binary="/t/fixed",
        iterations=2,
    )
    assert res.confirmed is True
    assert res.crash_function == "libraw_sget4_static"
    assert res.matches_sink is True
    assert res.winning_input == b"II"
    assert "CONFIRMED" in res.reason


def test_not_applicable_non_harness(monkeypatch) -> None:
    monkeypatch.setattr(ts.oracle, "is_asan_file_target", lambda b: False)
    res = ts.confirm_by_trace_synthesis(_meta(_DC), _Verdict(), "/t/elf", _LLM(_ENV, []))
    assert res.confirmed is False and "libFuzzer harness" in res.reason


def test_covers_function_does_not_match_uncovered_line(monkeypatch) -> None:
    """Regression: 'COVERED_FUNC:' is a substring of 'UNCOVERED_FUNC:', so an unanchored
    match reported every function (hits:0 included) as covered — a silent always-true
    false positive that faked reached_sink. Must anchor to a real COVERED line."""
    from zeroverse.sandbox_exec import ExecResult, LocalExecutor

    def fake_run(covered: bool):
        line = (
            "COVERED_FUNC: hits: 3 edges: 5/40 LibRaw::parseAdobeRAFMakernote() /f.cpp:210"
            if covered
            else "UNCOVERED_FUNC: hits: 0 edges: 0/412 LibRaw::parseAdobeRAFMakernote() /f.cpp:145"
        )
        return ExecResult(stdout=line)

    monkeypatch.setattr(ts.oracle, "_exec_path", lambda b: "/bin/true")
    monkeypatch.setattr(LocalExecutor, "run", lambda self, argv, **kw: fake_run(covered=False))
    assert ts._covers_function("/t/vuln", b"x", "parseAdobeRAFMakernote", 5.0) is False  # UNCOVERED
    monkeypatch.setattr(LocalExecutor, "run", lambda self, argv, **kw: fake_run(covered=True))
    assert ts._covers_function("/t/vuln", b"x", "parseAdobeRAFMakernote", 5.0) is True  # COVERED


def test_hybrid_fuzz_confirms_reaching_candidate(monkeypatch) -> None:
    """Synthesis reaches the sink parser but can't byte-place the fault; the hybrid hands
    the reaching candidate to directed-fuzz, which trips the OOB and confirms."""
    monkeypatch.setattr(ts.oracle, "is_asan_file_target", lambda b: True)
    _patch_oracle(monkeypatch, lambda b, d, **kw: _run(False))  # vuln never crashes on synth cand
    # candidate DOES dispatch to the sink parser (precise coverage True)
    monkeypatch.setattr(ts, "_covers_function", lambda v, c, fn, t: True)
    monkeypatch.setattr(ts, "_reached_depth", lambda v, c, p, t: (len(p), p[-1] if p else ""))

    # directed-fuzz (imported inside the hybrid block) confirms on the reaching seed.
    import zeroverse.directed_fuzz as dfz
    from zeroverse.directed_fuzz import DirectedFuzzResult

    monkeypatch.setattr(
        dfz,
        "confirm_by_directed_fuzz",
        lambda *a, **kw: DirectedFuzzResult(
            confirmed=True,
            crash_function="libraw_sget4_static",
            crash_cwe="CWE-125",
            matches_hypothesis=True,
            winning_input=b"FUZZ-MUTATED-OOB",
            reason="fuzz tripped it",
        ),
    )
    llm = _LLM(_ENV, ["4949", "494a", "494b"])
    res = ts.confirm_by_trace_synthesis(
        _meta(_DC),
        _Verdict(),
        "/t/vuln",
        llm,
        fixed_binary="/t/fixed",
        iterations=2,
        hybrid_fuzz=True,
    )
    assert res.reached_sink is True
    assert res.confirmed is True
    assert res.confirmed_via == "hybrid-fuzz"
    assert res.winning_input == b"FUZZ-MUTATED-OOB"


def test_honest_partial_reports_reached_depth(monkeypatch) -> None:
    monkeypatch.setattr(ts, "_covers_function", lambda v, c, fn, t: False)
    """No crash: the loop reports how far routing got (the trace-guided signal)."""
    monkeypatch.setattr(ts.oracle, "is_asan_file_target", lambda b: True)
    _patch_oracle(monkeypatch, lambda b, d, **kw: _run(False))
    # candidate reaches the first 2 path functions (coverage output names them).
    monkeypatch.setattr(
        ts,
        "_reached_depth",
        lambda vuln, cand, path, timeout: (2, path[1] if len(path) > 1 else ""),
    )
    llm = _LLM(_ENV, ["4949", "494a"])
    res = ts.confirm_by_trace_synthesis(
        _meta(_DC),
        _Verdict(),
        "/t/vuln",
        llm,
        fixed_binary="/t/fixed",
        iterations=2,
    )
    assert res.confirmed is False
    assert res.reached_depth == 2
    assert "reached 2" in res.reason


# --- rejected candidates accumulate instead of overwriting (issue #1705) ----


def test_rejected_text_accumulates_and_is_bounded() -> None:
    assert ts._rejected_text([]) == ""
    text = ts._rejected_text(["iter 1: aa", "iter 2: bb"])
    assert "iter 1: aa" in text and "iter 2: bb" in text
    assert "do NOT" in text and "2 attempt(s)" in text

    many = [f"iter {i}: cand{i}" for i in range(1, 21)]
    bounded = ts._rejected_text(many)
    assert bounded.count("cand") == ts._MAX_REJECTED_HISTORY
    assert "cand20" in bounded and "cand1:" not in bounded
    assert "20 attempt(s)" in bounded


def test_synthesize_structured_replays_every_rejected_candidate() -> None:
    seen: list[str] = []

    class _Recorder:
        def complete_json(self, system, prompt, schema):
            seen.append(prompt)
            return {"hex": "4949"}

    ts.synthesize_structured(
        ts.EnvelopeSpec(format_name="TIFF"),
        _Recorder(),
        feedback="latest only",
        history=["iter 1: 4141… — reached_sink=False", "iter 2: 4242… — reached_sink=False"],
    )
    assert "latest only" in seen[0]
    assert "4141" in seen[0] and "4242" in seen[0]
    assert "ALREADY TRIED AND REJECTED" in seen[0]


def test_refine_loop_shows_iteration_three_what_iteration_one_tried(monkeypatch) -> None:
    # The bug: only `feedback` (the latest) reached the model, so a candidate the
    # loop already measured as non-routing could be proposed again.
    monkeypatch.setattr(ts, "_covers_function", lambda v, c, fn, t: False)
    monkeypatch.setattr(ts.oracle, "is_asan_file_target", lambda b: True)
    _patch_oracle(monkeypatch, lambda b, d, **kw: _run(False))
    monkeypatch.setattr(ts, "_reached_depth", lambda vuln, cand, path, timeout: (1, "identify"))

    prompts: list[str] = []

    class _Recorder(_LLM):
        def complete_json(self, system, prompt, schema):
            if "controlled_field" not in str(schema.get("properties", {})):
                prompts.append(prompt)
            return super().complete_json(system, prompt, schema)

    llm = _Recorder(_ENV, ["4141", "4242", "4343"])
    ts.confirm_by_trace_synthesis(
        _meta(_DC), _Verdict(), "/t/vuln", llm, fixed_binary="/t/fixed", iterations=3,
    )

    assert len(prompts) == 3
    assert "ALREADY TRIED AND REJECTED" not in prompts[0]
    assert "4141" in prompts[1]
    # Iteration 3 sees BOTH earlier candidates, not just iteration 2's.
    assert "4141" in prompts[2] and "4242" in prompts[2]


def test_runtime_refiner_also_replays_its_accumulated_history() -> None:
    # The second overwrite site, in the gdb-guided refine loop: the refiner saw only
    # the CURRENT bytes plus the CURRENT instruction, so a candidate the probe had
    # already measured as bailing was invisible and could be walked back to.
    seen: list[str] = []

    class _Recorder:
        def complete_json(self, system, prompt, schema):
            seen.append(prompt)
            return {"hex": "4343"}

    out = ts._llm_refine_bytes(
        _Recorder(),
        b"\x43\x43",
        "the length check at line 61 rejected it",
        ["iter 1: 4141… — bailed at line 61", "iter 2: 4242… — bailed at line 61"],
    )
    assert out == b"\x43\x43"
    assert "the length check at line 61" in seen[0]
    assert "4141" in seen[0] and "4242" in seen[0]
    assert "ALREADY TRIED AND REJECTED" in seen[0]

    # No history is the same prompt it always built.
    ts._llm_refine_bytes(_Recorder(), b"\x43", "instr")
    assert "ALREADY TRIED AND REJECTED" not in seen[1]
