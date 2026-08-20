"""scan() over the MockAdapter: getenv() (source) -> system() (sink), the
command-injection flow, using the real shipped taint model."""

from pathlib import Path

from zeroverse.analyze import (
    Finding,
    filter_findings,
    ptr_taint_summary,
    reachable_functions,
    scan,
)
from zeroverse.backends.ghidra import ProgramMeta
from zeroverse.il import Inst, Kind, MockAdapter
from zeroverse.taint import load_model

CONF = Path(__file__).resolve().parents[1] / "conf"


def _model_insts() -> list[Inst]:
    # p = getenv("CMD");  system(p);    (a CAST sits between, as Ghidra emits)
    return [
        Inst(1, "main", 0x1000, Kind.CALL, dest="getenv", args=[20]),
        Inst(20, "main", 0x1000, Kind.CONST, text='"CMD"'),
        Inst(5, "main", 0x1008, Kind.OTHER, operands=[1]),   # cast of getenv result
        Inst(10, "main", 0x1010, Kind.CALL, dest="system", args=[5]),
        # an untainted system(constant) — must NOT be reported
        Inst(11, "main", 0x1020, Kind.CALL, dest="system", args=[30]),
        Inst(30, "main", 0x1020, Kind.CONST, text='"/bin/true"'),
    ]


def test_scan_finds_command_injection() -> None:
    insts = _model_insts()
    findings = scan(MockAdapter(insts), load_model(CONF), insts)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "getenv" and f.sink == "system"
    assert f.function == "main"
    assert f.sink_addr == 0x1010


def test_scan_memory_flow_shared_buffer() -> None:
    # read(fd, big, n) fills buffer 'big'; strcpy(dst, big) copies from it -> overflow.
    insts = [
        Inst(1, "main", 0x10, Kind.CALL, dest="read", arg_vars=[None, "big", None]),
        Inst(2, "main", 0x20, Kind.CALL, dest="strcpy", arg_vars=[None, "big"]),
        Inst(3, "main", 0x30, Kind.CALL, dest="strcpy", arg_vars=[None, "other"]),
    ]
    findings = scan(MockAdapter(insts), load_model(CONF), insts)
    assert any(f.source == "read" and f.sink == "strcpy" and f.sink_addr == 0x20 for f in findings)
    assert not any(f.sink_addr == 0x30 for f in findings)  # different buffer, no flow


def test_ptr_taint_summary_names_out_and_in_params() -> None:
    # The pointer/out-param summary (#2) names the buffer each tainted call touches.
    insts = [
        Inst(1, "main", 0x10, Kind.CALL, dest="read", arg_vars=[None, "big", None]),
        Inst(2, "main", 0x20, Kind.CALL, dest="strcpy", arg_vars=[None, "big"]),
    ]
    summary = ptr_taint_summary(insts, {1: "read", 2: "strcpy"})
    src = next(p for p in summary if p.role == "source")
    snk = next(p for p in summary if p.role == "sink")
    assert src.symbol == "read" and src.buf_arg == 1 and src.buf_var == "big"
    assert snk.symbol == "strcpy" and snk.buf_arg == 1 and snk.buf_var == "big"


def test_scan_handles_namespaced_names() -> None:
    # Ghidra sometimes emits "EXTERNAL::system" / "_getenv".
    insts = [
        Inst(1, "main", 0x10, Kind.CALL, dest="_getenv", args=[]),
        Inst(2, "main", 0x14, Kind.OTHER, operands=[1]),
        Inst(3, "main", 0x18, Kind.CALL, dest="EXTERNAL::system", args=[2]),
    ]
    findings = scan(MockAdapter(insts), load_model(CONF), insts)
    assert len(findings) == 1 and findings[0].source == "getenv"


# --- libFuzzer target-vs-driver focusing -----------------------------------


def _f(function: str, origin: str = "slice") -> Finding:
    return Finding(
        source="src", sink="memcpy", function=function,
        source_addr=0x10, sink_addr=0x20, path_len=1, origin=origin,
    )


def _libfuzzer_meta() -> ProgramMeta:
    # The libFuzzer driver (main -> FuzzerDriver -> ... -> ExecuteCallback) is a
    # separate island from the target (LLVMFuzzerTestOneInput -> cms* library),
    # exactly as a real ASan+libFuzzer binary decompiles (the call into the entry
    # is indirect, so the two are disconnected in the recovered call graph).
    return ProgramMeta(callgraph={
        "main": ["FuzzerDriver"],
        "FuzzerDriver": ["ExecuteCallback", "CrossOver"],
        "ExecuteCallback": [],
        "CrossOver": [],
        "LLVMFuzzerTestOneInput": ["cmsOpenProfile", "cmsDoTransform"],
        "cmsOpenProfile": ["cmsReadTag"],
        "cmsDoTransform": ["memcpy"],
        "cmsReadTag": [],
    })


def test_reachable_functions_roots_at_libfuzzer_entry() -> None:
    reach = reachable_functions(_libfuzzer_meta())
    assert reach is not None
    # target library reachable from the entry; driver island is not.
    assert {"cmsOpenProfile", "cmsDoTransform", "cmsReadTag"} <= reach
    assert "FuzzerDriver" not in reach and "CrossOver" not in reach


def test_filter_findings_keeps_target_drops_driver() -> None:
    findings = [
        _f("cmsDoTransform"),          # real target — kept (reachable)
        _f("cmsReadTag"),              # real target — kept (reachable)
        _f("CrossOver"),               # driver noise-name — dropped
        _f("FuzzerDriver"),            # driver, unreachable — dropped
        _f("some_unreachable_helper"), # not reachable from entry — dropped
    ]
    kept, note = filter_findings(findings, _libfuzzer_meta())
    fns = {f.function for f in kept}
    assert fns == {"cmsDoTransform", "cmsReadTag"}
    assert "dropped" in note


def test_filter_findings_noop_without_callgraph() -> None:
    # A toy / non-libFuzzer binary with no call graph must be untouched.
    findings = [_f("main"), _f("helper")]
    kept, note = filter_findings(findings, ProgramMeta())
    assert kept == findings and note == ""


def test_filter_findings_noop_when_all_reachable() -> None:
    # Normal binary: everything is reachable from main -> no strict subset -> no-op.
    meta = ProgramMeta(callgraph={"main": ["helper"], "helper": ["memcpy"]})
    findings = [_f("main"), _f("helper")]
    kept, note = filter_findings(findings, meta)
    assert kept == findings and note == ""


def test_filter_findings_libfuzzer_missing_entry_only_noise() -> None:
    # Cached-style graph: driver present but the entry symbol was noise-skipped, so
    # it is absent from the graph. Reachability must NOT fall back to main (that is
    # the driver); only the name-based noise filter drops the driver finding.
    meta = ProgramMeta(callgraph={
        "main": ["FuzzerDriver"],
        "FuzzerDriver": ["CrossOver"],
        "cmsDoTransform": ["memcpy"],  # target island, orphaned in the cached graph
    })
    findings = [_f("cmsDoTransform"), _f("CrossOver")]
    kept, note = filter_findings(findings, meta)
    fns = {f.function for f in kept}
    assert fns == {"cmsDoTransform"}  # cms kept, driver dropped by name
    assert "1 noise-named" in note and "0 unreachable" in note
