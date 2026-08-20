"""GhidraAdapter conforms to ILAdapter and drives the slicer over a Ghidra-shaped
JSON export — the same read→memcpy flow as the mock, but via the real backend."""

import json
from pathlib import Path

from zeroverse.backends.ghidra import GhidraAdapter
from zeroverse.il import ILAdapter
from zeroverse.slicer import BackwardSlicer, find_source_to_sink

FIXTURE = Path(__file__).parent / "fixtures" / "ghidra_read_memcpy.json"


def _adapter() -> GhidraAdapter:
    return GhidraAdapter.from_json(json.loads(FIXTURE.read_text()))


def test_conforms_to_protocol() -> None:
    assert isinstance(_adapter(), ILAdapter)


def test_functions_and_defs() -> None:
    a = _adapter()
    assert a.functions() == ["main"]
    assert a.get_def("buf", "main") == 1
    assert a.get_def("missing", "main") is None


def test_slicer_runs_over_ghidra_export() -> None:
    slicer = BackwardSlicer(_adapter())
    findings = find_source_to_sink(slicer, source_ids=[1], sink_ids=[10, 11])
    assert len(findings) == 1
    assert findings[0].source_id == 1 and findings[0].sink_id == 10


def test_from_export_path() -> None:
    a = GhidraAdapter.from_export(FIXTURE)
    assert a.inst(10).dest == "memcpy"


def test_meta_roundtrips_through_json() -> None:
    # to_json/from_json preserve the #1 program metadata (decompiled C, imports,
    # exports, call graph, unresolved_edges) so a decompile can be cached & replayed.
    from zeroverse.backends.ghidra import GhidraAdapter as GA
    from zeroverse.backends.ghidra import ProgramMeta

    meta = ProgramMeta(
        decompiled_c={"main": "int main(void){...}"},
        imports=["read", "strcpy"], exports=["main"],
        callgraph={"main": ["read", "strcpy"]},
        unresolved_edges=[{"func": "main", "addr": "0x401200", "op": "CALLIND"}],
    )
    base = _adapter()
    rich = GA(list(base.all_insts()), {}, {}, {}, {}, meta=meta)
    back = GA.from_json(json.loads(rich.to_json()))
    assert back.meta.imports == ["read", "strcpy"]
    assert back.meta.callgraph["main"] == ["read", "strcpy"]
    assert back.meta.unresolved_edges[0]["op"] == "CALLIND"
    assert back.meta.decompiled_c["main"].startswith("int main")
