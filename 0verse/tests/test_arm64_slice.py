"""ABI carry-over (#19): the same slice + pointer/out-param taint summary runs
over an AArch64-shaped Ghidra export. Ghidra high P-Code SSA is def-use over
named decompiler variables, so the slicer is architecture-neutral — this asserts
it on arm64 (read fills `big`, strcpy copies from it → overflow), and that the
program's ABI resolves to AAPCS64."""

from __future__ import annotations

from pathlib import Path

from zeroverse.abi import AAPCS64
from zeroverse.analyze import scan
from zeroverse.backends.ghidra import GhidraAdapter
from zeroverse.taint import load_model

CONF = Path(__file__).resolve().parents[1] / "conf"

# An arm64 export: read(fd, big, n) then strcpy(dst, big) — memory flow by name.
ARM64_EXPORT = {
    "functions": ["handle"],
    "insts": [
        {"id": 1, "func": "handle", "addr": 0x10, "kind": "CALL",
         "dest": "read", "arg_vars": [None, "big", None]},
        {"id": 2, "func": "handle", "addr": 0x20, "kind": "CALL",
         "dest": "strcpy", "arg_vars": [None, "big"]},
        {"id": 3, "func": "handle", "addr": 0x30, "kind": "CALL",
         "dest": "strcpy", "arg_vars": [None, "other"]},
    ],
    "defs": [], "mem_defs": [], "callers": [], "returns": [],
    "meta": {"processor": "AARCH64", "arch": "aarch64", "bits": 64,
             "decompiled_c": {}, "imports": [], "exports": [],
             "callgraph": {}, "unresolved_edges": []},
}


def test_slice_finds_read_to_strcpy_on_arm64() -> None:
    a = GhidraAdapter.from_json(ARM64_EXPORT)
    findings = scan(a, load_model(CONF), a.all_insts())
    assert any(
        f.source == "read" and f.sink == "strcpy" and f.sink_addr == 0x20
        for f in findings
    )
    # the untainted strcpy on a different buffer is not flagged
    assert not any(f.sink_addr == 0x30 for f in findings)


def test_program_abi_resolves_to_aapcs64() -> None:
    a = GhidraAdapter.from_json(ARM64_EXPORT)
    assert a.meta.processor == "AARCH64"
    assert a.meta.abi() is AAPCS64
