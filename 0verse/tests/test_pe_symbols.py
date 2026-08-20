from __future__ import annotations

import struct
import subprocess
from pathlib import Path

from zeroverse.backends.ghidra import GhidraAdapter, ProgramMeta
from zeroverse.il import Inst, Kind
from zeroverse.pe_symbols import (
    adjacent_pdb,
    coff_functions,
    enrich_ghidra_symbols,
    pdb_codeview_identity,
    pdb_function_records,
    pdb_functions,
    resolve_crash_frame,
)


def _pe_with_symbol(path: Path) -> None:
    blob = bytearray(0x400)
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\0\0"
    header = 0x84
    struct.pack_into("<H", blob, header + 2, 1)
    struct.pack_into("<II", blob, header + 8, 0x200, 1)
    struct.pack_into("<H", blob, header + 16, 0xF0)
    optional = header + 20
    struct.pack_into("<H", blob, optional, 0x20B)
    struct.pack_into("<Q", blob, optional + 24, 0x140000000)
    section = header + 20 + 0xF0
    blob[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<I", blob, section + 8, 0x200)
    struct.pack_into("<I", blob, section + 12, 0x1000)
    struct.pack_into("<I", blob, section + 16, 0x200)
    struct.pack_into("<I", blob, section + 20, 0x200)
    struct.pack_into("<I", blob, section + 36, 0x60000020)
    # Debug data-directory entry and one CodeView/RSDS record.
    struct.pack_into("<II", blob, optional + 112 + 6 * 8, 0x1100, 28)
    struct.pack_into("<IIIIIII", blob, 0x300, 0, 0, 0, 2, 33, 0x1140, 0x340)
    blob[0x340:0x344] = b"RSDS"
    blob[0x344:0x354] = bytes.fromhex("33221100554477668899aabbccddeeff")
    struct.pack_into("<I", blob, 0x354, 1)
    blob[0x358:0x361] = b"test.pdb\0"
    symbol = 0x200
    blob[symbol:symbol + 8] = b"parse\0\0\0"
    struct.pack_into("<IhHBB", blob, symbol + 8, 0x450, 1, 0x20, 2, 0)
    struct.pack_into("<I", blob, symbol + 18, 4)
    path.write_bytes(blob)


def test_coff_function_and_frame_resolution(tmp_path: Path) -> None:
    pe = tmp_path / "fixture.exe"
    _pe_with_symbol(pe)
    assert coff_functions(pe) == {0x1450: "parse"}
    assert resolve_crash_frame(pe, ["VerifierStop", "image123+0x14db"]) == "parse"


def test_invalid_pe_has_no_symbols(tmp_path: Path) -> None:
    path = tmp_path / "bad"
    path.write_bytes(b"not a PE")
    assert coff_functions(path) == {}
    assert resolve_crash_frame(path, ["image1+0x1234"]) == ""


def test_adjacent_pdb_requires_unambiguous_candidate(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "driver.sys"
    binary.touch()
    tagged = tmp_path / "driver-guid.pdb"
    tagged.touch()
    assert adjacent_pdb(binary) == tagged
    (tmp_path / "other.pdb").touch()
    assert adjacent_pdb(binary) == tagged
    (tmp_path / "driver-second.pdb").touch()
    assert adjacent_pdb(binary) is None
    explicit = tmp_path / "explicit.pdb"
    explicit.touch()
    monkeypatch.setenv("ZEROVERSE_PDB", str(explicit))
    assert adjacent_pdb(binary) == explicit


def test_pdb_functions_maps_executable_section_rva(
    tmp_path: Path, monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    pdb = tmp_path / "driver.pdb"
    pdb.touch()
    monkeypatch.setattr("zeroverse.pe_symbols.shutil.which", lambda _: "/llvm-pdbutil")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            0,
            stdout=(
                "  Age: 1\n"
                "  GUID: {00112233-4455-6677-8899-AABBCCDDEEFF}\n"
                "  Is stripped: false\n"
                "  68 | S_LPROC32 [size = 64] `ParseGuestPacket`\n"
                "       parent = 0, end = 132, addr = 0001:1104, code size = 42\n"
            ),
            stderr="",
        )

    assert pdb_functions(binary, pdb, run=fake_run) == {0x1450: "ParseGuestPacket"}


def test_pdb_codeview_identity_reads_actual_pdb_summary(tmp_path: Path, monkeypatch) -> None:
    pdb = tmp_path / "driver.pdb"
    pdb.touch()
    monkeypatch.setattr("zeroverse.pe_symbols.shutil.which", lambda _: "/llvm-pdbutil")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            0,
            stdout=(
                "Age: 1\nGUID: {00112233-4455-6677-8899-AABBCCDDEEFF}\n"
                "Is stripped: false\n"
            ),
            stderr="",
        )

    assert pdb_codeview_identity(pdb, run=fake_run) == (
        "00112233-4455-6677-8899-AABBCCDDEEFF",
        1,
        False,
    )


def test_pdb_functions_includes_function_publics_only(
    tmp_path: Path, monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    pdb = tmp_path / "driver.pdb"
    pdb.touch()
    monkeypatch.setattr("zeroverse.pe_symbols.shutil.which", lambda _: "/llvm-pdbutil")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0,
            stdout=(
                "Age: 1\nGUID: {00112233-4455-6677-8899-AABBCCDDEEFF}\n"
                "Is stripped: false\n"
                "S_PUB32 [size = 32] `PublicParser`\n"
                " flags = function, addr = 0001:1104\n"
                "S_PUB32 [size = 32] `PublicData`\n"
                " flags = none, addr = 0001:1120\n"
            ),
            stderr="",
        )

    assert pdb_functions(binary, pdb, run=fake_run) == {0x1450: "PublicParser"}


def test_pdb_function_records_preserve_duplicate_record_custody(
    tmp_path: Path, monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    pdb = tmp_path / "driver.pdb"
    pdb.touch()
    monkeypatch.setattr("zeroverse.pe_symbols.shutil.which", lambda _: "/llvm-pdbutil")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0,
            stdout=(
                "Age: 1\nGUID: {00112233-4455-6677-8899-AABBCCDDEEFF}\n"
                "Is stripped: true\n"
                "S_PUB32 [size = 32] `DriverEntry`\n"
                " flags = function, addr = 0001:1104\n"
                "S_PUB32 [size = 32] `DriverEntry`\n"
                " flags = function, addr = 0001:1120\n"
            ), stderr="",
        )

    records = pdb_function_records(binary, pdb, run=fake_run)
    assert [(row.kind, row.segment, row.offset, row.rva) for row in records] == [
        ("public-function", 1, 1104, 0x1450),
        ("public-function", 1, 1120, 0x1460),
    ]


def test_pdb_functions_rejects_wrong_guid(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    pdb = tmp_path / "driver.pdb"
    pdb.touch()
    monkeypatch.setattr("zeroverse.pe_symbols.shutil.which", lambda _: "/llvm-pdbutil")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0,
            stdout=(
                "Age: 1\nGUID: {11111111-2222-3333-4444-555555555555}\n"
                "Is stripped: false\n"
                "S_LPROC32 `ParseGuestPacket`\n"
                " parent = 0, end = 1, addr = 0001:1104\n"
            ),
            stderr="",
        )

    assert pdb_functions(binary, pdb, run=fake_run) == {}


def test_pdb_functions_allows_stripped_public_age_change(
    tmp_path: Path, monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    pdb = tmp_path / "driver.pdb"
    pdb.touch()
    monkeypatch.setattr("zeroverse.pe_symbols.shutil.which", lambda _: "/llvm-pdbutil")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0,
            stdout=(
                "Age: 4\nGUID: {00112233-4455-6677-8899-AABBCCDDEEFF}\n"
                "Is stripped: true\n"
                "S_LPROC32 `ParseGuestPacket`\n"
                " parent = 0, end = 1, addr = 0001:1104\n"
            ),
            stderr="",
        )

    assert pdb_functions(binary, pdb, run=fake_run) == {0x1450: "ParseGuestPacket"}


def test_pdb_functions_rejects_private_age_mismatch(
    tmp_path: Path, monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    pdb = tmp_path / "driver.pdb"
    pdb.touch()
    monkeypatch.setattr("zeroverse.pe_symbols.shutil.which", lambda _: "/llvm-pdbutil")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0,
            stdout=(
                "Age: 2\nGUID: {00112233-4455-6677-8899-AABBCCDDEEFF}\n"
                "Is stripped: false\n"
                "S_LPROC32 `ParseGuestPacket`\n"
                " parent = 0, end = 1, addr = 0001:1104\n"
            ),
            stderr="",
        )

    assert pdb_functions(binary, pdb, run=fake_run) == {}


def test_pdb_functions_without_tool_is_fail_soft(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    pdb = tmp_path / "driver.pdb"
    pdb.touch()
    monkeypatch.setattr("zeroverse.pe_symbols.shutil.which", lambda _: None)
    assert pdb_functions(binary, pdb) == {}


def test_enrich_ghidra_symbols_renames_all_adapter_surfaces(
    tmp_path: Path, monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    generic = "FUN_140001450"
    insts = [
        Inst(1, generic, 0x140001450, Kind.PARAM),
        Inst(2, "caller", 0x140001500, Kind.CALL, dest=generic, args=[1]),
    ]
    meta = ProgramMeta(
        decompiled_c={
            generic: f"void {generic}(void) {{}}",
            "caller": f"void caller(void) {{ {generic}(); }}",
        },
        callgraph={"caller": [generic]},
        unresolved_edges=[{"func": generic, "addr": "0x140001450"}],
        address_taken=[generic],
        ptr_tables=[{"members": [generic], "loaders": ["caller"]}],
    )
    adapter = GhidraAdapter(
        insts,
        {("arg", generic): 1},
        {},
        {(generic, 0): [(2, 1)]},
        {},
        meta,
    )
    monkeypatch.setattr(
        "zeroverse.pe_symbols.pdb_functions",
        lambda _: {0x1450: "ParseGuestPacket"},
    )

    assert enrich_ghidra_symbols(adapter, binary) == 1
    assert "ParseGuestPacket" in adapter.meta.decompiled_c
    assert generic not in "\n".join(adapter.meta.decompiled_c.values())
    assert adapter.inst(1).func == "ParseGuestPacket"
    assert adapter.inst(2).dest == "ParseGuestPacket"
    assert adapter.meta.callgraph == {"caller": ["ParseGuestPacket"]}
    assert adapter.get_def("arg", "ParseGuestPacket") == 1
    assert adapter.get_callers("ParseGuestPacket", 0) == [(2, 1)]


def test_enrichment_does_not_overwrite_stronger_symbol(
    tmp_path: Path, monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    adapter = GhidraAdapter([], {}, {}, {}, {}, ProgramMeta(
        decompiled_c={"AlreadyNamed": "void AlreadyNamed(void) {}"},
    ))
    monkeypatch.setattr(
        "zeroverse.pe_symbols.pdb_functions",
        lambda _: {0x1450: "DifferentName"},
    )
    assert enrich_ghidra_symbols(adapter, binary) == 0
    assert set(adapter.meta.decompiled_c) == {"AlreadyNamed"}


def test_enrichment_does_not_collapse_duplicate_pdb_names(
    tmp_path: Path, monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    _pe_with_symbol(binary)
    first = "FUN_140001450"
    second = "FUN_140001460"
    adapter = GhidraAdapter([], {}, {}, {}, {}, ProgramMeta(
        decompiled_c={first: "void a(void) {}", second: "void b(void) {}"},
    ))
    monkeypatch.setattr(
        "zeroverse.pe_symbols.pdb_functions",
        lambda _: {0x1450: "SameName", 0x1460: "SameName"},
    )
    assert enrich_ghidra_symbols(adapter, binary) == 0
    assert set(adapter.meta.decompiled_c) == {first, second}
