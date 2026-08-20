from __future__ import annotations

import copy
import hashlib
import json
import os
import struct
from pathlib import Path

import pytest

import zeroverse.windows_afd_selector as selector


def _native(rva: int, encoded: bytes) -> dict[str, object]:
    return {
        "rva": f"0x{rva:x}",
        "bytes": encoded.hex(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _ff15(rva: int, slot: int) -> dict[str, object]:
    return _native(rva, b"\x48\xff\x15" + struct.pack("<i", slot - rva - 7))


def _table(rva: int, width: int, raw: bytes, *, functions: bool = False) -> dict[str, object]:
    value: dict[str, object] = {
        "rva": f"0x{rva:x}",
        "section": ".rdata",
        "entry_width": width,
        "addressed_count": 74,
        "addressed_size": len(raw),
        "addressed_bytes": raw.hex(),
        "addressed_sha256": hashlib.sha256(raw).hexdigest(),
        "addressed_extent_complete": True,
        "pdb_declared_allocation_extent": False,
        "preferred_base_absolute_pointers": functions,
        "runtime_relocation_claimed": False,
    }
    if functions:
        value.update(
            {
                "all_entries_non_null": True,
                "all_targets_exact_executable_non_thunk": True,
            }
        )
    return value


def _facts() -> dict[str, object]:
    handler = 0xFB80
    image_base = 0x140000000
    keys = tuple(0x12003 + index * 4 for index in range(74))
    pointers = tuple(image_base + 0x2000 + index * 0x10 for index in range(74))
    key_raw = struct.pack("<74I", *keys)
    function_raw = struct.pack("<74Q", *pointers)
    thunk = 0x76C70
    slot = 0x8DBE8
    thunk_bytes = b"\xff\x25" + struct.pack("<i", slot - thunk - 6)
    call_bytes = b"\xe8" + struct.pack("<i", thunk - (handler + 0x67) - 5)
    rows = [
        {
            "index": index,
            "key": f"0x{key:x}",
            "target_rva": f"0x{pointer - image_base:x}",
            "target_section": ".text",
            "exact_function_entry": True,
            "executable": True,
            "non_thunk": True,
        }
        for index, (key, pointer) in enumerate(zip(keys, pointers, strict=True))
    ]
    return {
        "schema_version": selector.RAW_VERSION,
        "driver_sha256": "1" * 64,
        "pdb_sha256": "2" * 64,
        "pdb_identity": "GUID:3:stripped",
        "pe_codeview_identity": "GUID:1:afd.pdb",
        "architecture": "x86_64",
        "image_base": f"0x{image_base:x}",
        "tool": {"name": "ghidra", "version": "12.1.2"},
        "registration_commitment": {
            "schema_version": selector.REGISTRATION_VERSION,
            "path": "registration",
            "artifact_sha256": "3" * 64,
            "receipt_sha256": "4" * 64,
            "handler_rva": f"0x{handler:x}",
        },
        "wdm_projection": {
            "path": "registration/wdm-projection.json",
            "sha256": selector.PROJECTION_SHA256,
            "schema_version": selector.PROJECTION_VERSION,
            "authority_scope": selector.AUTHORITY_SCOPE,
            "exact_pdb_identity": False,
            "runtime_layout_exact": False,
        },
        "dispatch_abi_authority": {
            "path": "dispatch-abi",
            "schema_version": selector.ABI_MANIFEST_VERSION,
            "manifest_sha256": selector.ABI_MANIFEST_SHA256,
            "source_sha256": selector.ABI_SOURCE_SHA256,
        },
        "handler": {
            "name": "AfdDispatchDeviceControl",
            "rva": f"0x{handler:x}",
            "exact_function_entry": True,
            "executable": True,
            "non_thunk": True,
        },
        "irp_projection": {
            "argument_register": "RDX",
            "argument_width": 8,
            "current_stack_location_offset": "0xb8",
            "current_stack_location_width": 8,
            "current_stack_location_load": _native(handler + 0x0F, bytes.fromhex("488b9ab8000000")),
            "io_control_code_offset": "0x18",
            "io_control_code_width": 4,
            "io_control_code_load": _native(handler + 0x2C, bytes.fromhex("448b4318")),
        },
        "partition": {
            "predicate_import": "NetioNrtIsTrackerDevice",
            "predicate_iat_rva": "0x8d030",
            "predicate_call": _ff15(handler + 0x1C, 0x8D030),
            "tested_register": "AL",
            "local_branch": "AL==0",
            "alternate_branch": "AL!=0",
            "alternate_import": "NetioNrtDispatch",
            "alternate_iat_rva": "0x8d038",
            "alternate_call": _ff15(handler + 0x83, 0x8D038),
            "alternate_resolved": False,
        },
        "selector": {
            "source_register": "R8D",
            "width": 4,
            "shift_right": 2,
            "mask": "0x3ff",
            "unsigned_upper_exclusive": 74,
            "reject_condition": "index>=74",
            "key_comparison_width": 4,
            "key_equality_required": True,
        },
        "native_selector": _native_selector(handler),
        "key_table": _table(0x7D1C0, 4, key_raw),
        "function_table": _table(0x7A560, 8, function_raw, functions=True),
        "rows": rows,
        "dispatch": {
            "target_register": "RAX",
            "target_load_width": 8,
            "non_null_required": True,
            "call": _native(handler + 0x67, call_bytes),
            "thunk_rva": f"0x{thunk:x}",
            "thunk_bytes": thunk_bytes.hex(),
            "thunk_sha256": hashlib.sha256(thunk_bytes).hexdigest(),
            "load_config_field": "GuardCFDispatchFunctionPointer",
            "pointer_slot_rva": f"0x{slot:x}",
            "check_pointer_slot_rva": "0x8dbe0",
            "tail_jump": True,
            "rax_preserved_to_thunk": True,
            "helper_name": "_guard_dispatch_icall",
            "handler_transfer_opcode": "CALL",
        },
        "high_pcode": _high_pcode(handler),
        "accounting": {
            "addressed_rows": 74,
            "unique_targets": 74,
            "null_targets": 0,
            "limits_hit": [],
        },
    }


def _high_ref(
    rva: int, opcode: str, output_size: int | None, constants: list[int]
) -> dict[str, object]:
    return {
        "instruction_rva": f"0x{rva:x}",
        "pcode_order": 1,
        "opcode": opcode,
        "output_size": output_size,
        "input_sizes": [8, 8],
        "constants": constants,
    }


def _native_selector(handler: int) -> dict[str, object]:
    exact = {
        "tracker_result_test": (0x28, "84c0"),
        "tracker_alternate_branch": (0x2A, "7551"),
        "selector_copy": (0x30, "418bc0"),
        "selector_shift": (0x33, "c1e802"),
        "selector_mask": (0x36, "25ff030000"),
        "selector_bound": (0x3B, "83f84a"),
        "unsigned_reject_branch": (0x3E, "7378"),
        "key_mismatch_branch": (0x4F, "7567"),
        "selected_index_store": (0x51, "884301"),
        "target_test": (0x5C, "4885c0"),
        "null_reject_branch": (0x5F, "7457"),
        "stack_argument_move": (0x61, "488bd3"),
        "irp_argument_move": (0x64, "488bcf"),
    }
    result = {
        name: _native(handler + relative, bytes.fromhex(encoded))
        for name, (relative, encoded) in exact.items()
    }
    result.update(
        {
            "image_base_lea": _native(
                handler + 0x40, b"\x48\x8d\x15" + struct.pack("<i", -(handler + 0x47))
            ),
            "key_compare": _native(handler + 0x47, bytes.fromhex("44398482c0d10700")),
            "function_table_load": _native(handler + 0x54, bytes.fromhex("488b84c260a50700")),
        }
    )
    return result


def _forge_negative_table_displacement(raw: dict[str, object], *, function: bool) -> None:
    field = "function_table_load" if function else "key_compare"
    prefix = "488b84c2" if function else "44398482"
    encoded = bytes.fromhex(prefix + "ffffffff")
    raw["native_selector"][field].update(
        {"bytes": encoded.hex(), "sha256": hashlib.sha256(encoded).hexdigest()}
    )
    table = "function_table" if function else "key_table"
    raw[table]["rva"] = "0xffffffff"


def _high_pcode(handler: int) -> dict[str, object]:
    return {
        "forbidden_opcodes": ["CALLOTHER", "MULTIEQUAL", "PIECE", "SUBPIECE"],
        "irp_current_stack_load": [_high_ref(handler + 0x0F, "LOAD", 8, [])],
        "ioctl_load": [_high_ref(handler + 0x2C, "LOAD", 4, [])],
        "shift": [_high_ref(handler + 0x33, "INT_RIGHT", 4, [2])],
        "mask": [_high_ref(handler + 0x36, "INT_AND", 4, [0x3FF])],
        "unsigned_bound": [_high_ref(handler + 0x3B, "INT_LESS", 1, [74])],
        "key_load": [_high_ref(handler + 0x47, "LOAD", 4, [])],
        "key_equality": [_high_ref(handler + 0x47, "INT_EQUAL", 1, [])],
        "target_load": [_high_ref(handler + 0x54, "LOAD", 8, [])],
        "null_guard": [_high_ref(handler + 0x5C, "INT_EQUAL", 1, [0])],
        "guard_dispatch_call": [_high_ref(handler + 0x67, "CALLIND", 8, [])],
        "reviewed_sites_corroborated": True,
        "descendant_closure_established": False,
        "global_extra_transforms_excluded": False,
    }


def test_compiler_admits_only_bounded_local_branch() -> None:
    result = selector.compile_windows_afd_selector(_facts())
    assert result["local_selector_branch_established"] is True
    assert result["selector_inventory_complete"] is False
    assert result["pdb_declared_table_extent"] is False
    assert result["runtime_layout_exact"] is False
    assert result["execution_authorized"] is False
    assert result["candidate_count"] == 0
    assert result["vulnerability_established"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw["irp_projection"].update({"argument_register": "RCX"}),
        lambda raw: raw["irp_projection"].update({"current_stack_location_offset": "0xc0"}),
        lambda raw: raw["irp_projection"].update({"io_control_code_width": 2}),
        lambda raw: raw["partition"].update({"local_branch": "AL!=0"}),
        lambda raw: raw["partition"].update({"alternate_resolved": True}),
        lambda raw: raw["selector"].update({"shift_right": 3}),
        lambda raw: raw["selector"].update({"mask": "0x1ff"}),
        lambda raw: raw["selector"].update({"unsigned_upper_exclusive": 75}),
        lambda raw: raw["selector"].update({"key_comparison_width": 2}),
        lambda raw: raw["native_selector"]["key_compare"].update(
            {
                "bytes": "4439848256341200",
                "sha256": hashlib.sha256(bytes.fromhex("4439848256341200")).hexdigest(),
            }
        ),
        lambda raw: raw["native_selector"]["function_table_load"].update(
            {
                "bytes": "488b84c256341200",
                "sha256": hashlib.sha256(bytes.fromhex("488b84c256341200")).hexdigest(),
            }
        ),
        lambda raw: raw["key_table"].update({"rva": "0x123456"}),
        lambda raw: raw["function_table"].update({"rva": "0x123456"}),
        lambda raw: _forge_negative_table_displacement(raw, function=False),
        lambda raw: _forge_negative_table_displacement(raw, function=True),
        lambda raw: raw["key_table"].update({"section": ".data"}),
        lambda raw: raw["key_table"].update({"addressed_count": 73}),
        lambda raw: raw["key_table"].update({"pdb_declared_allocation_extent": True}),
        lambda raw: raw["function_table"].update({"all_entries_non_null": False}),
        lambda raw: raw["function_table"].update({"addressed_sha256": "f" * 64}),
        lambda raw: raw["rows"][3].update({"index": 4}),
        lambda raw: raw["rows"][3].update({"key": "0x12013"}),
        lambda raw: raw["rows"][3].update({"target_rva": "0x999"}),
        lambda raw: raw["rows"][3].update({"non_thunk": False}),
        lambda raw: raw["dispatch"].update({"target_register": "RCX"}),
        lambda raw: raw["dispatch"].update({"load_config_field": "GuardCFCheckFunctionPointer"}),
        lambda raw: raw["dispatch"].update({"helper_name": "FUN_140076c70"}),
        lambda raw: raw["dispatch"].update(
            {"check_pointer_slot_rva": raw["dispatch"]["pointer_slot_rva"]}
        ),
        lambda raw: raw["registration_commitment"].update({"handler_rva": "0xfb81"}),
        lambda raw: raw["wdm_projection"].update({"runtime_layout_exact": True}),
        lambda raw: raw["high_pcode"]["shift"][0].update({"opcode": "INT_SRIGHT"}),
        lambda raw: raw["high_pcode"]["mask"][0].update({"constants": [0x1FF]}),
        lambda raw: raw["high_pcode"].update({"descendant_closure_established": True}),
    ],
)
def test_compiler_rejects_counterexamples(mutation: object) -> None:
    raw = _facts()
    mutation(raw)
    with pytest.raises(ValueError):
        selector.compile_windows_afd_selector(raw)


def test_unknown_fields_and_claim_escalation_fail_closed() -> None:
    result = selector.compile_windows_afd_selector(_facts())
    result["selector_inventory_complete"] = True
    with pytest.raises(ValueError, match="claim boundary"):
        selector.canonical_selector_bytes(result)
    result = selector.compile_windows_afd_selector(_facts())
    result["global_table_extent"] = True
    with pytest.raises(ValueError, match="unknown or missing"):
        selector.canonical_selector_bytes(result)


def test_dispatch_authority_exact_bytes() -> None:
    root = Path("docs/evidence/windows-driver-dispatch-abi")
    result = selector.validate_dispatch_abi_authority(root)
    assert result["source_sha256"] == selector.ABI_SOURCE_SHA256
    assert (root / "nc-wdm-driver_dispatch.md").stat().st_size == selector.ABI_SOURCE_SIZE


def test_projection_checks_selector_paths() -> None:
    configured = os.environ.get("ZEROVERSE_WDM_PROJECTION")
    if not configured:
        pytest.skip("private WDM projection unavailable")
    raw = json.loads(Path(configured).read_text(encoding="utf-8"))
    selector.validate_selector_wdm_projection(raw)
    forged = copy.deepcopy(raw)
    forged["resolved_paths"]["_IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode"][
        "leaf_width_bytes"
    ] = 2
    with pytest.raises(ValueError):
        selector.validate_selector_wdm_projection(forged)


def test_receipt_rejects_topology_and_claim_tamper() -> None:
    receipt = {
        "schema_version": selector.RECEIPT_VERSION,
        "producer": selector.PRODUCER,
        "selector_path": "selector.json",
        "selector_sha256": "1" * 64,
        "registration_bundle": "registration",
        "registration_receipt_sha256": "2" * 64,
        "dispatch_abi_bundle": "dispatch-abi",
        "dispatch_abi_manifest_sha256": "3" * 64,
        "toolchain": {"test": "bound"},
        "extractor_config_sha256": selector.CONFIG_SHA256,
        "static_only": True,
        "execution_authorized": False,
    }
    selector._validate_receipt(receipt, {"test": "bound"})
    receipt["registration_bundle"] = "renamed"
    with pytest.raises(ValueError, match="receipt contract"):
        selector._validate_receipt(receipt, {"test": "bound"})


def test_authority_reader_rejects_fifo_and_symlink(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    root.mkdir()
    (root / "manifest.json").write_text("{}", encoding="utf-8")
    os.mkfifo(root / "nc-wdm-driver_dispatch.md")
    with pytest.raises(ValueError, match="bounded regular"):
        selector.validate_dispatch_abi_authority(root)
    (root / "nc-wdm-driver_dispatch.md").unlink()
    outside = tmp_path / "outside.md"
    outside.write_text("x", encoding="utf-8")
    (root / "nc-wdm-driver_dispatch.md").symlink_to(outside)
    with pytest.raises(ValueError, match="regular non-symlink"):
        selector.validate_dispatch_abi_authority(root)


def test_verifier_replays_private_snapshot_after_source_root_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "marker").write_bytes(b"original")
    original = tmp_path / "original"

    def snapshot(source_fd: int, destination_fd: int) -> None:
        del destination_fd
        source.rename(original)
        source.mkdir()
        (source / "marker").write_bytes(b"replacement")
        assert selector._read_regular_file_at(source_fd, "marker", "marker", 32) == b"original"

    def verify(retained: Path, home: Path) -> dict[str, object]:
        assert retained != source
        assert retained.name == "bundle"
        assert home == Path("/ghidra")
        return {"snapshot": True}

    monkeypatch.setattr(selector, "_snapshot_selector_bundle", snapshot)
    monkeypatch.setattr(selector, "_verify_snapshotted_selector_bundle", verify)
    assert selector.verify_windows_afd_selector_bundle(source, ghidra_home="/ghidra") == {
        "snapshot": True
    }


def test_snapshot_rejects_symlinked_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    outside = tmp_path / "outside"
    source.mkdir()
    destination.mkdir()
    outside.mkdir()
    (source / "receipt.json").write_bytes(b"{}")
    (source / "selector.json").write_bytes(b"{}")
    (source / "registration").symlink_to(outside, target_is_directory=True)
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    destination_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError):
            selector._snapshot_selector_bundle(source_fd, destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)


def test_snapshot_rejects_fifo_authority_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    (source / "receipt.json").write_bytes(b"{}")
    (source / "selector.json").write_bytes(b"{}")
    (source / "registration").mkdir()
    authority = source / "dispatch-abi"
    authority.mkdir()
    os.mkfifo(authority / "manifest.json")
    (authority / "nc-wdm-driver_dispatch.md").write_bytes(b"authority")
    monkeypatch.setattr(selector, "_snapshot_registration_bundle", lambda *_: None)
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    destination_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="bounded regular"):
            selector._snapshot_selector_bundle(source_fd, destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)


def test_retained_commitment_is_reconstructed_from_receipt_bytes(tmp_path: Path) -> None:
    registration = tmp_path / "registration"
    registration.mkdir()
    receipt = registration / "receipt.json"
    receipt.write_text(json.dumps({"registration_sha256": "a" * 64}), encoding="utf-8")
    authority = {
        "manifest_sha256": selector.ABI_MANIFEST_SHA256,
        "source_sha256": selector.ABI_SOURCE_SHA256,
    }
    commitment, projection, retained_authority = selector._retained_commitments(
        registration, 0xFB80, authority
    )
    assert commitment["artifact_sha256"] == "a" * 64
    assert commitment["receipt_sha256"] == hashlib.sha256(receipt.read_bytes()).hexdigest()
    assert commitment["handler_rva"] == "0xfb80"
    assert projection["sha256"] == selector.PROJECTION_SHA256
    assert retained_authority["manifest_sha256"] == selector.ABI_MANIFEST_SHA256
    forged = copy.deepcopy(commitment)
    forged["artifact_sha256"] = "b" * 64
    assert forged != commitment
