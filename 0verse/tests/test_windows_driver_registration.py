from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

import zeroverse.windows_driver_registration as registration
from zeroverse.windows_driver_registration_ghidra import (
    _audit_rbx_preserved,
    _exact_target_path,
)


def _ref(rva: str, order: int, opcode: str) -> dict[str, object]:
    return {
        "function_rva": "0x4fa14",
        "instruction_rva": rva,
        "pcode_order": order,
        "opcode": opcode,
    }


def _facts() -> dict[str, object]:
    alias = bytes.fromhex("488bd9")
    store = bytes.fromhex("488983e0000000")
    return {
        "schema_version": registration.RAW_VERSION,
        "driver_sha256": "1" * 64,
        "pdb_sha256": "2" * 64,
        "pdb_identity": "GUID:3:stripped",
        "pe_codeview_identity": "GUID:1:afd.pdb",
        "architecture": "x86_64",
        "image_base": "0x140000000",
        "tool": {"name": "ghidra", "version": "12.1.2"},
        "entry_bridge": {
            "schema_version": "0verse.windows-driver-entry-bridge/v3",
            "artifact_path": "entry-bridge/entry-bridge.json",
            "artifact_sha256": "3" * 64,
            "receipt_path": "entry-bridge/receipt.json",
            "receipt_sha256": "4" * 64,
            "driver_entry_rva": "0x4fa14",
        },
        "wdm_projection": {
            "path": "wdm-projection.json",
            "sha256": registration.PROJECTION_SHA256,
            "schema_version": registration.PROJECTION_VERSION,
            "authority_scope": registration.AUTHORITY_SCOPE,
            "exact_pdb_identity": False,
            "runtime_layout_exact": False,
        },
        "driver_object_alias": {
            "kind": "windows-x64-native-rcx-to-rbx/v1",
            "rva": "0x4fa3c",
            "bytes": alias.hex(),
            "sha256": hashlib.sha256(alias).hexdigest(),
            "original_argument": "RCX",
            "alias_register": "RBX",
            "width": 8,
            "unique_in_function": True,
            "entry_fallthrough_dominates_registration": True,
        },
        "registration": {
            "owner_function_rva": "0x4fa14",
            "projected_path": "_DRIVER_OBJECT.MajorFunction[14]",
            "projected_offset": "0xe0",
            "store_width": 8,
            "high_pcode_base_register": "RCX",
            "store": {
                "rva": "0x50025",
                "bytes": store.hex(),
                "sha256": hashlib.sha256(store).hexdigest(),
                "high_pcode_ref": _ref("0x50025", 99, "STORE"),
            },
            "address_dependency_refs": [_ref("0x50025", 98, "PTRSUB")],
            "target_dependency_refs": [_ref("0x5001e", 97, "PTRSUB")],
            "target": {
                "name": "AfdDispatchDeviceControl",
                "record_kind": "public-function",
                "segment": 1,
                "offset": 60352,
                "rva": "0xfb80",
                "target_lea_rva": "0x5001e",
                "target_lea_bytes": "488d055bfbfbff",
                "direct": True,
                "internal_executable": True,
                "non_thunk": True,
                "unique_exact_record": True,
            },
            "unique_direct_assignment": True,
            "later_reachable_projected_stores": 0,
            "no_later_reachable_exact_projected_store": True,
            "transitive_finality": False,
            "entry_reachable": True,
            "return_scope": "reachable-terminal-return-without-status-classification",
        },
        "accounting": {
            "driver_entry_pcode_ops": 4096,
            "reachable_projected_stores": 1,
            "matching_assignments": 1,
            "later_reachable_projected_stores": 0,
            "limits_hit": [],
        },
    }


def test_compiler_admits_only_bounded_projected_assignment() -> None:
    result = registration.compile_windows_driver_registration(_facts())
    assert result["outcome"] == "projected-device-control-assignment-proven"
    assert result["static_projected_registration_established"] is True
    assert result["runtime_layout_exact"] is False
    assert result["runtime_registration_established"] is False
    assert result["transitive_finality"] is False
    assert result["selector_claims"] == 0
    assert result["table_claims"] == 0
    assert result["candidate_count"] == 0
    assert result["vulnerability_established"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw["registration"].update({"projected_offset": "0xe8"}),
        lambda raw: raw["registration"].update({"store_width": 4}),
        lambda raw: raw["registration"]["store"].update({"bytes": "498983e0000000"}),
        lambda raw: raw["registration"].update({"later_reachable_projected_stores": 1}),
        lambda raw: raw["registration"].update({"entry_reachable": False}),
        lambda raw: raw["registration"]["target"].update({"non_thunk": False}),
        lambda raw: raw["registration"]["target"].update({"target_lea_bytes": "488d055cfbfbff"}),
        lambda raw: raw["wdm_projection"].update({"runtime_layout_exact": True}),
        lambda raw: raw["wdm_projection"].update({"sha256": "f" * 64}),
        lambda raw: raw["wdm_projection"].update({"path": "renamed.json"}),
        lambda raw: raw["entry_bridge"].update({"artifact_path": "entry-bridge/renamed.json"}),
        lambda raw: raw["entry_bridge"].update({"receipt_path": "renamed/receipt.json"}),
        lambda raw: raw["driver_object_alias"].update({"rva": "0x50026"}),
        lambda raw: raw["registration"]["target"].update({"target_lea_rva": "0x5001d"}),
        lambda raw: raw["registration"]["store"]["high_pcode_ref"].update(
            {"instruction_rva": "0x50024"}
        ),
        lambda raw: raw["registration"]["address_dependency_refs"][0].update(
            {"function_rva": "0x4fa15"}
        ),
        lambda raw: raw["registration"]["target_dependency_refs"][0].update(
            {"instruction_rva": "0x4ffff"}
        ),
        lambda raw: raw["registration"]["address_dependency_refs"][0].update(
            {"opcode": "CALLOTHER"}
        ),
        lambda raw: raw["registration"]["target_dependency_refs"][0].update({"opcode": "INT_ADD"}),
    ],
)
def test_compiler_rejects_assignment_and_authority_tamper(mutation: object) -> None:
    raw = _facts()
    mutation(raw)
    with pytest.raises(ValueError):
        registration.compile_windows_driver_registration(raw)


def test_canonical_export_rejects_unknown_fields_and_claim_escalation() -> None:
    export = registration.compile_windows_driver_registration(_facts())
    export["registrations"] = []
    with pytest.raises(ValueError, match="unknown or missing"):
        registration.canonical_registration_bytes(export)
    export = registration.compile_windows_driver_registration(_facts())
    export["runtime_registration_established"] = True
    with pytest.raises(ValueError, match="claim boundary"):
        registration.canonical_registration_bytes(export)


def test_reviewed_projection_is_content_pinned() -> None:
    configured = os.environ.get("ZEROVERSE_WDM_PROJECTION")
    if not configured:
        pytest.skip("ZEROVERSE_WDM_PROJECTION is not configured")
    path = Path(configured)
    if not path.is_file():
        pytest.skip("private reviewed projection is unavailable")
    raw = json.loads(path.read_text(encoding="utf-8"))
    registration.validate_wdm_projection(raw)
    fabricated = copy.deepcopy(raw)
    fabricated["authority_scope"] += " fabricated"
    with pytest.raises(ValueError):
        registration.validate_wdm_projection(fabricated)
    fabricated = copy.deepcopy(raw)
    fabricated["resolved_paths"]["_IRP.Tail.Overlay.CurrentStackLocation"][
        "absolute_offset_bytes"
    ] = 999
    with pytest.raises(ValueError, match="canonical authority"):
        registration.validate_wdm_projection(fabricated)


def _receipt() -> dict[str, object]:
    return {
        "schema_version": registration.RECEIPT_VERSION,
        "producer": registration.PRODUCER,
        "registration_path": "registration.json",
        "registration_sha256": "1" * 64,
        "entry_bridge_bundle": "entry-bridge",
        "entry_bridge_receipt_sha256": "2" * 64,
        "wdm_projection_path": "wdm-projection.json",
        "wdm_projection_sha256": registration.PROJECTION_SHA256,
        "toolchain": {"test": "bound"},
        "extractor_config_sha256": registration.CONFIG_SHA256,
        "static_only": True,
        "execution_authorized": False,
    }


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("registration_path", "renamed.json"),
        ("entry_bridge_bundle", "renamed-bridge"),
        ("wdm_projection_path", "renamed-projection.json"),
        ("wdm_projection_sha256", "f" * 64),
    ],
)
def test_receipt_rejects_coherent_topology_renames(field: str, forged: str) -> None:
    receipt = _receipt()
    registration._validate_registration_receipt(receipt, {"test": "bound"})
    receipt[field] = forged
    with pytest.raises(ValueError, match="receipt contract"):
        registration._validate_registration_receipt(receipt, {"test": "bound"})


def test_bounded_nofollow_reader_rejects_fifo_and_symlink_parent(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    fifo = root / "projection.json"
    os.mkfifo(fifo)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ValueError, match="bounded regular"):
            registration._read_regular_file_at(root_fd, fifo.name, "projection", 1024)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "data.json").write_text("{}", encoding="utf-8")
        (root / "alias").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match="parent ancestry"):
            registration._read_regular_file_at(root_fd, "alias/data.json", "projection", 1024)
    finally:
        os.close(root_fd)


def test_verifier_rejects_fifo_and_symlink_top_receipt_before_tool_use(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    receipt = bundle / "receipt.json"
    os.mkfifo(receipt)
    with pytest.raises(ValueError, match="bounded regular"):
        registration.verify_windows_driver_registration_bundle(
            bundle, ghidra_home=tmp_path / "missing-ghidra"
        )
    receipt.unlink()
    outside = tmp_path / "outside-receipt.json"
    outside.write_text("{}", encoding="utf-8")
    receipt.symlink_to(outside)
    with pytest.raises(ValueError, match="regular non-symlink"):
        registration.verify_windows_driver_registration_bundle(
            bundle, ghidra_home=tmp_path / "missing-ghidra"
        )


class _Node:
    def __init__(self, *, value: int | None = None, definition: object | None = None):
        self.value = value
        self.definition = definition

    def __str__(self) -> str:
        return f"node:{id(self)}"

    def isAddress(self) -> bool:
        return False

    def isConstant(self) -> bool:
        return self.value is not None

    def getOffset(self) -> int:
        assert self.value is not None
        return self.value

    def getDef(self) -> object | None:
        return self.definition


class _Op:
    def __init__(self, opcode: str, inputs: list[_Node]):
        self.opcode = opcode
        self.inputs = inputs

    def getMnemonic(self) -> str:
        return self.opcode

    def getNumInputs(self) -> int:
        return len(self.inputs)

    def getInput(self, index: int) -> _Node:
        return self.inputs[index]


def test_target_dependency_rejects_extra_constant_arithmetic() -> None:
    target = 0x14000FB80
    exact = _Node(definition=_Op("PTRSUB", [_Node(value=0), _Node(value=target)]))
    assert len(_exact_target_path(exact, target)) == 1
    extra = _Node(definition=_Op("PTRSUB", [_Node(value=1), _Node(value=target)]))
    with pytest.raises(ValueError, match="exact zero plus target"):
        _exact_target_path(extra, target)


class _Address:
    def __init__(self, offset: int):
        self.offset = offset

    def getOffset(self) -> int:
        return self.offset


class _Output:
    def isRegister(self) -> bool:
        return True

    def getAddress(self) -> _Address:
        return _Address(1)

    def getSize(self) -> int:
        return 8


class _LowOp:
    def getOutput(self) -> _Output:
        return _Output()


class _Instruction:
    def __init__(self, offset: int):
        self.offset = offset

    def getAddress(self) -> _Address:
        return _Address(self.offset)

    def getPcode(self) -> list[_LowOp]:
        return [_LowOp()]


class _Register:
    def __init__(self, name: str):
        self.name = name

    def getBaseRegister(self) -> None:
        return None

    def getName(self) -> str:
        return self.name


class _Program:
    def __init__(self, name: str):
        self.name = name

    def getRegister(self, _address: object, _size: int) -> _Register:
        return _Register(self.name)


def test_native_audit_rejects_rbx_clobber_between_alias_and_store() -> None:
    instructions = [_Instruction(0x1010)]
    with pytest.raises(ValueError, match="redefined"):
        _audit_rbx_preserved(
            instructions, _Program("RBX"), alias_offset=0x1000, store_offset=0x1020
        )
    _audit_rbx_preserved(instructions, _Program("RAX"), alias_offset=0x1000, store_offset=0x1020)
