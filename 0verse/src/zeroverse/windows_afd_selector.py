"""Custody-bound proof of the bounded local AFD IOCTL selector branch."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from .windows_afd_selector_ghidra import acquire_afd_selector_facts
from .windows_driver_entry_bridge import _toolchain_fingerprint
from .windows_driver_registration import (
    AUTHORITY_SCOPE,
    PROJECTION_SHA256,
    PROJECTION_VERSION,
    _exact,
    _hex,
    _obj,
    _read_regular_file_at,
    _relative_file,
    _sha,
    _sha_file,
    _snapshot_file_from_dirfd,
    _snapshot_v3_bridge_bundle,
    _unique,
    validate_wdm_projection,
    verify_windows_driver_registration_bundle,
)
from .windows_driver_registration import (
    EXPORT_VERSION as REGISTRATION_VERSION,
)
from .windows_variant import (
    _create_staging_directory,
    _open_directory_ancestry,
    _publish_directory_no_replace,
    _require_directory_path_identity,
    _write_new_file_at,
)

RAW_VERSION = "0verse.windows-afd-selector-facts/v1"
EXPORT_VERSION = "0verse.windows-afd-selector/v1"
RECEIPT_VERSION = "0verse.windows-afd-selector-receipt/v1"
PRODUCER = "zeroverse.windows-afd-selector/v1"
ABI_MANIFEST_VERSION = "0verse.windows-driver-dispatch-abi-authority/v1"
ABI_SOURCE_URL = (
    "https://raw.githubusercontent.com/MicrosoftDocs/windows-driver-docs-ddi/"
    "758b904a9035ee00c0bea6a2ed34a78202bcf8ce/"
    "wdk-ddi-src/content/wdm/nc-wdm-driver_dispatch.md"
)
ABI_SOURCE_SHA256 = "999809924074acbc0edd0c416f9d6f5477a99da3f042f734765fd062254f78c7"
ABI_SOURCE_SIZE = 12807
ABI_MANIFEST_SHA256 = "8054d2a8208b431c463a6ed652811e4c4fae737813e05ed530ff86d584929274"
_CONFIG = {
    "architecture": "x86_64",
    "registration_source": REGISTRATION_VERSION,
    "handler": "AfdDispatchDeviceControl",
    "projected_irp_stack_offset": 0xB8,
    "projected_ioctl_offset": 0x18,
    "selector": {"shift": 2, "mask": 0x3FF, "unsigned_upper_exclusive": 74},
    "key_width": 4,
    "target_width": 8,
    "partition": "NetioNrtIsTrackerDevice/AL==0",
    "alternate": "NetioNrtDispatch/unresolved",
    "dispatch": "PE-load-config-GuardCFDispatchFunctionPointer",
}
CONFIG_SHA256 = hashlib.sha256(
    json.dumps(_CONFIG, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
_PROOF_LIMIT = (
    "Static semantics inside the selected AfdDispatchDeviceControl assignment target and only "
    "its NetioNrtIsTrackerDevice AL==0 local branch. The external WDM projection is not an exact "
    "runtime AFD layout. Addressed 74-row byte extents are complete; no PDB allocation extent, "
    "may-alias, global selector completeness, effective/runtime registration, runtime or "
    "unprivileged reachability, execution, candidate, vulnerability, exploitability, novelty, "
    "or bounty eligibility is established. The AL!=0 NetioNrtDispatch branch is unresolved."
)


def validate_selector_wdm_projection(raw: object) -> dict[str, object]:
    value = validate_wdm_projection(raw)
    paths = _obj(value["resolved_paths"], "selector WDM paths")
    expected = {
        "_IRP.Tail.Overlay.CurrentStackLocation": (184, "0xb8", "ptr64", 8),
        "_IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode": (
            24,
            "0x18",
            "unsigned long",
            4,
        ),
    }
    for name, (offset, offset_hex, kind, width) in expected.items():
        path = _obj(paths.get(name), name)
        if (
            path.get("absolute_offset_bytes") != offset
            or path.get("absolute_offset_hex") != offset_hex
            or path.get("leaf_kind") != kind
            or path.get("leaf_width_bytes") != width
        ):
            raise ValueError(f"selector WDM projection mismatch for {name}")
    return value


def validate_dispatch_abi_authority(path: str | Path) -> dict[str, object]:
    root = Path(path)
    root_fd = _open_directory_ancestry(root, "dispatch ABI authority")
    try:
        manifest_bytes = _read_regular_file_at(
            root_fd, "manifest.json", "dispatch ABI manifest", 1024 * 1024
        )
        source = _read_regular_file_at(
            root_fd,
            "nc-wdm-driver_dispatch.md",
            "DRIVER_DISPATCH authority",
            1024 * 1024,
        )
    finally:
        os.close(root_fd)
    manifest = _obj(json.loads(manifest_bytes, object_pairs_hook=_unique), "dispatch ABI manifest")
    _exact(manifest, {"schema_version", "source"}, "dispatch ABI manifest")
    source_row = _obj(manifest["source"], "dispatch ABI source")
    _exact(
        source_row,
        {"path", "url", "commit", "sha256", "size_bytes"},
        "dispatch ABI source",
    )
    if (
        manifest["schema_version"] != ABI_MANIFEST_VERSION
        or source_row["path"] != "nc-wdm-driver_dispatch.md"
        or source_row["url"] != ABI_SOURCE_URL
        or source_row["commit"] != "758b904a9035ee00c0bea6a2ed34a78202bcf8ce"
        or source_row["sha256"] != ABI_SOURCE_SHA256
        or source_row["size_bytes"] != ABI_SOURCE_SIZE
        or hashlib.sha256(manifest_bytes).hexdigest() != ABI_MANIFEST_SHA256
        or len(source) != ABI_SOURCE_SIZE
        or hashlib.sha256(source).hexdigest() != ABI_SOURCE_SHA256
    ):
        raise ValueError("dispatch ABI authority differs from the reviewed source")
    return {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "source_sha256": ABI_SOURCE_SHA256,
    }


def compile_windows_afd_selector(raw: object) -> dict[str, object]:
    facts = _obj(json.loads(json.dumps(raw)), "selector facts")
    required = {
        "schema_version",
        "driver_sha256",
        "pdb_sha256",
        "pdb_identity",
        "pe_codeview_identity",
        "architecture",
        "image_base",
        "tool",
        "registration_commitment",
        "wdm_projection",
        "dispatch_abi_authority",
        "handler",
        "irp_projection",
        "partition",
        "selector",
        "native_selector",
        "key_table",
        "function_table",
        "rows",
        "dispatch",
        "high_pcode",
        "accounting",
    }
    _exact(facts, required, "selector facts")
    if facts["schema_version"] != RAW_VERSION:
        raise ValueError("unsupported AFD selector fact schema")
    export = {
        "schema_version": EXPORT_VERSION,
        "producer": PRODUCER,
        "extractor_config_sha256": CONFIG_SHA256,
        **{key: value for key, value in facts.items() if key != "schema_version"},
        "outcome": "bounded-local-selector-proven",
        "static_only": True,
        "runtime_layout_exact": False,
        "static_selected_assignment_target": True,
        "local_selector_branch_established": True,
        "local_key_table_addressed_extent_complete": True,
        "local_function_table_addressed_extent_complete": True,
        "pdb_declared_table_extent": False,
        "may_alias_finality": False,
        "selector_inventory_complete": False,
        "effective_registration_established": False,
        "runtime_registration_established": False,
        "runtime_reachability_established": False,
        "unprivileged_reachability_established": False,
        "device_ioctl_attempts": 0,
        "execution_authorized": False,
        "candidate_count": 0,
        "candidate_established": False,
        "vulnerability_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "bounty_eligible": False,
        "weaponization": False,
        "proof_limit": _PROOF_LIMIT,
    }
    return _validate(export)


def canonical_selector_bytes(raw: object) -> bytes:
    return (json.dumps(_validate(raw), sort_keys=True, separators=(",", ":")) + "\n").encode()


def _validate(raw: object) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), "selector")
    fact_fields = {
        "driver_sha256",
        "pdb_sha256",
        "pdb_identity",
        "pe_codeview_identity",
        "architecture",
        "image_base",
        "tool",
        "registration_commitment",
        "wdm_projection",
        "dispatch_abi_authority",
        "handler",
        "irp_projection",
        "partition",
        "selector",
        "native_selector",
        "key_table",
        "function_table",
        "rows",
        "dispatch",
        "high_pcode",
        "accounting",
    }
    claims = {
        "outcome": "bounded-local-selector-proven",
        "static_only": True,
        "runtime_layout_exact": False,
        "static_selected_assignment_target": True,
        "local_selector_branch_established": True,
        "local_key_table_addressed_extent_complete": True,
        "local_function_table_addressed_extent_complete": True,
        "pdb_declared_table_extent": False,
        "may_alias_finality": False,
        "selector_inventory_complete": False,
        "effective_registration_established": False,
        "runtime_registration_established": False,
        "runtime_reachability_established": False,
        "unprivileged_reachability_established": False,
        "device_ioctl_attempts": 0,
        "execution_authorized": False,
        "candidate_count": 0,
        "candidate_established": False,
        "vulnerability_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "bounty_eligible": False,
        "weaponization": False,
        "proof_limit": _PROOF_LIMIT,
    }
    _exact(
        value,
        {"schema_version", "producer", "extractor_config_sha256"} | fact_fields | set(claims),
        "selector",
    )
    if (
        value["schema_version"] != EXPORT_VERSION
        or value["producer"] != PRODUCER
        or value["extractor_config_sha256"] != CONFIG_SHA256
        or value["architecture"] != "x86_64"
    ):
        raise ValueError("selector schema/producer/config mismatch")
    if any(value.get(key) != expected for key, expected in claims.items()):
        raise ValueError("selector claim boundary mismatch")
    _sha(value["driver_sha256"], "selector driver")
    _sha(value["pdb_sha256"], "selector PDB")
    image_base = _hex(value["image_base"], "selector image base")
    registration = _obj(value["registration_commitment"], "registration commitment")
    _exact(
        registration,
        {"schema_version", "path", "artifact_sha256", "receipt_sha256", "handler_rva"},
        "registration commitment",
    )
    if (
        registration["schema_version"] != REGISTRATION_VERSION
        or registration["path"] != "registration"
    ):
        raise ValueError("selector registration commitment mismatch")
    _sha(registration["artifact_sha256"], "registration artifact")
    _sha(registration["receipt_sha256"], "registration receipt")
    handler_rva = _hex(registration["handler_rva"], "registered handler")
    projection = _obj(value["wdm_projection"], "selector projection commitment")
    _exact(
        projection,
        {
            "path",
            "sha256",
            "schema_version",
            "authority_scope",
            "exact_pdb_identity",
            "runtime_layout_exact",
        },
        "selector projection commitment",
    )
    if projection != {
        "path": "registration/wdm-projection.json",
        "sha256": PROJECTION_SHA256,
        "schema_version": PROJECTION_VERSION,
        "authority_scope": AUTHORITY_SCOPE,
        "exact_pdb_identity": False,
        "runtime_layout_exact": False,
    }:
        raise ValueError("selector projection commitment mismatch")
    abi = _obj(value["dispatch_abi_authority"], "dispatch ABI commitment")
    _exact(
        abi,
        {"path", "schema_version", "manifest_sha256", "source_sha256"},
        "dispatch ABI commitment",
    )
    if (
        abi["path"] != "dispatch-abi"
        or abi["schema_version"] != ABI_MANIFEST_VERSION
        or abi["source_sha256"] != ABI_SOURCE_SHA256
        or abi["manifest_sha256"] != ABI_MANIFEST_SHA256
    ):
        raise ValueError("selector dispatch ABI commitment mismatch")
    _sha(abi["manifest_sha256"], "dispatch ABI manifest")
    handler = _obj(value["handler"], "selector handler")
    _exact(
        handler,
        {"name", "rva", "exact_function_entry", "executable", "non_thunk"},
        "selector handler",
    )
    if handler != {
        "name": "AfdDispatchDeviceControl",
        "rva": f"0x{handler_rva:x}",
        "exact_function_entry": True,
        "executable": True,
        "non_thunk": True,
    }:
        raise ValueError("selector handler mismatch")
    irp = _obj(value["irp_projection"], "IRP projection")
    _exact(
        irp,
        {
            "argument_register",
            "argument_width",
            "current_stack_location_offset",
            "current_stack_location_width",
            "current_stack_location_load",
            "io_control_code_offset",
            "io_control_code_width",
            "io_control_code_load",
        },
        "IRP projection",
    )
    if (
        irp["argument_register"],
        irp["argument_width"],
        irp["current_stack_location_offset"],
        irp["current_stack_location_width"],
        irp["io_control_code_offset"],
        irp["io_control_code_width"],
    ) != ("RDX", 8, "0xb8", 8, "0x18", 4):
        raise ValueError("selector projected IRP path mismatch")
    _native(irp["current_stack_location_load"], handler_rva + 0x0F, "488b9ab8000000", "stack load")
    _native(irp["io_control_code_load"], handler_rva + 0x2C, "448b4318", "IOCTL load")
    partition = _obj(value["partition"], "selector partition")
    _exact(
        partition,
        {
            "predicate_import",
            "predicate_iat_rva",
            "predicate_call",
            "tested_register",
            "local_branch",
            "alternate_branch",
            "alternate_import",
            "alternate_iat_rva",
            "alternate_call",
            "alternate_resolved",
        },
        "selector partition",
    )
    if (
        partition["predicate_import"] != "NetioNrtIsTrackerDevice"
        or partition["tested_register"] != "AL"
        or partition["local_branch"] != "AL==0"
        or partition["alternate_branch"] != "AL!=0"
        or partition["alternate_import"] != "NetioNrtDispatch"
        or partition["alternate_resolved"] is not False
    ):
        raise ValueError("selector partition/polarity mismatch")
    _ff15(
        partition["predicate_call"],
        handler_rva + 0x1C,
        partition["predicate_iat_rva"],
        "predicate call",
    )
    _ff15(
        partition["alternate_call"],
        handler_rva + 0x83,
        partition["alternate_iat_rva"],
        "alternate call",
    )
    selector = _obj(value["selector"], "selector arithmetic")
    expected_selector = {
        "source_register": "R8D",
        "width": 4,
        "shift_right": 2,
        "mask": "0x3ff",
        "unsigned_upper_exclusive": 74,
        "reject_condition": "index>=74",
        "key_comparison_width": 4,
        "key_equality_required": True,
    }
    if selector != expected_selector:
        raise ValueError("selector arithmetic/polarity mismatch")
    key_rva, function_rva = _validate_native_selector(value["native_selector"], handler_rva)
    key_raw = _table(value["key_table"], 4, "key table", expected_rva=key_rva)
    function_raw = _table(
        value["function_table"],
        8,
        "function table",
        functions=True,
        expected_rva=function_rva,
    )
    keys = struct.unpack("<74I", key_raw)
    pointers = struct.unpack("<74Q", function_raw)
    rows = value["rows"]
    if not isinstance(rows, list) or len(rows) != 74:
        raise ValueError("selector rows must contain the exact addressed extent")
    for index, row_raw in enumerate(rows):
        row = _obj(row_raw, "selector row")
        _exact(
            row,
            {
                "index",
                "key",
                "target_rva",
                "target_section",
                "exact_function_entry",
                "executable",
                "non_thunk",
            },
            "selector row",
        )
        target_rva = pointers[index] - image_base
        if (
            pointers[index] < image_base
            or row["index"] != index
            or _hex(row["key"], "selector key") != keys[index]
            or ((keys[index] >> 2) & 0x3FF) != index
            or _hex(row["target_rva"], "selector target") != target_rva
            or not isinstance(row["target_section"], str)
            or not row["target_section"]
            or row["exact_function_entry"] is not True
            or row["executable"] is not True
            or row["non_thunk"] is not True
        ):
            raise ValueError("selector row/table cross-binding mismatch")
    dispatch = _obj(value["dispatch"], "selector dispatch")
    _exact(
        dispatch,
        {
            "target_register",
            "target_load_width",
            "non_null_required",
            "call",
            "thunk_rva",
            "thunk_bytes",
            "thunk_sha256",
            "load_config_field",
            "pointer_slot_rva",
            "check_pointer_slot_rva",
            "tail_jump",
            "rax_preserved_to_thunk",
            "helper_name",
            "handler_transfer_opcode",
        },
        "selector dispatch",
    )
    if (
        dispatch["target_register"] != "RAX"
        or dispatch["target_load_width"] != 8
        or dispatch["non_null_required"] is not True
        or dispatch["load_config_field"] != "GuardCFDispatchFunctionPointer"
        or dispatch["tail_jump"] is not True
        or dispatch["rax_preserved_to_thunk"] is not True
        or dispatch["helper_name"] != "_guard_dispatch_icall"
        or dispatch["handler_transfer_opcode"] != "CALL"
    ):
        raise ValueError("selector dispatch contract mismatch")
    call = _native(dispatch["call"], handler_rva + 0x67, None, "dispatch call")
    call_bytes = bytes.fromhex(cast(str, call["bytes"]))
    thunk_rva = _hex(dispatch["thunk_rva"], "dispatch thunk")
    if (
        len(call_bytes) != 5
        or call_bytes[0] != 0xE8
        or handler_rva + 0x6C + struct.unpack("<i", call_bytes[1:])[0] != thunk_rva
    ):
        raise ValueError("selector dispatch call target mismatch")
    thunk_bytes = bytes.fromhex(cast(str, dispatch["thunk_bytes"]))
    slot = _hex(dispatch["pointer_slot_rva"], "dispatch slot")
    if (
        len(thunk_bytes) != 6
        or thunk_bytes[:2] != b"\xff\x25"
        or thunk_rva + 6 + struct.unpack("<i", thunk_bytes[2:])[0] != slot
        or dispatch["thunk_sha256"] != hashlib.sha256(thunk_bytes).hexdigest()
        or slot == _hex(dispatch["check_pointer_slot_rva"], "check slot")
    ):
        raise ValueError("selector CFG thunk/load-config binding mismatch")
    _validate_high_pcode(value["high_pcode"], handler_rva)
    accounting = _obj(value["accounting"], "selector accounting")
    _exact(
        accounting,
        {"addressed_rows", "unique_targets", "null_targets", "limits_hit"},
        "selector accounting",
    )
    if accounting != {
        "addressed_rows": 74,
        "unique_targets": len(set(pointers)),
        "null_targets": 0,
        "limits_hit": [],
    }:
        raise ValueError("selector accounting mismatch")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def _native(
    raw: object, expected_rva: int, expected_bytes: str | None, label: str
) -> dict[str, object]:
    value = _obj(raw, label)
    _exact(value, {"rva", "bytes", "sha256"}, label)
    encoded = bytes.fromhex(cast(str, value["bytes"]))
    if (
        _hex(value["rva"], f"{label} RVA") != expected_rva
        or value["sha256"] != hashlib.sha256(encoded).hexdigest()
        or (expected_bytes is not None and value["bytes"] != expected_bytes)
    ):
        raise ValueError(f"selector {label} native binding mismatch")
    return cast(dict[str, object], value)


def _ff15(raw: object, expected_rva: int, slot_raw: object, label: str) -> None:
    ref = _native(raw, expected_rva, None, label)
    encoded = bytes.fromhex(cast(str, ref["bytes"]))
    slot = _hex(slot_raw, f"{label} IAT slot")
    if (
        len(encoded) != 7
        or encoded[:3] != b"\x48\xff\x15"
        or expected_rva + 7 + struct.unpack("<i", encoded[3:])[0] != slot
    ):
        raise ValueError(f"selector {label} IAT binding mismatch")


def _table(
    raw: object,
    width: int,
    label: str,
    *,
    functions: bool = False,
    expected_rva: int,
) -> bytes:
    value = _obj(raw, label)
    fields = {
        "rva",
        "section",
        "entry_width",
        "addressed_count",
        "addressed_size",
        "addressed_bytes",
        "addressed_sha256",
        "addressed_extent_complete",
        "pdb_declared_allocation_extent",
        "preferred_base_absolute_pointers",
        "runtime_relocation_claimed",
    }
    if functions:
        fields |= {"all_entries_non_null", "all_targets_exact_executable_non_thunk"}
    _exact(value, fields, label)
    encoded = bytes.fromhex(cast(str, value["addressed_bytes"]))
    if (
        value["section"] != ".rdata"
        or value["entry_width"] != width
        or value["addressed_count"] != 74
        or value["addressed_size"] != 74 * width
        or len(encoded) != 74 * width
        or value["addressed_sha256"] != hashlib.sha256(encoded).hexdigest()
        or value["addressed_extent_complete"] is not True
        or value["pdb_declared_allocation_extent"] is not False
        or value["preferred_base_absolute_pointers"] is not functions
        or value["runtime_relocation_claimed"] is not False
    ):
        raise ValueError(f"selector {label} addressed extent mismatch")
    if _hex(value["rva"], f"{label} RVA") != expected_rva:
        raise ValueError(f"selector {label} native-address cross-binding mismatch")
    if functions and (
        value["all_entries_non_null"] is not True
        or value["all_targets_exact_executable_non_thunk"] is not True
        or any(pointer == 0 for pointer in struct.unpack("<74Q", encoded))
    ):
        raise ValueError("selector function table target contract mismatch")
    return encoded


def _validate_native_selector(raw: object, handler_rva: int) -> tuple[int, int]:
    value = _obj(raw, "native selector")
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
    _exact(
        value,
        set(exact) | {"image_base_lea", "key_compare", "function_table_load"},
        "native selector",
    )
    for name, (relative, encoded) in exact.items():
        _native(value[name], handler_rva + relative, encoded, name)
    base = _native(value["image_base_lea"], handler_rva + 0x40, None, "image-base LEA")
    base_bytes = bytes.fromhex(cast(str, base["bytes"]))
    if (
        len(base_bytes) != 7
        or base_bytes[:3] != b"\x48\x8d\x15"
        or handler_rva + 0x47 + struct.unpack("<i", base_bytes[3:])[0] != 0
    ):
        raise ValueError("selector native image-base derivation mismatch")
    key = _native(value["key_compare"], handler_rva + 0x47, None, "key compare")
    key_bytes = bytes.fromhex(cast(str, key["bytes"]))
    if len(key_bytes) != 8 or key_bytes[:4] != b"\x44\x39\x84\x82":
        raise ValueError("selector native key-table addressing mismatch")
    function = _native(
        value["function_table_load"],
        handler_rva + 0x54,
        None,
        "function-table load",
    )
    function_bytes = bytes.fromhex(cast(str, function["bytes"]))
    if len(function_bytes) != 8 or function_bytes[:4] != b"\x48\x8b\x84\xc2":
        raise ValueError("selector native function-table addressing mismatch")
    key_rva = struct.unpack("<i", key_bytes[4:])[0]
    function_rva = struct.unpack("<i", function_bytes[4:])[0]
    if key_rva < 0 or function_rva < 0:
        raise ValueError("selector native table displacement is negative")
    return key_rva, function_rva


def _validate_high_pcode(raw: object, handler_rva: int) -> None:
    value = _obj(raw, "selector High-P-Code")
    stages = {
        "irp_current_stack_load": ({"LOAD"}, 8, None, {0x0F}),
        "ioctl_load": ({"LOAD"}, 4, None, {0x2C}),
        "shift": ({"INT_RIGHT"}, 4, 2, {0x33}),
        "mask": ({"INT_AND"}, 4, 0x3FF, {0x36}),
        "unsigned_bound": ({"INT_LESS"}, 1, 74, {0x3B, 0x3E}),
        "key_load": ({"LOAD"}, 4, None, {0x47}),
        "key_equality": ({"INT_EQUAL", "INT_NOTEQUAL"}, 1, None, {0x47, 0x4F}),
        "target_load": ({"LOAD"}, 8, None, {0x54}),
        "null_guard": ({"INT_EQUAL", "INT_NOTEQUAL"}, 1, 0, {0x5C, 0x5F}),
        # Ghidra collapses the native direct _guard_dispatch_icall helper into
        # the guarded indirect transfer in optimized High-P-Code.  The native
        # CALL and its exact helper target are validated separately above.
        "guard_dispatch_call": ({"CALLIND"}, 8, None, {0x67}),
    }
    _exact(
        value,
        set(stages)
        | {
            "forbidden_opcodes",
            "reviewed_sites_corroborated",
            "descendant_closure_established",
            "global_extra_transforms_excluded",
        },
        "selector High-P-Code",
    )
    if (
        value["forbidden_opcodes"] != ["CALLOTHER", "MULTIEQUAL", "PIECE", "SUBPIECE"]
        or value["reviewed_sites_corroborated"] is not True
        or value["descendant_closure_established"] is not False
        or value["global_extra_transforms_excluded"] is not False
    ):
        raise ValueError("selector High-P-Code classification mismatch")
    for name, (opcodes, output_size, constant, relatives) in stages.items():
        refs = value[name]
        if not isinstance(refs, list) or len(refs) != 1:
            raise ValueError(f"selector {name} High-P-Code cardinality mismatch")
        ref = _obj(refs[0], f"selector {name} ref")
        _exact(
            ref,
            {"instruction_rva", "pcode_order", "opcode", "output_size", "input_sizes", "constants"},
            f"selector {name} ref",
        )
        if (
            _hex(ref["instruction_rva"], f"selector {name} instruction") - handler_rva
            not in relatives
            or ref["opcode"] not in opcodes
            or ref["output_size"] != output_size
            or not isinstance(ref["pcode_order"], int)
            or ref["pcode_order"] < 0
            or not isinstance(ref["input_sizes"], list)
            or not all(isinstance(item, int) and item > 0 for item in ref["input_sizes"])
            or not isinstance(ref["constants"], list)
            or not all(isinstance(item, int) and item >= 0 for item in ref["constants"])
            or (constant is not None and ref["constants"].count(constant) != 1)
        ):
            raise ValueError(f"selector {name} High-P-Code binding mismatch")


def produce_windows_afd_selector(
    registration_bundle: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
    dispatch_abi_authority_dir: str | Path,
) -> dict[str, str]:
    source = Path(os.path.abspath(registration_bundle))  # noqa: PTH100 - lexical custody
    output = Path(os.path.abspath(output_dir))  # noqa: PTH100 - new lexical path
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody
    authority = Path(os.path.abspath(dispatch_abi_authority_dir))  # noqa: PTH100
    if output.exists() or output.is_symlink():
        raise FileExistsError("selector output already exists")
    authority_commitment = validate_dispatch_abi_authority(authority)
    toolchain = _toolchain_fingerprint(home)
    parent_fd = _open_directory_ancestry(output.parent, "selector output parent")
    source_fd = _open_directory_ancestry(source, "registration source")
    authority_fd = _open_directory_ancestry(authority, "dispatch ABI authority source")
    temporary_name = ""
    temporary_fd = -1
    published = False
    try:
        _require_directory_path_identity(output.parent, parent_fd, "selector output parent")
        temporary_name, temporary_fd = _create_staging_directory(parent_fd, f".{output.name}.tmp-")
        staging = output.parent / temporary_name
        _snapshot_registration_bundle(source_fd, temporary_fd)
        os.mkdir("dispatch-abi", 0o700, dir_fd=temporary_fd)
        abi_fd = os.open(
            "dispatch-abi", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=temporary_fd
        )
        try:
            for name in ("manifest.json", "nc-wdm-driver_dispatch.md"):
                _snapshot_file_from_dirfd(
                    authority_fd, name, abi_fd, name, "dispatch ABI authority", 1024 * 1024
                )
        finally:
            os.close(abi_fd)
        retained_registration = staging / "registration"
        registration_export = verify_windows_driver_registration_bundle(
            retained_registration, ghidra_home=home
        )
        retained_authority = validate_dispatch_abi_authority(staging / "dispatch-abi")
        if retained_authority != authority_commitment:
            raise ValueError("dispatch ABI authority changed during snapshot")
        registration_receipt = _json_file(
            retained_registration / "receipt.json", "registration receipt"
        )
        bridge_receipt = _json_file(
            retained_registration / "entry-bridge" / "receipt.json", "entry bridge receipt"
        )
        binary = _relative_file(
            retained_registration / "entry-bridge", bridge_receipt["binary_path"], "selector binary"
        )
        pdb = _relative_file(
            retained_registration / "entry-bridge", bridge_receipt["pdb_path"], "selector PDB"
        )
        projection_path = retained_registration / "wdm-projection.json"
        validate_selector_wdm_projection(_json_file(projection_path, "selector WDM projection"))
        handler_rva = _hex(
            _obj(registration_export["registration"], "registration")["target"]["rva"],
            "selector handler",
        )
        acquired = acquire_afd_selector_facts(binary, pdb, home, handler_rva=handler_rva)
        facts = {
            "schema_version": RAW_VERSION,
            **{
                key: registration_export[key]
                for key in (
                    "driver_sha256",
                    "pdb_sha256",
                    "pdb_identity",
                    "pe_codeview_identity",
                    "architecture",
                    "image_base",
                    "tool",
                )
            },
            "registration_commitment": {
                "schema_version": REGISTRATION_VERSION,
                "path": "registration",
                "artifact_sha256": registration_receipt["registration_sha256"],
                "receipt_sha256": _sha_file(retained_registration / "receipt.json"),
                "handler_rva": f"0x{handler_rva:x}",
            },
            "wdm_projection": {
                "path": "registration/wdm-projection.json",
                "sha256": PROJECTION_SHA256,
                "schema_version": PROJECTION_VERSION,
                "authority_scope": AUTHORITY_SCOPE,
                "exact_pdb_identity": False,
                "runtime_layout_exact": False,
            },
            "dispatch_abi_authority": {
                "path": "dispatch-abi",
                "schema_version": ABI_MANIFEST_VERSION,
                **retained_authority,
            },
            **acquired,
        }
        export = compile_windows_afd_selector(facts)
        artifact_bytes = canonical_selector_bytes(export)
        _write_new_file_at(temporary_fd, "selector.json", artifact_bytes)
        receipt = {
            "schema_version": RECEIPT_VERSION,
            "producer": PRODUCER,
            "selector_path": "selector.json",
            "selector_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "registration_bundle": "registration",
            "registration_receipt_sha256": _sha_file(retained_registration / "receipt.json"),
            "dispatch_abi_bundle": "dispatch-abi",
            "dispatch_abi_manifest_sha256": retained_authority["manifest_sha256"],
            "toolchain": toolchain,
            "extractor_config_sha256": CONFIG_SHA256,
            "static_only": True,
            "execution_authorized": False,
        }
        receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        _write_new_file_at(temporary_fd, "receipt.json", receipt_bytes)
        os.fsync(temporary_fd)
        _require_directory_path_identity(output.parent, parent_fd, "selector output parent")
        _publish_directory_no_replace(parent_fd, temporary_name, output.name)
        os.fsync(parent_fd)
        published = True
        return {
            "selector_path": f"{output.name}/selector.json",
            "selector_sha256": cast(str, receipt["selector_sha256"]),
            "receipt_path": f"{output.name}/receipt.json",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        }
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name and not published:
            _remove_tree_at(parent_fd, temporary_name)
        os.close(authority_fd)
        os.close(source_fd)
        os.close(parent_fd)


def verify_windows_afd_selector_bundle(
    bundle_path: str | Path, *, ghidra_home: str | Path
) -> dict[str, object]:
    source = Path(bundle_path)
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody
    source_fd = _open_directory_ancestry(source, "selector bundle")
    with TemporaryDirectory(prefix="zeroverse-selector-verify-") as temporary:
        # macOS exposes its temporary root through /var -> /private/var.  Resolve
        # that platform-owned alias before applying the no-symlink ancestry gate.
        retained = Path(temporary).resolve(strict=True) / "bundle"
        retained.mkdir(mode=0o700)
        retained_fd = os.open(retained, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _snapshot_selector_bundle(source_fd, retained_fd)
            os.fsync(retained_fd)
        finally:
            os.close(retained_fd)
            os.close(source_fd)
        return _verify_snapshotted_selector_bundle(retained, home)


def _verify_snapshotted_selector_bundle(bundle: Path, home: Path) -> dict[str, object]:
    bundle_fd = _open_directory_ancestry(bundle, "retained selector bundle")
    try:
        receipt_bytes = _read_regular_file_at(
            bundle_fd, "receipt.json", "selector receipt", 1024 * 1024
        )
        receipt = _obj(json.loads(receipt_bytes, object_pairs_hook=_unique), "selector receipt")
        _validate_receipt(receipt, _toolchain_fingerprint(home))
        artifact_bytes = _read_regular_file_at(
            bundle_fd, "selector.json", "selector artifact", 16 * 1024 * 1024
        )
        if hashlib.sha256(artifact_bytes).hexdigest() != receipt["selector_sha256"]:
            raise ValueError("selector artifact SHA-256 mismatch")
        export = _validate(json.loads(artifact_bytes, object_pairs_hook=_unique))
        if canonical_selector_bytes(export) != artifact_bytes:
            raise ValueError("selector artifact is not canonical")
        registration = bundle / "registration"
        registration_export = verify_windows_driver_registration_bundle(
            registration, ghidra_home=home
        )
        if _sha_file(registration / "receipt.json") != receipt["registration_receipt_sha256"]:
            raise ValueError("selector retained registration receipt mismatch")
        authority = validate_dispatch_abi_authority(bundle / "dispatch-abi")
        if authority["manifest_sha256"] != receipt["dispatch_abi_manifest_sha256"]:
            raise ValueError("selector dispatch ABI manifest mismatch")
        projection = validate_selector_wdm_projection(
            _json_file(registration / "wdm-projection.json", "selector projection")
        )
        del projection
        bridge_receipt = _json_file(
            registration / "entry-bridge" / "receipt.json", "entry bridge receipt"
        )
        binary = _relative_file(
            registration / "entry-bridge", bridge_receipt["binary_path"], "selector binary"
        )
        pdb = _relative_file(
            registration / "entry-bridge", bridge_receipt["pdb_path"], "selector PDB"
        )
        handler_rva = _hex(
            _obj(registration_export["registration"], "registration")["target"]["rva"],
            "selector handler",
        )
        (
            expected_registration_commitment,
            expected_projection_commitment,
            expected_authority_commitment,
        ) = _retained_commitments(registration, handler_rva, authority)
        if (
            export["registration_commitment"] != expected_registration_commitment
            or export["wdm_projection"] != expected_projection_commitment
            or export["dispatch_abi_authority"] != expected_authority_commitment
        ):
            raise ValueError("selector retained commitment mismatch")
        acquired = acquire_afd_selector_facts(binary, pdb, home, handler_rva=handler_rva)
        replay = {
            "schema_version": RAW_VERSION,
            **{
                key: registration_export[key]
                for key in (
                    "driver_sha256",
                    "pdb_sha256",
                    "pdb_identity",
                    "pe_codeview_identity",
                    "architecture",
                    "image_base",
                    "tool",
                )
            },
            "registration_commitment": expected_registration_commitment,
            "wdm_projection": expected_projection_commitment,
            "dispatch_abi_authority": expected_authority_commitment,
            **acquired,
        }
        if canonical_selector_bytes(compile_windows_afd_selector(replay)) != artifact_bytes:
            raise ValueError("selector structural proof replay mismatch")
        return export
    finally:
        os.close(bundle_fd)


def _retained_commitments(
    registration: Path, handler_rva: int, authority: dict[str, object]
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    registration_receipt = _json_file(registration / "receipt.json", "registration receipt")
    artifact_sha256 = registration_receipt.get("registration_sha256")
    _sha(artifact_sha256, "retained registration artifact")
    registration_commitment = {
        "schema_version": REGISTRATION_VERSION,
        "path": "registration",
        "artifact_sha256": artifact_sha256,
        "receipt_sha256": _sha_file(registration / "receipt.json"),
        "handler_rva": f"0x{handler_rva:x}",
    }
    projection_commitment = {
        "path": "registration/wdm-projection.json",
        "sha256": PROJECTION_SHA256,
        "schema_version": PROJECTION_VERSION,
        "authority_scope": AUTHORITY_SCOPE,
        "exact_pdb_identity": False,
        "runtime_layout_exact": False,
    }
    authority_commitment = {
        "path": "dispatch-abi",
        "schema_version": ABI_MANIFEST_VERSION,
        **authority,
    }
    return registration_commitment, projection_commitment, authority_commitment


def _snapshot_selector_bundle(source_fd: int, destination_fd: int) -> None:
    for name, limit in (("receipt.json", 1024 * 1024), ("selector.json", 16 * 1024 * 1024)):
        _snapshot_file_from_dirfd(
            source_fd, name, destination_fd, name, "selector retained file", limit
        )
    registration_source_fd = os.open(
        "registration",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=source_fd,
    )
    try:
        _snapshot_registration_bundle(registration_source_fd, destination_fd)
    finally:
        os.close(registration_source_fd)
    os.mkdir("dispatch-abi", 0o700, dir_fd=destination_fd)
    authority_source_fd = os.open(
        "dispatch-abi",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=source_fd,
    )
    authority_destination_fd = os.open(
        "dispatch-abi",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=destination_fd,
    )
    try:
        for name in ("manifest.json", "nc-wdm-driver_dispatch.md"):
            _snapshot_file_from_dirfd(
                authority_source_fd,
                name,
                authority_destination_fd,
                name,
                "dispatch ABI retained file",
                1024 * 1024,
            )
    finally:
        os.close(authority_destination_fd)
        os.close(authority_source_fd)


def _validate_receipt(receipt: dict[str, Any], toolchain: dict[str, object]) -> None:
    fields = {
        "schema_version",
        "producer",
        "selector_path",
        "selector_sha256",
        "registration_bundle",
        "registration_receipt_sha256",
        "dispatch_abi_bundle",
        "dispatch_abi_manifest_sha256",
        "toolchain",
        "extractor_config_sha256",
        "static_only",
        "execution_authorized",
    }
    _exact(receipt, fields, "selector receipt")
    if (
        receipt["schema_version"] != RECEIPT_VERSION
        or receipt["producer"] != PRODUCER
        or receipt["selector_path"] != "selector.json"
        or receipt["registration_bundle"] != "registration"
        or receipt["dispatch_abi_bundle"] != "dispatch-abi"
        or receipt["toolchain"] != toolchain
        or receipt["extractor_config_sha256"] != CONFIG_SHA256
        or receipt["static_only"] is not True
        or receipt["execution_authorized"] is not False
    ):
        raise ValueError("selector receipt contract mismatch")
    for key in ("selector_sha256", "registration_receipt_sha256", "dispatch_abi_manifest_sha256"):
        _sha(receipt[key], key)


def _snapshot_registration_bundle(source_fd: int, destination_fd: int) -> None:
    receipt = _obj(
        json.loads(
            _read_regular_file_at(source_fd, "receipt.json", "registration receipt", 1024 * 1024),
            object_pairs_hook=_unique,
        ),
        "registration receipt",
    )
    if (
        receipt.get("schema_version") != "0verse.windows-driver-registration-receipt/v1"
        or receipt.get("registration_path") != "registration.json"
        or receipt.get("wdm_projection_path") != "wdm-projection.json"
        or receipt.get("entry_bridge_bundle") != "entry-bridge"
    ):
        raise ValueError("selector requires the exact registration-v1 topology")
    os.mkdir("registration", 0o700, dir_fd=destination_fd)
    retained_fd = os.open(
        "registration", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination_fd
    )
    try:
        for name in ("receipt.json", "registration.json", "wdm-projection.json"):
            _snapshot_file_from_dirfd(
                source_fd, name, retained_fd, name, "registration retained file", 16 * 1024 * 1024
            )
        bridge_source_fd = os.open(
            "entry-bridge", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd
        )
        try:
            _snapshot_v3_bridge_bundle(bridge_source_fd, retained_fd)
        finally:
            os.close(bridge_source_fd)
    finally:
        os.close(retained_fd)


def _json_file(path: Path, label: str) -> dict[str, Any]:
    parent = _open_directory_ancestry(path.parent, f"{label} parent")
    try:
        return _obj(
            json.loads(
                _read_regular_file_at(parent, path.name, label, 16 * 1024 * 1024),
                object_pairs_hook=_unique,
            ),
            label,
        )
    finally:
        os.close(parent)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        for entry in os.listdir(  # noqa: PTH208  # foxguard: ignore[py/no-path-traversal]
            child_fd
        ):
            observed = os.stat(entry, dir_fd=child_fd, follow_symlinks=False)
            if stat.S_ISDIR(observed.st_mode):
                _remove_tree_at(child_fd, entry)
            else:
                with suppress(FileNotFoundError):
                    os.unlink(  # foxguard: ignore[py/no-path-traversal]
                        entry, dir_fd=child_fd
                    )
    finally:
        os.close(child_fd)
    with suppress(FileNotFoundError):
        os.rmdir(name, dir_fd=parent_fd)
