"""Custody-bound proof of one projected AFD device-control registration."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from .pe_symbols import pdb_function_records
from .windows_driver_entry_bridge import (
    EXPORT_VERSION_V3 as BRIDGE_VERSION,
)
from .windows_driver_entry_bridge import (
    _toolchain_fingerprint,
    verify_windows_driver_entry_bridge_bundle,
)
from .windows_driver_registration_ghidra import acquire_projected_registration_facts
from .windows_variant import (
    _create_staging_directory,
    _open_directory_ancestry,
    _publish_directory_no_replace,
    _require_directory_path_identity,
    _write_new_file_at,
)

RAW_VERSION = "0verse.windows-driver-registration-facts/v1"
EXPORT_VERSION = "0verse.windows-driver-registration/v1"
RECEIPT_VERSION = "0verse.windows-driver-registration-receipt/v1"
PRODUCER = "zeroverse.windows-driver-registration/v1"
PROJECTION_VERSION = "0verse.public-wdm-selected-physical-layout/v1"
PROJECTION_SHA256 = "d454d47b5795b0c69895e2cc2c45844cc437af05d73df11cd2a59a534a61f1bb"
PROJECTION_CANONICAL_SHA256 = "08f5a4bf77249612f681b2c72231fdd4cca312a4cbe09c26c67b0362d61f3ffa"
AUTHORITY_SCOPE = (
    "PE-GUID-keyed Microsoft-route-associated stripped public TPI plus external Windows AMD64 "
    "WDM ABI arithmetic; not exact runtime layout"
)
_CONFIG = {
    "architecture": "x86_64",
    "entry_source": "verified-windows-driver-entry-bridge/v3",
    "driver_object_alias": "exact-native-48-8b-d9",
    "projected_path": "_DRIVER_OBJECT.MajorFunction[14]",
    "projected_offset": 0xE0,
    "store_width": 8,
    "target_name": "AfdDispatchDeviceControl",
    "target_source": "unique-function-flagged-public-pdb-record",
    "later_reachable_projected_high_pcode_stores": "reject",
    "transitive_finality": False,
}
CONFIG_SHA256 = hashlib.sha256(
    json.dumps(_CONFIG, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
_PROOF_LIMIT = (
    "Static projected assignment only. The retained external WDM projection is not an exact "
    "runtime AFD layout. This profile proves one direct in-function assignment matching "
    "projected MajorFunction[14] and excludes later reachable stores only when their High-P-Code "
    "address independently matches the same exact path. It does not prove may-alias or transitive "
    "finality, runtime registration or reachability, selector or table semantics, candidate "
    "status, vulnerability, exploitability, novelty, or bounty eligibility."
)


def compile_windows_driver_registration(raw: object) -> dict[str, object]:
    facts = _obj(json.loads(json.dumps(raw)), "registration facts")
    _exact(
        facts,
        {
            "schema_version",
            "driver_sha256",
            "pdb_sha256",
            "pdb_identity",
            "pe_codeview_identity",
            "architecture",
            "image_base",
            "tool",
            "entry_bridge",
            "wdm_projection",
            "driver_object_alias",
            "registration",
            "accounting",
        },
        "registration facts",
    )
    if facts["schema_version"] != RAW_VERSION:
        raise ValueError("unsupported registration fact schema")
    export: dict[str, object] = {
        "schema_version": EXPORT_VERSION,
        "producer": PRODUCER,
        "extractor_config_sha256": CONFIG_SHA256,
        **{key: value for key, value in facts.items() if key != "schema_version"},
        "outcome": "projected-device-control-assignment-proven",
        "static_only": True,
        "runtime_layout_exact": False,
        "static_projected_registration_established": True,
        "runtime_registration_established": False,
        "transitive_finality": False,
        "selector_claims": 0,
        "table_claims": 0,
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


def canonical_registration_bytes(raw: object) -> bytes:
    return (json.dumps(_validate(raw), sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate_wdm_projection(raw: object) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), "WDM projection")
    _exact(
        value,
        {
            "schema_version",
            "authority_scope",
            "exact_pdb_identity",
            "runtime_layout_exact",
            "structures",
            "resolved_paths",
        },
        "WDM projection",
    )
    if (
        value["schema_version"] != PROJECTION_VERSION
        or value["exact_pdb_identity"] is not False
        or value["runtime_layout_exact"] is not False
        or value["authority_scope"] != AUTHORITY_SCOPE
    ):
        raise ValueError("WDM projection classification mismatch")
    structures = _obj(value["structures"], "WDM structures")
    if structures.get("_DRIVER_OBJECT") != {"size_bytes": 336}:
        raise ValueError("WDM projected DRIVER_OBJECT size mismatch")
    paths = _obj(value["resolved_paths"], "WDM resolved paths")
    path = _obj(paths.get("_DRIVER_OBJECT.MajorFunction[14]"), "MajorFunction projection")
    expected = {
        "components": [["MajorFunction", 112], ["[14]", 112]],
        "absolute_offset_bytes": 224,
        "absolute_offset_hex": "0xe0",
        "array_extent_elements": 28,
        "array_size_bytes": 224,
        "array_element_width_bytes": 8,
        "leaf_kind": "ptr64",
        "leaf_width_bytes": 8,
    }
    if any(path.get(key) != expected_value for key, expected_value in expected.items()):
        raise ValueError("WDM MajorFunction[14] projection mismatch")
    if set(path) != set(expected) | {"leaf_alignment_bytes", "alignment_basis", "type_indices"}:
        raise ValueError("WDM MajorFunction[14] projection has unknown or missing fields")
    if path["leaf_alignment_bytes"] != 8 or not isinstance(path["alignment_basis"], str):
        raise ValueError("WDM MajorFunction[14] alignment mismatch")
    indices = path["type_indices"]
    if (
        not isinstance(indices, list)
        or not indices
        or not all(isinstance(item, str) for item in indices)
    ):
        raise ValueError("WDM MajorFunction[14] type indices mismatch")
    canonical_sha256 = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if canonical_sha256 != PROJECTION_CANONICAL_SHA256:
        raise ValueError("WDM projection differs from the reviewed canonical authority")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def produce_windows_driver_registration(
    entry_bridge_bundle: str | Path,
    wdm_projection_path: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
) -> dict[str, str]:
    source_bridge = Path(os.path.abspath(entry_bridge_bundle))  # noqa: PTH100 - lexical path
    projection_source = Path(os.path.abspath(wdm_projection_path))  # noqa: PTH100
    output = Path(os.path.abspath(output_dir))  # noqa: PTH100 - new lexical path
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody path
    if output.exists() or output.is_symlink():
        raise FileExistsError("registration output already exists")
    toolchain = _toolchain_fingerprint(home)
    parent_fd = _open_directory_ancestry(output.parent, "registration output parent")
    source_bridge_fd = _open_directory_ancestry(source_bridge, "entry bridge source")
    projection_parent_fd = _open_directory_ancestry(
        projection_source.parent, "WDM projection source parent"
    )
    temporary_name = ""
    temporary_fd = -1
    published = False
    try:
        _require_directory_path_identity(output.parent, parent_fd, "registration output parent")
        temporary_name, temporary_fd = _create_staging_directory(parent_fd, f".{output.name}.tmp-")
        staging = output.parent / temporary_name
        retained_bridge = staging / "entry-bridge"
        _snapshot_v3_bridge_bundle(source_bridge_fd, temporary_fd)
        retained_projection = staging / "wdm-projection.json"
        _snapshot_file_from_dirfd(
            projection_parent_fd,
            projection_source.name,
            temporary_fd,
            "wdm-projection.json",
            "WDM projection",
            1024 * 1024,
        )
        projection = validate_wdm_projection(
            json.loads(
                _read_regular_file_at(
                    temporary_fd, "wdm-projection.json", "WDM projection", 1024 * 1024
                ),
                object_pairs_hook=_unique,
            )
        )
        if _sha_file(retained_projection) != PROJECTION_SHA256:
            raise ValueError("retained WDM projection left the reviewed authority")
        retained_export = verify_windows_driver_entry_bridge_bundle(
            retained_bridge, ghidra_home=home
        )
        if retained_export.get("schema_version") != BRIDGE_VERSION:
            raise ValueError("registration requires a verified v3 entry bridge")
        bridge_export = retained_export
        bridge_receipt = _load_object(retained_bridge / "receipt.json", "entry bridge receipt")
        binary = _relative_file(retained_bridge, bridge_receipt["binary_path"], "binary")
        pdb = _relative_file(retained_bridge, bridge_receipt["pdb_path"], "PDB")
        bridge_artifact = _relative_file(
            retained_bridge, bridge_receipt["entry_bridge_path"], "entry bridge artifact"
        )
        acquired = acquire_projected_registration_facts(
            binary,
            pdb,
            home,
            driver_entry_rva=_hex(
                _obj(bridge_export["pdb_driver_entry"], "bridge DriverEntry")["rva"],
                "DriverEntry RVA",
            ),
            records=pdb_function_records(binary, pdb),
        )
        facts = {
            "schema_version": RAW_VERSION,
            **{
                key: bridge_export[key]
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
            "entry_bridge": {
                "schema_version": BRIDGE_VERSION,
                "artifact_path": "entry-bridge/entry-bridge.json",
                "artifact_sha256": _sha_file(bridge_artifact),
                "receipt_path": "entry-bridge/receipt.json",
                "receipt_sha256": _sha_file(retained_bridge / "receipt.json"),
                "driver_entry_rva": _obj(bridge_export["pdb_driver_entry"], "bridge DriverEntry")[
                    "rva"
                ],
            },
            "wdm_projection": {
                "path": "wdm-projection.json",
                "sha256": _sha_file(retained_projection),
                "schema_version": PROJECTION_VERSION,
                "authority_scope": projection["authority_scope"],
                "exact_pdb_identity": False,
                "runtime_layout_exact": False,
            },
            **acquired,
        }
        export = compile_windows_driver_registration(facts)
        artifact_bytes = canonical_registration_bytes(export)
        _write_new_file_at(temporary_fd, "registration.json", artifact_bytes)
        bridge_commitment = _obj(facts["entry_bridge"], "entry bridge commitment")
        projection_commitment = _obj(facts["wdm_projection"], "projection commitment")
        receipt: dict[str, object] = {
            "schema_version": RECEIPT_VERSION,
            "producer": PRODUCER,
            "registration_path": "registration.json",
            "registration_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "entry_bridge_bundle": "entry-bridge",
            "entry_bridge_receipt_sha256": bridge_commitment["receipt_sha256"],
            "wdm_projection_path": "wdm-projection.json",
            "wdm_projection_sha256": projection_commitment["sha256"],
            "toolchain": toolchain,
            "extractor_config_sha256": CONFIG_SHA256,
            "static_only": True,
            "execution_authorized": False,
        }
        receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        _write_new_file_at(temporary_fd, "receipt.json", receipt_bytes)
        if _toolchain_fingerprint(home) != toolchain:
            raise ValueError("registration toolchain changed during acquisition")
        os.fsync(temporary_fd)
        _require_directory_path_identity(output.parent, parent_fd, "registration output parent")
        _publish_directory_no_replace(parent_fd, temporary_name, output.name)
        os.fsync(parent_fd)
        published = True
        return {
            "registration_path": f"{output.name}/registration.json",
            "registration_sha256": cast(str, receipt["registration_sha256"]),
            "receipt_path": f"{output.name}/receipt.json",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        }
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name and not published:
            _remove_registration_staging(parent_fd, temporary_name)
        os.close(projection_parent_fd)
        os.close(source_bridge_fd)
        os.close(parent_fd)


def verify_windows_driver_registration_bundle(
    bundle_path: str | Path, *, ghidra_home: str | Path
) -> dict[str, object]:
    bundle = Path(bundle_path)
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody path
    bundle_fd = _open_directory_ancestry(bundle, "registration bundle")
    try:
        receipt = _obj(
            json.loads(
                _read_regular_file_at(
                    bundle_fd, "receipt.json", "registration receipt", 1024 * 1024
                ),
                object_pairs_hook=_unique,
            ),
            "registration receipt",
        )
        _validate_registration_receipt(receipt, _toolchain_fingerprint(home))
        return _verify_validated_registration_bundle(bundle, bundle_fd, home, receipt)
    finally:
        os.close(bundle_fd)


def _validate_registration_receipt(receipt: dict[str, Any], toolchain: dict[str, object]) -> None:
    _exact(
        receipt,
        {
            "schema_version",
            "producer",
            "registration_path",
            "registration_sha256",
            "entry_bridge_bundle",
            "entry_bridge_receipt_sha256",
            "wdm_projection_path",
            "wdm_projection_sha256",
            "toolchain",
            "extractor_config_sha256",
            "static_only",
            "execution_authorized",
        },
        "registration receipt",
    )
    if (
        receipt["schema_version"] != RECEIPT_VERSION
        or receipt["producer"] != PRODUCER
        or receipt["registration_path"] != "registration.json"
        or receipt["entry_bridge_bundle"] != "entry-bridge"
        or receipt["wdm_projection_path"] != "wdm-projection.json"
        or receipt["wdm_projection_sha256"] != PROJECTION_SHA256
        or receipt["extractor_config_sha256"] != CONFIG_SHA256
        or receipt["toolchain"] != toolchain
        or receipt["static_only"] is not True
        or receipt["execution_authorized"] is not False
    ):
        raise ValueError("registration receipt contract mismatch")
    _sha(receipt["registration_sha256"], "registration receipt artifact")
    _sha(receipt["entry_bridge_receipt_sha256"], "registration receipt entry bridge")
    _sha(receipt["wdm_projection_sha256"], "registration receipt WDM projection")


def _verify_validated_registration_bundle(
    bundle: Path, bundle_fd: int, home: Path, receipt: dict[str, Any]
) -> dict[str, object]:
    toolchain = _toolchain_fingerprint(home)
    retained_bridge = _relative_directory(bundle, receipt["entry_bridge_bundle"], "entry bridge")
    retained_bridge_fd = os.open(
        "entry-bridge", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=bundle_fd
    )
    try:
        bridge_receipt_bytes = _read_regular_file_at(
            retained_bridge_fd, "receipt.json", "entry bridge receipt", 1024 * 1024
        )
        bridge_receipt = _obj(
            json.loads(bridge_receipt_bytes, object_pairs_hook=_unique), "entry bridge receipt"
        )
    finally:
        os.close(retained_bridge_fd)
    bridge_export = verify_windows_driver_entry_bridge_bundle(retained_bridge, ghidra_home=home)
    if bridge_export.get("schema_version") != BRIDGE_VERSION:
        raise ValueError("registration requires a retained v3 entry bridge")
    if hashlib.sha256(bridge_receipt_bytes).hexdigest() != receipt["entry_bridge_receipt_sha256"]:
        raise ValueError("registration entry bridge receipt mismatch")
    projection_bytes = _read_regular_file_at(
        bundle_fd, "wdm-projection.json", "WDM projection", 1024 * 1024
    )
    if hashlib.sha256(projection_bytes).hexdigest() != receipt["wdm_projection_sha256"]:
        raise ValueError("registration WDM projection SHA-256 mismatch")
    projection = validate_wdm_projection(json.loads(projection_bytes, object_pairs_hook=_unique))
    artifact_bytes = _read_regular_file_at(
        bundle_fd, "registration.json", "registration artifact", 16 * 1024 * 1024
    )
    if hashlib.sha256(artifact_bytes).hexdigest() != receipt["registration_sha256"]:
        raise ValueError("registration artifact SHA-256 mismatch")
    export = _validate(json.loads(artifact_bytes, object_pairs_hook=_unique))
    if canonical_registration_bytes(export) != artifact_bytes:
        raise ValueError("registration artifact is not canonical")
    binary = _relative_file(retained_bridge, bridge_receipt["binary_path"], "binary")
    pdb = _relative_file(retained_bridge, bridge_receipt["pdb_path"], "PDB")
    bridge_artifact = _relative_file(
        retained_bridge, bridge_receipt["entry_bridge_path"], "entry bridge artifact"
    )
    expected_bridge_commitment = {
        "schema_version": BRIDGE_VERSION,
        "artifact_path": "entry-bridge/entry-bridge.json",
        "artifact_sha256": _sha_file(bridge_artifact),
        "receipt_path": "entry-bridge/receipt.json",
        "receipt_sha256": _sha_file(retained_bridge / "receipt.json"),
        "driver_entry_rva": _obj(bridge_export["pdb_driver_entry"], "bridge DriverEntry")["rva"],
    }
    if export["entry_bridge"] != expected_bridge_commitment:
        raise ValueError("registration export entry bridge commitment mismatch")
    expected_projection_commitment = {
        "path": "wdm-projection.json",
        "sha256": PROJECTION_SHA256,
        "schema_version": PROJECTION_VERSION,
        "authority_scope": projection["authority_scope"],
        "exact_pdb_identity": False,
        "runtime_layout_exact": False,
    }
    if export["wdm_projection"] != expected_projection_commitment:
        raise ValueError("registration export WDM projection commitment mismatch")
    for key in (
        "driver_sha256",
        "pdb_sha256",
        "pdb_identity",
        "pe_codeview_identity",
        "architecture",
        "image_base",
        "tool",
    ):
        if export[key] != bridge_export[key]:
            raise ValueError("registration export differs from retained bridge identity")
    acquired = acquire_projected_registration_facts(
        binary,
        pdb,
        home,
        driver_entry_rva=_hex(
            _obj(bridge_export["pdb_driver_entry"], "bridge DriverEntry")["rva"],
            "DriverEntry RVA",
        ),
        records=pdb_function_records(binary, pdb),
    )
    replay_facts = {
        "schema_version": RAW_VERSION,
        **{
            key: bridge_export[key]
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
        "entry_bridge": export["entry_bridge"],
        "wdm_projection": export["wdm_projection"],
        **acquired,
    }
    if (
        canonical_registration_bytes(compile_windows_driver_registration(replay_facts))
        != artifact_bytes
    ):
        raise ValueError("registration structural proof replay mismatch")
    if _toolchain_fingerprint(home) != toolchain:
        raise ValueError("registration toolchain changed during verification")
    return export


def _validate(raw: object) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), "registration")
    fact_fields = {
        "driver_sha256",
        "pdb_sha256",
        "pdb_identity",
        "pe_codeview_identity",
        "architecture",
        "image_base",
        "tool",
        "entry_bridge",
        "wdm_projection",
        "driver_object_alias",
        "registration",
        "accounting",
    }
    claim_fields = {
        "outcome",
        "static_only",
        "runtime_layout_exact",
        "static_projected_registration_established",
        "runtime_registration_established",
        "transitive_finality",
        "selector_claims",
        "table_claims",
        "runtime_reachability_established",
        "unprivileged_reachability_established",
        "device_ioctl_attempts",
        "execution_authorized",
        "candidate_count",
        "candidate_established",
        "vulnerability_established",
        "exploitability_established",
        "novelty_established",
        "bounty_eligible",
        "weaponization",
        "proof_limit",
    }
    _exact(
        value,
        {"schema_version", "producer", "extractor_config_sha256"} | fact_fields | claim_fields,
        "registration",
    )
    if (
        value["schema_version"] != EXPORT_VERSION
        or value["producer"] != PRODUCER
        or value["extractor_config_sha256"] != CONFIG_SHA256
        or value["architecture"] != "x86_64"
    ):
        raise ValueError("registration schema/producer/config mismatch")
    _sha(value["driver_sha256"], "driver_sha256")
    _sha(value["pdb_sha256"], "pdb_sha256")
    _hex(value["image_base"], "image_base")
    if not isinstance(value["pdb_identity"], str) or not isinstance(
        value["pe_codeview_identity"], str
    ):
        raise ValueError("registration identities must be strings")
    tool = _obj(value["tool"], "tool")
    _exact(tool, {"name", "version"}, "tool")
    if tool["name"] != "ghidra" or not isinstance(tool["version"], str) or not tool["version"]:
        raise ValueError("registration tool mismatch")
    bridge = _obj(value["entry_bridge"], "entry bridge commitment")
    _exact(
        bridge,
        {
            "schema_version",
            "artifact_path",
            "artifact_sha256",
            "receipt_path",
            "receipt_sha256",
            "driver_entry_rva",
        },
        "entry bridge commitment",
    )
    if (
        bridge["schema_version"] != BRIDGE_VERSION
        or bridge["artifact_path"] != "entry-bridge/entry-bridge.json"
        or bridge["receipt_path"] != "entry-bridge/receipt.json"
    ):
        raise ValueError("registration entry bridge version mismatch")
    _sha(bridge["artifact_sha256"], "entry bridge artifact")
    _sha(bridge["receipt_sha256"], "entry bridge receipt")
    driver_entry = _hex(bridge["driver_entry_rva"], "DriverEntry RVA")
    projection = _obj(value["wdm_projection"], "WDM projection commitment")
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
        "WDM projection commitment",
    )
    if (
        projection["schema_version"] != PROJECTION_VERSION
        or projection["sha256"] != PROJECTION_SHA256
        or projection["path"] != "wdm-projection.json"
        or projection["exact_pdb_identity"] is not False
        or projection["runtime_layout_exact"] is not False
        or projection["authority_scope"] != AUTHORITY_SCOPE
    ):
        raise ValueError("registration WDM projection classification mismatch")
    _sha(projection["sha256"], "WDM projection")
    alias = _obj(value["driver_object_alias"], "DriverObject alias")
    _exact(
        alias,
        {
            "kind",
            "rva",
            "bytes",
            "sha256",
            "original_argument",
            "alias_register",
            "width",
            "unique_in_function",
            "entry_fallthrough_dominates_registration",
        },
        "DriverObject alias",
    )
    if (
        alias["kind"] != "windows-x64-native-rcx-to-rbx/v1"
        or alias["bytes"] != "488bd9"
        or alias["sha256"] != hashlib.sha256(bytes.fromhex("488bd9")).hexdigest()
        or alias["original_argument"] != "RCX"
        or alias["alias_register"] != "RBX"
        or alias["width"] != 8
        or alias["unique_in_function"] is not True
        or alias["entry_fallthrough_dominates_registration"] is not True
    ):
        raise ValueError("DriverObject alias proof mismatch")
    _hex(alias["rva"], "DriverObject alias RVA")
    registration = _obj(value["registration"], "registration fact")
    _exact(
        registration,
        {
            "owner_function_rva",
            "projected_path",
            "projected_offset",
            "store_width",
            "high_pcode_base_register",
            "store",
            "address_dependency_refs",
            "target_dependency_refs",
            "target",
            "unique_direct_assignment",
            "later_reachable_projected_stores",
            "no_later_reachable_exact_projected_store",
            "transitive_finality",
            "entry_reachable",
            "return_scope",
        },
        "registration fact",
    )
    if (
        _hex(registration["owner_function_rva"], "registration owner") != driver_entry
        or registration["projected_path"] != "_DRIVER_OBJECT.MajorFunction[14]"
        or registration["projected_offset"] != "0xe0"
        or registration["store_width"] != 8
        or registration["high_pcode_base_register"] != "RCX"
        or registration["unique_direct_assignment"] is not True
        or registration["later_reachable_projected_stores"] != 0
        or registration["no_later_reachable_exact_projected_store"] is not True
        or registration["transitive_finality"] is not False
        or registration["entry_reachable"] is not True
        or registration["return_scope"] != "reachable-terminal-return-without-status-classification"
    ):
        raise ValueError("registration assignment contract mismatch")
    store = _obj(registration["store"], "registration store")
    _exact(store, {"rva", "bytes", "sha256", "high_pcode_ref"}, "registration store")
    encoded_store = bytes.fromhex(cast(str, store["bytes"]))
    if (
        encoded_store != bytes.fromhex("488983e0000000")
        or store["sha256"] != hashlib.sha256(encoded_store).hexdigest()
    ):
        raise ValueError("registration native store mismatch")
    store_rva = _hex(store["rva"], "registration store RVA")
    store_ref = _ref(store["high_pcode_ref"], "registration store ref", {"STORE"})
    if (
        _hex(store_ref["function_rva"], "registration store ref function") != driver_entry
        or _hex(store_ref["instruction_rva"], "registration store ref instruction") != store_rva
    ):
        raise ValueError("registration store reference is not bound to DriverEntry/store")
    for name in ("address_dependency_refs", "target_dependency_refs"):
        refs = registration[name]
        if not isinstance(refs, list) or (name == "address_dependency_refs" and not refs):
            raise ValueError(f"registration {name} has an invalid bound")
        for raw_ref in refs:
            allowed = (
                {"COPY", "CAST", "INT_ADD", "PTRSUB"}
                if name == "address_dependency_refs"
                else {"COPY", "CAST", "PTRSUB"}
            )
            ref = _ref(raw_ref, name, allowed)
            if _hex(ref["function_rva"], f"{name}.function") != driver_entry:
                raise ValueError(f"registration {name} escapes DriverEntry")
            instruction_rva = _hex(ref["instruction_rva"], f"{name}.instruction")
            if name == "address_dependency_refs" and instruction_rva != store_rva:
                raise ValueError("registration address dependency is not bound to the store")
    target = _obj(registration["target"], "registration target")
    _exact(
        target,
        {
            "name",
            "record_kind",
            "segment",
            "offset",
            "rva",
            "target_lea_rva",
            "target_lea_bytes",
            "direct",
            "internal_executable",
            "non_thunk",
            "unique_exact_record",
        },
        "registration target",
    )
    lea = bytes.fromhex(cast(str, target["target_lea_bytes"]))
    lea_rva = _hex(target["target_lea_rva"], "target LEA RVA")
    target_rva = _hex(target["rva"], "registration target RVA")
    computed = (
        lea_rva + 7 + struct_unpack_i32(lea[3:])
        if len(lea) == 7 and lea[:3] == b"\x48\x8d\x05"
        else -1
    )
    if (
        target["name"] != "AfdDispatchDeviceControl"
        or target["record_kind"] not in {"procedure", "public-function"}
        or computed != target_rva
        or target["direct"] is not True
        or target["internal_executable"] is not True
        or target["non_thunk"] is not True
        or target["unique_exact_record"] is not True
    ):
        raise ValueError("registration target contract mismatch")
    alias_rva = _hex(alias["rva"], "DriverObject alias RVA")
    if not driver_entry <= alias_rva < lea_rva or lea_rva + len(lea) != store_rva:
        raise ValueError("registration native instruction ordering/topology mismatch")
    target_refs = cast(list[dict[str, object]], registration["target_dependency_refs"])
    if any(
        _hex(ref["instruction_rva"], "target dependency instruction") not in {lea_rva, store_rva}
        for ref in target_refs
    ):
        raise ValueError("registration target dependency is not bound to LEA/store")
    if (
        not isinstance(target["segment"], int)
        or target["segment"] <= 0
        or not isinstance(target["offset"], int)
        or target["offset"] < 0
    ):
        raise ValueError("registration target PDB coordinates mismatch")
    accounting = _obj(value["accounting"], "registration accounting")
    _exact(
        accounting,
        {
            "driver_entry_pcode_ops",
            "reachable_projected_stores",
            "matching_assignments",
            "later_reachable_projected_stores",
            "limits_hit",
        },
        "registration accounting",
    )
    if (
        not isinstance(accounting["driver_entry_pcode_ops"], int)
        or not 1 <= accounting["driver_entry_pcode_ops"] <= 16384
        or not isinstance(accounting["reachable_projected_stores"], int)
        or accounting["reachable_projected_stores"] < 1
        or accounting["matching_assignments"] != 1
        or accounting["later_reachable_projected_stores"] != 0
        or accounting["limits_hit"] != []
    ):
        raise ValueError("registration accounting mismatch")
    expected_claims = {
        "outcome": "projected-device-control-assignment-proven",
        "static_only": True,
        "runtime_layout_exact": False,
        "static_projected_registration_established": True,
        "runtime_registration_established": False,
        "transitive_finality": False,
        "selector_claims": 0,
        "table_claims": 0,
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
    if any(value.get(key) != expected for key, expected in expected_claims.items()):
        raise ValueError("registration claim boundary mismatch")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def struct_unpack_i32(raw: bytes) -> int:
    return cast(int, struct.unpack("<i", raw)[0])


def _ref(raw: object, label: str, allowed: set[str] | None) -> dict[str, object]:
    value = _obj(raw, label)
    _exact(value, {"function_rva", "instruction_rva", "pcode_order", "opcode"}, label)
    _hex(value["function_rva"], f"{label}.function_rva")
    _hex(value["instruction_rva"], f"{label}.instruction_rva")
    if not isinstance(value["pcode_order"], int) or value["pcode_order"] < 0:
        raise ValueError(f"{label} pcode order mismatch")
    if not isinstance(value["opcode"], str) or (
        allowed is not None and value["opcode"] not in allowed
    ):
        raise ValueError(f"{label} opcode mismatch")
    return cast(dict[str, object], value)


def _load_object(path: Path, label: str) -> dict[str, Any]:
    return _obj(
        json.loads(_read_regular_path(path, label, 1024 * 1024), object_pairs_hook=_unique),
        label,
    )


def _read_regular_path(path: Path, label: str, max_bytes: int) -> bytes:
    parent_fd = _open_directory_ancestry(path.parent, f"{label} parent")
    try:
        return _read_regular_file_at(parent_fd, path.name, label, max_bytes)
    finally:
        os.close(parent_fd)


def _relative_file(root: Path, raw: object, label: str) -> Path:
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute() or ".." in Path(raw).parts:
        raise ValueError(f"{label} path is invalid")
    path = root / raw
    root_fd = _open_directory_ancestry(root, f"{label} root")
    try:
        file_fd = _open_regular_file_at(root_fd, raw, label, 2 * 1024 * 1024 * 1024)
        os.close(file_fd)
    finally:
        os.close(root_fd)
    return path


def _relative_directory(root: Path, raw: object, label: str) -> Path:
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute() or ".." in Path(raw).parts:
        raise ValueError(f"{label} path is invalid")
    path = root / raw
    directory_fd = _open_directory_ancestry(path, label)
    os.close(directory_fd)
    return path


def _sha_file(path: Path) -> str:
    parent_fd = _open_directory_ancestry(path.parent, "SHA-256 file parent")
    try:
        fd = _open_regular_file_at(parent_fd, path.name, "SHA-256 file", 2 * 1024 * 1024 * 1024)
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        if "fd" in locals():
            os.close(fd)
        os.close(parent_fd)


def _obj(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _exact(value: dict[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ValueError(f"{label} has unknown or missing fields")


def _sha(raw: object, label: str) -> str:
    if (
        not isinstance(raw, str)
        or len(raw) != 64
        or any(ch not in "0123456789abcdef" for ch in raw)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return raw


def _hex(raw: object, label: str) -> int:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ValueError(f"{label} must be lowercase hexadecimal")
    try:
        value = int(raw, 16)
    except ValueError as exc:
        raise ValueError(f"{label} must be lowercase hexadecimal") from exc
    if raw != f"0x{value:x}" or value < 0:
        raise ValueError(f"{label} must be canonical hexadecimal")
    return value


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _open_relative_parent(root_fd: int, relative: str, label: str) -> tuple[int, str]:
    path = Path(relative)
    if not relative or path.is_absolute() or ".." in path.parts or path.name in {"", "."}:
        raise ValueError(f"{label} path is invalid")
    current = os.dup(root_fd)
    try:
        for part in path.parent.parts:
            if part in {"", "."}:
                continue
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current, path.name
    except OSError as exc:
        os.close(current)
        raise ValueError(f"{label} parent ancestry is not a no-follow directory path") from exc
    except BaseException:
        os.close(current)
        raise


def _open_regular_file_at(root_fd: int, relative: str, label: str, max_bytes: int) -> int:
    parent_fd, name = _open_relative_parent(root_fd, relative, label)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError(f"{label} must be a regular non-symlink file") from exc
    finally:
        os.close(parent_fd)
    observed = os.fstat(fd)
    if not stat.S_ISREG(observed.st_mode) or not 0 <= observed.st_size <= max_bytes:
        os.close(fd)
        raise ValueError(f"{label} must be a bounded regular non-symlink file")
    return fd


def _read_regular_file_at(root_fd: int, relative: str, label: str, max_bytes: int) -> bytes:
    fd = _open_regular_file_at(root_fd, relative, label, max_bytes)
    try:
        expected = os.fstat(fd).st_size
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > max_bytes:
                raise ValueError(f"{label} exceeds its byte bound")
        if consumed != expected or os.fstat(fd).st_size != expected:
            raise ValueError(f"{label} changed during bounded read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _snapshot_file_from_dirfd(
    source_root_fd: int,
    source_relative: str,
    destination_fd: int,
    destination_name: str,
    label: str,
    max_bytes: int,
) -> None:
    source_fd = _open_regular_file_at(source_root_fd, source_relative, label, max_bytes)
    output_fd = -1
    try:
        expected = os.fstat(source_fd).st_size
        output_fd = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=destination_fd,
        )
        consumed = 0
        while True:
            chunk = os.read(source_fd, min(1024 * 1024, max_bytes + 1 - consumed))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > max_bytes:
                raise ValueError(f"{label} exceeds its byte bound")
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                view = view[written:]
        if consumed != expected or os.fstat(source_fd).st_size != expected:
            raise ValueError(f"{label} changed during snapshot")
        os.fsync(output_fd)
    except BaseException:
        if output_fd >= 0:
            os.close(output_fd)
            output_fd = -1
        with suppress(FileNotFoundError):
            os.unlink(  # foxguard: ignore[py/no-path-traversal]
                destination_name, dir_fd=destination_fd
            )
        raise
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        os.close(source_fd)


def _snapshot_v3_bridge_bundle(source_fd: int, staging_fd: int) -> None:
    """Snapshot only the strict v3 bridge file topology through no-follow dirfds."""
    receipt = _obj(
        json.loads(
            _read_regular_file_at(source_fd, "receipt.json", "entry bridge receipt", 1024 * 1024),
            object_pairs_hook=_unique,
        ),
        "entry bridge receipt",
    )
    if receipt.get("schema_version") != "0verse.windows-driver-entry-bridge-receipt/v3":
        raise ValueError("registration requires a v3 entry bridge receipt")
    os.mkdir("entry-bridge", 0o700, dir_fd=staging_fd)
    bridge_fd = os.open(
        "entry-bridge", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging_fd
    )
    try:
        paths = {
            "receipt.json",
            cast(str, receipt.get("binary_path")),
            cast(str, receipt.get("pdb_path")),
            cast(str, receipt.get("entry_bridge_path")),
        }
        authority = _obj(receipt.get("abi_authority"), "entry bridge ABI authority")
        if authority.get("bundle_path") != "abi-authority":
            raise ValueError("entry bridge ABI authority path mismatch")
        paths.update(
            {
                "abi-authority/manifest.json",
                "abi-authority/x64-calling-convention.md",
                "abi-authority/nc-wdm-driver_initialize.md",
            }
        )
        if receipt.get("public_pdb_receipt_sha256") is not None:
            pdb_path = Path(cast(str, receipt.get("pdb_path")))
            paths.add((pdb_path.parent / "receipt.json").as_posix())
        for relative in sorted(paths):
            if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("entry bridge retained path is invalid")
            destination_fd = _ensure_relative_directories(bridge_fd, Path(relative).parent.parts)
            try:
                _snapshot_file_from_dirfd(
                    source_fd,
                    relative,
                    destination_fd,
                    Path(relative).name,
                    "entry bridge retained file",
                    2 * 1024 * 1024 * 1024,
                )
            finally:
                if destination_fd != bridge_fd:
                    os.close(destination_fd)
    finally:
        os.close(bridge_fd)


def _ensure_relative_directories(root_fd: int, parts: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    for part in parts:
        if part in {"", ".", ".."}:
            continue
        with suppress(FileExistsError):
            os.mkdir(part, 0o700, dir_fd=current)
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
        os.close(current)
        current = child
    if not parts or parts == (".",):
        os.close(current)
        return root_fd
    return current


def _remove_registration_staging(parent_fd: int, name: str) -> None:
    directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        _remove_directory_contents(directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _remove_directory_contents(directory_fd: int) -> None:
    for name in os.listdir(  # foxguard: ignore[py/no-path-traversal]
        directory_fd
    ):
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                _remove_directory_contents(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(  # foxguard: ignore[py/no-path-traversal]
                name, dir_fd=directory_fd
            )
