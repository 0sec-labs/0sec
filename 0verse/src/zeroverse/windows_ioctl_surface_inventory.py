"""Custody-bound unsupported Windows IOCTL surface checkpoint.

Version 1 establishes and emits no registration, selector, table, helper-call,
or dispatch-surface facts. It never loads a driver, opens a device, issues an
IOCTL, or emits candidate/vulnerability claims.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from .pe_symbols import pdb_codeview_identity, pdb_functions, pe_codeview_identity
from .windows_ioctl_ghidra_export import _operation_ref
from .windows_public_pdb import PublicPdbReceipt, verify_public_pdb_receipt
from .windows_variant import (
    _anchored_working_directory,
    _create_staging_directory,
    _open_directory_ancestry,
    _publish_directory_no_replace,
    _require_directory_path_identity,
    _snapshot_file_at,
    _write_new_file_at,
)

RAW_VERSION = "0verse.windows-ioctl-surface-inventory-facts/v1"
EXPORT_VERSION = "0verse.windows-ioctl-surface-inventory/v1"
RECEIPT_VERSION = "0verse.windows-ioctl-surface-inventory-receipt/v1"
PRODUCER = "zeroverse.windows-ioctl-surface-inventory/v1"
EXTRACTOR_PROFILE = PRODUCER
_CONFIG = {
    "entry_source": "pe-address-of-entry-point",
    "major_function_index": 14,
    "max_codes": 128,
    "max_functions": 4096,
    "max_ops_per_function": 16384,
    "max_total_ops": 262144,
    "max_entry_thunks": 16,
    "semantic_admission": False,
}
EXTRACTOR_CONFIG_SHA256 = hashlib.sha256(
    json.dumps(_CONFIG, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
_CACHE_DOMAIN = b"0verse-windows-ioctl-surface-inventory-cache-v2\0"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RVA = re.compile(r"0x[0-9a-f]+")
_DRIVER_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.sys", re.I)
_WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_PROOF_LIMIT = (
    "Custody-bound unsupported checkpoint only. Version 1 establishes and emits no "
    "registration, selector, table, helper-call, IOCTL-root, handler, or dispatch-surface "
    "facts. It does not establish runtime or unprivileged reachability, semantic sink "
    "coverage, vulnerability, exploitability, novelty, causality, candidate status, or "
    "bounty eligibility."
)


def canonical_inventory_bytes(raw: object) -> bytes:
    inventory = _validate_inventory(raw)
    return (json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n").encode()


def compile_windows_ioctl_surface_inventory(raw: object) -> dict[str, object]:
    facts = _object(json.loads(json.dumps(raw)), "surface facts")
    if facts.get("schema_version") != RAW_VERSION:
        raise ValueError("unsupported Windows IOCTL surface fact schema")
    _exact(
        facts,
        {
            "schema_version",
            "driver_sha256",
            "pdb_sha256",
            "pdb_identity",
            "pe_codeview_identity",
            "architecture",
            "pointer_size",
            "image_base",
            "pe_entry_point_rva",
            "tool",
            "outcome",
            "entry",
            "registrations",
            "device_control",
            "accounting",
            "completeness",
            "unsupported",
        },
        "surface facts",
    )
    _sort_facts(facts)
    inventory: dict[str, object] = {
        "schema_version": EXPORT_VERSION,
        "producer": PRODUCER,
        "extractor_profile": EXTRACTOR_PROFILE,
        "extractor_config_sha256": EXTRACTOR_CONFIG_SHA256,
        **{
            name: facts[name]
            for name in (
                "driver_sha256",
                "pdb_sha256",
                "pdb_identity",
                "pe_codeview_identity",
                "architecture",
                "pointer_size",
                "image_base",
                "pe_entry_point_rva",
                "tool",
                "outcome",
                "entry",
                "registrations",
                "device_control",
                "accounting",
                "completeness",
                "unsupported",
            )
        },
        "static_only": True,
        "device_ioctl_attempts": 0,
        "execution_authorized": False,
        "capability_measure": False,
        "candidate_count": 0,
        "candidate_established": False,
        "vulnerability_established": False,
        "reachability_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "bounty_eligible": False,
        "automatic_disclosure": False,
        "weaponization": False,
        "proof_limit": _PROOF_LIMIT,
    }
    return _validate_inventory(inventory)


def produce_windows_ioctl_surface_inventory(
    binary_path: str | Path,
    pdb_path: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
    public_pdb_bundle: str | Path | None = None,
) -> dict[str, str]:
    """Atomically retain inputs, run the fixed analyzer, and publish an inventory."""
    binary = Path(os.path.abspath(binary_path))  # noqa: PTH100 - lexical custody path
    pdb = Path(os.path.abspath(pdb_path))  # noqa: PTH100 - lexical custody path
    destination = Path(os.path.abspath(output_dir))  # noqa: PTH100 - new path
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - lexical tool path
    binary_name = _driver_basename(binary.name)
    if Path(destination.name).name != destination.name or destination.name in {"", ".", ".."}:
        raise ValueError("surface inventory output basename is invalid")
    source_route = (
        verify_public_pdb_receipt(binary, Path(public_pdb_bundle))
        if public_pdb_bundle is not None
        else None
    )
    if source_route is not None and _lexical_absolute(pdb) != _lexical_absolute(
        source_route.artifact_path
    ):
        raise ValueError("positional PDB must be the verified public-route artifact")
    parent_fd = _open_directory_ancestry(destination.parent, "surface inventory output parent")
    temporary_name = ""
    temporary_fd = -1
    published = False
    try:
        _require_directory_path_identity(
            destination.parent, parent_fd, "surface inventory output parent"
        )
        temporary_name, temporary_fd = _create_staging_directory(
            parent_fd, f".{destination.name}.tmp-"
        )
        staging = destination.parent / temporary_name
        retained_binary = staging / binary_name
        binary_sha = _snapshot_file_at(
            binary, temporary_fd, binary_name, "driver", 512 * 1024 * 1024
        )
        retained_route: PublicPdbReceipt | None = None
        if source_route is None:
            retained_pdb = staging / "target.pdb"
            pdb_sha = _snapshot_file_at(
                pdb, temporary_fd, "target.pdb", "PDB", 2 * 1024 * 1024 * 1024
            )
            _require_exact_full_identity(retained_binary, retained_pdb)
        else:
            cas = staging / "public-pdb" / source_route.artifact_sha256
            os.mkdir("public-pdb", 0o700, dir_fd=temporary_fd)
            public_fd = os.open(
                "public-pdb",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=temporary_fd,
            )
            try:
                os.mkdir(source_route.artifact_sha256, 0o700, dir_fd=public_fd)
                cas_fd = os.open(
                    source_route.artifact_sha256,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=public_fd,
                )
                try:
                    retained_pdb = cas / "artifact"
                    pdb_sha = _snapshot_file_at(
                        source_route.artifact_path,
                        cas_fd,
                        "artifact",
                        "public PDB",
                        2 * 1024 * 1024 * 1024,
                    )
                    _snapshot_file_at(
                        source_route.bundle_path / "receipt.json",
                        cas_fd,
                        "receipt.json",
                        "public PDB receipt",
                        1024 * 1024,
                    )
                finally:
                    os.close(cas_fd)
            finally:
                os.close(public_fd)
            retained_route = verify_public_pdb_receipt(retained_binary, cas)
            _same_route(source_route, retained_route)
        before_binary = _file_identity(retained_binary)
        before_pdb = _file_identity(retained_pdb)
        with _anchored_working_directory(temporary_fd):
            facts = _acquire_surface_facts(
                Path(binary_name),
                Path(retained_pdb.relative_to(staging)),
                ghidra_home=home,
                public_pdb_bundle=(
                    Path(retained_route.bundle_path.relative_to(staging))
                    if retained_route
                    else None
                ),
            )
        if (
            _file_identity(retained_binary) != before_binary
            or _file_identity(retained_pdb) != before_pdb
        ):
            raise ValueError("surface inventory analyzer mutated retained PE/PDB inputs")
        post_route = (
            verify_public_pdb_receipt(retained_binary, retained_route.bundle_path)
            if retained_route is not None
            else None
        )
        if source_route is not None and retained_route is not None and post_route is not None:
            _same_route(source_route, retained_route)
            _same_route(retained_route, post_route)
        tool_version = _ghidra_version(home)
        inventory = compile_windows_ioctl_surface_inventory(facts)
        _bind_inventory_artifacts(inventory, retained_binary, retained_pdb)
        if inventory["tool"] != {"name": "ghidra", "version": tool_version}:
            raise ValueError("surface inventory tool artifact binding mismatch")
        inventory_bytes = canonical_inventory_bytes(inventory)
        inventory_sha = hashlib.sha256(inventory_bytes).hexdigest()
        _write_new_file_at(temporary_fd, "inventory.json", inventory_bytes)
        route_sha = post_route.receipt_sha256 if post_route else ""
        cache_key = hashlib.sha256(
            _CACHE_DOMAIN
            + b"\0".join(
                value.encode()
                for value in (
                    binary_sha,
                    pdb_sha,
                    route_sha,
                    inventory_sha,
                    EXTRACTOR_CONFIG_SHA256,
                    tool_version,
                    EXPORT_VERSION,
                    EXTRACTOR_PROFILE,
                )
            )
        ).hexdigest()
        receipt: dict[str, object] = {
            "schema_version": RECEIPT_VERSION,
            "producer": PRODUCER,
            "binary_path": retained_binary.name,
            "binary_sha256": binary_sha,
            "pdb": _receipt_pdb(retained_binary, retained_pdb, pdb_sha, post_route),
            "inventory_path": "inventory.json",
            "inventory_sha256": inventory_sha,
            "tool": "ghidra",
            "tool_version": tool_version,
            "extractor_profile": EXTRACTOR_PROFILE,
            "extractor_config_sha256": EXTRACTOR_CONFIG_SHA256,
            "cache_key": cache_key,
            "public_pdb": _route_record(post_route, staging) if post_route else None,
            "static_only": True,
            "execution_authorized": False,
        }
        receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        _write_new_file_at(temporary_fd, "receipt.json", receipt_bytes)
        os.fsync(temporary_fd)
        _require_directory_path_identity(
            destination.parent, parent_fd, "surface inventory output parent"
        )
        _publish_directory_no_replace(parent_fd, temporary_name, destination.name)
        os.fsync(parent_fd)
        published = True
        return {
            "inventory_path": f"{destination.name}/inventory.json",
            "inventory_sha256": inventory_sha,
            "receipt_path": f"{destination.name}/receipt.json",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        }
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name and not published:
            _remove_surface_staging_at(parent_fd, temporary_name, binary_name)
        os.close(parent_fd)


def verify_windows_ioctl_surface_inventory_bundle(
    bundle_path: str | Path,
) -> dict[str, object]:
    """Rehash and revalidate one retained inventory bundle."""
    bundle = Path(bundle_path)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("surface inventory bundle must be a regular directory")
    receipt_path = _relative_file(bundle, "receipt.json", "receipt")
    receipt = _object(json.loads(receipt_path.read_bytes(), object_pairs_hook=_unique), "receipt")
    _exact(
        receipt,
        {
            "schema_version",
            "producer",
            "binary_path",
            "binary_sha256",
            "pdb",
            "inventory_path",
            "inventory_sha256",
            "tool",
            "tool_version",
            "extractor_profile",
            "extractor_config_sha256",
            "cache_key",
            "public_pdb",
            "static_only",
            "execution_authorized",
        },
        "receipt",
    )
    if receipt["schema_version"] != RECEIPT_VERSION or receipt["producer"] != PRODUCER:
        raise ValueError("surface inventory receipt schema/producer mismatch")
    if (
        receipt["tool"] != "ghidra"
        or not isinstance(receipt["tool_version"], str)
        or not receipt["tool_version"]
        or receipt["extractor_profile"] != EXTRACTOR_PROFILE
        or receipt["extractor_config_sha256"] != EXTRACTOR_CONFIG_SHA256
        or receipt["static_only"] is not True
        or receipt["execution_authorized"] is not False
    ):
        raise ValueError("surface inventory receipt contract mismatch")
    binary = _relative_file(bundle, receipt["binary_path"], "binary")
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    if binary_sha != _sha(receipt["binary_sha256"], "binary_sha256"):
        raise ValueError("surface inventory binary SHA-256 mismatch")
    inventory_path = _relative_file(bundle, receipt["inventory_path"], "inventory")
    inventory_bytes = inventory_path.read_bytes()
    if hashlib.sha256(inventory_bytes).hexdigest() != _sha(
        receipt["inventory_sha256"], "inventory_sha256"
    ):
        raise ValueError("surface inventory SHA-256 mismatch")
    inventory_raw = json.loads(inventory_bytes, object_pairs_hook=_unique)
    inventory = _validate_inventory(inventory_raw)
    if canonical_inventory_bytes(inventory) != inventory_bytes:
        raise ValueError("surface inventory is not canonical")
    if inventory["tool"] != {"name": receipt["tool"], "version": receipt["tool_version"]}:
        raise ValueError("surface inventory receipt tool binding mismatch")
    pdb_record = _object(receipt["pdb"], "pdb")
    _exact(
        pdb_record,
        {
            "path",
            "sha256",
            "identity",
            "pe_route_codeview_identity",
            "public_route_bound",
        },
        "pdb",
    )
    pdb = _relative_file(bundle, pdb_record["path"], "pdb")
    pdb_sha = hashlib.sha256(pdb.read_bytes()).hexdigest()
    if pdb_sha != _sha(pdb_record["sha256"], "pdb.sha256"):
        raise ValueError("surface inventory PDB SHA-256 mismatch")
    public = receipt["public_pdb"]
    route_sha = ""
    route: PublicPdbReceipt | None = None
    if public is None:
        _require_exact_full_identity(binary, pdb)
        if pdb_record["public_route_bound"] is not False:
            raise ValueError("surface inventory exact PDB route flag mismatch")
    else:
        public_record = _object(public, "public_pdb")
        _exact(
            public_record,
            {
                "bundle_path",
                "receipt_sha256",
                "requested_url",
                "pe_guid",
                "pe_age",
                "pdb_guid",
                "pdb_age",
                "stripped",
                "exact_age_match",
            },
            "public_pdb",
        )
        route = verify_public_pdb_receipt(
            binary, _relative_directory(bundle, public_record["bundle_path"], "public_pdb")
        )
        expected = _route_record(route, bundle)
        if public_record != expected or pdb.resolve() != route.artifact_path.resolve():
            raise ValueError("surface inventory public-PDB binding mismatch")
        route_sha = route.receipt_sha256
        if pdb_record["public_route_bound"] is not True:
            raise ValueError("surface inventory public PDB route flag mismatch")
    _bind_inventory_artifacts(inventory, binary, pdb)
    expected_pdb_record = _receipt_pdb(binary, pdb, pdb_sha, route)
    if pdb_record != expected_pdb_record:
        raise ValueError("surface inventory receipt PDB identity binding mismatch")
    expected_cache = hashlib.sha256(
        _CACHE_DOMAIN
        + b"\0".join(
            value.encode()
            for value in (
                binary_sha,
                pdb_sha,
                route_sha,
                _sha(receipt["inventory_sha256"], "inventory_sha256"),
                EXTRACTOR_CONFIG_SHA256,
                str(receipt["tool_version"]),
                EXPORT_VERSION,
                EXTRACTOR_PROFILE,
            )
        )
    ).hexdigest()
    if receipt["cache_key"] != expected_cache:
        raise ValueError("surface inventory cache key mismatch")
    return inventory


def _validate_inventory(raw: object) -> dict[str, object]:
    value = _object(raw, "inventory")
    _exact(
        value,
        {
            "schema_version",
            "producer",
            "extractor_profile",
            "extractor_config_sha256",
            "driver_sha256",
            "pdb_sha256",
            "pdb_identity",
            "pe_codeview_identity",
            "architecture",
            "pointer_size",
            "image_base",
            "pe_entry_point_rva",
            "tool",
            "outcome",
            "entry",
            "registrations",
            "device_control",
            "accounting",
            "completeness",
            "unsupported",
            "static_only",
            "device_ioctl_attempts",
            "execution_authorized",
            "capability_measure",
            "candidate_count",
            "candidate_established",
            "vulnerability_established",
            "reachability_established",
            "exploitability_established",
            "novelty_established",
            "bounty_eligible",
            "automatic_disclosure",
            "weaponization",
            "proof_limit",
        },
        "inventory",
    )
    if value["schema_version"] != EXPORT_VERSION or value["producer"] != PRODUCER:
        raise ValueError("surface inventory schema/producer mismatch")
    if (
        value["extractor_profile"] != EXTRACTOR_PROFILE
        or value["extractor_config_sha256"] != EXTRACTOR_CONFIG_SHA256
    ):
        raise ValueError("surface inventory extractor contract mismatch")
    _sha(value["driver_sha256"], "driver_sha256")
    _sha(value["pdb_sha256"], "pdb_sha256")
    _pdb_identity(value["pdb_identity"], "pdb_identity")
    _pe_identity(value["pe_codeview_identity"], "pe_codeview_identity")
    if value["architecture"] not in {"x86", "x86_64", "arm64"}:
        raise ValueError("surface inventory architecture is invalid")
    expected_pointer = 4 if value["architecture"] == "x86" else 8
    if value["pointer_size"] != expected_pointer:
        raise ValueError("surface inventory architecture/pointer-size mismatch")
    _rva(value["image_base"], "image_base")
    _rva(value["pe_entry_point_rva"], "pe_entry_point_rva")
    tool = _object(value["tool"], "inventory.tool")
    _exact(tool, {"name", "version"}, "inventory.tool")
    if tool["name"] != "ghidra" or not isinstance(tool["version"], str) or not tool["version"]:
        raise ValueError("surface inventory tool contract mismatch")
    if value["outcome"] != "unsupported":
        raise ValueError("v1 surface inventory must remain unsupported")

    entry = _object(value["entry"], "entry")
    _exact(entry, {"function_rva", "function_name", "thunk_chain", "exact_function_entry"}, "entry")
    unresolved_entry = entry == {
        "function_rva": None,
        "function_name": None,
        "thunk_chain": [],
        "exact_function_entry": False,
    }
    resolved_entry = (
        isinstance(entry["function_rva"], str)
        and _rva(entry["function_rva"], "entry.function_rva")
        == _rva(value["pe_entry_point_rva"], "pe_entry_point_rva")
        and isinstance(entry["function_name"], str)
        and bool(entry["function_name"])
        and entry["thunk_chain"] == []
        and entry["exact_function_entry"] is True
    )
    if not unresolved_entry and not resolved_entry:
        raise ValueError("inventory entry must be unresolved or one exact non-thunk function")

    if _list(value["registrations"], "registrations", 0) != []:
        raise ValueError("v1 cannot claim a MajorFunction registration")
    device = _object(value["device_control"], "device_control")
    _exact(
        device,
        {
            "major_function_index",
            "registration_ref",
            "handler_rva",
            "handler_name",
            "ioctl_root",
            "selectors",
            "calls",
            "unresolved_edges",
            "dynamic_dispatch",
            "truncated",
        },
        "device_control",
    )
    if (
        device["major_function_index"] != 14
        or device["registration_ref"] is not None
        or device["handler_rva"] is not None
        or device["handler_name"] is not None
        or device["selectors"] != []
        or device["calls"] != []
        or device["dynamic_dispatch"] is not False
        or device["truncated"] is not False
    ):
        raise ValueError("v1 device-control surface must remain unclaimed")
    ioctl_root = _object(device["ioctl_root"], "device_control.ioctl_root")
    _exact(
        ioctl_root,
        {"source", "load_ref", "pdb_type_path", "width", "derivation_refs"},
        "device_control.ioctl_root",
    )
    if ioctl_root != {
        "source": "unresolved",
        "load_ref": None,
        "pdb_type_path": None,
        "width": None,
        "derivation_refs": [],
    }:
        raise ValueError("v1 cannot claim a resolved IOCTL root")

    unsupported = _list(value["unsupported"], "unsupported", 512)
    if not unsupported:
        raise ValueError("unsupported v1 inventory requires explicit reasons")
    for raw_reason in unsupported:
        reason = _object(raw_reason, "unsupported reason")
        _exact(reason, {"stage", "owner_rva", "ref", "reason_code", "detail"}, "unsupported reason")
        _rva(reason["owner_rva"], "unsupported.owner_rva")
        evidence = _evidence_ref(reason["ref"], "unsupported.ref")
        if evidence.get("kind") == "pe-header-field" and evidence["rva"] != value[
            "pe_entry_point_rva"
        ]:
            raise ValueError("unsupported PE-entry evidence cross-binding mismatch")
        if not all(
            isinstance(reason[name], str) and reason[name]
            for name in ("stage", "reason_code", "detail")
        ):
            raise ValueError("unsupported reason strings must be nonempty")
    fallback_reasons = [
        _object(reason, "unsupported reason")
        for reason in unsupported
        if _object(reason, "unsupported reason")["reason_code"]
        == "exact-pdb-entry-function-unavailable"
    ]
    if unresolved_entry:
        if len(fallback_reasons) != 1:
            raise ValueError("unresolved entry requires one exact PDB-entry fallback reason")
        fallback = fallback_reasons[0]
        if (
            fallback["stage"] != "entry-resolution"
            or fallback["owner_rva"] != value["pe_entry_point_rva"]
            or fallback["ref"]
            != {
                "kind": "pe-header-field",
                "artifact": "driver",
                "field": "AddressOfEntryPoint",
                "rva": value["pe_entry_point_rva"],
            }
        ):
            raise ValueError("PDB-entry fallback reason is not PE-entry cross-bound")
    elif fallback_reasons:
        raise ValueError("resolved entry forbids a PDB-entry fallback reason")
    if device["unresolved_edges"] != unsupported:
        raise ValueError("unsupported/unresolved-edge cross-binding mismatch")

    accounting = _object(value["accounting"], "accounting")
    _exact(
        accounting,
        {
            "functions_total",
            "functions_entry_reachable",
            "functions_decompiled",
            "operations_total",
            "registrations_observed",
            "selectors_observed",
            "table_entries_observed",
            "limits_hit",
        },
        "accounting",
    )
    for field, maximum in {
        "functions_total": 4096,
        "functions_entry_reachable": 4096,
        "functions_decompiled": 4096,
        "operations_total": 262144,
    }.items():
        _integer(accounting[field], f"accounting.{field}", 0, maximum)
    if (
        accounting["functions_entry_reachable"] > accounting["functions_total"]
        or accounting["functions_decompiled"] != accounting["functions_total"]
        or accounting["registrations_observed"] != 0
        or accounting["selectors_observed"] != 0
        or accounting["table_entries_observed"] != 0
        or accounting["limits_hit"] != []
    ):
        raise ValueError("surface inventory accounting cross-field mismatch")

    completeness = _object(value["completeness"], "completeness")
    _exact(
        completeness,
        {
            "entrypoint_resolved",
            "registration_complete",
            "ioctl_root_resolved",
            "selector_inventory_complete",
            "call_edges_complete",
            "table_extents_complete",
            "semantic_admission_allowed",
        },
        "completeness",
    )
    if any(observed is not False for observed in completeness.values()):
        raise ValueError("v1 unsupported inventory completeness must remain false")

    false_claims = {
        "static_only": True,
        "device_ioctl_attempts": 0,
        "execution_authorized": False,
        "capability_measure": False,
        "candidate_count": 0,
        "candidate_established": False,
        "vulnerability_established": False,
        "reachability_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "bounty_eligible": False,
        "automatic_disclosure": False,
        "weaponization": False,
    }
    if any(value.get(name) != expected for name, expected in false_claims.items()):
        raise ValueError("surface inventory claim boundary mismatch")
    if value["proof_limit"] != _PROOF_LIMIT:
        raise ValueError("surface inventory proof limit mismatch")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def _acquire_surface_facts(
    binary: Path,
    pdb: Path,
    *,
    ghidra_home: Path,
    public_pdb_bundle: Path | None,
) -> dict[str, object]:
    """Fixed Ghidra analyzer entry; no handler/RVA/allowlist caller inputs."""
    # The adapter is intentionally isolated so mock tests exercise the strict
    # compiler/custody boundary. Real acquisition emits only the unsupported
    # checkpoint; it establishes no registration, selector, table, helper-call,
    # IOCTL-root, handler, or dispatch-surface facts.
    return _acquire_surface_facts_ghidra(
        binary, pdb, ghidra_home=ghidra_home, public_pdb_bundle=public_pdb_bundle
    )


def _acquire_surface_facts_ghidra(
    binary: Path,
    pdb: Path,
    *,
    ghidra_home: Path,
    public_pdb_bundle: Path | None,
) -> dict[str, object]:
    """Acquire a custody-bound unsupported checkpoint without surface claims."""
    if public_pdb_bundle is None:
        _require_exact_full_identity(binary, pdb)
    else:
        route = verify_public_pdb_receipt(binary, public_pdb_bundle)
        if _lexical_absolute(route.artifact_path) != _lexical_absolute(pdb):
            raise ValueError("inventory PDB is not the verified public-route artifact")
    from .windows_ioctl_ghidra_export import (
        _bounded_functions,
        _complete_internal_surface,
        _pe_machine,
        _requested_ghidra_version,
    )

    requested = _requested_ghidra_version(ghidra_home)
    image_base, architecture, pointer_size = _pe_machine(binary)
    entry_rva = _pe_entry_rva(binary)
    _initialize_ghidra(ghidra_home, requested)
    if entry_rva not in pdb_functions(binary, pdb):
        return _unsupported_entry_checkpoint(
            binary,
            pdb,
            requested=requested,
            image_base=image_base,
            architecture=architecture,
            pointer_size=pointer_size,
            entry_rva=entry_rva,
        )
    import pyghidra
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    with tempfile.TemporaryDirectory(prefix="zeroverse-surface-") as temporary:
        target = Path(temporary) / "target.sys"
        shutil.copyfile(binary, target)
        shutil.copyfile(pdb, Path(temporary) / "target.pdb")
        with pyghidra.open_program(str(target)) as flat:
            program = flat.getCurrentProgram()
            monitor = ConsoleTaskMonitor()
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            manager = program.getFunctionManager()
            functions = _bounded_functions(manager.getFunctions(True))
            surface = _complete_internal_surface(decompiler, functions, monitor)
            absolute_entry = image_base + entry_rva
            entry_function = manager.getFunctionAt(
                program.getAddressFactory().getDefaultAddressSpace().getAddress(absolute_entry)
            )
            if entry_function is None or bool(entry_function.isThunk()):
                raise ValueError("PE entry point is not one exact non-thunk internal function")
            entry_address = int(entry_function.getEntryPoint().getOffset())
            if entry_address != absolute_entry or entry_address not in surface:
                raise ValueError("PE entry function is not exact in the decompiled surface")
            entry_ops = surface[entry_address][3]
            if not entry_ops:
                raise ValueError("PE entry function has no High-P-Code evidence")
            reason = _unsupported(
                "surface-admission",
                entry_rva,
                _operation_ref(entry_ops[0], entry_function, image_base),
                "exact-surface-proof-unavailable",
                (
                    "v1 does not authorize MajorFunction alias uniqueness, IOCTL-root, "
                    "selector-polarity, or exhaustive table claims"
                ),
            )
            pe_identity = pe_codeview_identity(binary)
            pdb_identity = pdb_codeview_identity(pdb)
            if pe_identity is None or pdb_identity is None:
                raise ValueError("inventory identities are unavailable")
            return {
                "schema_version": RAW_VERSION,
                "driver_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "pdb_sha256": hashlib.sha256(pdb.read_bytes()).hexdigest(),
                "pdb_identity": (
                    f"{pdb_identity[0]}:{pdb_identity[1]}:"
                    f"{'stripped' if pdb_identity[2] else 'full'}"
                ),
                "pe_codeview_identity": f"{pe_identity[0]}:{pe_identity[1]}:{pe_identity[2]}",
                "architecture": architecture,
                "pointer_size": pointer_size,
                "image_base": f"0x{image_base:x}",
                "pe_entry_point_rva": f"0x{entry_rva:x}",
                "tool": {"name": "ghidra", "version": requested},
                "outcome": "unsupported",
                "entry": {
                    "function_rva": f"0x{entry_rva:x}",
                    "function_name": str(entry_function.getName()),
                    "thunk_chain": [],
                    "exact_function_entry": True,
                },
                "registrations": [],
                "device_control": {
                    "major_function_index": 14,
                    "registration_ref": None,
                    "handler_rva": None,
                    "handler_name": None,
                    "ioctl_root": {
                        "source": "unresolved",
                        "load_ref": None,
                        "pdb_type_path": None,
                        "width": None,
                        "derivation_refs": [],
                    },
                    "selectors": [],
                    "calls": [],
                    "unresolved_edges": [reason],
                    "dynamic_dispatch": False,
                    "truncated": False,
                },
                "accounting": {
                    "functions_total": len(surface),
                    "functions_entry_reachable": 1,
                    "functions_decompiled": len(surface),
                    "operations_total": sum(len(row[3]) for row in surface.values()),
                    "registrations_observed": 0,
                    "selectors_observed": 0,
                    "table_entries_observed": 0,
                    "limits_hit": [],
                },
                "completeness": {
                    "entrypoint_resolved": False,
                    "registration_complete": False,
                    "ioctl_root_resolved": False,
                    "selector_inventory_complete": False,
                    "call_edges_complete": False,
                    "table_extents_complete": False,
                    "semantic_admission_allowed": False,
                },
                "unsupported": [reason],
            }


def _initialize_ghidra(ghidra_home: Path, requested: str) -> None:
    try:
        import pyghidra
    except ImportError as exc:
        raise RuntimeError("PyGhidra is unavailable for surface inventory") from exc
    from .windows_ioctl_ghidra_export import _require_active_ghidra_version

    pyghidra.start(install_dir=ghidra_home)
    from ghidra.framework import Application

    _require_active_ghidra_version(str(Application.getApplicationVersion()), requested)


def _unsupported_entry_checkpoint(
    binary: Path,
    pdb: Path,
    *,
    requested: str,
    image_base: int,
    architecture: str,
    pointer_size: int,
    entry_rva: int,
) -> dict[str, object]:
    pe_identity = pe_codeview_identity(binary)
    pdb_identity = pdb_codeview_identity(pdb)
    if pe_identity is None or pdb_identity is None:
        raise ValueError("inventory identities are unavailable")
    reason = _unsupported(
        "entry-resolution",
        entry_rva,
        {
            "kind": "pe-header-field",
            "artifact": "driver",
            "field": "AddressOfEntryPoint",
            "rva": f"0x{entry_rva:x}",
        },
        "exact-pdb-entry-function-unavailable",
        "the PDB does not provide one exact function at the PE entry RVA",
    )
    return {
        "schema_version": RAW_VERSION,
        "driver_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "pdb_sha256": hashlib.sha256(pdb.read_bytes()).hexdigest(),
        "pdb_identity": (
            f"{pdb_identity[0]}:{pdb_identity[1]}:"
            f"{'stripped' if pdb_identity[2] else 'full'}"
        ),
        "pe_codeview_identity": f"{pe_identity[0]}:{pe_identity[1]}:{pe_identity[2]}",
        "architecture": architecture,
        "pointer_size": pointer_size,
        "image_base": f"0x{image_base:x}",
        "pe_entry_point_rva": f"0x{entry_rva:x}",
        "tool": {"name": "ghidra", "version": requested},
        "outcome": "unsupported",
        "entry": {
            "function_rva": None,
            "function_name": None,
            "thunk_chain": [],
            "exact_function_entry": False,
        },
        "registrations": [],
        "device_control": {
            "major_function_index": 14,
            "registration_ref": None,
            "handler_rva": None,
            "handler_name": None,
            "ioctl_root": {
                "source": "unresolved",
                "load_ref": None,
                "pdb_type_path": None,
                "width": None,
                "derivation_refs": [],
            },
            "selectors": [],
            "calls": [],
            "unresolved_edges": [reason],
            "dynamic_dispatch": False,
            "truncated": False,
        },
        "accounting": {
            "functions_total": 0,
            "functions_entry_reachable": 0,
            "functions_decompiled": 0,
            "operations_total": 0,
            "registrations_observed": 0,
            "selectors_observed": 0,
            "table_entries_observed": 0,
            "limits_hit": [],
        },
        "completeness": {
            "entrypoint_resolved": False,
            "registration_complete": False,
            "ioctl_root_resolved": False,
            "selector_inventory_complete": False,
            "call_edges_complete": False,
            "table_extents_complete": False,
            "semantic_admission_allowed": False,
        },
        "unsupported": [reason],
    }
def _unsupported(stage: str, owner: int, ref: object, code: str, detail: str) -> dict[str, object]:
    return {
        "stage": stage,
        "owner_rva": f"0x{owner:x}",
        "ref": ref,
        "reason_code": code,
        "detail": detail,
    }


def _sort_facts(facts: dict[str, Any]) -> None:
    registrations = _list(facts.get("registrations"), "registrations", 32)
    registrations.sort(
        key=lambda row: (
            str(_object(row, "registration").get("owner_function_rva", "")),
            str(_object(row, "registration").get("store_ref", "")),
        )
    )
    device = _object(facts.get("device_control"), "device_control")
    selectors = _list(device.get("selectors"), "selectors", 128)
    for selector_raw in selectors:
        selector = _object(selector_raw, "selector")
        if isinstance(selector.get("entries"), list):
            cast(list[dict[str, object]], selector["entries"]).sort(
                key=lambda row: (
                    cast(int, row.get("index", -1)),
                    cast(int, row.get("ioctl_code", -1)),
                )
            )
    selectors.sort(
        key=lambda row: (
            str(_object(row, "selector").get("owner_rva", "")),
            str(_object(row, "selector").get("kind", "")),
        )
    )
    for name in ("calls", "unresolved_edges"):
        values = _list(device.get(name), f"device_control.{name}", 512)
        values.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
    unsupported = _list(facts.get("unsupported"), "unsupported", 512)
    unsupported.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))


def _require_exact_full_identity(binary: Path, pdb: Path) -> None:
    pe = pe_codeview_identity(binary)
    symbols = pdb_codeview_identity(pdb)
    if pe is None or symbols is None or symbols[2] or pe[:2] != symbols[:2]:
        raise ValueError("surface inventory exact lane requires a full matching PDB")


def _same_route(left: PublicPdbReceipt, right: PublicPdbReceipt) -> None:
    fields = (
        "artifact_sha256",
        "artifact_size_bytes",
        "receipt_sha256",
        "requested_url",
        "pe_guid",
        "pe_age",
        "pdb_guid",
        "pdb_age",
        "exact_age_match",
    )
    if tuple(getattr(left, name) for name in fields) != tuple(
        getattr(right, name) for name in fields
    ):
        raise ValueError("public-PDB route changed during inventory")


def _receipt_pdb(
    binary: Path, pdb: Path, digest: str, route: PublicPdbReceipt | None
) -> dict[str, object]:
    pe = pe_codeview_identity(binary)
    symbols = pdb_codeview_identity(pdb)
    if pe is None or symbols is None:
        raise ValueError("receipt PE/PDB identity is unavailable")
    return {
        "path": str(pdb.relative_to(binary.parent)),
        "sha256": digest,
        "identity": {"guid": symbols[0], "age": symbols[1], "stripped": symbols[2]},
        "pe_route_codeview_identity": f"{pe[0]}:{pe[1]}:{pe[2]}",
        "public_route_bound": route is not None,
    }


def _route_record(route: PublicPdbReceipt, staging: Path) -> dict[str, object]:
    return {
        "bundle_path": route.bundle_path.relative_to(staging).as_posix(),
        "receipt_sha256": route.receipt_sha256,
        "requested_url": route.requested_url,
        "pe_guid": route.pe_guid,
        "pe_age": route.pe_age,
        "pdb_guid": route.pdb_guid,
        "pdb_age": route.pdb_age,
        "stripped": True,
        "exact_age_match": route.exact_age_match,
    }


def _file_identity(path: Path) -> tuple[int, int, int, int, str]:
    observed = path.stat(follow_symlinks=False)
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_size,
        observed.st_mtime_ns,
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def _pe_entry_rva(path: Path) -> int:
    data = path.read_bytes()
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe : pe + 4] != b"PE\0\0":
            raise ValueError
        return cast(int, struct.unpack_from("<I", data, pe + 24 + 16)[0])
    except (IndexError, struct.error, ValueError) as exc:
        raise ValueError("PE AddressOfEntryPoint is unavailable") from exc


def _ghidra_version(home: Path) -> str:
    for path in (home / "Ghidra" / "application.properties", home / "application.properties"):
        if path.is_file() and not path.is_symlink():
            for line in path.read_text(encoding="utf-8").splitlines():
                key, separator, value = line.partition("=")
                if separator and key.strip() == "application.version" and value.strip():
                    return value.strip()
    raise ValueError("Ghidra application.version is unavailable")


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _list(raw: object, label: str, maximum: int) -> list[Any]:
    if not isinstance(raw, list) or len(raw) > maximum:
        raise ValueError(f"{label} must be a bounded array")
    return raw


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} has unknown or missing fields")


def _sha(raw: object, label: str) -> str:
    if not isinstance(raw, str) or _SHA256.fullmatch(raw) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return raw


def _rva(raw: object, label: str) -> int:
    if not isinstance(raw, str) or _RVA.fullmatch(raw) is None:
        raise ValueError(f"{label} must be a canonical lowercase RVA")
    return int(raw, 16)


def _integer(raw: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return raw


def _pdb_identity(raw: object, label: str) -> None:
    if not isinstance(raw, str):
        raise ValueError(f"{label} must be a PDB identity string")
    parts = raw.split(":")
    if (
        len(parts) != 3
        or not parts[0]
        or not parts[1].isdigit()
        or int(parts[1]) < 0
        or parts[2] not in {"full", "stripped"}
    ):
        raise ValueError(f"{label} must be GUID:age:full-or-stripped")


def _pe_identity(raw: object, label: str) -> None:
    if not isinstance(raw, str):
        raise ValueError(f"{label} must be a PE CodeView identity string")
    guid, separator, rest = raw.partition(":")
    age, separator2, pdb_name = rest.partition(":")
    if not guid or not separator or not separator2 or not age.isdigit() or not pdb_name:
        raise ValueError(f"{label} must be GUID:age:pdb-name")


def _proof_ref(raw: object, label: str, opcode: str | None = None) -> dict[str, object]:
    ref = _object(raw, label)
    _exact(ref, {"function_rva", "instruction_rva", "pcode_order", "opcode"}, label)
    _rva(ref["function_rva"], f"{label}.function_rva")
    _rva(ref["instruction_rva"], f"{label}.instruction_rva")
    _integer(ref["pcode_order"], f"{label}.pcode_order", 0, 65535)
    if not isinstance(ref["opcode"], str) or not ref["opcode"]:
        raise ValueError(f"{label}.opcode must be nonempty")
    if opcode is not None and ref["opcode"] != opcode:
        raise ValueError(f"{label} must reference {opcode}")
    return cast(dict[str, object], ref)


def _evidence_ref(raw: object, label: str) -> dict[str, object]:
    ref = _object(raw, label)
    if ref.get("kind") != "pe-header-field":
        return _proof_ref(ref, label)
    _exact(ref, {"kind", "artifact", "field", "rva"}, label)
    if ref["artifact"] != "driver" or ref["field"] != "AddressOfEntryPoint":
        raise ValueError(f"{label} PE-header evidence is invalid")
    _rva(ref["rva"], f"{label}.rva")
    return cast(dict[str, object], ref)


def _bind_inventory_artifacts(inventory: dict[str, object], binary: Path, pdb: Path) -> None:
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    pdb_sha = hashlib.sha256(pdb.read_bytes()).hexdigest()
    pe = pe_codeview_identity(binary)
    symbols = pdb_codeview_identity(pdb)
    if pe is None or symbols is None:
        raise ValueError("inventory PE/PDB identity is unavailable")
    expected = {
        "driver_sha256": binary_sha,
        "pdb_sha256": pdb_sha,
        "pdb_identity": f"{symbols[0]}:{symbols[1]}:{'stripped' if symbols[2] else 'full'}",
        "pe_codeview_identity": f"{pe[0]}:{pe[1]}:{pe[2]}",
        "pe_entry_point_rva": f"0x{_pe_entry_rva(binary):x}",
    }
    for field, observed in expected.items():
        if inventory.get(field) != observed:
            raise ValueError(f"surface inventory {field} artifact binding mismatch")
    entry = _object(inventory.get("entry"), "inventory.entry")
    has_pdb_entry = _pe_entry_rva(binary) in pdb_functions(binary, pdb)
    unresolved_entry = entry.get("exact_function_entry") is False
    if unresolved_entry == has_pdb_entry:
        raise ValueError("surface inventory PDB-entry resolution state mismatch")


def _driver_basename(raw: str) -> str:
    if (
        Path(raw).name != raw
        or "\\" in raw
        or _DRIVER_BASENAME.fullmatch(raw) is None
        or raw[:-4].rstrip(" .").casefold() in _WINDOWS_RESERVED
    ):
        raise ValueError("driver must have a safe non-reserved .sys component basename")
    return raw


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))  # noqa: PTH100 - compare custody names, not targets


def _remove_surface_staging_at(parent_fd: int, name: str, binary_name: str) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        directory_fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        for filename in ("inventory.json", "receipt.json", "target.pdb", binary_name):
            with suppress(FileNotFoundError):
                os.unlink(  # foxguard: ignore[py/no-path-traversal]
                    filename, dir_fd=directory_fd
                )
        with suppress(FileNotFoundError):
            public_fd = os.open("public-pdb", flags, dir_fd=directory_fd)
            try:
                entries = os.listdir(  # noqa: PTH208  # foxguard: ignore[py/no-path-traversal]
                    public_fd
                )
                if len(entries) != 1 or _SHA256.fullmatch(entries[0]) is None:
                    raise ValueError("staged public-PDB CAS directory is malformed")
                cas_fd = os.open(entries[0], flags, dir_fd=public_fd)
                try:
                    for filename in ("artifact", "receipt.json"):
                        with suppress(FileNotFoundError):
                            os.unlink(  # foxguard: ignore[py/no-path-traversal]
                                filename, dir_fd=cas_fd
                            )
                finally:
                    os.close(cas_fd)
                os.rmdir(entries[0], dir_fd=public_fd)
            finally:
                os.close(public_fd)
            os.rmdir("public-pdb", dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _relative_file(base: Path, raw: object, label: str) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise ValueError(f"{label} path is invalid")
    relative = Path(raw)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"{label} path must be normalized and relative")
    path = base / relative
    cursor = base
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"{label} path traverses a symlink")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    if not path.resolve().is_relative_to(base.resolve()):
        raise ValueError(f"{label} escapes the inventory bundle")
    return path


def _relative_directory(base: Path, raw: object, label: str) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise ValueError(f"{label} path is invalid")
    relative = Path(raw)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"{label} path must be normalized and relative")
    path = base / relative
    cursor = base
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"{label} path traverses a symlink")
    if path.is_symlink() or not path.is_dir() or not path.resolve().is_relative_to(base.resolve()):
        raise ValueError(f"{label} must be a contained non-symlink directory")
    return path


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result
