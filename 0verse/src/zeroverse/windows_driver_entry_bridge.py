"""Static, custody-bound proof of a PE entry wrapper to PDB DriverEntry bridge.

This profile proves one deliberately narrow structural fact.  It never admits
registration, selector, dispatch-table, candidate, vulnerability, or runtime
reachability claims and performs no driver or device execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from .pe_symbols import (
    pdb_codeview_identity,
    pdb_function_records,
    pe_codeview_identity,
)
from .windows_ioctl_surface_inventory import (
    _driver_basename,
    _ghidra_version,
    _pe_entry_rva,
    _require_exact_full_identity,
)
from .windows_public_pdb import PublicPdbReceipt, verify_public_pdb_receipt
from .windows_variant import (
    _anchored_working_directory,
    _create_staging_directory,
    _open_directory_ancestry,
    _publish_directory_no_replace,
    _relative_directory,
    _relative_file,
    _require_directory_path_identity,
    _snapshot_file_at,
    _write_new_file_at,
)

RAW_VERSION = "0verse.windows-driver-entry-bridge-facts/v2"
EXPORT_VERSION = "0verse.windows-driver-entry-bridge/v2"
RECEIPT_VERSION = "0verse.windows-driver-entry-bridge-receipt/v2"
PRODUCER = "zeroverse.windows-driver-entry-bridge/v2"
RAW_VERSION_V3 = "0verse.windows-driver-entry-bridge-facts/v3"
EXPORT_VERSION_V3 = "0verse.windows-driver-entry-bridge/v3"
RECEIPT_VERSION_V3 = "0verse.windows-driver-entry-bridge-receipt/v3"
PRODUCER_V3 = "zeroverse.windows-driver-entry-bridge/v3"
ABI_MANIFEST_SHA256 = "76f04d8acc824c87d2be6851b0a0cb57404ecce3d69c9f2b3a9a06d7b553415e"
CONFIG = {
    "architecture": "x86_64",
    "wrapper_source": "pe-address-of-entry-point",
    "callee_source": "structural-candidate-then-unique-function-flagged-pdb-corroboration",
    "allowed_argument_path_ops": ["CAST", "COPY"],
    "preserved_argument_registers": ["RCX", "RDX"],
    "max_wrapper_pcode_ops": 4096,
    "max_control_transfers": 64,
    "dominance": "all-return-blocks",
    "return_value": "bridge-call-output-via-width-preserving-copy-cast",
}
CONFIG_SHA256 = hashlib.sha256(
    json.dumps(CONFIG, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
CONFIG_V3 = {
    **CONFIG,
    "abi_manifest_sha256": ABI_MANIFEST_SHA256,
    "return_channel_fallback": "exact-afd-x64-native-suffix/v1",
    "max_native_suffix_instructions": 16,
    "max_native_suffix_bytes": 64,
}
CONFIG_SHA256_V3 = hashlib.sha256(
    json.dumps(CONFIG_V3, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
_PROOF_LIMIT = (
    "Static entry-bridge fact only. This profile proves the PE entry wrapper calls the exact "
    "function-flagged PDB DriverEntry record while preserving original RCX/RDX, and that the "
    "bridge dominates wrapper returns with return-value propagation. It establishes no driver "
    "registration, selector, table, handler, IOCTL surface, runtime or unprivileged reachability, "
    "candidate, vulnerability, exploitability, novelty, bounty eligibility, or weaponization."
)


def compile_windows_driver_entry_bridge(raw: object) -> dict[str, object]:
    facts = _obj(json.loads(json.dumps(raw)), "entry bridge facts")
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
            "pe_entry_point_rva",
            "tool",
            "pdb_driver_entry",
            "wrapper",
            "accounting",
        },
        "entry bridge facts",
    )
    export: dict[str, object] = {
        "schema_version": EXPORT_VERSION,
        "producer": PRODUCER,
        "extractor_config_sha256": CONFIG_SHA256,
        **{key: facts[key] for key in facts if key != "schema_version"},
        "outcome": "entry-bridge-proven",
        "static_only": True,
        "execution_authorized": False,
        "device_ioctl_attempts": 0,
        "registration_claims": 0,
        "selector_claims": 0,
        "table_claims": 0,
        "candidate_count": 0,
        "candidate_established": False,
        "vulnerability_established": False,
        "runtime_reachability_established": False,
        "unprivileged_reachability_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "bounty_eligible": False,
        "weaponization": False,
        "proof_limit": _PROOF_LIMIT,
    }
    return _validate(export)


def canonical_bridge_bytes(raw: object) -> bytes:
    return (json.dumps(_validate(raw), sort_keys=True, separators=(",", ":")) + "\n").encode()


def compile_windows_driver_entry_bridge_v3(raw: object) -> dict[str, object]:
    facts = _obj(json.loads(json.dumps(raw)), "v3 entry bridge facts")
    if facts.get("schema_version") != RAW_VERSION_V3:
        raise ValueError("unsupported v3 entry bridge fact schema")
    authority = facts.pop("abi_authority", None)
    wrapper = _obj(facts["wrapper"], "v3 wrapper")
    return_channel = wrapper.pop("return_channel", None)
    facts["schema_version"] = RAW_VERSION
    base = compile_windows_driver_entry_bridge(facts)
    base["schema_version"] = EXPORT_VERSION_V3
    base["producer"] = PRODUCER_V3
    base["extractor_config_sha256"] = CONFIG_SHA256_V3
    base["abi_authority"] = authority
    _obj(base["wrapper"], "v3 wrapper")["return_channel"] = return_channel
    return _validate_v3(base)


def canonical_bridge_v3_bytes(raw: object) -> bytes:
    return (json.dumps(_validate_v3(raw), sort_keys=True, separators=(",", ":")) + "\n").encode()


def _validate_v3(raw: object) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), "v3 entry bridge")
    if (
        value.get("schema_version") != EXPORT_VERSION_V3
        or value.get("producer") != PRODUCER_V3
        or value.get("extractor_config_sha256") != CONFIG_SHA256_V3
    ):
        raise ValueError("v3 entry bridge schema/producer/config mismatch")
    authority = _obj(value.pop("abi_authority", None), "abi_authority")
    _exact(authority, {"manifest_path", "manifest_sha256", "sources"}, "abi_authority")
    if (
        authority["manifest_path"] != "docs/evidence/windows-driver-entry-abi/manifest.json"
        or authority["manifest_sha256"] != ABI_MANIFEST_SHA256
        or authority["sources"]
        != [
            "043986cc9256b62c29b4b18fba978cfece03da69e8680054d210d40b625d89c0",
            "aa853c41b56d1f299e370ea09c48c335bc98ec964f378374774d7288731c947d",
        ]
    ):
        raise ValueError("v3 ABI authority binding mismatch")
    wrapper = _obj(value["wrapper"], "v3 wrapper")
    return_channel = _obj(wrapper.pop("return_channel", None), "return_channel")
    _validate_return_channel(return_channel, wrapper)
    value["schema_version"] = EXPORT_VERSION
    value["producer"] = PRODUCER
    value["extractor_config_sha256"] = CONFIG_SHA256
    _validate(value)
    value["schema_version"] = EXPORT_VERSION_V3
    value["producer"] = PRODUCER_V3
    value["extractor_config_sha256"] = CONFIG_SHA256_V3
    value["abi_authority"] = authority
    _obj(value["wrapper"], "v3 wrapper")["return_channel"] = return_channel
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def _validate_return_channel(channel: dict[str, Any], wrapper: dict[str, Any]) -> None:
    kind = channel.get("kind")
    if kind == "high-pcode-ssa/v1":
        _exact(channel, {"kind"}, "SSA return channel")
        return
    _exact(channel, {"kind", "conclusion", "bridge", "suffix"}, "native return channel")
    if (
        kind != "windows-x64-rax-preserved/v1"
        or channel["conclusion"]
        != "DriverEntry NTSTATUS return channel preserved across wrapper suffix"
    ):
        raise ValueError("native return-channel conclusion mismatch")
    bridge = _obj(channel["bridge"], "native bridge")
    _exact(bridge, {"rva", "size", "bytes", "sha256", "computed_target_rva"}, "native bridge")
    call = _obj(wrapper["bridge_call"], "bridge_call")
    bridge_rva = _hex(bridge["rva"], "native bridge RVA")
    target_rva = _hex(bridge["computed_target_rva"], "native bridge target RVA")
    encoded_bridge = bytes.fromhex(bridge["bytes"]) if isinstance(bridge["bytes"], str) else b""
    recomputed_target = (
        bridge_rva + 5 + struct.unpack("<i", encoded_bridge[1:])[0]
        if len(encoded_bridge) == 5 and encoded_bridge[:1] == b"\xe8"
        else -1
    )
    if (
        bridge["rva"] != _obj(call["ref"], "bridge ref")["instruction_rva"]
        or bridge["computed_target_rva"] != call["target_rva"]
        or bridge["size"] != 5
        or hashlib.sha256(encoded_bridge).hexdigest() != bridge["sha256"]
        or recomputed_target != target_rva
        or target_rva != _hex(call["target_rva"], "bridge call target")
    ):
        raise ValueError("native bridge evidence mismatch")
    suffix = _obj(channel["suffix"], "native suffix")
    _exact(
        suffix,
        {
            "start_rva",
            "end_rva",
            "sha256",
            "instructions",
            "instruction_count",
            "byte_count",
            "all_paths_return",
            "later_calls",
            "rax_alias_writes",
            "limits_hit",
        },
        "native suffix",
    )
    rows = suffix["instructions"]
    if not isinstance(rows, list) or len(rows) != 4 or suffix["instruction_count"] != 4:
        raise ValueError("native suffix instruction inventory mismatch")
    expected = ["488b5c2430", "4883c420", "5f", "c3"]
    if [row.get("bytes") for row in rows if isinstance(row, dict)] != expected:
        raise ValueError("native suffix grammar mismatch")
    combined = bytes.fromhex("".join(expected))
    cursor = bridge_rva + 5
    if (
        _hex(suffix["start_rva"], "native suffix start") != cursor
        or suffix["byte_count"] != len(combined)
        or suffix["sha256"] != hashlib.sha256(combined).hexdigest()
        or suffix["all_paths_return"] is not True
        or suffix["later_calls"] != 0
        or suffix["rax_alias_writes"] != []
        or suffix["limits_hit"] != []
    ):
        raise ValueError("native suffix proof boundary mismatch")
    for index, raw_row in enumerate(rows):
        row = _obj(raw_row, "native instruction")
        _exact(
            row,
            {"rva", "size", "bytes", "flow", "successors", "low_pcode_sha256", "resolved_writes"},
            "native instruction",
        )
        if _hex(row["rva"], "native instruction RVA") != cursor:
            raise ValueError("native instruction cursor mismatch")
        encoded = bytes.fromhex(row["bytes"])
        if row["size"] != len(encoded) or encoded.hex() != expected[index]:
            raise ValueError("native instruction size/bytes mismatch")
        _sha(row["low_pcode_sha256"], "native low-P-Code SHA-256")
        if not isinstance(row["resolved_writes"], list):
            raise ValueError("native resolved writes must be an array")
        for raw_write in row["resolved_writes"]:
            write = _obj(raw_write, "native resolved write")
            if write.get("kind") == "register":
                _exact(write, {"kind", "name", "base"}, "native register write")
                if (
                    not isinstance(write["name"], str)
                    or not write["name"]
                    or not isinstance(write["base"], str)
                    or not write["base"]
                    or write["base"].upper() == "RAX"
                    or write["name"].upper() in {"RAX", "EAX", "AX", "AL", "AH"}
                ):
                    raise ValueError("native suffix contains an RAX-alias write")
            elif write.get("kind") == "storage":
                _exact(write, {"kind", "space", "offset", "size"}, "native storage write")
                if not isinstance(write["space"], str) or not write["space"]:
                    raise ValueError("native storage write space is invalid")
                _hex(write["offset"], "native storage write offset")
                _int(write["size"], "native storage write size", 1, 64)
            else:
                raise ValueError("native resolved write kind is unsupported")
        cursor += len(encoded)
        if index == 3:
            if row["flow"] != "return" or row["successors"] != []:
                raise ValueError("native RET evidence mismatch")
        elif row["flow"] != "fallthrough" or row["successors"] != [f"0x{cursor:x}"]:
            raise ValueError("native fallthrough evidence mismatch")
    if _hex(suffix["end_rva"], "native suffix end") != cursor:
        raise ValueError("native suffix end mismatch")


def produce_windows_driver_entry_bridge(
    binary_path: str | Path,
    pdb_path: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
    public_pdb_bundle: str | Path | None = None,
    _profile_version: str = "v2",
    _abi_authority_dir: str | Path | None = None,
) -> dict[str, str]:
    """Acquire and atomically publish a retained v2 entry-bridge bundle."""
    binary = Path(os.path.abspath(binary_path))  # noqa: PTH100
    pdb = Path(os.path.abspath(pdb_path))  # noqa: PTH100
    output = Path(os.path.abspath(output_dir))  # noqa: PTH100
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100
    if _profile_version not in {"v2", "v3"}:
        raise ValueError("entry bridge producer profile is unsupported")
    authority_source = (
        Path(os.path.abspath(_abi_authority_dir))  # noqa: PTH100
        if _abi_authority_dir is not None
        else None
    )
    if _profile_version == "v3" and authority_source is None:
        raise ValueError("v3 entry bridge requires an explicit ABI authority directory")
    name = _driver_basename(binary.name)
    if Path(output.name).name != output.name or output.name in {"", ".", ".."}:
        raise ValueError("entry bridge output basename is invalid")
    route = verify_public_pdb_receipt(binary, public_pdb_bundle) if public_pdb_bundle else None
    if route is None:
        _require_exact_full_identity(binary, pdb)
    elif route.artifact_path.resolve() != pdb.resolve():
        raise ValueError("entry bridge PDB must be the verified public-route artifact")
    parent_fd = _open_directory_ancestry(output.parent, "entry bridge output parent")
    temporary_name = ""
    temporary_fd = -1
    published = False
    try:
        _require_directory_path_identity(output.parent, parent_fd, "entry bridge output parent")
        temporary_name, temporary_fd = _create_staging_directory(parent_fd, f".{output.name}.tmp-")
        toolchain_before = _toolchain_fingerprint(home)
        binary_sha = _snapshot_file_at(binary, temporary_fd, name, "driver", 512 * 1024 * 1024)
        retained_binary = Path(name)
        retained_route: PublicPdbReceipt | None = None
        if route is None:
            pdb_sha = _snapshot_file_at(
                pdb, temporary_fd, "target.pdb", "PDB", 2 * 1024 * 1024 * 1024
            )
            retained_pdb = Path("target.pdb")
            retained_route_path: Path | None = None
        else:
            os.mkdir("public-pdb", 0o700, dir_fd=temporary_fd)
            public_fd = os.open(
                "public-pdb", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=temporary_fd
            )
            try:
                os.mkdir(route.artifact_sha256, 0o700, dir_fd=public_fd)
                cas_fd = os.open(
                    route.artifact_sha256,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=public_fd,
                )
                try:
                    pdb_sha = _snapshot_file_at(
                        route.artifact_path,
                        cas_fd,
                        "artifact",
                        "public PDB",
                        2 * 1024 * 1024 * 1024,
                    )
                    _snapshot_file_at(
                        route.bundle_path / "receipt.json",
                        cas_fd,
                        "receipt.json",
                        "public PDB receipt",
                        1024 * 1024,
                    )
                finally:
                    os.close(cas_fd)
            finally:
                os.close(public_fd)
            retained_route_path = Path("public-pdb") / route.artifact_sha256
            retained_pdb = retained_route_path / "artifact"
        retained_authority: Path | None = None
        retained_authority_record: dict[str, object] | None = None
        if _profile_version == "v3":
            assert authority_source is not None
            _abi_authority(authority_source)
            os.mkdir("abi-authority", 0o700, dir_fd=temporary_fd)
            authority_fd = os.open(
                "abi-authority",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=temporary_fd,
            )
            try:
                for filename, maximum in (
                    ("manifest.json", 1024 * 1024),
                    ("x64-calling-convention.md", 1024 * 1024),
                    ("nc-wdm-driver_initialize.md", 1024 * 1024),
                ):
                    _snapshot_file_at(
                        authority_source / filename,
                        authority_fd,
                        filename,
                        f"ABI authority {filename}",
                        maximum,
                    )
            finally:
                os.close(authority_fd)
            retained_authority = Path("abi-authority")
        with _anchored_working_directory(temporary_fd):
            if route is None:
                _require_exact_full_identity(retained_binary, retained_pdb)
            else:
                retained_route = verify_public_pdb_receipt(
                    retained_binary, cast(Path, retained_route_path)
                )
                if _route_tuple(route) != _route_tuple(retained_route):
                    raise ValueError("public-PDB route changed while retaining entry bridge")
            authority_before = (
                tuple(
                    _identity(retained_authority / filename)
                    for filename in (
                        "manifest.json",
                        "x64-calling-convention.md",
                        "nc-wdm-driver_initialize.md",
                    )
                )
                if retained_authority is not None
                else ()
            )
            before = (_identity(retained_binary), _identity(retained_pdb), authority_before)
            if _profile_version == "v3":
                assert retained_authority is not None
                retained_authority_record = _abi_authority(retained_authority)
                facts = _acquire_entry_bridge_facts_v3(
                    retained_binary,
                    retained_pdb,
                    ghidra_home=home,
                    public_pdb_bundle=retained_route_path,
                    abi_authority_dir=retained_authority,
                )
            else:
                facts = _acquire_entry_bridge_facts(
                    retained_binary,
                    retained_pdb,
                    ghidra_home=home,
                    public_pdb_bundle=retained_route_path,
                )
            authority_after = (
                tuple(
                    _identity(retained_authority / filename)
                    for filename in (
                        "manifest.json",
                        "x64-calling-convention.md",
                        "nc-wdm-driver_initialize.md",
                    )
                )
                if retained_authority is not None
                else ()
            )
            if before != (_identity(retained_binary), _identity(retained_pdb), authority_after):
                raise ValueError("entry bridge analyzer mutated retained inputs")
            post_route = (
                verify_public_pdb_receipt(retained_binary, retained_route_path)
                if retained_route_path is not None
                else None
            )
            if (
                route is not None
                and post_route is not None
                and _route_tuple(route) != _route_tuple(post_route)
            ):
                raise ValueError("public-PDB route changed after entry bridge acquisition")
            export = (
                compile_windows_driver_entry_bridge_v3(facts)
                if _profile_version == "v3"
                else compile_windows_driver_entry_bridge(facts)
            )
            _bind(export, retained_binary, retained_pdb)
        toolchain_after = _toolchain_fingerprint(home)
        if toolchain_before != toolchain_after:
            raise ValueError("entry bridge toolchain changed during acquisition")
        export_bytes = (
            canonical_bridge_v3_bytes(export)
            if _profile_version == "v3"
            else canonical_bridge_bytes(export)
        )
        export_sha = hashlib.sha256(export_bytes).hexdigest()
        _write_new_file_at(temporary_fd, "entry-bridge.json", export_bytes)
        receipt = {
            "schema_version": RECEIPT_VERSION_V3 if _profile_version == "v3" else RECEIPT_VERSION,
            "producer": PRODUCER_V3 if _profile_version == "v3" else PRODUCER,
            "binary_path": name,
            "binary_sha256": binary_sha,
            "pdb_path": retained_pdb.as_posix(),
            "pdb_sha256": pdb_sha,
            "entry_bridge_path": "entry-bridge.json",
            "entry_bridge_sha256": export_sha,
            "tool_version": _ghidra_version(home),
            "toolchain": toolchain_after,
            "extractor_config_sha256": (
                CONFIG_SHA256_V3 if _profile_version == "v3" else CONFIG_SHA256
            ),
            "abi_authority": (
                {"bundle_path": "abi-authority", **retained_authority_record}
                if retained_authority_record is not None
                else None
            ),
            "public_pdb_receipt_sha256": post_route.receipt_sha256 if post_route else None,
            "static_only": True,
            "execution_authorized": False,
        }
        if _profile_version == "v2":
            receipt.pop("abi_authority")
        receipt["cache_key"] = hashlib.sha256(
            (
                b"0verse-windows-driver-entry-bridge-cache-v3\0"
                if _profile_version == "v3"
                else b"0verse-windows-driver-entry-bridge-cache-v2\0"
            )
            + b"\0".join(
                value.encode()
                for value in (
                    cast(str, receipt["binary_sha256"]),
                    cast(str, receipt["pdb_sha256"]),
                    export_sha,
                    CONFIG_SHA256_V3 if _profile_version == "v3" else CONFIG_SHA256,
                    ABI_MANIFEST_SHA256 if _profile_version == "v3" else "",
                    cast(str, receipt["public_pdb_receipt_sha256"] or ""),
                    hashlib.sha256(
                        json.dumps(toolchain_after, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                )
            )
        ).hexdigest()
        receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        _write_new_file_at(temporary_fd, "receipt.json", receipt_bytes)
        os.fsync(temporary_fd)
        _require_directory_path_identity(output.parent, parent_fd, "entry bridge output parent")
        _publish_directory_no_replace(parent_fd, temporary_name, output.name)
        os.fsync(parent_fd)
        published = True
        return {
            "entry_bridge_path": f"{output.name}/entry-bridge.json",
            "entry_bridge_sha256": export_sha,
            "receipt_path": f"{output.name}/receipt.json",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        }
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name and not published:
            _remove_staging_at(
                parent_fd,
                temporary_name,
                name,
                route.artifact_sha256 if route else None,
                _profile_version == "v3",
            )
        os.close(parent_fd)


def produce_windows_driver_entry_bridge_v3(
    binary_path: str | Path,
    pdb_path: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
    abi_authority_dir: str | Path,
    public_pdb_bundle: str | Path | None = None,
) -> dict[str, str]:
    return produce_windows_driver_entry_bridge(
        binary_path,
        pdb_path,
        output_dir,
        ghidra_home=ghidra_home,
        public_pdb_bundle=public_pdb_bundle,
        _profile_version="v3",
        _abi_authority_dir=abi_authority_dir,
    )


def verify_windows_driver_entry_bridge_bundle(
    bundle_path: str | Path, *, ghidra_home: str | Path
) -> dict[str, object]:
    bundle = Path(bundle_path)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("entry bridge bundle must be a regular directory")
    receipt = _obj(
        json.loads(
            _relative_file(bundle, "receipt.json", "entry bridge receipt").read_bytes(),
            object_pairs_hook=_unique,
        ),
        "receipt",
    )
    is_v3 = receipt.get("schema_version") == RECEIPT_VERSION_V3
    receipt_fields = {
        "schema_version",
        "producer",
        "binary_path",
        "binary_sha256",
        "pdb_path",
        "pdb_sha256",
        "entry_bridge_path",
        "entry_bridge_sha256",
        "tool_version",
        "toolchain",
        "extractor_config_sha256",
        "cache_key",
        "public_pdb_receipt_sha256",
        "static_only",
        "execution_authorized",
    }
    if is_v3:
        receipt_fields.add("abi_authority")
    _exact(
        receipt,
        receipt_fields,
        "receipt",
    )
    if (receipt["schema_version"], receipt["producer"]) != (
        RECEIPT_VERSION_V3 if is_v3 else RECEIPT_VERSION,
        PRODUCER_V3 if is_v3 else PRODUCER,
    ):
        raise ValueError("entry bridge receipt schema/producer mismatch")
    if (
        receipt["extractor_config_sha256"] != (CONFIG_SHA256_V3 if is_v3 else CONFIG_SHA256)
        or receipt["static_only"] is not True
        or receipt["execution_authorized"] is not False
    ):
        raise ValueError("entry bridge receipt contract mismatch")
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100
    toolchain = _toolchain_fingerprint(home)
    if receipt["toolchain"] != toolchain:
        raise ValueError("entry bridge toolchain fingerprint mismatch")
    binary = _relative_file(bundle, receipt["binary_path"], "entry bridge binary")
    pdb = _relative_file(bundle, receipt["pdb_path"], "entry bridge PDB")
    retained_authority: Path | None = None
    if is_v3:
        authority_receipt = _obj(receipt["abi_authority"], "receipt ABI authority")
        retained_authority = _relative_directory(
            bundle, authority_receipt.get("bundle_path"), "entry bridge ABI authority"
        )
        expected_authority = {"bundle_path": "abi-authority", **_abi_authority(retained_authority)}
        if authority_receipt != expected_authority:
            raise ValueError("entry bridge retained ABI authority mismatch")
    if _identity(binary) != receipt["binary_sha256"] or _identity(pdb) != receipt["pdb_sha256"]:
        raise ValueError("entry bridge retained artifact SHA-256 mismatch")
    if receipt["public_pdb_receipt_sha256"] is None:
        _require_exact_full_identity(binary, pdb)
    else:
        route = verify_public_pdb_receipt(binary, pdb.parent)
        if (
            route.artifact_path.resolve() != pdb.resolve()
            or route.receipt_sha256 != receipt["public_pdb_receipt_sha256"]
        ):
            raise ValueError("entry bridge public-PDB receipt binding mismatch")
    artifact = _relative_file(bundle, receipt["entry_bridge_path"], "entry bridge artifact")
    artifact_bytes = artifact.read_bytes()
    if hashlib.sha256(artifact_bytes).hexdigest() != receipt["entry_bridge_sha256"]:
        raise ValueError("entry bridge artifact SHA-256 mismatch")
    export = (
        _validate_v3(json.loads(artifact_bytes, object_pairs_hook=_unique))
        if is_v3
        else _validate(json.loads(artifact_bytes, object_pairs_hook=_unique))
    )
    canonical = canonical_bridge_v3_bytes(export) if is_v3 else canonical_bridge_bytes(export)
    if canonical != artifact_bytes:
        raise ValueError("entry bridge artifact is not canonical")
    _bind(export, binary, pdb)
    if is_v3 and export.get("abi_authority") != {
        key: value
        for key, value in cast(dict[str, object], receipt["abi_authority"]).items()
        if key != "bundle_path"
    }:
        raise ValueError("entry bridge export/receipt ABI authority mismatch")
    if export["tool"] != {"name": "ghidra", "version": receipt["tool_version"]}:
        raise ValueError("entry bridge tool binding mismatch")
    expected_cache = hashlib.sha256(
        (
            b"0verse-windows-driver-entry-bridge-cache-v3\0"
            if is_v3
            else b"0verse-windows-driver-entry-bridge-cache-v2\0"
        )
        + b"\0".join(
            value.encode()
            for value in (
                cast(str, receipt["binary_sha256"]),
                cast(str, receipt["pdb_sha256"]),
                cast(str, receipt["entry_bridge_sha256"]),
                CONFIG_SHA256_V3 if is_v3 else CONFIG_SHA256,
                ABI_MANIFEST_SHA256 if is_v3 else "",
                cast(str, receipt["public_pdb_receipt_sha256"] or ""),
                hashlib.sha256(
                    json.dumps(toolchain, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
            )
        )
    ).hexdigest()
    if receipt["cache_key"] != expected_cache:
        raise ValueError("entry bridge cache key mismatch")
    replay_facts = (
        _acquire_entry_bridge_facts_v3(
            binary,
            pdb,
            ghidra_home=home,
            public_pdb_bundle=(
                pdb.parent if receipt["public_pdb_receipt_sha256"] is not None else None
            ),
            abi_authority_dir=cast(Path, retained_authority),
        )
        if is_v3
        else _acquire_entry_bridge_facts(
            binary,
            pdb,
            ghidra_home=home,
            public_pdb_bundle=(
                pdb.parent if receipt["public_pdb_receipt_sha256"] is not None else None
            ),
        )
    )
    replay = (
        compile_windows_driver_entry_bridge_v3(replay_facts)
        if is_v3
        else compile_windows_driver_entry_bridge(replay_facts)
    )
    replay_bytes = canonical_bridge_v3_bytes(replay) if is_v3 else canonical_bridge_bytes(replay)
    if replay_bytes != artifact_bytes:
        raise ValueError("entry bridge structural proof replay mismatch")
    if _toolchain_fingerprint(home) != toolchain:
        raise ValueError("entry bridge toolchain changed during verification")
    return export


def _validate(raw: object) -> dict[str, object]:
    value = _obj(raw, "entry bridge")
    fact_fields = {
        "driver_sha256",
        "pdb_sha256",
        "pdb_identity",
        "pe_codeview_identity",
        "architecture",
        "image_base",
        "pe_entry_point_rva",
        "tool",
        "pdb_driver_entry",
        "wrapper",
        "accounting",
    }
    claims = {
        "outcome",
        "static_only",
        "execution_authorized",
        "device_ioctl_attempts",
        "registration_claims",
        "selector_claims",
        "table_claims",
        "candidate_count",
        "candidate_established",
        "vulnerability_established",
        "runtime_reachability_established",
        "unprivileged_reachability_established",
        "exploitability_established",
        "novelty_established",
        "bounty_eligible",
        "weaponization",
        "proof_limit",
    }
    _exact(
        value,
        {"schema_version", "producer", "extractor_config_sha256"} | fact_fields | claims,
        "entry bridge",
    )
    if (
        value["schema_version"] != EXPORT_VERSION
        or value["producer"] != PRODUCER
        or value["extractor_config_sha256"] != CONFIG_SHA256
    ):
        raise ValueError("entry bridge schema/producer/config mismatch")
    _sha(value["driver_sha256"], "driver_sha256")
    _sha(value["pdb_sha256"], "pdb_sha256")
    if value["architecture"] != "x86_64":
        raise ValueError("entry bridge supports x86_64 only")
    image_base = _hex(value["image_base"], "image_base")
    pe_entry = _hex(value["pe_entry_point_rva"], "pe_entry_point_rva")
    if not isinstance(value["pdb_identity"], str) or not isinstance(
        value["pe_codeview_identity"], str
    ):
        raise ValueError("entry bridge identities must be strings")
    tool = _obj(value["tool"], "tool")
    _exact(tool, {"name", "version"}, "tool")
    if tool["name"] != "ghidra" or not isinstance(tool["version"], str) or not tool["version"]:
        raise ValueError("entry bridge tool contract mismatch")
    record = _obj(value["pdb_driver_entry"], "pdb_driver_entry")
    _exact(
        record,
        {
            "name",
            "record_kind",
            "function_flag",
            "segment",
            "offset",
            "rva",
            "executable_section",
            "unique_exact_record",
        },
        "pdb_driver_entry",
    )
    driver_rva = _hex(record["rva"], "pdb_driver_entry.rva")
    if (
        record["name"] != "DriverEntry"
        or record["record_kind"] not in {"procedure", "public-function"}
        or record["function_flag"] is not True
        or record["executable_section"] is not True
        or record["unique_exact_record"] is not True
    ):
        raise ValueError("PDB DriverEntry record contract mismatch")
    _int(record["segment"], "segment", 1, 65535)
    _int(record["offset"], "offset", 0, 0xFFFFFFFF)
    wrapper = _obj(value["wrapper"], "wrapper")
    _exact(
        wrapper,
        {
            "function_rva",
            "exact_pe_entry",
            "non_thunk",
            "pre_bridge_call",
            "bridge_call",
            "rcx_path",
            "rdx_path",
            "bridge_dominates_all_returns",
            "return_value_propagated",
            "return_refs",
            "bounded_control_transfers",
        },
        "wrapper",
    )
    if (
        _hex(wrapper["function_rva"], "wrapper.function_rva") != pe_entry
        or wrapper["exact_pe_entry"] is not True
        or wrapper["non_thunk"] is not True
    ):
        raise ValueError("wrapper is not exact PE entry")
    pre_bridge = _call(wrapper["pre_bridge_call"], "pre_bridge_call")
    bridge = _call(wrapper["bridge_call"], "bridge_call")
    if (
        _hex(bridge["target_rva"], "bridge target") != driver_rva
        or pre_bridge["target_rva"] == bridge["target_rva"]
    ):
        raise ValueError("bridge target is not exact unique PDB DriverEntry")
    for register in ("RCX", "RDX"):
        path = wrapper[register.lower() + "_path"]
        if not isinstance(path, list) or len(path) > 64:
            raise ValueError(f"{register} path must be bounded")
        for ref in path:
            _ref(ref, f"{register} path", {"COPY", "CAST"})
    returns = wrapper["return_refs"]
    if not isinstance(returns, list) or not 1 <= len(returns) <= 64:
        raise ValueError("return refs must be bounded and nonempty")
    for ref in returns:
        _ref(ref, "return ref", {"RETURN"})
    if (
        wrapper["bridge_dominates_all_returns"] is not True
        or wrapper["return_value_propagated"] is not True
    ):
        raise ValueError("bridge dominance/return propagation is unproven")
    transfers = wrapper["bounded_control_transfers"]
    if not isinstance(transfers, list) or not 2 <= len(transfers) <= 64:
        raise ValueError("control transfers must be bounded")
    for ref in transfers:
        _ref(ref, "control transfer", {"CALL", "BRANCH", "CBRANCH", "RETURN"})
    accounting = _obj(value["accounting"], "accounting")
    _exact(
        accounting,
        {
            "wrapper_pcode_ops",
            "control_transfers",
            "direct_calls",
            "indirect_calls",
            "returns",
            "limits_hit",
        },
        "accounting",
    )
    _int(accounting["wrapper_pcode_ops"], "wrapper_pcode_ops", 1, 4096)
    _int(accounting["control_transfers"], "control_transfers", 2, 64)
    if (
        accounting["control_transfers"] != len(transfers)
        or accounting["direct_calls"] != 2
        or accounting["indirect_calls"] != 0
        or accounting["returns"] != len(returns)
        or accounting["limits_hit"] != []
    ):
        raise ValueError("entry bridge accounting mismatch")
    expected = {
        "outcome": "entry-bridge-proven",
        "static_only": True,
        "execution_authorized": False,
        "device_ioctl_attempts": 0,
        "registration_claims": 0,
        "selector_claims": 0,
        "table_claims": 0,
        "candidate_count": 0,
        "candidate_established": False,
        "vulnerability_established": False,
        "runtime_reachability_established": False,
        "unprivileged_reachability_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "bounty_eligible": False,
        "weaponization": False,
        "proof_limit": _PROOF_LIMIT,
    }
    if any(value[key] != expected_value for key, expected_value in expected.items()):
        raise ValueError("entry bridge claim boundary mismatch")
    if image_base <= 0:
        raise ValueError("image base is invalid")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def _acquire_entry_bridge_facts(
    binary: Path, pdb: Path, *, ghidra_home: Path, public_pdb_bundle: Path | None
) -> dict[str, object]:
    """Live adapter boundary; structural implementation is isolated for review."""
    if public_pdb_bundle is None:
        _require_exact_full_identity(binary, pdb)
    else:
        route = verify_public_pdb_receipt(binary, public_pdb_bundle)
        if route.artifact_path.resolve() != pdb.resolve():
            raise ValueError("entry bridge PDB route mismatch")
    records = pdb_function_records(binary, pdb)
    if not records:
        raise ValueError("entry bridge requires executable PDB function records")
    from .windows_driver_entry_bridge_ghidra import acquire_entry_bridge_high_pcode

    return acquire_entry_bridge_high_pcode(binary, pdb, ghidra_home, records)


def _acquire_entry_bridge_facts_v3(
    binary: Path,
    pdb: Path,
    *,
    ghidra_home: Path,
    public_pdb_bundle: Path | None,
    abi_authority_dir: Path,
) -> dict[str, object]:
    authority = _abi_authority(abi_authority_dir)
    if public_pdb_bundle is None:
        _require_exact_full_identity(binary, pdb)
    else:
        route = verify_public_pdb_receipt(binary, public_pdb_bundle)
        if route.artifact_path.resolve() != pdb.resolve():
            raise ValueError("entry bridge PDB route mismatch")
    records = pdb_function_records(binary, pdb)
    if not records:
        raise ValueError("entry bridge requires executable PDB function records")
    from .windows_driver_entry_bridge_ghidra import acquire_entry_bridge_high_pcode

    facts = acquire_entry_bridge_high_pcode(binary, pdb, ghidra_home, records, profile_version="v3")
    facts["abi_authority"] = authority
    return facts


def _abi_authority(directory: Path | None = None) -> dict[str, object]:
    if directory is None:
        root = Path(__file__).resolve().parents[2]
        directory = root / "docs" / "evidence" / "windows-driver-entry-abi"
    manifest = directory / "manifest.json"
    if _identity(manifest) != ABI_MANIFEST_SHA256:
        raise ValueError("entry bridge ABI manifest SHA-256 mismatch")
    raw = _obj(json.loads(manifest.read_bytes(), object_pairs_hook=_unique), "ABI manifest")
    sources = raw.get("sources")
    if not isinstance(sources, list) or len(sources) != 2:
        raise ValueError("entry bridge ABI manifest source inventory mismatch")
    expected = [
        (
            "x64-calling-convention.md",
            "043986cc9256b62c29b4b18fba978cfece03da69e8680054d210d40b625d89c0",
            18835,
        ),
        (
            "nc-wdm-driver_initialize.md",
            "aa853c41b56d1f299e370ea09c48c335bc98ec964f378374774d7288731c947d",
            5030,
        ),
    ]
    for row, (name, digest, size) in zip(sources, expected, strict=True):
        source = _obj(row, "ABI source")
        path = directory / name
        if (
            source.get("path") != name
            or source.get("raw_sha256") != digest
            or source.get("raw_size_bytes") != size
            or source.get("snapshot_sha256") != digest
            or source.get("snapshot_size_bytes") != size
            or path.stat().st_size != size
            or _identity(path) != digest
        ):
            raise ValueError("entry bridge ABI source custody mismatch")
    return {
        "manifest_path": "docs/evidence/windows-driver-entry-abi/manifest.json",
        "manifest_sha256": ABI_MANIFEST_SHA256,
        "sources": [digest for _, digest, _ in expected],
    }


def _bind(export: dict[str, object], binary: Path, pdb: Path) -> None:
    pe = pe_codeview_identity(binary)
    symbols = pdb_codeview_identity(pdb)
    if pe is None or symbols is None:
        raise ValueError("entry bridge artifact identities unavailable")
    expected = {
        "driver_sha256": _identity(binary),
        "pdb_sha256": _identity(pdb),
        "pdb_identity": f"{symbols[0]}:{symbols[1]}:{'stripped' if symbols[2] else 'full'}",
        "pe_codeview_identity": f"{pe[0]}:{pe[1]}:{pe[2]}",
        "pe_entry_point_rva": f"0x{_pe_entry_rva(binary):x}",
    }
    if any(export.get(key) != observed for key, observed in expected.items()):
        raise ValueError("entry bridge artifact binding mismatch")
    records = [
        record for record in pdb_function_records(binary, pdb) if record.name == "DriverEntry"
    ]
    record = _obj(export["pdb_driver_entry"], "pdb_driver_entry")
    if len(records) != 1 or (
        record["record_kind"],
        record["segment"],
        record["offset"],
        record["rva"],
    ) != (records[0].kind, records[0].segment, records[0].offset, f"0x{records[0].rva:x}"):
        raise ValueError("entry bridge PDB record binding mismatch")


def _call(raw: object, label: str) -> dict[str, Any]:
    value = _obj(raw, label)
    _exact(value, {"ref", "target_rva", "direct", "internal_executable"}, label)
    _ref(value["ref"], f"{label}.ref", {"CALL"})
    _hex(value["target_rva"], f"{label}.target_rva")
    if value["direct"] is not True or value["internal_executable"] is not True:
        raise ValueError(f"{label} must be direct internal executable")
    return value


def _ref(raw: object, label: str, opcodes: set[str]) -> None:
    value = _obj(raw, label)
    _exact(value, {"function_rva", "instruction_rva", "pcode_order", "opcode"}, label)
    _hex(value["function_rva"], f"{label}.function_rva")
    _hex(value["instruction_rva"], f"{label}.instruction_rva")
    _int(value["pcode_order"], f"{label}.pcode_order", 0, 65535)
    if value["opcode"] not in opcodes:
        raise ValueError(f"{label} opcode is invalid")


def _obj(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} has unknown or missing fields")


def _sha(raw: object, label: str) -> None:
    if (
        not isinstance(raw, str)
        or len(raw) != 64
        or any(char not in "0123456789abcdef" for char in raw)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _hex(raw: object, label: str) -> int:
    if not isinstance(raw, str) or not raw.startswith("0x") or raw != f"0x{int(raw, 16):x}":
        raise ValueError(f"{label} must be canonical lowercase hex")
    return int(raw, 16)


def _int(raw: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return raw


def _identity(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("entry bridge input must be a regular non-symlink file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _route_tuple(route: PublicPdbReceipt) -> tuple[object, ...]:
    return (
        route.artifact_sha256,
        route.artifact_size_bytes,
        route.receipt_sha256,
        route.requested_url,
        route.pe_guid,
        route.pe_age,
        route.pdb_guid,
        route.pdb_age,
        route.exact_age_match,
    )


def _toolchain_fingerprint(ghidra_home: Path) -> dict[str, object]:
    """Content-bind every regular file in Ghidra/PyGhidra and the exact PDB parser."""
    import importlib.metadata

    import pyghidra

    llvm = shutil.which("llvm-pdbutil")
    if llvm is None:
        raise ValueError("llvm-pdbutil is required for entry bridge custody")
    llvm_path = Path(llvm).resolve()
    pyghidra_file = Path(pyghidra.__file__).resolve()
    pyghidra_root = pyghidra_file.parent
    return {
        "ghidra_version": _ghidra_version(ghidra_home),
        "ghidra_tree_sha256": _tree_digest(ghidra_home),
        "pyghidra_version": importlib.metadata.version("pyghidra"),
        "pyghidra_tree_sha256": _tree_digest(pyghidra_root),
        "llvm_pdbutil_path": str(llvm_path),
        "llvm_pdbutil_sha256": _identity(llvm_path),
        "llvm_pdbutil_version": subprocess.run(
            [str(llvm_path), "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip(),
    }


def _tree_digest(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("entry bridge tool root must be a regular directory")
    digest = hashlib.sha256()
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError("entry bridge tool tree contains a symlink")
        if not path.is_file():
            continue
        count += 1
        if count > 100000:
            raise ValueError("entry bridge tool tree exceeds file bound")
        relative = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(hashlib.sha256(content).digest())
    if count == 0:
        raise ValueError("entry bridge tool tree is empty")
    return digest.hexdigest()


def _remove_staging_at(
    parent_fd: int,
    name: str,
    binary_name: str,
    public_sha: str | None,
    has_authority: bool = False,
) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        directory_fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        for filename in ("entry-bridge.json", "receipt.json", "target.pdb", binary_name):
            with suppress(FileNotFoundError):
                os.unlink(filename, dir_fd=directory_fd)  # foxguard: ignore[py/no-path-traversal]
        if public_sha is not None:
            with suppress(FileNotFoundError):
                public_fd = os.open("public-pdb", flags, dir_fd=directory_fd)
                try:
                    cas_fd = os.open(public_sha, flags, dir_fd=public_fd)
                    try:
                        for filename in ("artifact", "receipt.json"):
                            with suppress(FileNotFoundError):
                                os.unlink(  # foxguard: ignore[py/no-path-traversal]
                                    filename, dir_fd=cas_fd
                                )
                    finally:
                        os.close(cas_fd)
                    os.rmdir(public_sha, dir_fd=public_fd)
                finally:
                    os.close(public_fd)
                os.rmdir("public-pdb", dir_fd=directory_fd)
        if has_authority:
            with suppress(FileNotFoundError):
                authority_fd = os.open("abi-authority", flags, dir_fd=directory_fd)
                try:
                    for filename in (
                        "manifest.json",
                        "x64-calling-convention.md",
                        "nc-wdm-driver_initialize.md",
                    ):
                        with suppress(FileNotFoundError):
                            os.unlink(  # foxguard: ignore[py/no-path-traversal]
                                filename, dir_fd=authority_fd
                            )
                finally:
                    os.close(authority_fd)
                os.rmdir("abi-authority", dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result
