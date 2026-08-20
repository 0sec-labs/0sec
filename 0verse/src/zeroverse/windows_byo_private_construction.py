"""Pure construction profile for private Windows BYO HMAC commitments.

This module validates already-loaded in-memory objects and computes commitments.
It deliberately exposes no filesystem, key-loading, resolution, signing, CLI,
network, execution, or publication surface.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

CONSTRUCTION_PROFILE = "0verse.windows-byo-hmac-construction/v1"
COMMITMENT_SCHEME = "hmac-sha256-private-256-bit-key/v1"
ITEM_IDENTITY_SCHEMA = "0verse.windows-byo-private-item-identity/v1"
BUNDLE_MANIFEST_SCHEMA = "0verse.windows-byo-private-evidence-bundle/v1"
SOURCE_INDEX_SCHEMA = "0verse.windows-byo-private-source-index/v1"

KEY_COMMITMENT_DOMAIN = b"0verse-windows-byo-blinding-key-commitment-v1\0"
ITEM_COMMITMENT_DOMAIN = b"0verse-windows-byo-item-v1\0"
BUNDLE_COMMITMENT_DOMAIN = b"0verse-windows-byo-private-evidence-bundle-v1\0"
SOURCE_INDEX_COMMITMENT_DOMAIN = b"0verse-windows-byo-source-index-v1\0"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_INVENTORY_ID = re.compile(r"inventory-[0-9a-f]{64}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,128}")
_ROLE = re.compile(r"[a-z][a-z0-9._-]{0,63}")
_MAX_FILES = 4096
_MAX_ENTRIES = 4096


@dataclass(frozen=True)
class SelectedPrivateConstruction:
    """Opaque commitments produced after every private object cross-check passes."""

    key_commitment_sha256: str
    source_index_commitment_sha256: str
    item_commitment_sha256: str
    private_bundle_commitment_sha256: str


def canonical_private_json(raw: object) -> bytes:
    """Return the one byte encoding used by construction profile v1."""
    return json.dumps(
        raw,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def key_commitment(key: bytes | bytearray) -> str:
    """Commit to one exact 256-bit private HMAC key."""
    secret = _key(key)
    return hashlib.sha256(KEY_COMMITMENT_DOMAIN + secret).hexdigest()


def item_commitment(
    key: bytes | bytearray,
    inventory_id: str,
    inventory_nonce: str,
    item_identity: dict[str, Any],
) -> str:
    """Commit to one typed private item identity."""
    validate_item_identity(item_identity)
    return _commit(
        key,
        ITEM_COMMITMENT_DOMAIN,
        inventory_id,
        inventory_nonce,
        item_identity,
    )


def bundle_commitment(
    key: bytes | bytearray,
    inventory_id: str,
    inventory_nonce: str,
    bundle_manifest: dict[str, Any],
) -> str:
    """Commit to one typed private evidence-bundle manifest."""
    validate_bundle_manifest(bundle_manifest)
    _same_inventory(bundle_manifest, inventory_id, inventory_nonce, "bundle manifest")
    embedded_item = _object(bundle_manifest["item_identity"], "bundle item identity")
    expected_item = item_commitment(key, inventory_id, inventory_nonce, embedded_item)
    if not hmac.compare_digest(bundle_manifest["item_commitment_sha256"], expected_item):
        raise ValueError("private bundle embedded item commitment mismatch")
    return _commit(
        key,
        BUNDLE_COMMITMENT_DOMAIN,
        inventory_id,
        inventory_nonce,
        bundle_manifest,
    )


def source_index_commitment(
    key: bytes | bytearray,
    inventory_id: str,
    inventory_nonce: str,
    source_index: dict[str, Any],
) -> str:
    """Commit to the complete typed private tuple-to-bundle index."""
    validate_source_index(source_index)
    _same_inventory(source_index, inventory_id, inventory_nonce, "source index")
    return _commit(
        key,
        SOURCE_INDEX_COMMITMENT_DOMAIN,
        inventory_id,
        inventory_nonce,
        source_index,
    )


def construct_selected_tuple(
    key: bytes | bytearray,
    inventory_id: str,
    inventory_nonce: str,
    item_identity: dict[str, Any],
    bundle_manifest: dict[str, Any],
    source_index: dict[str, Any],
    bundle_manifest_relative_path: str,
) -> SelectedPrivateConstruction:
    """Cross-check one exact private tuple and return only opaque commitments."""
    item = item_commitment(key, inventory_id, inventory_nonce, item_identity)
    validate_bundle_manifest(bundle_manifest)
    if bundle_manifest["item_commitment_sha256"] != item:
        raise ValueError("private bundle selected item commitment mismatch")
    if bundle_manifest["item_identity"] != item_identity:
        raise ValueError("private bundle embedded item identity mismatch")
    bundle = bundle_commitment(key, inventory_id, inventory_nonce, bundle_manifest)
    validate_source_index(source_index)
    _same_inventory(source_index, inventory_id, inventory_nonce, "source index")
    path = _relative_path(bundle_manifest_relative_path, "selected bundle manifest path")
    selected = {
        "item_commitment_sha256": item,
        "private_bundle_commitment_sha256": bundle,
        "bundle_manifest_relative_path": path,
    }
    if selected not in source_index["entries"]:
        raise ValueError("selected private tuple is absent from the committed source index")
    return SelectedPrivateConstruction(
        key_commitment(key),
        source_index_commitment(key, inventory_id, inventory_nonce, source_index),
        item,
        bundle,
    )


def validate_item_identity(raw: dict[str, Any]) -> None:
    """Validate the exact non-directional artifact identity schema."""
    _object(raw, "item identity")
    _exact(
        raw,
        {
            "schema_version",
            "driver_sha256",
            "pdb_sha256",
            "pdb_codeview_identity",
            "analysis_sha256",
            "analysis_receipt_sha256",
        },
        "item identity",
    )
    if raw["schema_version"] != ITEM_IDENTITY_SCHEMA:
        raise ValueError("private item identity schema mismatch")
    for field in (
        "driver_sha256",
        "pdb_sha256",
        "analysis_sha256",
        "analysis_receipt_sha256",
    ):
        _sha(raw[field], f"item identity {field}")
    _text(raw["pdb_codeview_identity"], "item identity pdb_codeview_identity", 512)


def validate_bundle_manifest(raw: dict[str, Any]) -> None:
    """Validate an exact private bundle manifest without opening its files."""
    _object(raw, "bundle manifest")
    _exact(
        raw,
        {
            "schema_version",
            "construction_profile",
            "inventory_id",
            "inventory_nonce",
            "item_commitment_sha256",
            "item_identity",
            "files",
        },
        "bundle manifest",
    )
    if raw["schema_version"] != BUNDLE_MANIFEST_SCHEMA:
        raise ValueError("private bundle manifest schema mismatch")
    if raw["construction_profile"] != CONSTRUCTION_PROFILE:
        raise ValueError("private bundle construction profile mismatch")
    _inventory(raw["inventory_id"], raw["inventory_nonce"])
    _sha(raw["item_commitment_sha256"], "bundle item commitment")
    validate_item_identity(_object(raw["item_identity"], "bundle item identity"))
    files = raw["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= _MAX_FILES:
        raise ValueError("private bundle files must be a bounded nonempty array")
    order: list[tuple[str, str]] = []
    file_hashes: dict[str, str] = {}
    for index, value in enumerate(files):
        record = _object(value, f"bundle files[{index}]")
        _exact(record, {"role", "relative_path", "sha256", "size_bytes"}, "bundle file")
        role = _match(record["role"], _ROLE, "bundle file role")
        path = _relative_path(record["relative_path"], "bundle file relative_path")
        digest = _sha(record["sha256"], "bundle file sha256")
        size = record["size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 2**40:
            raise ValueError("bundle file size_bytes is invalid")
        order.append((role, path))
        if role in file_hashes:
            raise ValueError("private bundle file roles must be unique")
        file_hashes[role] = digest
    if order != sorted(order) or len(order) != len(set(order)):
        raise ValueError("private bundle files must be canonically sorted and unique")
    if len({path for _, path in order}) != len(order):
        raise ValueError("private bundle file paths must be unique across roles")
    identity = _object(raw["item_identity"], "bundle item identity")
    expected_hashes = {
        "analysis-export": identity["analysis_sha256"],
        "analysis-receipt": identity["analysis_receipt_sha256"],
        "driver": identity["driver_sha256"],
        "pdb": identity["pdb_sha256"],
    }
    if file_hashes != expected_hashes:
        raise ValueError("private bundle required file roles must match the item identity")


def validate_source_index(raw: dict[str, Any]) -> None:
    """Validate the exact private index that preserves tuple pairing."""
    _object(raw, "source index")
    _exact(
        raw,
        {
            "schema_version",
            "construction_profile",
            "commitment_scheme",
            "inventory_id",
            "inventory_nonce",
            "entries",
        },
        "source index",
    )
    if raw["schema_version"] != SOURCE_INDEX_SCHEMA:
        raise ValueError("private source index schema mismatch")
    if raw["construction_profile"] != CONSTRUCTION_PROFILE:
        raise ValueError("private source index construction profile mismatch")
    if raw["commitment_scheme"] != COMMITMENT_SCHEME:
        raise ValueError("private source index commitment scheme mismatch")
    _inventory(raw["inventory_id"], raw["inventory_nonce"])
    entries = raw["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= _MAX_ENTRIES:
        raise ValueError("private source index entries must be a bounded nonempty array")
    order: list[tuple[str, str, str]] = []
    for index, value in enumerate(entries):
        entry = _object(value, f"source index entries[{index}]")
        _exact(
            entry,
            {
                "item_commitment_sha256",
                "private_bundle_commitment_sha256",
                "bundle_manifest_relative_path",
            },
            "source index entry",
        )
        item = _sha(entry["item_commitment_sha256"], "source index item commitment")
        bundle = _sha(
            entry["private_bundle_commitment_sha256"],
            "source index bundle commitment",
        )
        path = _relative_path(
            entry["bundle_manifest_relative_path"],
            "source index bundle_manifest_relative_path",
        )
        order.append((item, bundle, path))
    if order != sorted(order) or len(order) != len(set(order)):
        raise ValueError("private source index entries must be canonically sorted and unique")
    if len({item for item, _, _ in order}) != len(order):
        raise ValueError("private source index item commitments must be unique")
    if len({bundle for _, bundle, _ in order}) != len(order):
        raise ValueError("private source index bundle commitments must be unique")
    if len({path for _, _, path in order}) != len(order):
        raise ValueError("private source index bundle paths must be unique")


def _commit(
    key: bytes | bytearray,
    domain: bytes,
    inventory_id: str,
    inventory_nonce: str,
    raw: object,
) -> str:
    inventory, nonce = _inventory(inventory_id, inventory_nonce)
    material = (
        domain
        + inventory.encode("ascii")
        + b"\0"
        + nonce.encode("ascii")
        + b"\0"
        + canonical_private_json(raw)
    )
    return hmac.new(_key(key), material, hashlib.sha256).hexdigest()


def _key(raw: bytes | bytearray) -> bytes:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise ValueError("private HMAC key must be exactly 32 bytes")
    return bytes(raw)


def _same_inventory(
    raw: dict[str, Any], inventory_id: str, inventory_nonce: str, label: str
) -> None:
    if raw["inventory_id"] != inventory_id or raw["inventory_nonce"] != inventory_nonce:
        raise ValueError(f"{label} inventory binding mismatch")


def _inventory(inventory_id: object, inventory_nonce: object) -> tuple[str, str]:
    return (
        _match(inventory_id, _INVENTORY_ID, "inventory_id"),
        _match(inventory_nonce, _NONCE, "inventory_nonce"),
    )


def _relative_path(raw: object, label: str) -> str:
    value = _text(raw, label, 512)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value in {"", "."}
        or "\\" in value
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} must be a safe relative POSIX path")
    return value


def _sha(raw: object, label: str) -> str:
    return _match(raw, _SHA256, label)


def _match(raw: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(raw, str) or pattern.fullmatch(raw) is None:
        raise ValueError(f"{label} is invalid")
    return raw


def _text(raw: object, label: str, max_bytes: int) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or len(raw.encode("utf-8")) > max_bytes
        or any(character in raw for character in "\x00\r\n")
    ):
        raise ValueError(f"{label} is empty or unsafe")
    return raw


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    return raw


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} fields mismatch")
