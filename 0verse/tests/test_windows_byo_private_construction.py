from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

import pytest

from zeroverse.windows_byo_private_construction import (
    BUNDLE_MANIFEST_SCHEMA,
    COMMITMENT_SCHEME,
    CONSTRUCTION_PROFILE,
    ITEM_IDENTITY_SCHEMA,
    SOURCE_INDEX_SCHEMA,
    bundle_commitment,
    construct_selected_tuple,
    item_commitment,
    key_commitment,
    source_index_commitment,
    validate_bundle_manifest,
    validate_item_identity,
    validate_source_index,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _objects() -> tuple[bytes, str, str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    key = bytes(range(32))
    inventory_id = f"inventory-{_sha('private-inventory')}"
    inventory_nonce = "private-inventory-nonce-000000000001"
    item = {
        "schema_version": ITEM_IDENTITY_SCHEMA,
        "driver_sha256": _sha("driver"),
        "pdb_sha256": _sha("pdb"),
        "pdb_codeview_identity": "00112233445566778899AABBCCDDEEFF:1:driver.pdb",
        "analysis_sha256": _sha("analysis"),
        "analysis_receipt_sha256": _sha("analysis-receipt"),
    }
    item_digest = item_commitment(key, inventory_id, inventory_nonce, item)
    bundle = {
        "schema_version": BUNDLE_MANIFEST_SCHEMA,
        "construction_profile": CONSTRUCTION_PROFILE,
        "inventory_id": inventory_id,
        "inventory_nonce": inventory_nonce,
        "item_commitment_sha256": item_digest,
        "item_identity": item,
        "files": [
            {
                "role": "analysis-export",
                "relative_path": "analysis/export.json",
                "sha256": item["analysis_sha256"],
                "size_bytes": 2048,
            },
            {
                "role": "analysis-receipt",
                "relative_path": "receipts/analysis.json",
                "sha256": item["analysis_receipt_sha256"],
                "size_bytes": 412,
            },
            {
                "role": "driver",
                "relative_path": "artifacts/driver.sys",
                "sha256": item["driver_sha256"],
                "size_bytes": 8192,
            },
            {
                "role": "pdb",
                "relative_path": "symbols/driver.pdb",
                "sha256": item["pdb_sha256"],
                "size_bytes": 16384,
            },
        ],
    }
    bundle_digest = bundle_commitment(key, inventory_id, inventory_nonce, bundle)
    index = {
        "schema_version": SOURCE_INDEX_SCHEMA,
        "construction_profile": CONSTRUCTION_PROFILE,
        "commitment_scheme": COMMITMENT_SCHEME,
        "inventory_id": inventory_id,
        "inventory_nonce": inventory_nonce,
        "entries": [
            {
                "item_commitment_sha256": item_digest,
                "private_bundle_commitment_sha256": bundle_digest,
                "bundle_manifest_relative_path": "bundles/selected.json",
            }
        ],
    }
    return key, inventory_id, inventory_nonce, item, bundle, index


def test_profile_v1_golden_commitments_are_frozen() -> None:
    key, inventory_id, inventory_nonce, item, bundle, index = _objects()
    assert key_commitment(key) == "25ccfe5c1a2a9db4f1ef9ef008ce37a6826af347cb82bd1c9485612105df7633"
    assert item_commitment(key, inventory_id, inventory_nonce, item) == (
        "e961f4c0ab207232c8ad1656609fa5748e41ca68c5c260748c67f6c0be9650d7"
    )
    assert bundle_commitment(key, inventory_id, inventory_nonce, bundle) == (
        "10167d8675ed5afb1ca9655b3f540f3328d1f826ebb4664ba5dac1377b2e6d5e"
    )
    assert source_index_commitment(key, inventory_id, inventory_nonce, index) == (
        "ed3316f3e0337f271f4dbdf493119509f37d03accc82ef1dfa575abbdc6b3fa5"
    )


def test_validators_accept_exact_non_directional_private_objects() -> None:
    _key, _inventory_id, _inventory_nonce, item, bundle, index = _objects()
    validate_item_identity(item)
    validate_bundle_manifest(bundle)
    validate_source_index(index)
    encoded = str({"item": item, "bundle": bundle, "index": index})
    for forbidden in ("vulnerable", "fixed", "candidate", "control", "cve", "bounty"):
        assert forbidden not in encoded.lower()


def test_selected_tuple_cross_checks_every_private_link() -> None:
    key, inventory_id, inventory_nonce, item, bundle, index = _objects()
    selected = construct_selected_tuple(
        key,
        inventory_id,
        inventory_nonce,
        item,
        bundle,
        index,
        "bundles/selected.json",
    )
    assert selected.item_commitment_sha256 == index["entries"][0][  # type: ignore[index]
        "item_commitment_sha256"
    ]
    assert selected.private_bundle_commitment_sha256 == index["entries"][0][  # type: ignore[index]
        "private_bundle_commitment_sha256"
    ]
    assert "driver" not in str(selected)
    assert "bundles/" not in str(selected)


@pytest.mark.parametrize("mutation", ["embedded-item", "bundle-item", "index-tuple", "path"])
def test_selected_tuple_rejects_swaps(mutation: str) -> None:
    key, inventory_id, inventory_nonce, item, bundle, index = _objects()
    item = deepcopy(item)
    bundle = deepcopy(bundle)
    index = deepcopy(index)
    path = "bundles/selected.json"
    if mutation == "embedded-item":
        bundle["item_identity"]["driver_sha256"] = _sha("other-driver")  # type: ignore[index]
    elif mutation == "bundle-item":
        bundle["item_commitment_sha256"] = _sha("other-item")
    elif mutation == "index-tuple":
        index["entries"][0]["private_bundle_commitment_sha256"] = _sha(  # type: ignore[index]
            "other-bundle"
        )
    else:
        path = "bundles/other.json"
    with pytest.raises(ValueError, match=r"mismatch|absent|match the item identity"):
        construct_selected_tuple(
            key, inventory_id, inventory_nonce, item, bundle, index, path
        )


@pytest.mark.parametrize("length", [0, 31, 33])
def test_rejects_non_256_bit_keys(length: int) -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        key_commitment(b"k" * length)


def test_inventory_domain_binding_prevents_cross_inventory_reuse() -> None:
    key, inventory_id, inventory_nonce, item, _bundle, _index = _objects()
    original = item_commitment(key, inventory_id, inventory_nonce, item)
    changed_id = f"inventory-{_sha('other-inventory')}"
    assert item_commitment(key, changed_id, inventory_nonce, item) != original
    assert (
        item_commitment(
            key, inventory_id, "other-inventory-nonce-0000000000001", item
        )
        != original
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("extra-item-field", "fields mismatch"),
        ("direction-label", "fields mismatch"),
        ("bundle-parent-path", "safe relative"),
        ("bundle-unsorted", "canonically sorted"),
        ("index-absolute-path", "safe relative"),
        ("index-duplicate-item", "item commitments must be unique"),
        ("wrong-profile", "construction profile mismatch"),
    ],
)
def test_rejects_ambiguous_directional_or_unsafe_private_objects(
    mutation: str, message: str
) -> None:
    _key, _inventory_id, _inventory_nonce, item, bundle, index = _objects()
    item = deepcopy(item)
    bundle = deepcopy(bundle)
    index = deepcopy(index)
    if mutation == "extra-item-field":
        item["basename"] = "driver.sys"
        target = "item"
    elif mutation == "direction-label":
        item["role"] = "vulnerable"
        target = "item"
    elif mutation == "bundle-parent-path":
        bundle["files"][0]["relative_path"] = "../escape"  # type: ignore[index]
        target = "bundle"
    elif mutation == "bundle-unsorted":
        bundle["files"].reverse()  # type: ignore[union-attr]
        target = "bundle"
    elif mutation == "index-absolute-path":
        index["entries"][0]["bundle_manifest_relative_path"] = "/private/bundle"  # type: ignore[index]
        target = "index"
    elif mutation == "index-duplicate-item":
        duplicate = dict(index["entries"][0])  # type: ignore[index]
        duplicate["private_bundle_commitment_sha256"] = _sha("second-bundle")
        duplicate["bundle_manifest_relative_path"] = "bundles/second.json"
        index["entries"].append(duplicate)  # type: ignore[union-attr]
        index["entries"].sort(  # type: ignore[union-attr]
            key=lambda value: tuple(value.values())
        )
        target = "index"
    else:
        bundle["construction_profile"] = "caller-defined/v1"
        target = "bundle"
    with pytest.raises(ValueError, match=message):
        if target == "item":
            validate_item_identity(item)
        elif target == "bundle":
            validate_bundle_manifest(bundle)
        else:
            validate_source_index(index)


def test_bundle_and_index_must_match_explicit_inventory_arguments() -> None:
    key, inventory_id, inventory_nonce, _item, bundle, index = _objects()
    other = f"inventory-{_sha('other')}"
    with pytest.raises(ValueError, match="inventory binding mismatch"):
        bundle_commitment(key, other, inventory_nonce, bundle)
    with pytest.raises(ValueError, match="inventory binding mismatch"):
        source_index_commitment(key, inventory_id, "other-nonce-0000000000000000000001", index)


@pytest.mark.parametrize(
    "alias",
    [
        "analysis//export.json",
        "analysis/./export.json",
        "analysis/export.json/",
        "analysis\\export.json",
    ],
)
def test_rejects_noncanonical_path_aliases(alias: str) -> None:
    _key, _inventory_id, _inventory_nonce, _item, bundle, _index = _objects()
    bundle["files"][0]["relative_path"] = alias  # type: ignore[index]
    with pytest.raises(ValueError, match="safe relative"):
        validate_bundle_manifest(bundle)


def test_required_file_roles_are_singleton_and_match_item_hashes() -> None:
    _key, _inventory_id, _inventory_nonce, _item, bundle, _index = _objects()
    missing = deepcopy(bundle)
    missing["files"].pop()  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="required file roles"):
        validate_bundle_manifest(missing)

    mismatched = deepcopy(bundle)
    mismatched["files"][0]["sha256"] = _sha("wrong-analysis")  # type: ignore[index]
    with pytest.raises(ValueError, match="match the item identity"):
        validate_bundle_manifest(mismatched)

    aliased = deepcopy(bundle)
    aliased["files"][1]["relative_path"] = aliased["files"][0]["relative_path"]  # type: ignore[index]
    aliased["files"].sort(key=lambda record: (record["role"], record["relative_path"]))  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="paths must be unique"):
        validate_bundle_manifest(aliased)


def test_bundle_commitment_recomputes_embedded_item_commitment() -> None:
    key, inventory_id, inventory_nonce, _item, bundle, _index = _objects()
    bundle["item_identity"]["driver_sha256"] = _sha("substituted-driver")  # type: ignore[index]
    bundle["files"][2]["sha256"] = _sha("substituted-driver")  # type: ignore[index]
    with pytest.raises(ValueError, match="embedded item commitment mismatch"):
        bundle_commitment(key, inventory_id, inventory_nonce, bundle)
