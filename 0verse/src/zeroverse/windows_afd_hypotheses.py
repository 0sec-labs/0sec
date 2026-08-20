"""Custody-bound, non-executing paired AFD handler-analysis hypotheses."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from .windows_afd_selector import (
    EXPORT_VERSION as SELECTOR_VERSION,
)
from .windows_afd_selector import (
    _remove_tree_at,
    _snapshot_selector_bundle,
    _verify_snapshotted_selector_bundle,
    canonical_selector_bytes,
)
from .windows_afd_selector import (
    _validate as _validate_selector,
)
from .windows_driver_registration import (
    _exact,
    _hex,
    _obj,
    _read_regular_file_at,
    _sha,
    _snapshot_file_from_dirfd,
    _unique,
)
from .windows_variant import (
    _create_staging_directory,
    _open_directory_ancestry,
    _publish_directory_no_replace,
    _require_directory_path_identity,
    _write_new_file_at,
)

EXPORT_VERSION = "0verse.windows-afd-hypotheses/v1"
RECEIPT_VERSION = "0verse.windows-afd-hypotheses-receipt/v1"
PRODUCER = "zeroverse.windows-afd-hypotheses/v1"
_EXPECTED_ROWS = 74
_EXPECTED_CLASSES = 33
_OBJECTIVE = (
    "extract and compare normalized request-source, sensitive-sink, local semantic-proof, "
    "guard, CFG, and bounded function-body commitments for the two exact selected entries"
)
_ALTERNATIVE = (
    "preferred-base RVA and table-byte differences may reflect relocation, layout, or "
    "unrelated code-generation drift rather than a security-relevant semantic change"
)
_NEXT = (
    "custody-bound paired handler-semantics extraction for these exact function entries; "
    "no device open, IOCTL, driver load, or runtime promotion"
)
_STATIC_LIMITS = {
    "max_function_bytes_per_side": 65536,
    "max_instructions_per_side": 20000,
    "max_basic_blocks_per_side": 4096,
    "max_pcode_ops_per_side": 100000,
    "max_wall_clock_seconds_per_side": 300,
}
_PROOF_LIMIT = (
    "Operator-declared paired static-analysis scheduling over equal 74-key local-selector "
    "alias topology only. No servicing lineage or adjacency, vulnerable/fixed role, patch "
    "causality, handler-body semantics, source/sink flow, guard delta, effective/runtime "
    "registration, runtime or unprivileged reachability, execution, candidate, crash, "
    "vulnerability, LPE, exploitability, novelty, bounty eligibility, or weaponization."
)
_CONFIG = {
    "selector_schema": SELECTOR_VERSION,
    "row_count": _EXPECTED_ROWS,
    "alias_class_count": _EXPECTED_CLASSES,
    "pairing": "equal-key-bytes-and-equal-row-alias-partition",
    "ordering": "canonical-min-row-enumeration",
    "work": "paired-static-handler-semantic-extraction",
    "static_limits": dict(_STATIC_LIMITS),
}
CONFIG_SHA256 = hashlib.sha256(
    json.dumps(_CONFIG, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


def compile_windows_afd_hypotheses(
    side_a_raw: object,
    side_b_raw: object,
    *,
    side_a_receipt_sha256: str,
    side_b_receipt_sha256: str,
) -> dict[str, object]:
    """Compile two already verified selector exports into inert work descriptors."""
    side_a = _selector(side_a_raw, "side A")
    side_b = _selector(side_b_raw, "side B")
    receipts = (
        _sha(side_a_receipt_sha256, "side A selector receipt"),
        _sha(side_b_receipt_sha256, "side B selector receipt"),
    )
    if side_a["driver_sha256"] == side_b["driver_sha256"]:
        raise ValueError("AFD hypotheses require two distinct driver artifacts")
    for field in ("architecture", "selector"):
        if side_a[field] != side_b[field]:
            raise ValueError(f"AFD selector pair {field} differs")
    if _partition_semantics(side_a["partition"]) != _partition_semantics(side_b["partition"]):
        raise ValueError("AFD selector pair partition semantics differ")
    if side_a["key_table"]["addressed_bytes"] != side_b["key_table"]["addressed_bytes"]:
        raise ValueError("AFD selector pair key-table bytes differ")
    rows_a = cast(list[dict[str, Any]], side_a["rows"])
    rows_b = cast(list[dict[str, Any]], side_b["rows"])
    if [(row["index"], row["key"]) for row in rows_a] != [
        (row["index"], row["key"]) for row in rows_b
    ]:
        raise ValueError("AFD selector pair row keys differ")
    groups_a = _alias_groups(rows_a)
    groups_b = _alias_groups(rows_b)
    if [indices for indices, _rva in groups_a] != [indices for indices, _rva in groups_b]:
        raise ValueError("AFD selector pair alias topology differs")
    if len(groups_a) != _EXPECTED_CLASSES:
        raise ValueError("AFD hypotheses v1 requires the reviewed 33-class topology")
    modal_size = max(len(indices) for indices, _rva in groups_a)
    if sum(len(indices) == modal_size for indices, _rva in groups_a) != 1:
        raise ValueError("AFD selector pair requires one unique modal alias class")
    paired = list(zip(groups_a, groups_b, strict=True))
    side_records = {
        "side_a": _side_record(side_a, receipts[0], "side-a-selector"),
        "side_b": _side_record(side_b, receipts[1], "side-b-selector"),
    }
    hypotheses: list[dict[str, object]] = []
    for order, ((indices, rva_a), (other_indices, rva_b)) in enumerate(paired, 1):
        if indices != other_indices:
            raise ValueError("AFD selector pair alias topology changed during compilation")
        keys = [rows_a[index]["key"] for index in indices]
        material = {
            "side_a_selector_sha256": side_records["side_a"]["selector_sha256"],
            "side_b_selector_sha256": side_records["side_b"]["selector_sha256"],
            "row_indices": list(indices),
            "ioctl_keys": keys,
            "side_a_target_rva": rva_a,
            "side_b_target_rva": rva_b,
        }
        hypothesis_id = hashlib.sha256(
            b"0verse-windows-afd-handler-hypothesis-v1\0" + _canonical(material)
        ).hexdigest()
        hypotheses.append(
            {
                "enumeration_order": order,
                "hypothesis_id": hypothesis_id,
                "kind": "paired-static-handler-semantic-extraction",
                "status": "analysis-hypothesis",
                "row_indices": list(indices),
                "ioctl_keys": keys,
                "modal_alias_class": len(indices) == modal_size,
                "side_a_target_rva": rva_a,
                "side_b_target_rva": rva_b,
                "max_function_entries_per_side": 1,
                "static_limits": _STATIC_LIMITS,
                "runtime_consumable": False,
                "attempts": {
                    "driver_load": 0,
                    "device_open": 0,
                    "device_ioctl": 0,
                    "runtime": 0,
                    "model_invocations": 0,
                    "network": False,
                },
                "objective": _OBJECTIVE,
                "alternative_explanation": _ALTERNATIVE,
                "required_next_validator": _NEXT,
            }
        )
    result = {
        "schema_version": EXPORT_VERSION,
        "producer": PRODUCER,
        "compiler_config_sha256": CONFIG_SHA256,
        "pair_role": "operator-declared-order-only",
        "sides": side_records,
        "comparison": {
            "addressed_rows": _EXPECTED_ROWS,
            "key_table_bytes_equal": True,
            "row_key_mapping_equal": True,
            "alias_partition_equal": True,
            "alias_class_count": _EXPECTED_CLASSES,
            "unique_modal_alias_class": True,
            "servicing_lineage_established": False,
            "servicing_adjacency_established": False,
            "vulnerable_fixed_roles_established": False,
            "patch_causality_established": False,
        },
        "hypothesis_count": len(hypotheses),
        "hypotheses": hypotheses,
        "candidate_count": 0,
        "candidate_established": False,
        "handler_identity_established": False,
        "handler_body_semantics_established": False,
        "handler_body_change_established": False,
        "ranking_performed": False,
        "labels_consumed": False,
        "ground_truth_consumed": False,
        "network_performed": False,
        "model_invocations": 0,
        "driver_load_attempts": 0,
        "device_open_attempts": 0,
        "runtime_attempts": 0,
        "runtime_reachability_established": False,
        "unprivileged_reachability_established": False,
        "device_ioctl_attempts": 0,
        "runtime_consumable": False,
        "execution_authorized": False,
        "vulnerability_established": False,
        "lpe_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "claim_eligible": False,
        "bounty_eligible": False,
        "weaponization": False,
        "automatic_disclosure": False,
        "human_promotion_gate": True,
        "proof_limit": _PROOF_LIMIT,
    }
    return _validate(result)


def canonical_hypotheses_bytes(raw: object) -> bytes:
    return _canonical(_validate(raw)) + b"\n"


def produce_windows_afd_hypotheses(
    side_a_bundle: str | Path,
    side_b_bundle: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
) -> dict[str, str]:
    output = Path(os.path.abspath(output_dir))  # noqa: PTH100 - lexical publication path
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody path
    if output.exists() or output.is_symlink():
        raise FileExistsError("AFD hypotheses output already exists")
    parent_fd = _open_directory_ancestry(output.parent, "AFD hypotheses output parent")
    source_a_fd = -1
    source_b_fd = -1
    temporary_name, temporary_fd, published = "", -1, False
    try:
        source_a_fd = _open_directory_ancestry(Path(side_a_bundle), "side A selector source")
        source_b_fd = _open_directory_ancestry(Path(side_b_bundle), "side B selector source")
        _require_directory_path_identity(output.parent, parent_fd, "AFD hypotheses output parent")
        with TemporaryDirectory(prefix="zeroverse-afd-hypotheses-produce-") as private:
            retained = Path(private).resolve(strict=True) / "bundle"
            retained.mkdir(mode=0o700)
            retained_fd = os.open(retained, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for name, source_fd in (
                    ("side-a-selector", source_a_fd),
                    ("side-b-selector", source_b_fd),
                ):
                    os.mkdir(name, 0o700, dir_fd=retained_fd)
                    destination_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=retained_fd,
                    )
                    try:
                        _snapshot_selector_bundle(source_fd, destination_fd)
                    finally:
                        os.close(destination_fd)
                side_a_path = retained / "side-a-selector"
                side_b_path = retained / "side-b-selector"
                side_a = _verify_snapshotted_selector_bundle(side_a_path, home)
                side_b = _verify_snapshotted_selector_bundle(side_b_path, home)
                receipt_a = _sha_file(side_a_path / "receipt.json")
                receipt_b = _sha_file(side_b_path / "receipt.json")
                export = compile_windows_afd_hypotheses(
                    side_a,
                    side_b,
                    side_a_receipt_sha256=receipt_a,
                    side_b_receipt_sha256=receipt_b,
                )
                artifact_bytes = canonical_hypotheses_bytes(export)
                artifact_sha = _write_new_file_at(retained_fd, "hypotheses.json", artifact_bytes)
                receipt = {
                    "schema_version": RECEIPT_VERSION,
                    "producer": PRODUCER,
                    "hypotheses_path": "hypotheses.json",
                    "hypotheses_sha256": artifact_sha,
                    "side_a_selector_bundle": "side-a-selector",
                    "side_a_selector_receipt_sha256": receipt_a,
                    "side_b_selector_bundle": "side-b-selector",
                    "side_b_selector_receipt_sha256": receipt_b,
                    "compiler_config_sha256": CONFIG_SHA256,
                    "static_only": True,
                    "execution_authorized": False,
                    "device_ioctl_attempts": 0,
                }
                receipt_bytes = json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n"
                _write_new_file_at(retained_fd, "receipt.json", receipt_bytes)
                os.fsync(retained_fd)
                _verify_snapshotted_hypotheses_bundle(retained, home)
                temporary_name, temporary_fd = _create_staging_directory(
                    parent_fd, f".{output.name}.tmp-"
                )
                _snapshot_hypotheses_bundle(retained_fd, temporary_fd)
                os.fsync(temporary_fd)
            finally:
                os.close(retained_fd)
        _require_directory_path_identity(output.parent, parent_fd, "AFD hypotheses output parent")
        _publish_directory_no_replace(parent_fd, temporary_name, output.name)
        os.fsync(parent_fd)
        published = True
        return {
            "hypotheses_path": f"{output.name}/hypotheses.json",
            "hypotheses_sha256": artifact_sha,
            "receipt_path": f"{output.name}/receipt.json",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        }
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name and not published:
            _remove_tree_at(parent_fd, temporary_name)
        if source_b_fd >= 0:
            os.close(source_b_fd)
        if source_a_fd >= 0:
            os.close(source_a_fd)
        os.close(parent_fd)


def verify_windows_afd_hypotheses_bundle(
    bundle_path: str | Path, *, ghidra_home: str | Path
) -> dict[str, object]:
    source_fd = _open_directory_ancestry(Path(bundle_path), "AFD hypotheses bundle")
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody path
    try:
        with TemporaryDirectory(prefix="zeroverse-afd-hypotheses-verify-") as temporary:
            retained = Path(temporary).resolve(strict=True) / "bundle"
            retained.mkdir(mode=0o700)
            retained_fd = os.open(retained, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _snapshot_hypotheses_bundle(source_fd, retained_fd)
                os.fsync(retained_fd)
            finally:
                os.close(retained_fd)
            return _verify_snapshotted_hypotheses_bundle(retained, home)
    finally:
        os.close(source_fd)


def _verify_snapshotted_hypotheses_bundle(bundle: Path, home: Path) -> dict[str, object]:
    bundle_fd = _open_directory_ancestry(bundle, "retained AFD hypotheses bundle")
    try:
        receipt_bytes = _read_regular_file_at(
            bundle_fd, "receipt.json", "AFD hypotheses receipt", 1024 * 1024
        )
        receipt = _obj(
            json.loads(receipt_bytes, object_pairs_hook=_unique), "AFD hypotheses receipt"
        )
        _validate_receipt(receipt)
        artifact_bytes = _read_regular_file_at(
            bundle_fd, "hypotheses.json", "AFD hypotheses artifact", 16 * 1024 * 1024
        )
        if hashlib.sha256(artifact_bytes).hexdigest() != receipt["hypotheses_sha256"]:
            raise ValueError("AFD hypotheses artifact SHA-256 mismatch")
        artifact = _validate(json.loads(artifact_bytes, object_pairs_hook=_unique))
        if canonical_hypotheses_bytes(artifact) != artifact_bytes:
            raise ValueError("AFD hypotheses artifact is not canonical")
        side_a_path, side_b_path = bundle / "side-a-selector", bundle / "side-b-selector"
        side_a = _verify_snapshotted_selector_bundle(side_a_path, home)
        side_b = _verify_snapshotted_selector_bundle(side_b_path, home)
        receipt_a, receipt_b = _sha_file(side_a_path / "receipt.json"), _sha_file(
            side_b_path / "receipt.json"
        )
        if (
            receipt_a != receipt["side_a_selector_receipt_sha256"]
            or receipt_b != receipt["side_b_selector_receipt_sha256"]
        ):
            raise ValueError("AFD hypotheses retained selector receipt mismatch")
        replay = compile_windows_afd_hypotheses(
            side_a,
            side_b,
            side_a_receipt_sha256=receipt_a,
            side_b_receipt_sha256=receipt_b,
        )
        if canonical_hypotheses_bytes(replay) != artifact_bytes:
            raise ValueError("AFD hypotheses replay mismatch")
        return artifact
    finally:
        os.close(bundle_fd)


def _snapshot_hypotheses_bundle(source_fd: int, destination_fd: int) -> None:
    for name, limit in (("receipt.json", 1024 * 1024), ("hypotheses.json", 16 * 1024 * 1024)):
        _snapshot_file_from_dirfd(
            source_fd, name, destination_fd, name, "AFD hypotheses retained file", limit
        )
    for name in ("side-a-selector", "side-b-selector"):
        source_side_fd = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd
        )
        destination_side_fd = -1
        try:
            os.mkdir(name, 0o700, dir_fd=destination_fd)
            destination_side_fd = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination_fd
            )
            _snapshot_selector_bundle(source_side_fd, destination_side_fd)
        finally:
            if destination_side_fd >= 0:
                os.close(destination_side_fd)
            os.close(source_side_fd)


def _selector(raw: object, label: str) -> dict[str, Any]:
    try:
        value = cast(dict[str, Any], _validate_selector(raw))
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid selector-v1 export") from exc
    if (
        value.get("static_only") is not True
        or value.get("execution_authorized") is not False
        or value.get("device_ioctl_attempts") != 0
        or value.get("candidate_count") != 0
        or value.get("selector_inventory_complete") is not False
    ):
        raise ValueError(f"{label} selector claim boundary mismatch")
    rows = value.get("rows")
    if not isinstance(rows, list) or len(rows) != _EXPECTED_ROWS:
        raise ValueError(f"{label} selector row extent mismatch")
    if _obj(value.get("accounting"), f"{label} accounting").get("unique_targets") != 33:
        raise ValueError(f"{label} selector unique-target topology mismatch")
    return value


def _partition_semantics(raw: object) -> dict[str, object]:
    value = _obj(raw, "selector partition")
    return {
        key: value[key]
        for key in (
            "predicate_import",
            "tested_register",
            "local_branch",
            "alternate_branch",
            "alternate_import",
            "alternate_resolved",
        )
    }


def _alias_groups(rows: list[dict[str, Any]]) -> list[tuple[tuple[int, ...], str]]:
    by_target: dict[str, list[int]] = {}
    for expected, row_raw in enumerate(rows):
        row = _obj(row_raw, "selector row")
        if row.get("index") != expected:
            raise ValueError("AFD selector row order is not canonical")
        target = str(row.get("target_rva"))
        _hex(target, "selector row target")
        by_target.setdefault(target, []).append(expected)
    return sorted(
        ((tuple(indices), target) for target, indices in by_target.items()),
        key=lambda item: item[0],
    )


def _side_record(selector: dict[str, Any], receipt_sha: str, path: str) -> dict[str, object]:
    registration = _obj(selector["registration_commitment"], "selector registration")
    return {
        "path": path,
        "selector_schema": SELECTOR_VERSION,
        "selector_sha256": hashlib.sha256(canonical_selector_bytes(selector)).hexdigest(),
        "selector_receipt_sha256": receipt_sha,
        "driver_sha256": selector["driver_sha256"],
        "pdb_sha256": selector["pdb_sha256"],
        "registration_artifact_sha256": registration["artifact_sha256"],
        "registration_receipt_sha256": registration["receipt_sha256"],
        "selected_handler_rva": registration["handler_rva"],
        "key_table_sha256": _obj(selector["key_table"], "key table")["addressed_sha256"],
        "function_table_sha256": _obj(selector["function_table"], "function table")[
            "addressed_sha256"
        ],
    }


def _validate(raw: object) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), "AFD hypotheses")
    fields = {
        "schema_version", "producer", "compiler_config_sha256", "pair_role", "sides",
        "comparison", "hypothesis_count", "hypotheses", "candidate_count",
        "candidate_established", "handler_identity_established",
        "handler_body_semantics_established", "handler_body_change_established",
        "ranking_performed", "labels_consumed", "ground_truth_consumed",
        "network_performed", "model_invocations", "driver_load_attempts",
        "device_open_attempts", "runtime_attempts",
        "runtime_reachability_established", "unprivileged_reachability_established",
        "device_ioctl_attempts", "runtime_consumable", "execution_authorized",
        "vulnerability_established",
        "lpe_established", "exploitability_established", "novelty_established",
        "claim_eligible", "bounty_eligible", "weaponization", "automatic_disclosure",
        "human_promotion_gate", "proof_limit",
    }
    _exact(value, fields, "AFD hypotheses")
    if (
        value["schema_version"] != EXPORT_VERSION
        or value["producer"] != PRODUCER
        or value["compiler_config_sha256"] != CONFIG_SHA256
        or value["pair_role"] != "operator-declared-order-only"
        or not _exact_int(value["hypothesis_count"], _EXPECTED_CLASSES)
        or not _exact_int(value["candidate_count"], 0)
        or not _exact_int(value["device_ioctl_attempts"], 0)
        or not _exact_int(value["model_invocations"], 0)
        or not _exact_int(value["driver_load_attempts"], 0)
        or not _exact_int(value["device_open_attempts"], 0)
        or not _exact_int(value["runtime_attempts"], 0)
        or value["human_promotion_gate"] is not True
        or value["proof_limit"] != _PROOF_LIMIT
    ):
        raise ValueError("AFD hypotheses contract mismatch")
    false_fields = fields - {
        "schema_version", "producer", "compiler_config_sha256", "pair_role", "sides",
        "comparison", "hypothesis_count", "hypotheses", "device_ioctl_attempts",
        "model_invocations", "driver_load_attempts", "device_open_attempts",
        "runtime_attempts", "candidate_count", "human_promotion_gate", "proof_limit",
    }
    if any(value[field] is not False for field in false_fields):
        raise ValueError("AFD hypotheses claim boundary mismatch")
    sides = _obj(value["sides"], "AFD hypotheses sides")
    _exact(sides, {"side_a", "side_b"}, "AFD hypotheses sides")
    for label, path in (("side_a", "side-a-selector"), ("side_b", "side-b-selector")):
        side = _obj(sides[label], label)
        _exact(side, {
            "path", "selector_schema", "selector_sha256", "selector_receipt_sha256",
            "driver_sha256", "pdb_sha256", "registration_artifact_sha256",
            "registration_receipt_sha256", "selected_handler_rva", "key_table_sha256",
            "function_table_sha256",
        }, label)
        if side["path"] != path or side["selector_schema"] != SELECTOR_VERSION:
            raise ValueError("AFD hypotheses side topology mismatch")
        for key in (
            "selector_sha256", "selector_receipt_sha256", "driver_sha256", "pdb_sha256",
            "registration_artifact_sha256", "registration_receipt_sha256", "key_table_sha256",
            "function_table_sha256",
        ):
            _sha(side[key], f"{label}.{key}")
        _hex(side["selected_handler_rva"], f"{label}.selected_handler_rva")
    comparison = _obj(value["comparison"], "AFD hypotheses comparison")
    expected_comparison = {
        "addressed_rows": 74, "key_table_bytes_equal": True, "row_key_mapping_equal": True,
        "alias_partition_equal": True, "alias_class_count": 33,
        "unique_modal_alias_class": True, "servicing_lineage_established": False,
        "servicing_adjacency_established": False, "vulnerable_fixed_roles_established": False,
        "patch_causality_established": False,
    }
    if comparison != expected_comparison:
        raise ValueError("AFD hypotheses comparison boundary mismatch")
    hypotheses = value["hypotheses"]
    if not isinstance(hypotheses, list) or len(hypotheses) != 33:
        raise ValueError("AFD hypotheses worklist extent mismatch")
    seen_rows: list[int] = []
    seen_ids: set[str] = set()
    modal = 0
    for order, raw_row in enumerate(hypotheses, 1):
        row = _obj(raw_row, "AFD hypothesis")
        _exact(row, {
            "enumeration_order", "hypothesis_id", "kind", "status", "row_indices", "ioctl_keys",
            "modal_alias_class", "side_a_target_rva", "side_b_target_rva",
            "max_function_entries_per_side", "static_limits", "runtime_consumable",
            "attempts", "objective", "alternative_explanation",
            "required_next_validator",
        }, "AFD hypothesis")
        indices, keys = row["row_indices"], row["ioctl_keys"]
        static_limits = row["static_limits"]
        if (
            not _exact_int(row["enumeration_order"], order)
            or row["kind"] != "paired-static-handler-semantic-extraction"
            or row["status"] != "analysis-hypothesis"
            or not isinstance(indices, list) or not indices
            or indices != sorted(set(indices))
            or not isinstance(keys, list) or len(keys) != len(indices)
            or not _exact_int(row["max_function_entries_per_side"], 1)
            or not isinstance(static_limits, dict)
            or set(static_limits) != set(_STATIC_LIMITS)
            or any(
                type(static_limits[name]) is not int
                or static_limits[name] != expected
                for name, expected in _STATIC_LIMITS.items()
            )
            or row["runtime_consumable"] is not False
            or not isinstance(row["attempts"], dict)
            or set(row["attempts"]) != {
                "driver_load", "device_open", "device_ioctl", "runtime",
                "model_invocations", "network",
            }
            or any(
                not _exact_int(row["attempts"][name], 0)
                for name in (
                    "driver_load", "device_open", "device_ioctl", "runtime", "model_invocations"
                )
            )
            or row["attempts"]["network"] is not False
            or row["attempts"] != {
                "driver_load": 0, "device_open": 0, "device_ioctl": 0, "runtime": 0,
                "model_invocations": 0, "network": False,
            }
            or row["objective"] != _OBJECTIVE
            or row["alternative_explanation"] != _ALTERNATIVE
            or row["required_next_validator"] != _NEXT
        ):
            raise ValueError("AFD hypothesis descriptor mismatch")
        for index, key in zip(indices, keys, strict=True):
            if type(index) is not int or not 0 <= index < 74:
                raise ValueError("AFD hypothesis row index mismatch")
            key_value = _hex(key, "AFD hypothesis IOCTL key")
            if ((key_value >> 2) & 0x3FF) != index:
                raise ValueError("AFD hypothesis IOCTL key/index mismatch")
        _hex(row["side_a_target_rva"], "side A target")
        _hex(row["side_b_target_rva"], "side B target")
        hypothesis_id = _sha(row["hypothesis_id"], "hypothesis_id")
        expected_id = hashlib.sha256(
            b"0verse-windows-afd-handler-hypothesis-v1\0"
            + _canonical(
                {
                    "side_a_selector_sha256": sides["side_a"]["selector_sha256"],
                    "side_b_selector_sha256": sides["side_b"]["selector_sha256"],
                    "row_indices": indices,
                    "ioctl_keys": keys,
                    "side_a_target_rva": row["side_a_target_rva"],
                    "side_b_target_rva": row["side_b_target_rva"],
                }
            )
        ).hexdigest()
        if hypothesis_id != expected_id:
            raise ValueError("AFD hypothesis identity mismatch")
        if hypothesis_id in seen_ids:
            raise ValueError("duplicate AFD hypothesis identity")
        seen_ids.add(hypothesis_id)
        seen_rows.extend(indices)
        if row["modal_alias_class"] is not True and row["modal_alias_class"] is not False:
            raise ValueError("AFD hypothesis modal flag mismatch")
        modal += row["modal_alias_class"] is True
    class_sizes = [len(row["row_indices"]) for row in hypotheses]
    maximum_size = max(class_sizes)
    modal_flags = [row["modal_alias_class"] for row in hypotheses]
    minima = [min(row["row_indices"]) for row in hypotheses]
    if (
        sorted(seen_rows) != list(range(74))
        or modal != 1
        or class_sizes.count(maximum_size) != 1
        or modal_flags != [size == maximum_size for size in class_sizes]
        or minima != sorted(minima)
    ):
        raise ValueError("AFD hypothesis partition mismatch")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def _validate_receipt(receipt: dict[str, Any]) -> None:
    _exact(receipt, {
        "schema_version", "producer", "hypotheses_path", "hypotheses_sha256",
        "side_a_selector_bundle", "side_a_selector_receipt_sha256", "side_b_selector_bundle",
        "side_b_selector_receipt_sha256", "compiler_config_sha256", "static_only",
        "execution_authorized", "device_ioctl_attempts",
    }, "AFD hypotheses receipt")
    if (
        receipt["schema_version"] != RECEIPT_VERSION or receipt["producer"] != PRODUCER
        or receipt["hypotheses_path"] != "hypotheses.json"
        or receipt["side_a_selector_bundle"] != "side-a-selector"
        or receipt["side_b_selector_bundle"] != "side-b-selector"
        or receipt["compiler_config_sha256"] != CONFIG_SHA256
        or receipt["static_only"] is not True or receipt["execution_authorized"] is not False
        or not _exact_int(receipt["device_ioctl_attempts"], 0)
    ):
        raise ValueError("AFD hypotheses receipt contract mismatch")
    for key in (
        "hypotheses_sha256", "side_a_selector_receipt_sha256", "side_b_selector_receipt_sha256"
    ):
        _sha(receipt[key], key)


def _canonical(raw: object) -> bytes:
    return json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()


def _exact_int(raw: object, expected: int) -> bool:
    return type(raw) is int and raw == expected


def _sha_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)
