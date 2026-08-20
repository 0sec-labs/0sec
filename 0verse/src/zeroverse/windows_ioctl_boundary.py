"""Inert, deterministic planning contract for a Windows IOCTL discovery lane.

This module does not open a device, issue an IOCTL, create payload bytes, or run a
Windows process.  It validates a synthetic fixture manifest and emits bounded
mutation *descriptors* that a future, separately authorized worker may consume.
Every result remains a candidate.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "0verse.windows-ioctl-boundary/v1"
RESULT_VERSION = "0verse.windows-ioctl-plan/v1"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_GUID = re.compile(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}")
_METHODS = {"buffered": 0, "in-direct": 1, "out-direct": 2, "neither": 3}
_ACCESS = {"any": 0, "read": 1, "write": 2, "read-write": 3}
_FIELD_KINDS = {"length", "count", "offset", "flags"}


@dataclass(frozen=True)
class MutationField:
    name: str
    offset: int
    width: int
    byte_order: str
    kind: str


@dataclass(frozen=True)
class Seed:
    sha256: str
    size: int
    fields: tuple[MutationField, ...]


@dataclass(frozen=True)
class Ioctl:
    code: int
    device_type: int
    function: int
    method: str
    access: str
    handler_name: str
    handler_rva: int
    max_output_bytes: int


def plan_windows_ioctl_boundary(manifest_path: str | Path) -> dict[str, object]:
    """Validate one inert fixture and return a deterministic bounded plan."""
    path = Path(manifest_path)
    raw_bytes = path.read_bytes()
    raw = json.loads(raw_bytes, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("Windows IOCTL boundary manifest must be a JSON object")
    _exact(
        raw,
        {
            "schema_version",
            "campaign_id",
            "synthetic_fixture",
            "scope_manifest_sha256",
            "worker",
            "target",
            "boundary",
            "budgets",
            "ioctls",
            "seeds",
            "policy",
        },
        "manifest",
    )
    if raw["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported Windows IOCTL boundary schema: {raw['schema_version']}")
    if raw["synthetic_fixture"] is not True:
        raise ValueError("v1 is an inert synthetic-fixture contract only")
    campaign_id = _identifier(raw["campaign_id"], "campaign_id")
    scope_digest = _sha(raw["scope_manifest_sha256"], "scope_manifest_sha256")
    worker = _worker(raw["worker"])
    target = _target(raw["target"])
    boundary = _boundary(raw["boundary"], worker, target)
    budgets = _budgets(raw["budgets"])
    policy = _policy(raw["policy"])
    ioctls = _ioctls(raw["ioctls"], target["device_type"], budgets)
    seeds = _seeds(raw["seeds"], budgets)

    manifest_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    rows: list[dict[str, object]] = []
    for ioctl in ioctls:
        for seed in seeds:
            for field in seed.fields:
                for value in _mutation_values(field, seed.size, budgets["max_input_bytes"]):
                    material = {
                        "manifest_sha256": manifest_sha256,
                        "ioctl_code": ioctl.code,
                        "seed_sha256": seed.sha256,
                        "field": field.name,
                        "value": value,
                    }
                    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
                    rows.append(
                        {
                            "candidate_id": hashlib.sha256(
                                b"0verse-windows-ioctl-candidate-v1\0" + encoded
                            ).hexdigest(),
                            "status": "candidate",
                            "ioctl_code": f"0x{ioctl.code:08x}",
                            "handler_name": ioctl.handler_name,
                            "handler_rva": f"0x{ioctl.handler_rva:x}",
                            "method": ioctl.method,
                            "access": ioctl.access,
                            "seed_sha256": seed.sha256,
                            "seed_size": seed.size,
                            "mutation": {
                                "field": field.name,
                                "kind": field.kind,
                                "offset": field.offset,
                                "width": field.width,
                                "byte_order": field.byte_order,
                                "value": value,
                            },
                            "max_output_bytes": ioctl.max_output_bytes,
                            "required_next_validator": (
                                "signed natural-standard-user boundary observation, then "
                                "an isolated snapshot worker with target/control adjudication"
                            ),
                        }
                    )
                    if len(rows) > budgets["max_candidates"]:
                        raise ValueError("planned candidates exceed max_candidates")

    rows.sort(
        key=lambda row: (
            int(str(row["ioctl_code"]), 16),
            str(row["seed_sha256"]),
            str(row["mutation"]["field"]),  # type: ignore[index]
            int(row["mutation"]["value"]),  # type: ignore[index]
        )
    )
    return {
        "schema_version": RESULT_VERSION,
        "campaign_id": campaign_id,
        "manifest_sha256": manifest_sha256,
        "scope_manifest_sha256": scope_digest,
        "worker": worker,
        "target": target,
        "boundary": boundary,
        "budgets": budgets,
        "policy": policy,
        "candidate_count": len(rows),
        "candidates": rows,
        "device_ioctl_attempts": 0,
        "all_results_are_candidates": True,
        "capability_measure": False,
        "claim_eligible": False,
        "bounty_eligible": False,
        "weaponization": False,
        "automatic_disclosure": False,
        "human_report_gate": True,
        "proof_limit": (
            "Synthetic deterministic planning only. This result does not prove device "
            "reachability, handler ownership, execution, a crash, vulnerability, impact, "
            "exploitability, novelty, or bounty eligibility."
        ),
    }


def _worker(raw: object) -> dict[str, object]:
    value = _object(raw, "worker")
    _exact(
        value, {"fqdn", "machine_id", "build_lab_ex", "architecture", "collector_sha256"}, "worker"
    )
    architecture = str(value["architecture"])
    if architecture not in {"amd64", "arm64"}:
        raise ValueError("worker.architecture must be amd64 or arm64")
    return {
        "fqdn": _identifier(value["fqdn"], "worker.fqdn"),
        "machine_id": _sha(value["machine_id"], "worker.machine_id"),
        "build_lab_ex": _text(value["build_lab_ex"], "worker.build_lab_ex", 256),
        "architecture": architecture,
        "collector_sha256": _sha(value["collector_sha256"], "worker.collector_sha256"),
    }


def _target(raw: object) -> dict[str, object]:
    value = _object(raw, "target")
    _exact(
        value,
        {"driver_sha256", "pdb_sha256", "analysis_receipt_sha256", "service_name", "device_type"},
        "target",
    )
    device_type = _integer(value["device_type"], "target.device_type", 0, 0xFFFF)
    return {
        "driver_sha256": _sha(value["driver_sha256"], "target.driver_sha256"),
        "pdb_sha256": _sha(value["pdb_sha256"], "target.pdb_sha256"),
        "analysis_receipt_sha256": _sha(
            value["analysis_receipt_sha256"], "target.analysis_receipt_sha256"
        ),
        "service_name": _identifier(value["service_name"], "target.service_name"),
        "device_type": device_type,
    }


def _boundary(
    raw: object, worker: dict[str, object], target: dict[str, object]
) -> dict[str, object]:
    value = _object(raw, "boundary")
    _exact(
        value,
        {
            "schema_version",
            "receipt_sha256",
            "worker_machine_id",
            "build_lab_ex",
            "driver_sha256",
            "interface_class_guid",
            "instance_id",
            "starting_context_assertion",
            "open_result_assertion",
        },
        "boundary",
    )
    if value["schema_version"] != "0verse.windows-boundary-observation/fixture-v1":
        raise ValueError("boundary fixture schema mismatch")
    if (
        value["starting_context_assertion"] != "synthetic-standard-user"
        or value["open_result_assertion"] != "synthetic-allowed"
    ):
        raise ValueError("boundary must carry only inert synthetic assertions")
    if (
        value["worker_machine_id"] != worker["machine_id"]
        or value["build_lab_ex"] != worker["build_lab_ex"]
        or value["driver_sha256"] != target["driver_sha256"]
    ):
        raise ValueError("boundary observation is not bound to worker/build/driver")
    guid = str(value["interface_class_guid"]).lower()
    if _GUID.fullmatch(guid) is None:
        raise ValueError("boundary.interface_class_guid must be a canonical braced GUID")
    return {
        "schema_version": value["schema_version"],
        "receipt_sha256": _sha(value["receipt_sha256"], "boundary.receipt_sha256"),
        "worker_machine_id": value["worker_machine_id"],
        "build_lab_ex": value["build_lab_ex"],
        "driver_sha256": value["driver_sha256"],
        "interface_class_guid": guid,
        "instance_id": _text(value["instance_id"], "boundary.instance_id", 512),
        "starting_context_assertion": value["starting_context_assertion"],
        "open_result_assertion": value["open_result_assertion"],
        "receipt_verified": False,
    }


def _budgets(raw: object) -> dict[str, int]:
    value = _object(raw, "budgets")
    _exact(
        value,
        {
            "max_ioctls",
            "max_seeds",
            "max_fields_per_seed",
            "max_candidates",
            "max_input_bytes",
            "max_output_bytes",
            "timeout_ms",
        },
        "budgets",
    )
    limits = {
        "max_ioctls": (1, 32),
        "max_seeds": (1, 64),
        "max_fields_per_seed": (1, 16),
        "max_candidates": (1, 4096),
        "max_input_bytes": (1, 1 << 20),
        "max_output_bytes": (0, 1 << 20),
        "timeout_ms": (100, 60_000),
    }
    return {
        name: _integer(value[name], f"budgets.{name}", low, high)
        for name, (low, high) in limits.items()
    }


def _policy(raw: object) -> dict[str, object]:
    value = _object(raw, "policy")
    _exact(
        value,
        {
            "owned_isolated_lab",
            "snapshot_reset_required",
            "network_allowed",
            "concurrency",
            "attempts_per_candidate",
            "runtime_enabled",
            "automatic_disclosure",
            "human_report_gate",
        },
        "policy",
    )
    expected: dict[str, object] = {
        "owned_isolated_lab": True,
        "snapshot_reset_required": True,
        "network_allowed": False,
        "concurrency": 1,
        "attempts_per_candidate": 1,
        "runtime_enabled": False,
        "automatic_disclosure": False,
        "human_report_gate": True,
    }
    if value != expected:
        raise ValueError("policy must equal the inert v1 safety policy")
    return expected


def _ioctls(raw: object, target_device_type: object, budgets: dict[str, int]) -> tuple[Ioctl, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= budgets["max_ioctls"]:
        raise ValueError("ioctls must be a nonempty bounded array")
    out: list[Ioctl] = []
    codes: set[int] = set()
    for index, item in enumerate(raw):
        value = _object(item, f"ioctls[{index}]")
        _exact(
            value,
            {
                "code",
                "device_type",
                "function",
                "method",
                "access",
                "handler_name",
                "handler_rva",
                "max_output_bytes",
            },
            f"ioctls[{index}]",
        )
        code = _integer(value["code"], f"ioctls[{index}].code", 0, 0xFFFFFFFF)
        device_type = _integer(value["device_type"], f"ioctls[{index}].device_type", 0, 0xFFFF)
        function = _integer(value["function"], f"ioctls[{index}].function", 0, 0xFFF)
        method, access = str(value["method"]), str(value["access"])
        if method != "buffered":
            raise ValueError("v1 permits only METHOD_BUFFERED descriptors")
        if access not in _ACCESS:
            raise ValueError("unsupported IOCTL access")
        if (
            device_type != target_device_type
            or (code >> 16) != device_type
            or ((code >> 2) & 0xFFF) != function
            or (code & 3) != _METHODS[method]
            or ((code >> 14) & 3) != _ACCESS[access]
        ):
            raise ValueError("IOCTL code does not match declared CTL_CODE decomposition")
        if code in codes:
            raise ValueError("duplicate IOCTL code")
        codes.add(code)
        output_cap = _integer(
            value["max_output_bytes"],
            f"ioctls[{index}].max_output_bytes",
            0,
            budgets["max_output_bytes"],
        )
        out.append(
            Ioctl(
                code,
                device_type,
                function,
                method,
                access,
                _identifier(value["handler_name"], f"ioctls[{index}].handler_name"),
                _integer(
                    value["handler_rva"], f"ioctls[{index}].handler_rva", 1, 0xFFFFFFFFFFFFFFFF
                ),
                output_cap,
            )
        )
    return tuple(sorted(out, key=lambda item: item.code))


def _seeds(raw: object, budgets: dict[str, int]) -> tuple[Seed, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= budgets["max_seeds"]:
        raise ValueError("seeds must be a nonempty bounded array")
    out: list[Seed] = []
    digests: set[str] = set()
    for index, item in enumerate(raw):
        value = _object(item, f"seeds[{index}]")
        _exact(value, {"sha256", "size", "fields"}, f"seeds[{index}]")
        digest = _sha(value["sha256"], f"seeds[{index}].sha256")
        size = _integer(value["size"], f"seeds[{index}].size", 1, budgets["max_input_bytes"])
        fields_raw = value["fields"]
        if (
            not isinstance(fields_raw, list)
            or not 1 <= len(fields_raw) <= budgets["max_fields_per_seed"]
        ):
            raise ValueError("seed fields must be a nonempty bounded array")
        fields: list[MutationField] = []
        names: set[str] = set()
        for field_index, field_raw in enumerate(fields_raw):
            field = _object(field_raw, f"seeds[{index}].fields[{field_index}]")
            _exact(
                field,
                {"name", "offset", "width", "byte_order", "kind"},
                f"seeds[{index}].fields[{field_index}]",
            )
            name = _identifier(field["name"], "mutation field name")
            width = _integer(field["width"], "mutation field width", 1, 8)
            offset = _integer(field["offset"], "mutation field offset", 0, size - 1)
            if offset + width > size:
                raise ValueError("mutation field extends beyond seed")
            if field["byte_order"] not in {"little", "big"} or field["kind"] not in _FIELD_KINDS:
                raise ValueError("unsupported mutation field encoding")
            if name in names:
                raise ValueError("duplicate mutation field name")
            names.add(name)
            fields.append(
                MutationField(name, offset, width, str(field["byte_order"]), str(field["kind"]))
            )
        if digest in digests:
            raise ValueError("duplicate seed digest")
        digests.add(digest)
        out.append(
            Seed(digest, size, tuple(sorted(fields, key=lambda item: (item.offset, item.name))))
        )
    return tuple(sorted(out, key=lambda item: item.sha256))


def _mutation_values(field: MutationField, seed_size: int, max_input: int) -> tuple[int, ...]:
    maximum = min((1 << (8 * field.width)) - 1, max_input)
    if field.kind == "flags":
        values = {0, 1, maximum}
    else:
        values = {0, 1, max(0, seed_size - 1), seed_size, min(maximum, seed_size + 1), maximum}
    return tuple(sorted(value for value in values if 0 <= value <= maximum))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _exact(raw: dict[str, Any], expected: set[str], label: str) -> None:
    if set(raw) != expected:
        raise ValueError(f"{label} fields mismatch: expected {sorted(expected)}, got {sorted(raw)}")


def _sha(raw: object, label: str) -> str:
    value = str(raw)
    if _HEX64.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _identifier(raw: object, label: str) -> str:
    value = str(raw)
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} has invalid syntax")
    return value


def _text(raw: object, label: str, maximum: int) -> str:
    value = str(raw)
    if not value.strip() or len(value) > maximum or any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{label} must be bounded printable text")
    return value


def _integer(raw: object, label: str, low: int, high: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not low <= raw <= high:
        raise ValueError(f"{label} must be an integer in [{low}, {high}]")
    return raw
