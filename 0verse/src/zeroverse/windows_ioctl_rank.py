"""Rank hash-bound static IOCTL SSA evidence without executing a device call."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .windows_ioctl_boundary import plan_windows_ioctl_boundary
from .windows_variant import _load_artifact

SCHEMA_VERSION = "0verse.windows-ioctl-static-campaign/v1"
EXPORT_VERSION = "0verse.windows-ioctl-ssa-export/v1"
RESULT_VERSION = "0verse.windows-ioctl-static-candidates/v1"
SCORE_VERSION = "0verse.windows-ioctl-static-score/v1"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SOURCES = {"SystemBuffer", "InputBufferLength", "OutputBufferLength"}
_SINKS = {"copy", "fill", "indexed-store", "allocation"}
_GUARDS = {
    "input-buffer-length",
    "output-buffer-length",
    "field-within-input",
    "checked-arithmetic",
    "previous-mode",
}
_FIELD_KINDS = {"length", "count", "offset", "flags"}


def rank_windows_ioctl_static(campaign_path: str | Path) -> dict[str, object]:
    """Validate one inert campaign and rank its exact static SSA evidence."""
    campaign_file = Path(campaign_path)
    campaign_bytes = _read_bounded(campaign_file, 1024 * 1024, "static campaign")
    raw = _load_object(campaign_bytes, "static campaign")
    _exact(
        raw,
        {
            "schema_version",
            "plan_path",
            "plan_sha256",
            "analysis_path",
            "analysis_sha256",
            "artifact",
        },
        "static campaign",
    )
    if raw["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported Windows IOCTL static campaign schema")
    plan_file = _relative_file(campaign_file.parent, raw["plan_path"], "plan_path")
    analysis_file = _relative_file(campaign_file.parent, raw["analysis_path"], "analysis_path")
    plan_bytes = _read_bounded(plan_file, 4 * 1024 * 1024, "IOCTL plan")
    analysis_bytes = _read_bounded(analysis_file, 16 * 1024 * 1024, "SSA export")
    if hashlib.sha256(plan_bytes).hexdigest() != _sha(raw["plan_sha256"], "plan_sha256"):
        raise ValueError("Windows IOCTL plan SHA-256 mismatch")
    if hashlib.sha256(analysis_bytes).hexdigest() != _sha(
        raw["analysis_sha256"], "analysis_sha256"
    ):
        raise ValueError("Windows IOCTL SSA export SHA-256 mismatch")

    artifact_raw = _object(raw["artifact"], "artifact")
    _preflight_artifact_files(campaign_file.parent, artifact_raw)
    artifact = _load_artifact(artifact_raw, campaign_file.parent, "artifact")
    if not artifact.synthetic_fixture:
        raise ValueError("static ranker v1 accepts synthetic analysis fixtures only")
    plan = plan_windows_ioctl_boundary(plan_file)
    plan_digest = hashlib.sha256(plan_bytes).hexdigest()
    if plan["manifest_sha256"] != plan_digest:
        raise ValueError("Windows IOCTL plan changed while it was being verified")
    export = _load_object(analysis_bytes, "SSA export")
    _exact(
        export,
        {
            "schema_version",
            "producer",
            "driver_sha256",
            "dispatches",
        },
        "SSA export",
    )
    if export["schema_version"] != EXPORT_VERSION or export["producer"] != "ghidra-high-pcode":
        raise ValueError("unsupported Windows IOCTL SSA export contract")
    target = _object(plan["target"], "plan.target")
    if analysis_file.resolve() != artifact.export_path.resolve():
        raise ValueError("SSA evidence must be the exact receipt-bound Ghidra export")
    if hashlib.sha256(analysis_bytes).hexdigest() != artifact.export_sha256:
        raise ValueError("SSA evidence differs from the verified Ghidra export")
    if (
        export["driver_sha256"] != target["driver_sha256"]
        or artifact.binary_sha256 != target["driver_sha256"]
    ):
        raise ValueError("SSA export driver is not bound to the IOCTL plan")
    if target["analysis_receipt_sha256"] != artifact.analysis_receipt_sha256:
        raise ValueError("IOCTL plan is not bound to the verified analysis receipt")
    if not artifact.synthetic_fixture and target["pdb_sha256"] != artifact.pdb_sha256:
        raise ValueError("IOCTL plan is not bound to the verified PDB")
    plan_rows = _plan_rows(plan)
    dispatches = export["dispatches"]
    if not isinstance(dispatches, list) or not 1 <= len(dispatches) <= 32:
        raise ValueError("SSA export dispatches must be a nonempty bounded array")
    seen_codes: set[int] = set()
    seen_candidate_ids: set[str] = set()
    candidates: list[dict[str, object]] = []
    for index, item in enumerate(dispatches):
        dispatch = _object(item, f"dispatches[{index}]")
        _exact(
            dispatch,
            {
                "ioctl_code",
                "handler_name",
                "handler_rva",
                "registration_rva",
                "dispatch_resolved",
                "unresolved_edges",
                "fields",
            },
            f"dispatches[{index}]",
        )
        code = _integer(dispatch["ioctl_code"], "ioctl_code", 0, 0xFFFFFFFF)
        if code in seen_codes:
            raise ValueError("duplicate SSA IOCTL dispatch")
        seen_codes.add(code)
        if dispatch["dispatch_resolved"] is not True or dispatch["unresolved_edges"] != []:
            raise ValueError("SSA IOCTL dispatch has unresolved edges")
        registration_rva = _integer(
            dispatch["registration_rva"], "registration_rva", 1, 0xFFFFFFFFFFFFFFFF
        )
        matching = plan_rows.get(code)
        if matching is None:
            raise ValueError("SSA export contains an IOCTL outside the exact plan")
        if (
            dispatch["handler_name"] != matching["handler_name"]
            or f"0x{_integer(dispatch['handler_rva'], 'handler_rva', 1, 0xFFFFFFFFFFFFFFFF):x}"
            != matching["handler_rva"]
            or matching["method"] != "buffered"
        ):
            raise ValueError("SSA IOCTL handler evidence differs from the exact plan")
        fields = dispatch["fields"]
        if not isinstance(fields, list) or not 1 <= len(fields) <= 16:
            raise ValueError("SSA IOCTL fields must be a nonempty bounded array")
        seen_fields: set[tuple[object, ...]] = set()
        for field_index, field_raw in enumerate(fields):
            field = _object(field_raw, f"dispatches[{index}].fields[{field_index}]")
            _exact(
                field,
                {
                    "name",
                    "offset",
                    "width",
                    "kind",
                    "source",
                    "source_inst_id",
                    "sink_kind",
                    "sink_function",
                    "sink_address",
                    "sink_inst_id",
                    "guards",
                },
                f"dispatches[{index}].fields[{field_index}]",
            )
            key = (
                str(field["name"]),
                _integer(field["offset"], "field.offset", 0, 1 << 20),
                _integer(field["width"], "field.width", 1, 8),
                str(field["kind"]),
            )
            if key[3] not in _FIELD_KINDS or key not in matching["fields"]:
                raise ValueError("SSA field geometry is not bound to a planned seed field")
            source = str(field["source"])
            sink_kind = str(field["sink_kind"])
            if source not in _SOURCES or sink_kind not in _SINKS:
                raise ValueError("unsupported SSA source or sink")
            guards_raw = field["guards"]
            if (
                not isinstance(guards_raw, list)
                or any(not isinstance(value, str) for value in guards_raw)
                or guards_raw != sorted(set(guards_raw))
                or not set(guards_raw) <= _GUARDS
            ):
                raise ValueError("SSA guards must be a sorted unique supported array")
            required = {"input-buffer-length", "field-within-input"}
            if key[3] in {"length", "count", "offset"}:
                required.add("checked-arithmetic")
            missing = sorted(required - set(guards_raw))
            if not missing:
                continue
            evidence = {
                "ioctl_code": f"0x{code:08x}",
                "registration_rva": f"0x{registration_rva:x}",
                "handler_name": dispatch["handler_name"],
                "handler_rva": matching["handler_rva"],
                "source": source,
                "source_inst_id": _integer(field["source_inst_id"], "source_inst_id", 1, 1 << 63),
                "field": {"name": key[0], "offset": key[1], "width": key[2], "kind": key[3]},
                "sink_kind": sink_kind,
                "sink_function": _text(field["sink_function"], "sink_function"),
                "sink_address": _hex(field["sink_address"], "sink_address"),
                "sink_inst_id": _integer(field["sink_inst_id"], "sink_inst_id", 1, 1 << 63),
                "present_guards": guards_raw,
                "missing_guards": missing,
            }
            evidence_identity = (
                code,
                key,
                source,
                field["source_inst_id"],
                sink_kind,
                field["sink_function"],
                field["sink_address"],
                field["sink_inst_id"],
            )
            if evidence_identity in seen_fields:
                raise ValueError("duplicate SSA field evidence")
            seen_fields.add(evidence_identity)
            material = json.dumps(
                {
                    "campaign_sha256": hashlib.sha256(campaign_bytes).hexdigest(),
                    "plan_sha256": plan_digest,
                    "analysis_sha256": artifact.export_sha256,
                    "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
                    "driver_sha256": artifact.binary_sha256,
                    "evidence": evidence,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            candidate_id = hashlib.sha256(
                b"0verse-windows-ioctl-static-candidate-v1\0" + material
            ).hexdigest()
            if candidate_id in seen_candidate_ids:
                raise ValueError("duplicate static candidate identity")
            seen_candidate_ids.add(candidate_id)
            score_components = {
                "base": 55,
                "missing_guard_count": 15 * len(missing),
                "copy_sink": 5 if sink_kind == "copy" else 0,
            }
            candidates.append(
                {
                    "candidate_id": candidate_id,
                    "status": "candidate",
                    "score_version": SCORE_VERSION,
                    "score_components": score_components,
                    "score": min(100, sum(score_components.values())),
                    "ssa_evidence": evidence,
                    "required_next_validator": (
                        "independently bound signed device-open receipt, then isolated "
                        "target/control adjudication"
                    ),
                }
            )
            if len(candidates) > int(_object(plan["budgets"], "plan.budgets")["max_candidates"]):
                raise ValueError("static candidates exceed the exact plan budget")
    candidates.sort(
        key=lambda row: (
            -(row["score"] if isinstance(row["score"], int) else 0),
            str(row["candidate_id"]),
        )
    )
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = rank
    return {
        "schema_version": RESULT_VERSION,
        "campaign_sha256": hashlib.sha256(campaign_bytes).hexdigest(),
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "analysis_sha256": hashlib.sha256(analysis_bytes).hexdigest(),
        "driver_sha256": target["driver_sha256"],
        "synthetic_fixture": True,
        "contract_only": True,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "device_ioctl_attempts": 0,
        "all_results_are_candidates": True,
        "capability_measure": False,
        "claim_eligible": False,
        "bounty_eligible": False,
        "weaponization": False,
        "automatic_disclosure": False,
        "human_report_gate": True,
        "proof_limit": (
            "Static High-P-Code evidence only. No device call, reachability, crash, "
            "vulnerability, impact, novelty, or bounty eligibility is established."
        ),
    }


def _plan_rows(plan: dict[str, object]) -> dict[int, dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    candidates = plan["candidates"]
    if not isinstance(candidates, list):
        raise ValueError("IOCTL plan candidates are malformed")
    for raw in candidates:
        row = _object(raw, "plan candidate")
        code = int(str(row["ioctl_code"]), 16)
        mutation = _object(row["mutation"], "plan mutation")
        record = rows.setdefault(
            code,
            {
                "handler_name": row["handler_name"],
                "handler_rva": row["handler_rva"],
                "method": row["method"],
                "fields": set(),
            },
        )
        record["fields"].add(
            (mutation["field"], mutation["offset"], mutation["width"], mutation["kind"])
        )
    return rows


def _load_object(data: bytes, label: str) -> dict[str, Any]:
    raw = json.loads(data, object_pairs_hook=_unique_object)
    return _object(raw, label)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _exact(raw: dict[str, Any], expected: set[str], label: str) -> None:
    if set(raw) != expected:
        raise ValueError(f"{label} fields mismatch")


def _sha(raw: object, label: str) -> str:
    value = str(raw)
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _integer(raw: object, label: str, low: int, high: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not low <= raw <= high:
        raise ValueError(f"{label} must be an integer in [{low}, {high}]")
    return raw


def _text(raw: object, label: str) -> str:
    value = str(raw)
    if not value or value != value.strip() or len(value) > 256 or "\x00" in value:
        raise ValueError(f"{label} is invalid")
    return value


def _hex(raw: object, label: str) -> str:
    value = str(raw)
    if re.fullmatch(r"0x[0-9a-f]+", value) is None:
        raise ValueError(f"{label} must be canonical lowercase hexadecimal")
    return value


def _read_bounded(path: Path, maximum: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError(f"{label} must be a bounded regular non-symlink file")
    data = path.read_bytes()
    if len(data) > maximum:
        raise ValueError(f"{label} exceeds its size bound")
    return data


def _preflight_artifact_files(base: Path, raw: dict[str, Any]) -> None:
    expected = {
        "binary_path",
        "ghidra_export_path",
        "binary_sha256",
        "ghidra_export_sha256",
        "analysis_receipt_path",
        "analysis_receipt_sha256",
    }
    _exact(raw, expected, "artifact")
    for field, maximum in (
        ("binary_path", 128 * 1024 * 1024),
        ("ghidra_export_path", 64 * 1024 * 1024),
        ("analysis_receipt_path", 1024 * 1024),
    ):
        path = _relative_file(base, raw[field], f"artifact.{field}")
        _read_bounded(path, maximum, f"artifact.{field}")
        if field == "analysis_receipt_path":
            _load_object(path.read_bytes(), "analysis receipt")


def _relative_file(base: Path, raw: object, label: str) -> Path:
    value = Path(str(raw))
    if value.is_absolute() or ".." in value.parts:
        raise ValueError(f"{label} must be relative")
    path = base / value
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base.resolve()):
        raise ValueError(f"{label} must be a regular in-tree non-symlink file")
    return path
