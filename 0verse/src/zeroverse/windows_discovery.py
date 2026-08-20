"""Candidate-only discovery over validated Windows IOCTL semantic-v3 exports.

Inputs preserve operator-declared order only. They establish no servicing lineage,
adjacency, execution authority, vulnerability, novelty, or bounty eligibility.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from .windows_ioctl_ghidra_export import (
    EXPORT_VERSION_V3,
    EXTRACTOR_CONFIG_SHA256,
    EXTRACTOR_PROFILE,
    validate_windows_ioctl_high_pcode_export,
)
from .windows_variant import Artifact, _artifact_record, _load_artifact

CAMPAIGN_VERSION = "0verse.windows-discovery-campaign/v1"
PAIR_INPUT_VERSION = "0verse.windows-driver-local-pair-input/v1"
PAIR_INPUT_PRODUCER = "zeroverse.windows-driver-pair-intake/v1"
PAIR_INPUT_VERSION_V2 = "0verse.windows-driver-local-pair-input/v2"
PAIR_INPUT_PRODUCER_V2 = "zeroverse.windows-driver-pair-intake/v2"
PAIR_INPUT_VERSION_V3 = "0verse.windows-driver-local-pair-input/v3"
PAIR_INPUT_PRODUCER_V3 = "zeroverse.windows-driver-pair-intake/v3"
RESULT_VERSION = "0verse.windows-discovery-result/v1"
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROOFS = {"input-field-readable", "source-copy-span", "destination-copy-span"}
_PAIR_FIELDS = {
    "schema_version",
    "producer",
    "campaign_id",
    "intake_manifest_sha256",
    "pair_id",
    "declared_local_series",
    "snapshots",
    "role_neutral",
    "labels_consumed",
    "network_performed",
    "execution_performed",
    "device_ioctl_attempts",
    "all_outputs_are_discovery_inputs",
    "capability_measure",
    "reachability_established",
    "vulnerability_established",
    "novelty_established",
    "claim_eligible",
    "bounty_eligible",
    "weaponization",
    "automatic_disclosure",
    "human_promotion_gate",
    "windows_discovery_campaign",
    "proof_limit",
}


def discover_windows_candidates(manifest_path: str | Path) -> dict[str, object]:
    path = Path(os.path.abspath(manifest_path))  # noqa: PTH100
    payload = _read_regular(path, "Windows discovery manifest")
    raw = _object(_json(payload, "Windows discovery manifest"), "manifest")
    digest = hashlib.sha256(payload).hexdigest()
    campaign, binding = _campaign_from_input(raw, digest)
    declaration = _source_declaration(campaign["source_declaration"])
    previous = _load_artifact(campaign["previous"], path.parent, "previous")
    current = _load_artifact(campaign["current"], path.parent, "current")
    _bind_source_kind(declaration, previous, current)
    if previous.binary_sha256 == current.binary_sha256:
        raise ValueError("discovery requires distinct artifact versions")
    _require_comparable(previous, current)
    _bind_pair_artifacts(binding, previous, current)
    candidates = _discover_sites(
        _validated_sites(previous, "previous"),
        _validated_sites(current, "current"),
        digest,
        cast(str, binding.get("pair_id", "")),
        current,
    )
    return {
        "schema_version": RESULT_VERSION,
        "input_manifest_sha256": digest,
        "source_declaration": declaration,
        "pair_intake_binding": binding,
        "execution_authority_established": False,
        "servicing_lineage_established": False,
        "servicing_adjacency_established": False,
        "version_order_is_producer_declared": True,
        "previous": _artifact_record(previous),
        "current": _artifact_record(current),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "safety": {
            "network_access": False,
            "process_execution": False,
            "driver_loading": False,
            "device_ioctl_attempts": 0,
            "automatic_disclosure": False,
            "weaponization": False,
        },
        "proof_limit": (
            "Validated v3 static request-source, sink, and local semantic-proof facts only; "
            "no Microsoft servicing lineage or adjacency, runtime or unprivileged reachability, "
            "vulnerability, LPE, novelty, execution authority, or bounty eligibility."
        ),
    }


def _campaign_from_input(
    raw: dict[str, Any], manifest_sha256: str
) -> tuple[dict[str, Any], dict[str, object]]:
    if raw.get("schema_version") == CAMPAIGN_VERSION:
        _exact(raw, {"schema_version", "source_declaration", "previous", "current"}, "campaign")
        return raw, {"pair_intake_consumed": False, "pair_id": "", "intake_manifest_sha256": ""}
    pair_version = str(raw.get("schema_version", ""))
    if pair_version not in {
        PAIR_INPUT_VERSION,
        PAIR_INPUT_VERSION_V2,
        PAIR_INPUT_VERSION_V3,
    }:
        raise ValueError("unsupported Windows discovery input schema")
    _exact(raw, _PAIR_FIELDS, "local-pair input")
    expected_producer = {
        PAIR_INPUT_VERSION: PAIR_INPUT_PRODUCER,
        PAIR_INPUT_VERSION_V2: PAIR_INPUT_PRODUCER_V2,
        PAIR_INPUT_VERSION_V3: PAIR_INPUT_PRODUCER_V3,
    }[pair_version]
    if raw["producer"] != expected_producer:
        raise ValueError("local-pair producer mismatch")
    _pair_safety(raw)
    pair_id = _sha256(raw["pair_id"], "pair_id")
    intake = _sha256(raw["intake_manifest_sha256"], "intake_manifest_sha256")
    snapshots_raw = raw["snapshots"]
    if not isinstance(snapshots_raw, list) or len(snapshots_raw) != 2:
        raise ValueError("local-pair input must contain two snapshots")
    snapshots = [
        _pair_snapshot(value, index, str(pair_version))
        for index, value in enumerate(snapshots_raw)
    ]
    campaign = _object(raw["windows_discovery_campaign"], "embedded campaign")
    _exact(
        campaign,
        {"schema_version", "source_declaration", "previous", "current"},
        "embedded campaign",
    )
    if campaign["schema_version"] != CAMPAIGN_VERSION:
        raise ValueError("embedded campaign schema mismatch")
    if (
        campaign["previous"] != snapshots[0]["discovery_artifact"]
        or campaign["current"] != snapshots[1]["discovery_artifact"]
    ):
        raise ValueError("embedded campaign is not bound to pair snapshots")
    declaration = _source_declaration(campaign["source_declaration"])
    if any(snapshot["source_kind"] != declaration["kind"] for snapshot in snapshots):
        raise ValueError("source declaration is not bound to pair snapshots")
    material = {
        "intake_sha256": intake,
        "snapshot_manifest_sha256s": [value["manifest_sha256"] for value in snapshots],
        "binary_sha256s": [value["binary_sha256"] for value in snapshots],
    }
    pair_domain = {
        PAIR_INPUT_VERSION: b"0verse-windows-driver-discovery-pair-v1\0",
        PAIR_INPUT_VERSION_V2: b"0verse-windows-driver-discovery-pair-v2\0",
        PAIR_INPUT_VERSION_V3: b"0verse-windows-driver-discovery-pair-v3\0",
    }[pair_version]
    expected = hashlib.sha256(pair_domain + _canonical(material)).hexdigest()
    if pair_id != expected:
        raise ValueError("pair_id does not bind retained snapshots")
    artifact_bindings = [
        {
            name: value[name]
            for name in (
                "binary_sha256",
                "pdb_sha256",
                "pdb_codeview_identity",
                "ghidra_export_sha256",
                "analysis_receipt_sha256",
            )
        }
        | (
            {"public_pdb": value["public_pdb"]}
            if pair_version == PAIR_INPUT_VERSION_V3
            else {}
        )
        for value in snapshots
    ]
    return campaign, {
        "pair_intake_consumed": True,
        "pair_input_sha256": manifest_sha256,
        "pair_id": pair_id,
        "intake_manifest_sha256": intake,
        "snapshot_artifact_bindings": artifact_bindings,
    }


def _pair_safety(raw: dict[str, Any]) -> None:
    expected = {
        "role_neutral": True,
        "labels_consumed": False,
        "network_performed": False,
        "execution_performed": False,
        "device_ioctl_attempts": 0,
        "all_outputs_are_discovery_inputs": True,
        "capability_measure": False,
        "reachability_established": False,
        "vulnerability_established": False,
        "novelty_established": False,
        "claim_eligible": False,
        "bounty_eligible": False,
        "weaponization": False,
        "automatic_disclosure": False,
        "human_promotion_gate": True,
    }
    if any(raw.get(name) != value for name, value in expected.items()):
        raise ValueError("local-pair safety boundary mismatch")
    series = _object(raw["declared_local_series"], "declared_local_series")
    if (
        series.get("producer_series_ordinals_consecutive") is not True
        or series.get("servicing_lineage_verified") is not False
        or series.get("servicing_adjacency_verified") is not False
    ):
        raise ValueError("local-pair series claim boundary mismatch")


def _pair_snapshot(raw: object, index: int, pair_version: str) -> dict[str, Any]:
    value = _object(raw, f"snapshots[{index}]")
    fields = {
        "slot",
        "snapshot_id",
        "source_kind",
        "producer_series_ordinal",
        "build_lab_ex",
        "manifest_path",
        "manifest_sha256",
        "binary_sha256",
        "pdb_sha256",
        "pdb_codeview_identity",
        "ghidra_export_sha256",
        "analysis_receipt_sha256",
        "ghidra_version",
        "extractor_profile",
        "extractor_config_sha256",
        "discovery_artifact",
    }
    if pair_version in {PAIR_INPUT_VERSION_V2, PAIR_INPUT_VERSION_V3}:
        fields.update(
            {
                "current_build",
                "ubr",
                "file_version",
                "servicing_evidence_path",
                "servicing_evidence_sha256",
            }
        )
    if pair_version == PAIR_INPUT_VERSION_V3:
        fields.add("public_pdb")
    _exact(value, fields, f"snapshots[{index}]")
    if value["slot"] != f"snapshot-{index}":
        raise ValueError("snapshot slots are not canonical")
    expected_source = (
        "public-artifact" if pair_version == PAIR_INPUT_VERSION_V3 else "owned-fixture"
    )
    if value["source_kind"] != expected_source:
        if pair_version != PAIR_INPUT_VERSION_V3 and value["source_kind"] == "public-artifact":
            raise ValueError(
                "public-artifact local-pair discovery is unsupported until its public-PDB "
                "receipt is bound by a versioned semantic-v3 analysis receipt"
            )
        raise ValueError(
            "local-pair source_kind does not match its versioned intake contract"
        )
    if pair_version == PAIR_INPUT_VERSION_V3:
        public = _object(value["public_pdb"], "public_pdb")
        _exact(
            public,
            {
                "receipt_sha256",
                "requested_url",
                "pe_guid",
                "pe_age",
                "pdb_guid",
                "pdb_age",
                "exact_age_match",
            },
            "public_pdb",
        )
        _sha256(public["receipt_sha256"], "public_pdb.receipt_sha256")
        if (
            not isinstance(public["requested_url"], str)
            or not public["requested_url"].startswith(
                "https://msdl.microsoft.com/download/symbols/"
            )
            or not isinstance(public["exact_age_match"], bool)
            or not isinstance(public["pe_guid"], str)
            or not public["pe_guid"]
            or not isinstance(public["pdb_guid"], str)
            or not public["pdb_guid"]
            or isinstance(public["pe_age"], bool)
            or not isinstance(public["pe_age"], int)
            or public["pe_age"] < 0
            or isinstance(public["pdb_age"], bool)
            or not isinstance(public["pdb_age"], int)
            or public["pdb_age"] < 0
        ):
            raise ValueError("public_pdb route binding is malformed")
    descriptor = _object(value["discovery_artifact"], "discovery_artifact")
    descriptor_fields = {
        "binary_path",
        "binary_sha256",
        "ghidra_export_path",
        "ghidra_export_sha256",
        "analysis_receipt_path",
        "analysis_receipt_sha256",
    }
    _exact(descriptor, descriptor_fields, "discovery_artifact")
    for name in ("binary_sha256", "ghidra_export_sha256", "analysis_receipt_sha256"):
        if value[name] != descriptor[name]:
            raise ValueError("pair snapshot discovery descriptor hash mismatch")
    for name in (
        "manifest_sha256",
        "binary_sha256",
        "pdb_sha256",
        "ghidra_export_sha256",
        "analysis_receipt_sha256",
    ):
        _sha256(value[name], f"snapshots[{index}].{name}")
    if (
        value["extractor_profile"] != EXTRACTOR_PROFILE
        or value["extractor_config_sha256"] != EXTRACTOR_CONFIG_SHA256
    ):
        raise ValueError("pair snapshot semantic-v3 profile mismatch")
    return value


def _require_comparable(previous: Artifact, current: Artifact) -> None:
    if previous.binary_path.name.casefold() != current.binary_path.name.casefold():
        raise ValueError("artifact versions must have the same component basename")
    if previous.ghidra_version != current.ghidra_version:
        raise ValueError("artifact versions must use the same Ghidra version")
    for name in ("architecture", "pointer_size", "extractor_profile", "extractor_config_sha256"):
        if _header(previous.export, name) != _header(current.export, name):
            raise ValueError(f"artifact versions have incompatible {name}")


def _bind_source_kind(
    declaration: dict[str, str], previous: Artifact, current: Artifact
) -> None:
    public = [bool(row.public_pdb_receipt_sha256) for row in (previous, current)]
    if public[0] != public[1]:
        raise ValueError("discovery artifacts mix public and legacy analysis receipts")
    expected = "public-artifact" if public[0] else "owned-fixture"
    if declaration["kind"] != expected:
        raise ValueError("source_declaration.kind does not match loaded artifact provenance")


def _header(export: dict[str, Any], name: str) -> object:
    if name in {"extractor_profile", "extractor_config_sha256"}:
        return export.get(name)
    facts = export.get("facts")
    return facts.get(name) if isinstance(facts, dict) else None


def _bind_pair_artifacts(binding: dict[str, object], previous: Artifact, current: Artifact) -> None:
    if binding.get("pair_intake_consumed") is not True:
        return
    values = binding.get("snapshot_artifact_bindings")
    if not isinstance(values, list) or len(values) != 2:
        raise ValueError("pair artifact bindings are missing")
    for label, raw, artifact in zip(
        ("previous", "current"), values, (previous, current), strict=True
    ):
        expected: dict[str, object] = {
            "binary_sha256": artifact.binary_sha256,
            "pdb_sha256": artifact.pdb_sha256,
            "pdb_codeview_identity": artifact.pdb_identity,
            "ghidra_export_sha256": artifact.export_sha256,
            "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
        }
        if artifact.public_pdb_receipt_sha256:
            expected["public_pdb"] = {
                "receipt_sha256": artifact.public_pdb_receipt_sha256,
                "requested_url": artifact.public_pdb_requested_url,
                "pe_guid": artifact.public_pdb_pe_guid,
                "pe_age": artifact.public_pdb_pe_age,
                "pdb_guid": artifact.public_pdb_pdb_guid,
                "pdb_age": artifact.public_pdb_pdb_age,
                "exact_age_match": artifact.public_pdb_exact_age_match,
            }
        if _object(raw, f"{label} pair binding") != expected:
            raise ValueError(f"{label} artifact differs from pair-intake binding")


def _validated_sites(artifact: Artifact, label: str) -> dict[str, dict[str, Any]]:
    export = artifact.export
    if (
        export.get("schema_version") != EXPORT_VERSION_V3
        or export.get("extractor_profile") != EXTRACTOR_PROFILE
        or export.get("extractor_config_sha256") != EXTRACTOR_CONFIG_SHA256
    ):
        raise ValueError(f"{label} must use the supported semantic High-P-Code v3 profile")
    validate_windows_ioctl_high_pcode_export(export)
    if (
        export.get("driver_sha256") != artifact.binary_sha256
        or export.get("pdb_sha256") != artifact.pdb_sha256
        or export.get("pdb_codeview_identity") != artifact.pdb_identity
    ):
        raise ValueError(f"{label} v3 export is not bound to its PE/PDB artifact")
    facts = _object(export.get("facts"), f"{label} facts")
    summaries, rich = export.get("dispatches"), facts.get("dispatches")
    if not isinstance(summaries, list) or not isinstance(rich, list) or len(summaries) != len(rich):
        raise ValueError(f"{label} dispatch projections are malformed")
    raw_sites: list[dict[str, Any]] = []
    for summary_raw, rich_raw in zip(summaries, rich, strict=True):
        summary = _object(summary_raw, "dispatch summary")
        rich_dispatch = _object(rich_raw, "rich dispatch")
        if summary.get("ioctl_code") != rich_dispatch.get("ioctl_code"):
            raise ValueError(f"{label} dispatch projection mismatch")
        fields, rich_fields = summary.get("fields"), rich_dispatch.get("fields")
        if (
            not isinstance(fields, list)
            or not isinstance(rich_fields, list)
            or len(fields) != len(rich_fields)
        ):
            raise ValueError(f"{label} field projections are malformed")
        for field_raw, rich_field_raw in zip(fields, rich_fields, strict=True):
            field, rich_field = _object(field_raw, "field"), _object(rich_field_raw, "rich field")
            proof_values = rich_field.get("safety_proofs")
            taint_values = rich_field.get("taint_path")
            if not isinstance(proof_values, list) or not isinstance(taint_values, list):
                raise ValueError(f"{label} proof or taint facts are malformed")
            proofs = sorted(
                str(_object(value, "proof").get("proof_kind")) for value in proof_values
            )
            if len(proofs) != len(set(proofs)) or not set(proofs) <= _PROOFS:
                raise ValueError(f"{label} semantic proof vocabulary mismatch")
            taint = tuple(str(_object(value, "taint ref").get("opcode")) for value in taint_values)
            semantic_key = (
                summary["ioctl_code"],
                field["offset"],
                field["width"],
                field["kind"],
                field["source"],
                field["sink_kind"],
                rich_field["sink_argument_index"],
                taint,
            )
            raw_sites.append(
                {
                    "key": semantic_key,
                    "dispatch": summary,
                    "field": field,
                    "proofs": proofs,
                    "taint": list(taint),
                }
            )
    grouped: dict[tuple[object, ...], list[dict[str, Any]]] = defaultdict(list)
    for site in raw_sites:
        grouped[cast(tuple[object, ...], site["key"])].append(site)
    sites: dict[str, dict[str, Any]] = {}
    for key, values in grouped.items():
        values.sort(
            key=lambda value: (
                str(value["field"]["sink_address"]),
                int(value["field"]["source_inst_id"]),
                int(value["field"]["sink_inst_id"]),
            )
        )
        for ordinal, site in enumerate(values):
            site_id = hashlib.sha256(
                b"0verse-windows-discovery-semantic-site-v1\0"
                + _canonical({"key": key, "occurrence": ordinal})
            ).hexdigest()
            site["site_id"], site["ordinal"] = site_id, ordinal
            sites[site_id] = site
    return sites


def _required_proofs(field: dict[str, Any]) -> set[str]:
    source, kind = str(field["source"]), str(field["kind"])
    if source == "SystemBuffer":
        required = {"input-field-readable"}
        if kind in {"length", "count", "offset"}:
            required |= {"source-copy-span", "destination-copy-span"}
        return required
    if source == "InputBufferLength" and kind in {"length", "count", "offset"}:
        return {"destination-copy-span"}
    if source == "OutputBufferLength":
        # V3 defines no output-buffer-length proof. Inventing the legacy label here
        # would make every output-extent site an unavoidable false positive.
        return set()
    raise ValueError("unsupported v3 request source or field kind")


def _discover_sites(
    previous: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
    manifest_sha256: str,
    pair_id: str,
    artifact: Artifact,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for site_id, site in current.items():
        old = previous.get(site_id)
        field, dispatch = (
            cast(dict[str, Any], site["field"]),
            cast(dict[str, Any], site["dispatch"]),
        )
        present = set(cast(list[str], site["proofs"]))
        missing = sorted(_required_proofs(field) - present)
        removed = sorted(set(cast(list[str], old["proofs"])) - present) if old else []
        if not missing and not removed:
            continue
        change = (
            "current-only-surface"
            if old is None
            else ("semantic-proof-removal" if removed else "persistent-proof-gap")
        )
        evidence = {
            "semantic_site_id": site_id,
            "semantic_site_occurrence": site["ordinal"],
            "ioctl_code": f"0x{int(dispatch['ioctl_code']):08x}",
            "handler_name": dispatch["handler_name"],
            "handler_rva": dispatch["handler_rva"],
            "change": change,
            "request_source": field["source"],
            "source_inst_id": field["source_inst_id"],
            "field": {name: field[name] for name in ("offset", "width", "kind")},
            "sink_kind": field["sink_kind"],
            "sink_function": field["sink_function"],
            "sink_address": field["sink_address"],
            "sink_inst_id": field["sink_inst_id"],
            "taint_opcodes": site["taint"],
            "present_semantic_proofs": sorted(present),
            "missing_semantic_proofs": missing,
            "removed_semantic_proofs": removed,
        }
        content_id = hashlib.sha256(
            b"0verse-windows-discovery-content-v2\0" + _canonical(evidence)
        ).hexdigest()
        candidate_id = hashlib.sha256(
            b"0verse-windows-discovery-candidate-v2\0"
            + b"\0".join(
                value.encode("ascii")
                for value in (
                    manifest_sha256,
                    pair_id,
                    artifact.binary_sha256,
                    artifact.export_sha256,
                    content_id,
                )
            )
        ).hexdigest()
        candidates.append(
            {
                "candidate_id": candidate_id,
                "candidate_content_id": content_id,
                "status": "candidate",
                "class": "request-field-sensitive-operation-proof-gap",
                "score": min(100, 55 + 15 * len(missing) + 15 * bool(removed) + 5 * (old is None)),
                "hypothesis": (
                    "a request-derived field reaches a sensitive operation without "
                    "applicable local v3 semantic proof coverage"
                ),
                "evidence": evidence,
                "alternative_explanation": (
                    "a caller, framework, type invariant, or runtime condition may supply "
                    "the missing safety property"
                ),
                "required_next_validator": (
                    "independently establish unprivileged dispatch reachability, then use a "
                    "separately authorized snapshot worker and fixed control"
                ),
            }
        )
    candidates.sort(key=lambda row: (-cast(int, row["score"]), str(row["candidate_id"])))
    for rank, row in enumerate(candidates, 1):
        row["rank"] = rank
    return candidates


def _source_declaration(raw: object) -> dict[str, str]:
    value = _object(raw, "source_declaration")
    _exact(value, {"kind", "description"}, "source_declaration")
    kind, description = value["kind"], value["description"]
    if kind not in {"owned-fixture", "public-artifact"}:
        raise ValueError("unsupported source_declaration.kind")
    if not isinstance(description, str) or not description.strip() or "\0" in description:
        raise ValueError("source_declaration.description is required")
    return {"kind": kind, "description": description.strip()}


def _read_regular(path: Path, label: str) -> bytes:
    if path.resolve() != path.absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > _MAX_MANIFEST_BYTES
        ):
            raise ValueError(f"{label} must be a bounded nonempty regular file")
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_MANIFEST_BYTES:
                raise ValueError(f"{label} exceeds size cap")
        after = os.fstat(descriptor)
        before_id = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_id = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if before_id != after_id or total != before.st_size:
            raise ValueError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_private_json(path: Path, value: object) -> None:
    destination = Path(os.path.abspath(path))  # noqa: PTH100
    parent = destination.parent
    if parent.resolve() != parent or not parent.is_dir() or destination.name in {"", ".", ".."}:
        raise ValueError("output parent must be a regular non-symlink directory")
    directory = os.open(
        parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    stage_created = False
    try:
        descriptor = os.open(
            ".zeroverse-windows-discovery.tmp",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        stage_created = True
        payload = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write while retaining discovery output")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(
            ".zeroverse-windows-discovery.tmp",
            destination.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.unlink(".zeroverse-windows-discovery.tmp", dir_fd=directory)
        stage_created = False
        os.fsync(directory)
    except FileExistsError as exc:
        raise ValueError("output path already exists") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if stage_created:
            with suppress(FileNotFoundError):
                os.unlink(".zeroverse-windows-discovery.tmp", dir_fd=directory)
        os.close(directory)


def _json(payload: bytes, label: str) -> object:
    try:
        return json.loads(payload, object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _exact(raw: dict[str, Any], expected: set[str], label: str) -> None:
    if set(raw) != expected:
        raise ValueError(f"{label} has unexpected or missing fields")


def _sha256(raw: object, label: str) -> str:
    if not isinstance(raw, str) or _SHA256.fullmatch(raw) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return raw


def _canonical(raw: object) -> bytes:
    return json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
