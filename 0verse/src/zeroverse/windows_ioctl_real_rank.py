"""Rank signed, provenance-bound real Windows IOCTL evidence without execution."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_byo_corpus import verify_windows_byo_corpus_manifest
from .windows_ioctl_rank import (
    SCORE_VERSION,
    _hex,
    _integer,
    _load_object,
    _object,
    _preflight_artifact_files,
    _read_bounded,
    _relative_file,
    _sha,
    _text,
)
from .windows_ioctl_site_identity import ioctl_site_id, site_universe_sha256
from .windows_variant import _load_artifact

CAMPAIGN_VERSION = "0verse.windows-ioctl-real-static-campaign/v1"
CAMPAIGN_VERSION_V2 = "0verse.windows-ioctl-real-static-campaign/v2"
ADMISSION_VERSION = "0verse.windows-ioctl-analysis-admission/v1"
ADMISSION_VERSION_V2 = "0verse.windows-ioctl-analysis-admission/v2"
ADMISSION_VERSION_V3 = "0verse.windows-ioctl-analysis-admission/v3"
EXPORT_VERSION = "0verse.windows-ioctl-real-ssa-export/v1"
EXPORT_VERSION_V2 = "0verse.windows-ioctl-real-ssa-export/v2"
EXPORT_VERSION_V3 = "0verse.windows-ioctl-real-ssa-export/v3"
RESULT_VERSION = "0verse.windows-ioctl-real-static-candidates/v1"
RESULT_VERSION_V2 = "0verse.windows-ioctl-real-static-candidates/v2"
RESULT_VERSION_V3 = "0verse.windows-ioctl-real-static-candidates/v3"
SIGNATURE_NAMESPACE = "0verse-windows-ioctl-analysis-admission-v1"
SIGNATURE_NAMESPACE_V2 = "0verse-windows-ioctl-analysis-admission-v2"
SIGNATURE_NAMESPACE_V3 = "0verse-windows-ioctl-analysis-admission-v3"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-ioctl-analysis-admission.allowed_signers")
RANK_PROOF_LIMIT = (
    "Signed static High-P-Code candidate evidence only; no device call, "
    "reachability, vulnerability, impact, novelty, claim, bounty eligibility, "
    "execution authority, weaponization, or disclosure is established."
)
BYO_ADMISSION_PROOF_LIMIT = (
    "Signed selection of one opaque item/private-bundle commitment from a verified BYO "
    "inventory only; the private bundle is unresolved and no artifact mapping, provenance, "
    "reachability, vulnerability, impact, novelty, execution authority, or claim eligibility "
    "is established."
)

_PURPOSE = "static-candidate-ranking-only"
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
_TOKEN = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,128}")
BYO_BINDING_FIELDS = {
    "byo_inventory_sha256",
    "byo_inventory_signature_sha256",
    "byo_inventory_id",
    "byo_inventory_nonce",
    "byo_curator_principal",
    "byo_curator_authority_key_commitment",
    "byo_blinding_key_commitment_sha256",
    "byo_source_index_commitment_sha256",
    "byo_item_commitment_sha256",
    "byo_private_bundle_commitment_sha256",
    "byo_declared_frozen_at",
}
BYO_SHA_FIELDS = {
    name
    for name in BYO_BINDING_FIELDS
    if name.endswith("sha256") or name.endswith("key_commitment")
}


def rank_windows_ioctl_real_static(
    campaign_path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Validate one signed real-artifact contract and rank static SSA facts only."""
    campaign_file = Path(campaign_path)
    campaign_bytes = _read_bounded(campaign_file, 1024 * 1024, "real static campaign")
    campaign = _load_object(campaign_bytes, "real static campaign")
    campaign_fields = {
        "schema_version",
        "campaign_id",
        "artifact",
        "admission_path",
        "admission_sha256",
    }
    if campaign.get("schema_version") == CAMPAIGN_VERSION_V2:
        campaign_fields.update(
            {
                "byo_inventory_path",
                "byo_inventory_sha256",
                "byo_inventory_signature_sha256",
                "byo_item_commitment_sha256",
                "byo_private_bundle_commitment_sha256",
            }
        )
    _exact(campaign, campaign_fields, "real static campaign")
    if campaign["schema_version"] not in {CAMPAIGN_VERSION, CAMPAIGN_VERSION_V2}:
        raise ValueError("unsupported Windows IOCTL real static campaign schema")
    campaign_id = _token(campaign["campaign_id"], "campaign_id")

    artifact_raw = _object(campaign["artifact"], "artifact")
    _preflight_artifact_files(campaign_file.parent, artifact_raw)
    artifact = _load_artifact(artifact_raw, campaign_file.parent, "artifact")
    if artifact.synthetic_fixture:
        raise ValueError("real static ranker rejects synthetic analysis fixtures")

    byo_binding: dict[str, str] | None = None
    if campaign["schema_version"] == CAMPAIGN_VERSION_V2:
        inventory_path = _relative_file(
            campaign_file.parent, campaign["byo_inventory_path"], "byo_inventory_path"
        )
        inventory = verify_windows_byo_corpus_manifest(inventory_path)
        if inventory.inventory_sha256 != _sha(
            campaign["byo_inventory_sha256"], "byo_inventory_sha256"
        ) or inventory.signature_sha256 != _sha(
            campaign["byo_inventory_signature_sha256"],
            "byo_inventory_signature_sha256",
        ):
            raise ValueError("BYO campaign inventory bytes/signature binding mismatch")
        item = _sha(campaign["byo_item_commitment_sha256"], "byo_item_commitment_sha256")
        bundle = _sha(
            campaign["byo_private_bundle_commitment_sha256"],
            "byo_private_bundle_commitment_sha256",
        )
        if (item, bundle) not in set(
            zip(
                inventory.item_commitment_sha256s,
                inventory.private_bundle_commitment_sha256s,
                strict=True,
            )
        ):
            raise ValueError("BYO campaign selected item/bundle is not in the verified inventory")
        byo_binding = {
            "byo_inventory_sha256": inventory.inventory_sha256,
            "byo_inventory_signature_sha256": inventory.signature_sha256,
            "byo_inventory_id": inventory.inventory_id,
            "byo_inventory_nonce": inventory.inventory_nonce,
            "byo_curator_principal": inventory.manifest_signer_identity,
            "byo_curator_authority_key_commitment": (inventory.authority_key_commitment_sha256),
            "byo_blinding_key_commitment_sha256": inventory.blinding_key_commitment_sha256,
            "byo_source_index_commitment_sha256": (
                inventory.declared_source_index_commitment_sha256
            ),
            "byo_item_commitment_sha256": item,
            "byo_private_bundle_commitment_sha256": bundle,
            "byo_declared_frozen_at": inventory.declared_frozen_at,
        }

    admission_file = _relative_file(
        campaign_file.parent, campaign["admission_path"], "admission_path"
    )
    admission_bytes = _read_bounded(admission_file, 1024 * 1024, "analysis admission")
    admission_sha256 = hashlib.sha256(admission_bytes).hexdigest()
    if admission_sha256 != _sha(campaign["admission_sha256"], "admission_sha256"):
        raise ValueError("analysis admission SHA-256 mismatch")
    admission = _load_object(admission_bytes, "analysis admission")
    admission_meta = _validate_admission(
        admission,
        campaign_id=campaign_id,
        artifact=artifact,
        policy=(Path(allowed_signers) if allowed_signers is not None else DEFAULT_ALLOWED_SIGNERS),
        require_trusted_policy=allowed_signers is None,
        now=now,
        byo_binding=byo_binding,
    )

    export_bytes = _read_bounded(artifact.export_path, 64 * 1024 * 1024, "real SSA export")
    if hashlib.sha256(export_bytes).hexdigest() != artifact.export_sha256:
        raise ValueError("real SSA export changed after artifact verification")
    export = _load_object(export_bytes, "real SSA export")
    if export.get("schema_version") in {EXPORT_VERSION, EXPORT_VERSION_V2}:
        raise ValueError(
            "legacy IOCTL export lacks semantic branch-polarity and compound-span proofs; "
            "re-analyze with export v3"
        )
    if export.get("schema_version") == EXPORT_VERSION_V3:
        from .windows_ioctl_ghidra_export import (
            EXTRACTOR_CONFIG_SHA256,
            EXTRACTOR_PROFILE,
            validate_windows_ioctl_high_pcode_export,
        )

        if (
            export.get("extractor_profile") != EXTRACTOR_PROFILE
            or export.get("extractor_config_sha256") != EXTRACTOR_CONFIG_SHA256
        ):
            raise ValueError("unsupported Windows IOCTL real SSA v3 extractor contract")
        validate_windows_ioctl_high_pcode_export(export)
        dispatches = _legacy_dispatch_summary_v2(export["dispatches"])
        if dispatches != export["dispatches"]:
            raise ValueError("real SSA v3 derived legacy dispatch summary mismatch")
    else:
        raise ValueError("unsupported Windows IOCTL real SSA export contract")
    if (
        export["driver_sha256"] != artifact.binary_sha256
        or export["pdb_sha256"] != artifact.pdb_sha256
        or export["pdb_codeview_identity"] != artifact.pdb_identity
    ):
        raise ValueError("real SSA export is not bound to the verified PE/PDB receipt")

    max_dispatches = _integer(admission["max_dispatches"], "max_dispatches", 1, 128)
    if not isinstance(dispatches, list) or not 1 <= len(dispatches) <= max_dispatches:
        raise ValueError("real SSA dispatches exceed the signed admission bound")
    max_fields = _integer(admission["max_fields_per_dispatch"], "max_fields_per_dispatch", 1, 64)
    max_candidates = _integer(admission["max_candidates"], "max_candidates", 1, 4096)
    candidates, sites = _rank_dispatches(
        cast(list[object], dispatches),
        artifact_identity={
            "driver_sha256": artifact.binary_sha256,
            "pdb_sha256": artifact.pdb_sha256,
            "pdb_codeview_identity": artifact.pdb_identity,
            "analysis_sha256": artifact.export_sha256,
            "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
        },
        admission_sha256=admission_sha256,
        max_fields=max_fields,
        max_candidates=max_candidates,
    )
    analysis_run_id = hashlib.sha256(
        b"0verse-windows-ioctl-real-analysis-run-v1\0" + admission_sha256.encode("ascii")
    ).hexdigest()
    result: dict[str, Any] = {
        "schema_version": admission_meta["rank_contract"],
        "campaign_id": campaign_id,
        "campaign_sha256": hashlib.sha256(campaign_bytes).hexdigest(),
        "admission_sha256": admission_sha256,
        "analysis_run_id": analysis_run_id,
        "driver_sha256": artifact.binary_sha256,
        "pdb_sha256": artifact.pdb_sha256,
        "pdb_codeview_identity": artifact.pdb_identity,
        "analysis_sha256": artifact.export_sha256,
        "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
        "score_version": SCORE_VERSION,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "synthetic_fixture": False,
        "contract_only": True,
        "static_only": True,
        "runtime_consumable": False,
        "execution_authorized": False,
        "device_ioctl_attempts": 0,
        "all_results_are_candidates": True,
        "capability_measure": False,
        "reachability_established": False,
        "vulnerability_established": False,
        "impact_established": False,
        "novelty_established": False,
        "claim_eligible": False,
        "bounty_eligible": False,
        "weaponization": False,
        "automatic_disclosure": False,
        "human_promotion_gate": True,
        "human_report_gate": True,
        "redistribution": False,
        "proof_limit": RANK_PROOF_LIMIT,
    }
    if admission_meta["rank_contract"] in {RESULT_VERSION_V2, RESULT_VERSION_V3}:
        result.update(
            {
                "label_manifest_commitment_sha256": admission_meta[
                    "label_manifest_commitment_sha256"
                ],
                "admission_principal": admission_meta["admission_principal"],
                "admission_authority_key_commitment": admission_meta[
                    "admission_authority_key_commitment"
                ],
                "admission_issued_at": admission_meta["admission_issued_at"],
                "site_count": len(sites),
                "site_universe_sha256": site_universe_sha256(sites),
            }
        )
        if admission_meta["rank_contract"] == RESULT_VERSION_V3:
            result.update(
                {
                    **{name: admission_meta[name] for name in BYO_BINDING_FIELDS},
                    "admission_expires_at": admission_meta["admission_expires_at"],
                    "private_bundle_verified": admission_meta["private_bundle_verified"],
                }
            )
    return result


def _legacy_dispatch_summary_v2(raw: object) -> list[dict[str, object]]:
    """Project a fully validated v2 fact graph into the immutable v1 score input."""
    if not isinstance(raw, list):
        raise ValueError("real SSA v2 dispatches must be an array")
    summary: list[dict[str, object]] = []
    for index, item in enumerate(raw):
        dispatch = _object(item, f"v2.dispatches[{index}]")
        fields_raw = dispatch["fields"]
        if not isinstance(fields_raw, list):
            raise ValueError(f"v2.dispatches[{index}].fields must be an array")
        fields: list[dict[str, object]] = []
        for field_index, item_raw in enumerate(fields_raw):
            field = _object(item_raw, f"v2.dispatches[{index}].fields[{field_index}]")
            fields.append(
                {
                    "offset": field["offset"],
                    "width": field["width"],
                    "kind": field["kind"],
                    "source": field["source"],
                    "source_inst_id": field["source_inst_id"],
                    "sink_kind": field["sink_kind"],
                    "sink_function": field["sink_function"],
                    "sink_address": field["sink_address"],
                    "sink_inst_id": field["sink_inst_id"],
                    "guards": field["guards"],
                }
            )
        summary.append(
            {
                "ioctl_code": dispatch["ioctl_code"],
                "device_type": dispatch["device_type"],
                "function": dispatch["function"],
                "method": dispatch["method"],
                "access": dispatch["access"],
                "handler_name": dispatch["handler_name"],
                "handler_rva": dispatch["handler_rva"],
                "registration_rva": dispatch["registration_rva"],
                "dispatch_resolved": dispatch["dispatch_resolved"],
                "unresolved_edges": dispatch["unresolved_edges"],
                "fields": fields,
            }
        )
    return summary


def _validate_admission(
    raw: dict[str, Any],
    *,
    campaign_id: str,
    artifact: Any,
    policy: Path,
    require_trusted_policy: bool,
    now: datetime | None,
    byo_binding: dict[str, str] | None,
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "purpose",
        "campaign_id",
        "driver_sha256",
        "pdb_sha256",
        "pdb_codeview_identity",
        "ghidra_export_sha256",
        "analysis_receipt_sha256",
        "rank_contract",
        "score_version",
        "max_dispatches",
        "max_fields_per_dispatch",
        "max_candidates",
        "issued_at",
        "expires_at",
        "nonce",
        "admitted_by",
        "signature_ssh",
    }
    schema = raw.get("schema_version")
    if not isinstance(schema, str):
        raise ValueError("analysis admission schema_version must be a string")
    if schema in {ADMISSION_VERSION_V2, ADMISSION_VERSION_V3}:
        fields.add("label_manifest_commitment_sha256")
    if schema == ADMISSION_VERSION_V3:
        fields.update(BYO_BINDING_FIELDS | {"private_bundle_verified", "proof_limit"})
    _exact(raw, fields, "analysis admission")
    if schema not in {ADMISSION_VERSION, ADMISSION_VERSION_V2, ADMISSION_VERSION_V3}:
        raise ValueError("analysis admission contract binding mismatch")
    expected_rank = {
        ADMISSION_VERSION: RESULT_VERSION,
        ADMISSION_VERSION_V2: RESULT_VERSION_V2,
        ADMISSION_VERSION_V3: RESULT_VERSION_V3,
    }[schema]
    if (
        raw["purpose"] != _PURPOSE
        or raw["campaign_id"] != campaign_id
        or raw["rank_contract"] != expected_rank
        or raw["score_version"] != SCORE_VERSION
    ):
        raise ValueError("analysis admission contract binding mismatch")
    if (schema == ADMISSION_VERSION_V3) != (byo_binding is not None):
        raise ValueError("BYO campaign and admission contract versions must match")
    expected = (
        ("driver_sha256", artifact.binary_sha256),
        ("pdb_sha256", artifact.pdb_sha256),
        ("pdb_codeview_identity", artifact.pdb_identity),
        ("ghidra_export_sha256", artifact.export_sha256),
        ("analysis_receipt_sha256", artifact.analysis_receipt_sha256),
    )
    if any(raw[field] != value for field, value in expected):
        raise ValueError("analysis admission artifact binding mismatch")
    for field in ("driver_sha256", "pdb_sha256", "ghidra_export_sha256", "analysis_receipt_sha256"):
        _sha(raw[field], field)
    identity = _token(raw["admitted_by"], "admitted_by")
    _nonce(raw["nonce"])
    _integer(raw["max_dispatches"], "max_dispatches", 1, 128)
    _integer(raw["max_fields_per_dispatch"], "max_fields_per_dispatch", 1, 64)
    _integer(raw["max_candidates"], "max_candidates", 1, 4096)
    _fresh_window(raw["issued_at"], raw["expires_at"], now=now)
    policy_sha256, authority_commitment = _strict_policy(policy, identity)
    verify_ssh_signature(
        canonical_signed_material(raw),
        raw["signature_ssh"],
        identity=identity,
        namespace=(
            {
                ADMISSION_VERSION: SIGNATURE_NAMESPACE,
                ADMISSION_VERSION_V2: SIGNATURE_NAMESPACE_V2,
                ADMISSION_VERSION_V3: SIGNATURE_NAMESPACE_V3,
            }[schema]
        ),
        allowed_signers=policy,
        label="Windows IOCTL analysis admission",
        require_trusted_policy=require_trusted_policy,
    )
    if (
        hashlib.sha256(
            _read_bounded(policy, 64 * 1024, "analysis admission allowed-signers policy")
        ).hexdigest()
        != policy_sha256
    ):
        raise ValueError("analysis admission allowed-signers policy changed during verification")
    label_commitment = ""
    if schema in {ADMISSION_VERSION_V2, ADMISSION_VERSION_V3}:
        label_commitment = _sha(
            raw["label_manifest_commitment_sha256"], "label_manifest_commitment_sha256"
        )
    result: dict[str, Any] = {
        "rank_contract": expected_rank,
        "label_manifest_commitment_sha256": label_commitment,
        "admission_principal": identity,
        "admission_authority_key_commitment": authority_commitment,
        "admission_issued_at": str(raw["issued_at"]),
    }
    if schema == ADMISSION_VERSION_V3:
        assert byo_binding is not None
        if any(raw[name] != value for name, value in byo_binding.items()):
            raise ValueError("analysis admission BYO inventory binding mismatch")
        for name in BYO_SHA_FIELDS:
            _sha(raw[name], name)
        curator = _token(raw["byo_curator_principal"], "byo_curator_principal")
        _token(raw["byo_inventory_id"], "byo_inventory_id")
        _nonce(raw["byo_inventory_nonce"])
        frozen = _timestamp(raw["byo_declared_frozen_at"], "byo_declared_frozen_at")
        issued = _timestamp(raw["issued_at"], "issued_at")
        if frozen > issued:
            raise ValueError("BYO inventory freeze must not postdate admission issuance")
        if (
            curator == identity
            or raw["byo_curator_authority_key_commitment"] == authority_commitment
        ):
            raise ValueError("BYO curator and admission authorities must differ")
        if (
            raw["private_bundle_verified"] is not False
            or raw["proof_limit"] != BYO_ADMISSION_PROOF_LIMIT
        ):
            raise ValueError("BYO admission must keep the private bundle unresolved")
        result.update({name: str(raw[name]) for name in BYO_BINDING_FIELDS})
        result["admission_expires_at"] = str(raw["expires_at"])
        result["private_bundle_verified"] = raw["private_bundle_verified"]
    return result


def _rank_dispatches(
    dispatches: list[object],
    *,
    artifact_identity: dict[str, str],
    admission_sha256: str,
    max_fields: int,
    max_candidates: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    seen_codes: set[int] = set()
    seen_content: set[str] = set()
    seen_sites: set[str] = set()
    candidates: list[dict[str, object]] = []
    sites: list[dict[str, object]] = []
    for index, item in enumerate(dispatches):
        dispatch = _object(item, f"dispatches[{index}]")
        _exact(
            dispatch,
            {
                "ioctl_code",
                "device_type",
                "function",
                "method",
                "access",
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
        device_type = _integer(dispatch["device_type"], "device_type", 0, 0xFFFF)
        function = _integer(dispatch["function"], "function", 0, 0xFFF)
        method = _integer(dispatch["method"], "method", 0, 3)
        access = _integer(dispatch["access"], "access", 0, 3)
        if code != ((device_type << 16) | (access << 14) | (function << 2) | method):
            raise ValueError("real SSA IOCTL CTL_CODE decomposition mismatch")
        if method != 0:
            raise ValueError("real SSA ranker v1 accepts METHOD_BUFFERED only")
        if code in seen_codes:
            raise ValueError("duplicate real SSA IOCTL dispatch")
        seen_codes.add(code)
        if dispatch["dispatch_resolved"] is not True or dispatch["unresolved_edges"] != []:
            raise ValueError("real SSA IOCTL dispatch has unresolved edges")
        registration_rva = _rva(dispatch["registration_rva"], "registration_rva")
        handler_name = _text(dispatch["handler_name"], "handler_name")
        handler_rva = _rva(dispatch["handler_rva"], "handler_rva")
        fields = dispatch["fields"]
        if not isinstance(fields, list) or not 1 <= len(fields) <= max_fields:
            raise ValueError("real SSA fields exceed the signed admission bound")
        seen_fields: set[tuple[object, ...]] = set()
        for field_index, item_raw in enumerate(fields):
            field = _object(item_raw, f"dispatches[{index}].fields[{field_index}]")
            _exact(
                field,
                {
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
            geometry = (
                _integer(field["offset"], "field.offset", 0, 1 << 20),
                _integer(field["width"], "field.width", 1, 8),
                str(field["kind"]),
            )
            if geometry[2] not in _FIELD_KINDS:
                raise ValueError("unsupported real SSA field kind")
            source, sink = str(field["source"]), str(field["sink_kind"])
            if source not in _SOURCES or sink not in _SINKS:
                raise ValueError("unsupported real SSA source or sink")
            source_inst_id = _integer(field["source_inst_id"], "source_inst_id", 1, 1 << 63)
            sink_function = _text(field["sink_function"], "sink_function")
            sink_address = _rva(field["sink_address"], "sink_address")
            sink_inst_id = _integer(field["sink_inst_id"], "sink_inst_id", 1, 1 << 63)
            evidence_identity = (
                code,
                geometry,
                source,
                source_inst_id,
                sink,
                sink_function,
                sink_address,
                sink_inst_id,
            )
            if evidence_identity in seen_fields:
                raise ValueError("duplicate real SSA field evidence")
            seen_fields.add(evidence_identity)
            site_record: dict[str, object] = {
                "ioctl_code": f"0x{code:08x}",
                "registration_rva": registration_rva,
                "handler_name": handler_name,
                "handler_rva": handler_rva,
                "source": source,
                "source_inst_id": source_inst_id,
                "field_offset": geometry[0],
                "field_width": geometry[1],
                "field_kind": geometry[2],
                "sink_kind": sink,
                "sink_function": sink_function,
                "sink_address": sink_address,
                "sink_inst_id": sink_inst_id,
            }
            site_id = ioctl_site_id(
                artifact_identity["driver_sha256"],
                artifact_identity["analysis_sha256"],
                site_record,
            )
            if site_id in seen_sites:
                raise ValueError("duplicate real SSA site identity")
            seen_sites.add(site_id)
            sites.append({"site_id": site_id, **site_record})
            guards = field["guards"]
            if (
                not isinstance(guards, list)
                or any(not isinstance(value, str) for value in guards)
                or guards != sorted(set(guards))
                or not set(guards) <= _GUARDS
            ):
                raise ValueError("real SSA guards must be a sorted unique supported array")
            if source == "SystemBuffer":
                required = {"input-buffer-length", "field-within-input"}
            elif source == "InputBufferLength":
                required = {"input-buffer-length"}
            else:
                required = {"output-buffer-length"}
            if geometry[2] in {"length", "count", "offset"}:
                required.add("checked-arithmetic")
            missing = sorted(required - set(guards))
            if not missing:
                continue
            evidence = {
                "ioctl_code": f"0x{code:08x}",
                "device_type": device_type,
                "function": function,
                "method": method,
                "access": access,
                "registration_rva": registration_rva,
                "handler_name": handler_name,
                "handler_rva": handler_rva,
                "source": source,
                "source_inst_id": source_inst_id,
                "field": {"offset": geometry[0], "width": geometry[1], "kind": geometry[2]},
                "sink_kind": sink,
                "sink_function": sink_function,
                "sink_address": sink_address,
                "sink_inst_id": sink_inst_id,
                "present_guards": guards,
                "missing_guards": missing,
            }
            identity = json.dumps(
                {**artifact_identity, "score_version": SCORE_VERSION, "evidence": evidence},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            content_id = hashlib.sha256(
                b"0verse-windows-ioctl-real-content-v1\0" + identity
            ).hexdigest()
            if content_id in seen_content:
                raise ValueError("duplicate real SSA field evidence")
            seen_content.add(content_id)
            candidate_id = hashlib.sha256(
                b"0verse-windows-ioctl-real-candidate-v1\0"
                + admission_sha256.encode("ascii")
                + b"\0"
                + content_id.encode("ascii")
            ).hexdigest()
            components = {
                "base": 55,
                "missing_guard_count": 15 * len(missing),
                "copy_sink": 5 if sink == "copy" else 0,
            }
            candidates.append(
                {
                    "candidate_id": candidate_id,
                    "candidate_content_id": content_id,
                    "status": "candidate",
                    "score_version": SCORE_VERSION,
                    "score_components": components,
                    "score": min(100, sum(components.values())),
                    "ssa_evidence": evidence,
                    "required_next_validator": (
                        "independent human review and separately authorized "
                        "target/control validation"
                    ),
                }
            )
            if len(candidates) > max_candidates:
                raise ValueError("real SSA candidates exceed the signed admission bound")
    candidates.sort(
        key=lambda row: (
            -(row["score"] if isinstance(row["score"], int) else 0),
            str(row["candidate_content_id"]),
        )
    )
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = rank
    sites.sort(key=lambda row: str(row["site_id"]))
    return candidates, sites


def _fresh_window(issued_raw: object, expires_raw: object, *, now: datetime | None) -> None:
    issued = _timestamp(issued_raw, "issued_at")
    expires = _timestamp(expires_raw, "expires_at")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    if issued > current + timedelta(minutes=5) or expires <= current:
        raise ValueError("analysis admission is not currently fresh")
    if expires <= issued or expires - issued > timedelta(hours=24):
        raise ValueError("analysis admission lifetime must be positive and at most 24 hours")


def _timestamp(raw: object, label: str) -> datetime:
    try:
        value = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if value.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _strict_policy(path: Path, identity: str) -> tuple[str, str]:
    data = _read_bounded(path, 64 * 1024, "analysis admission allowed-signers policy")
    try:
        lines = [
            line
            for line in data.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except UnicodeDecodeError as exc:
        raise ValueError("analysis admission allowed-signers policy must be UTF-8") from exc
    if len(lines) != 1:
        raise ValueError("analysis admission policy must contain exactly one signer")
    parts = lines[0].split()
    if len(parts) not in {3, 4} or parts[0] != identity or parts[1] != "ssh-ed25519":
        raise ValueError(
            "analysis admission policy must be one literal principal and ssh-ed25519 key"
        )
    try:
        key = base64.b64decode(parts[2], validate=True)
        if not key:
            raise ValueError
    except ValueError as exc:
        raise ValueError("analysis admission policy key is malformed") from exc
    authority_commitment = hashlib.sha256(
        b"0verse-ssh-authority-key-v1\0ssh-ed25519\0" + key
    ).hexdigest()
    return hashlib.sha256(data).hexdigest(), authority_commitment


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} fields mismatch")


def _token(raw: object, label: str) -> str:
    value = str(raw)
    if _TOKEN.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _nonce(raw: object) -> str:
    value = str(raw)
    if _NONCE.fullmatch(value) is None:
        raise ValueError("analysis admission nonce is invalid")
    return value


def _rva(raw: object, label: str) -> str:
    value = _hex(raw, label)
    parsed = int(value, 16)
    if not 1 <= parsed <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{label} must be a nonzero 64-bit RVA")
    return value
