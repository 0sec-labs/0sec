"""Open pre-analysis blinded labels against an immutable IOCTL rank result."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_ioctl_rank import (
    SCORE_VERSION,
    _integer,
    _load_object,
    _object,
    _read_bounded,
    _sha,
    _text,
)
from .windows_ioctl_real_rank import (
    BYO_BINDING_FIELDS,
    BYO_SHA_FIELDS,
    RANK_PROOF_LIMIT,
    RESULT_VERSION_V2,
    RESULT_VERSION_V3,
    _nonce,
    _rva,
    _timestamp,
    _token,
)
from .windows_ioctl_site_identity import ioctl_site_id, site_universe_sha256

LABEL_VERSION = "0verse.windows-ioctl-real-labels/v1"
LABEL_VERSION_V2 = "0verse.windows-ioctl-real-labels/v2"
EVAL_VERSION = "0verse.windows-ioctl-real-evaluation/v1"
EVAL_VERSION_V2 = "0verse.windows-ioctl-real-evaluation/v2"
SIGNATURE_NAMESPACE = "0verse-windows-ioctl-real-labels-v1"
SIGNATURE_NAMESPACE_V2 = "0verse-windows-ioctl-real-labels-v2"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-ioctl-real-labels.allowed_signers")
RANK_RECEIPT_VERSION = "0verse.windows-ioctl-rank-result-receipt/v1"
RANK_RECEIPT_VERSION_V2 = "0verse.windows-ioctl-rank-result-receipt/v2"
RANK_RECEIPT_NAMESPACE = "0verse-windows-ioctl-rank-result-receipt-v1"
RANK_RECEIPT_NAMESPACE_V2 = "0verse-windows-ioctl-rank-result-receipt-v2"
DEFAULT_RANK_RECEIPT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-ioctl-rank-result.allowed_signers")
RANK_RECEIPT_PROOF_LIMIT = (
    "Signed observation of exact static rank-result bytes only; no receipt establishes "
    "reachability, vulnerability, impact, novelty, execution authority, or claim eligibility."
)
RANK_RECEIPT_PROOF_LIMIT_V2 = (
    "Signed observation of exact static rank-result and opaque BYO commitment bytes only; "
    "the private bundle is unresolved and no receipt establishes artifact mapping, "
    "reachability, vulnerability, impact, novelty, execution authority, or claim eligibility."
)
_PURPOSE = "blinded-static-corpus-labels-only"
LABEL_PROOF_LIMIT = (
    "Frozen blinded static site labels only; no label establishes reachability, "
    "vulnerability, impact, novelty, exploitability, claim, or bounty eligibility."
)
LABEL_PROOF_LIMIT_V2 = (
    "Frozen blinded static site labels bound to opaque BYO commitments only; the private "
    "bundle is unresolved and no label establishes artifact mapping, reachability, "
    "vulnerability, impact, novelty, exploitability, claim, or bounty eligibility."
)
EVAL_PROOF_LIMIT_V2 = (
    "One precommitted blinded static label set and opaque BYO commitment chain only; the "
    "private bundle is unresolved and metrics do not establish artifact mapping, capability, "
    "reachability, vulnerability, impact, novelty, claim, bounty eligibility, execution "
    "authority, disclosure, or weaponization."
)
_SALT = re.compile(r"[0-9a-f]{64,128}")
_IOCTL_CODE = re.compile(r"0x[0-9a-f]{8}")
_SOURCES = {"SystemBuffer", "InputBufferLength", "OutputBufferLength"}
_SINKS = {"copy", "fill", "indexed-store", "allocation"}
_FIELD_KINDS = {"length", "count", "offset", "flags"}
_SITE_FIELDS = {
    "site_id",
    "ioctl_code",
    "registration_rva",
    "handler_name",
    "handler_rva",
    "source",
    "source_inst_id",
    "field_offset",
    "field_width",
    "field_kind",
    "sink_kind",
    "sink_function",
    "sink_address",
    "sink_inst_id",
}


def evaluate_windows_ioctl_real_static(
    rank_output_path: str | Path,
    rank_receipt_path: str | Path,
    labels_path: str | Path,
    *,
    label_allowed_signers: str | Path | None = None,
    rank_receipt_allowed_signers: str | Path | None = None,
    now: datetime | None = None,
    verification_ssh_keygen: str | Path = "ssh-keygen",
    verification_inherit_environment: bool = True,
) -> dict[str, object]:
    """Evaluate exact retained v2/v3 rank bytes against their precommitted labels."""
    rank_bytes = _read_bounded(Path(rank_output_path), 16 * 1024 * 1024, "real rank output")
    result = _load_object(rank_bytes, "real rank output")
    _validate_rank_result(result)
    receipt_policy = Path(rank_receipt_allowed_signers or DEFAULT_RANK_RECEIPT_ALLOWED_SIGNERS)
    receipt_bytes = _read_bounded(Path(rank_receipt_path), 1024 * 1024, "real rank result receipt")
    receipt = _load_object(receipt_bytes, "real rank result receipt")
    receipt_principal, receipt_commitment = _validate_rank_receipt(
        receipt,
        result=result,
        rank_bytes=rank_bytes,
        policy=receipt_policy,
        require_trusted_policy=rank_receipt_allowed_signers is None,
        now=now,
        verification_ssh_keygen=verification_ssh_keygen,
        verification_inherit_environment=verification_inherit_environment,
    )
    if (
        receipt_principal == result["admission_principal"]
        or receipt_commitment == result["admission_authority_key_commitment"]
    ):
        raise ValueError("rank receipt and admission authorities must differ")
    if result["schema_version"] == RESULT_VERSION_V3 and (
        receipt_principal == result["byo_curator_principal"]
        or receipt_commitment == result["byo_curator_authority_key_commitment"]
    ):
        raise ValueError("rank receipt and BYO curator authorities must differ")

    label_bytes = _read_bounded(Path(labels_path), 4 * 1024 * 1024, "real IOCTL labels")
    label_sha256 = hashlib.sha256(label_bytes).hexdigest()
    if label_sha256 != result["label_manifest_commitment_sha256"]:
        raise ValueError("signed labels do not open the pre-analysis admission commitment")
    labels = _load_object(label_bytes, "real IOCTL labels")
    label_policy = Path(label_allowed_signers or DEFAULT_ALLOWED_SIGNERS)
    label_principal, label_commitment = _validate_labels(
        labels,
        result=result,
        policy=label_policy,
        require_trusted_policy=label_allowed_signers is None,
        verification_ssh_keygen=verification_ssh_keygen,
        verification_inherit_environment=verification_inherit_environment,
    )
    if label_principal == result["admission_principal"]:
        raise ValueError("label and admission principals must differ")
    if label_commitment == result["admission_authority_key_commitment"]:
        raise ValueError("label and admission policies must use different Ed25519 keys")
    if receipt_principal in {label_principal, result["admission_principal"]}:
        raise ValueError("rank receipt, label, and admission principals must differ")
    if receipt_commitment in {
        label_commitment,
        result["admission_authority_key_commitment"],
    }:
        raise ValueError("rank receipt, label, and admission keys must differ")
    if result["schema_version"] == RESULT_VERSION_V3:
        principals = {
            label_principal,
            receipt_principal,
            result["admission_principal"],
            result["byo_curator_principal"],
        }
        commitments = {
            label_commitment,
            receipt_commitment,
            result["admission_authority_key_commitment"],
            result["byo_curator_authority_key_commitment"],
        }
        if len(principals) != 4 or len(commitments) != 4:
            raise ValueError("BYO curator, admission, receipt, and label authorities must differ")

    expected = _site_set(labels["expected_sites"], "expected_sites")
    controls = _site_set(labels["control_sites"], "control_sites")
    abstentions = _site_set(labels["abstention_sites"], "abstention_sites")
    if expected & controls or expected & abstentions or controls & abstentions:
        raise ValueError("expected, control, and abstention sites must be disjoint")
    if not expected or not controls:
        raise ValueError("expected and control label sets must both be nonempty")
    labeled = expected | controls | abstentions
    _validate_site_ids(labeled, result)
    labeled_records = _site_records(labeled)
    if (
        len(labeled_records) != result["site_count"]
        or site_universe_sha256(labeled_records) != result["site_universe_sha256"]
    ):
        raise ValueError("labels do not exactly partition the ranked SSA site universe")

    candidates = result["candidates"]
    if not isinstance(candidates, list):
        raise ValueError("real rank output candidates must be an array")
    emitted: list[str] = []
    for index, raw_candidate in enumerate(candidates):
        candidate = _object(raw_candidate, f"candidates[{index}]")
        site = _candidate_site(result, candidate)
        site_tuple = _site_tuple(site)
        if site_tuple not in labeled:
            raise ValueError("rank output contains an unknown emitted site")
        emitted.append(str(site["site_id"]))
    if len(set(emitted)) != len(emitted):
        raise ValueError("rank output contains duplicate emitted sites")

    cutoff = _integer(labels["rank_cutoff"], "rank_cutoff", 1, 4096)
    site_id_index = sorted(_SITE_FIELDS).index("site_id")
    expected_ids = {str(site[site_id_index]) for site in expected}
    control_ids = {str(site[site_id_index]) for site in controls}
    abstention_ids = {str(site[site_id_index]) for site in abstentions}
    emitted_set = set(emitted)
    top = set(emitted[:cutoff])
    recall = len(expected_ids & top) / len(expected_ids) if expected_ids else 1.0
    suppression = 1.0 - (len(control_ids & emitted_set) / len(control_ids) if control_ids else 0.0)
    abstention_rate = len(abstention_ids & emitted_set) / len(emitted_set) if emitted_set else 0.0
    minimum_recall = _ratio(labels["minimum_recall_at_cutoff"], "minimum_recall_at_cutoff")
    minimum_suppression = _ratio(
        labels["minimum_control_suppression"], "minimum_control_suppression"
    )
    maximum_abstention = _ratio(
        labels["maximum_emitted_abstention_rate"], "maximum_emitted_abstention_rate"
    )
    gates = {
        "recall_at_cutoff": recall >= minimum_recall,
        "control_suppression": suppression >= minimum_suppression,
        "emitted_abstention_rate": abstention_rate <= maximum_abstention,
        "static_only": True,
    }
    evaluation = {
        "schema_version": (
            EVAL_VERSION_V2 if result["schema_version"] == RESULT_VERSION_V3 else EVAL_VERSION
        ),
        "rank_result_sha256": hashlib.sha256(rank_bytes).hexdigest(),
        "labels_sha256": label_sha256,
        "rank_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "campaign_id": result["campaign_id"],
        "analysis_run_id": result["analysis_run_id"],
        "driver_sha256": result["driver_sha256"],
        "analysis_sha256": result["analysis_sha256"],
        "score_version": result["score_version"],
        "split": labels["split"],
        "family_id": labels["family_id"],
        "rank_cutoff": cutoff,
        "expected_count": len(expected_ids),
        "expected_found_at_cutoff": len(expected_ids & top),
        "recall_at_cutoff": round(recall, 6),
        "control_count": len(control_ids),
        "controls_emitted": len(control_ids & emitted_set),
        "control_suppression": round(suppression, 6),
        "abstention_count": len(abstention_ids),
        "emitted_abstention_rate": round(abstention_rate, 6),
        "gates": gates,
        "passed": all(gates.values()),
        "benchmark_only": True,
        "static_only": True,
        "runtime_consumable": False,
        "execution_authorized": False,
        "device_ioctl_attempts": 0,
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
        "proof_limit": (
            EVAL_PROOF_LIMIT_V2
            if result["schema_version"] == RESULT_VERSION_V3
            else (
                "One precommitted blinded static label set only; metrics do not establish "
                "capability, reachability, vulnerability, impact, novelty, claim, bounty "
                "eligibility, execution authority, disclosure, or weaponization."
            )
        ),
    }
    if result["schema_version"] == RESULT_VERSION_V3:
        evaluation.update(
            {
                **{name: result[name] for name in BYO_BINDING_FIELDS},
                "admission_expires_at": result["admission_expires_at"],
                "private_bundle_verified": False,
                "redistribution": False,
            }
        )
    return evaluation


def _validate_rank_receipt(
    raw: dict[str, Any],
    *,
    result: dict[str, Any],
    rank_bytes: bytes,
    policy: Path,
    require_trusted_policy: bool,
    now: datetime | None,
    verification_ssh_keygen: str | Path = "ssh-keygen",
    verification_inherit_environment: bool = True,
) -> tuple[str, str]:
    fields = {
        "schema_version",
        "producer",
        "purpose",
        "rank_contract",
        "result_schema_version",
        "rank_result_sha256",
        "rank_result_size_bytes",
        "campaign_id",
        "campaign_sha256",
        "admission_sha256",
        "label_manifest_commitment_sha256",
        "driver_sha256",
        "pdb_sha256",
        "pdb_codeview_identity",
        "analysis_sha256",
        "analysis_receipt_sha256",
        "score_version",
        "candidate_count",
        "ordered_candidate_content_ids_sha256",
        "site_count",
        "site_universe_sha256",
        "analysis_run_id",
        "static_only",
        "runtime_consumable",
        "execution_authorized",
        "device_ioctl_attempts",
        "ranker_executable_sha256",
        "ranker_configuration_sha256",
        "worker_machine_id",
        "started_at",
        "completed_at",
        "issued_at",
        "run_nonce",
        "proof_limit",
        "receipt_signer_identity",
        "signature_ssh",
    }
    result_version = result.get("schema_version")
    if result_version == RESULT_VERSION_V3:
        fields.update(BYO_BINDING_FIELDS | {"admission_expires_at", "private_bundle_verified"})
    _exact(raw, fields, "real rank result receipt")
    expected_receipt_version = (
        RANK_RECEIPT_VERSION_V2 if result_version == RESULT_VERSION_V3 else RANK_RECEIPT_VERSION
    )
    expected_namespace = (
        RANK_RECEIPT_NAMESPACE_V2 if result_version == RESULT_VERSION_V3 else RANK_RECEIPT_NAMESPACE
    )
    expected_proof_limit = (
        RANK_RECEIPT_PROOF_LIMIT_V2
        if result_version == RESULT_VERSION_V3
        else RANK_RECEIPT_PROOF_LIMIT
    )
    if (
        raw["schema_version"] != expected_receipt_version
        or raw["producer"] != "zeroverse.windows-ioctl-real-rank-worker/v1"
        or raw["purpose"] != "static-rank-result-observation-only"
        or raw["rank_contract"] != result_version
        or raw["result_schema_version"] != result_version
        or raw["proof_limit"] != expected_proof_limit
    ):
        raise ValueError("unsupported real rank result receipt contract")
    candidates = result["candidates"]
    if not isinstance(candidates, list):
        raise ValueError("real rank result candidates are malformed")
    content_ids = [
        _sha(_object(candidate, "candidate")["candidate_content_id"], "candidate_content_id")
        for candidate in candidates
    ]
    ordered_digest = hashlib.sha256(
        b"0verse-windows-ioctl-ordered-candidate-content-ids-v1\0"
        + json.dumps(content_ids, separators=(",", ":")).encode()
    ).hexdigest()
    expected = {
        "rank_result_sha256": hashlib.sha256(rank_bytes).hexdigest(),
        "rank_result_size_bytes": len(rank_bytes),
        "campaign_id": result["campaign_id"],
        "campaign_sha256": result["campaign_sha256"],
        "admission_sha256": result["admission_sha256"],
        "label_manifest_commitment_sha256": result["label_manifest_commitment_sha256"],
        "driver_sha256": result["driver_sha256"],
        "pdb_sha256": result["pdb_sha256"],
        "pdb_codeview_identity": result["pdb_codeview_identity"],
        "analysis_sha256": result["analysis_sha256"],
        "analysis_receipt_sha256": result["analysis_receipt_sha256"],
        "score_version": result["score_version"],
        "candidate_count": result["candidate_count"],
        "ordered_candidate_content_ids_sha256": ordered_digest,
        "site_count": result["site_count"],
        "site_universe_sha256": result["site_universe_sha256"],
        "analysis_run_id": result["analysis_run_id"],
        "static_only": True,
        "runtime_consumable": False,
        "execution_authorized": False,
        "device_ioctl_attempts": 0,
    }
    if result_version == RESULT_VERSION_V3:
        expected.update(
            {
                **{name: result[name] for name in BYO_BINDING_FIELDS},
                "admission_expires_at": result["admission_expires_at"],
                "private_bundle_verified": False,
            }
        )
    if any(raw[name] != value for name, value in expected.items()):
        raise ValueError("real rank result receipt is not bound to the exact result")
    _integer(raw["rank_result_size_bytes"], "rank_result_size_bytes", 1, 16 * 1024 * 1024)
    _integer(raw["candidate_count"], "candidate_count", 0, 4096)
    _integer(raw["site_count"], "site_count", 1, 8192)
    _sha(raw["site_universe_sha256"], "site_universe_sha256")
    for name in ("ranker_executable_sha256", "ranker_configuration_sha256"):
        _sha(raw[name], f"rank_receipt.{name}")
    _token(raw["worker_machine_id"], "rank_receipt.worker_machine_id")
    started = _timestamp(raw["started_at"], "rank_receipt.started_at")
    completed = _timestamp(raw["completed_at"], "rank_receipt.completed_at")
    issued = _timestamp(raw["issued_at"], "rank_receipt.issued_at")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    admission_issued = _timestamp(result["admission_issued_at"], "result.admission_issued_at")
    admission_expires = (
        _timestamp(result["admission_expires_at"], "result.admission_expires_at")
        if result_version == RESULT_VERSION_V3
        else None
    )
    inventory_frozen = (
        _timestamp(result["byo_declared_frozen_at"], "result.byo_declared_frozen_at")
        if result_version == RESULT_VERSION_V3
        else admission_issued
    )
    if (
        inventory_frozen > admission_issued
        or started < admission_issued
        or (admission_expires is not None and started >= admission_expires)
        or (admission_expires is not None and completed > admission_expires)
        or started > completed
        or completed > issued
        or completed - started > timedelta(minutes=10)
        or issued - completed > timedelta(minutes=5)
        or completed > current.astimezone(UTC) + timedelta(minutes=5)
        or issued > current.astimezone(UTC) + timedelta(minutes=5)
    ):
        raise ValueError("real rank result receipt timing/commitment order is invalid")
    _nonce(raw["run_nonce"])
    identity = _token(raw["receipt_signer_identity"], "rank_receipt.receipt_signer_identity")
    policy_sha256, authority_commitment = _strict_policy(policy, identity, "rank result receipt")
    verify_ssh_signature(
        canonical_signed_material(raw),
        raw["signature_ssh"],
        identity=identity,
        namespace=expected_namespace,
        allowed_signers=policy,
        label="Windows IOCTL rank result receipt",
        require_trusted_policy=require_trusted_policy,
        ssh_keygen=verification_ssh_keygen,
        inherit_environment=verification_inherit_environment,
    )
    _require_policy_unchanged(policy, policy_sha256, "rank result receipt")
    return identity, authority_commitment


def _validate_rank_result(raw: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "campaign_id",
        "campaign_sha256",
        "admission_sha256",
        "analysis_run_id",
        "driver_sha256",
        "pdb_sha256",
        "pdb_codeview_identity",
        "analysis_sha256",
        "analysis_receipt_sha256",
        "score_version",
        "candidate_count",
        "candidates",
        "synthetic_fixture",
        "contract_only",
        "label_manifest_commitment_sha256",
        "admission_principal",
        "admission_authority_key_commitment",
        "admission_issued_at",
        "site_count",
        "site_universe_sha256",
        "static_only",
        "runtime_consumable",
        "execution_authorized",
        "device_ioctl_attempts",
        "all_results_are_candidates",
        "capability_measure",
        "reachability_established",
        "vulnerability_established",
        "impact_established",
        "novelty_established",
        "claim_eligible",
        "bounty_eligible",
        "weaponization",
        "automatic_disclosure",
        "human_promotion_gate",
        "human_report_gate",
        "redistribution",
        "proof_limit",
    }
    version = raw.get("schema_version")
    if version == RESULT_VERSION_V3:
        required.update(BYO_BINDING_FIELDS | {"admission_expires_at", "private_bundle_verified"})
    _exact(raw, required, "real rank output")
    if (
        version not in {RESULT_VERSION_V2, RESULT_VERSION_V3}
        or raw["score_version"] != SCORE_VERSION
    ):
        raise ValueError("real rank output is not a supported blinded score contract")
    false_fields = required & {
        "runtime_consumable",
        "execution_authorized",
        "capability_measure",
        "reachability_established",
        "vulnerability_established",
        "impact_established",
        "novelty_established",
        "claim_eligible",
        "bounty_eligible",
        "weaponization",
        "automatic_disclosure",
    }
    if any(raw[name] is not False for name in false_fields):
        raise ValueError("real rank output safety flags are not fail-closed")
    if (
        raw["static_only"] is not True
        or raw["contract_only"] is not True
        or raw["all_results_are_candidates"] is not True
        or raw["human_promotion_gate"] is not True
        or raw["human_report_gate"] is not True
    ):
        raise ValueError("real rank output human/static gates are not fail-closed")
    if (
        raw["synthetic_fixture"] is not False
        or raw["redistribution"] is not False
        or raw["proof_limit"] != RANK_PROOF_LIMIT
    ):
        raise ValueError("real rank output provenance/proof gates are not fail-closed")
    if raw["device_ioctl_attempts"] != 0:
        raise ValueError("real rank output records device attempts")
    for name in (
        "admission_sha256",
        "analysis_run_id",
        "driver_sha256",
        "pdb_sha256",
        "analysis_sha256",
        "analysis_receipt_sha256",
        "label_manifest_commitment_sha256",
        "admission_authority_key_commitment",
        "site_universe_sha256",
    ):
        _sha(raw[name], name)
    _token(raw["campaign_id"], "campaign_id")
    _token(raw["admission_principal"], "admission_principal")
    _timestamp(raw["admission_issued_at"], "admission_issued_at")
    if version == RESULT_VERSION_V3:
        if raw["private_bundle_verified"] is not False:
            raise ValueError("BYO private bundle must remain unverified")
        for name in BYO_SHA_FIELDS:
            _sha(raw[name], name)
        _token(raw["byo_curator_principal"], "byo_curator_principal")
        _token(raw["byo_inventory_id"], "byo_inventory_id")
        _nonce(raw["byo_inventory_nonce"])
        frozen = _timestamp(raw["byo_declared_frozen_at"], "byo_declared_frozen_at")
        admitted = _timestamp(raw["admission_issued_at"], "admission_issued_at")
        expires = _timestamp(raw["admission_expires_at"], "admission_expires_at")
        if frozen > admitted or admitted >= expires:
            raise ValueError("BYO inventory freeze must not postdate admission issuance")
    candidates = raw["candidates"]
    count = _integer(raw["candidate_count"], "candidate_count", 0, 4096)
    _integer(raw["site_count"], "site_count", 1, 8192)
    if not isinstance(candidates, list) or count != len(candidates):
        raise ValueError("real rank output candidate count mismatch")
    seen_content: set[str] = set()
    previous_order: tuple[int, str] | None = None
    for index, item in enumerate(candidates):
        candidate = _object(item, f"candidates[{index}]")
        _exact(
            candidate,
            {
                "candidate_id",
                "candidate_content_id",
                "status",
                "score_version",
                "score_components",
                "score",
                "ssa_evidence",
                "required_next_validator",
                "rank",
            },
            f"candidates[{index}]",
        )
        content_id = _sha(candidate["candidate_content_id"], "candidate_content_id")
        candidate_id = _sha(candidate["candidate_id"], "candidate_id")
        expected_candidate_id = hashlib.sha256(
            b"0verse-windows-ioctl-real-candidate-v1\0"
            + str(raw["admission_sha256"]).encode("ascii")
            + b"\0"
            + content_id.encode("ascii")
        ).hexdigest()
        score = _integer(candidate["score"], "candidate.score", 0, 100)
        rank = _integer(candidate["rank"], "candidate.rank", 1, 4096)
        if (
            candidate_id != expected_candidate_id
            or content_id in seen_content
            or candidate["status"] != "candidate"
            or candidate["score_version"] != SCORE_VERSION
            or rank != index + 1
        ):
            raise ValueError("real rank output candidate identity/order is invalid")
        order = (-score, content_id)
        if previous_order is not None and order < previous_order:
            raise ValueError("real rank output candidate ordering is invalid")
        previous_order = order
        seen_content.add(content_id)


def _validate_labels(
    raw: dict[str, Any],
    *,
    result: dict[str, Any],
    policy: Path,
    require_trusted_policy: bool,
    verification_ssh_keygen: str | Path = "ssh-keygen",
    verification_inherit_environment: bool = True,
) -> tuple[str, str]:
    fields = {
        "schema_version",
        "purpose",
        "label_set_id",
        "family_id",
        "blind_salt",
        "split",
        "campaign_id",
        "driver_sha256",
        "pdb_sha256",
        "pdb_codeview_identity",
        "analysis_sha256",
        "analysis_receipt_sha256",
        "rank_contract",
        "score_version",
        "rank_cutoff",
        "minimum_recall_at_cutoff",
        "minimum_control_suppression",
        "maximum_emitted_abstention_rate",
        "provenance_source_sha256s",
        "frozen_at",
        "issued_at",
        "expires_at",
        "nonce",
        "expected_sites",
        "control_sites",
        "abstention_sites",
        "proof_limit",
        "labeled_by",
        "signature_ssh",
    }
    result_version = result.get("schema_version")
    if result_version == RESULT_VERSION_V3:
        fields.update(BYO_BINDING_FIELDS | {"private_bundle_verified"})
    _exact(raw, fields, "real IOCTL labels")
    expected_label_version = (
        LABEL_VERSION_V2 if result_version == RESULT_VERSION_V3 else LABEL_VERSION
    )
    expected_namespace = (
        SIGNATURE_NAMESPACE_V2 if result_version == RESULT_VERSION_V3 else SIGNATURE_NAMESPACE
    )
    if (
        raw["schema_version"] != expected_label_version
        or raw["purpose"] != _PURPOSE
        or raw["rank_contract"] != result_version
        or raw["score_version"] != SCORE_VERSION
        or raw["split"] not in {"train", "validation", "holdout"}
    ):
        raise ValueError("real IOCTL label contract binding mismatch")
    _token(raw["label_set_id"], "label_set_id")
    _token(raw["family_id"], "family_id")
    if _SALT.fullmatch(str(raw["blind_salt"])) is None:
        raise ValueError("real IOCTL labels require at least 256 bits of blind salt")
    identity = _token(raw["labeled_by"], "labeled_by")
    _nonce(raw["nonce"])
    expected_proof_limit = (
        LABEL_PROOF_LIMIT_V2 if result_version == RESULT_VERSION_V3 else LABEL_PROOF_LIMIT
    )
    if raw["proof_limit"] != expected_proof_limit:
        raise ValueError("real IOCTL label proof limit mismatch")
    expected = {
        "campaign_id": result["campaign_id"],
        "driver_sha256": result["driver_sha256"],
        "pdb_sha256": result["pdb_sha256"],
        "pdb_codeview_identity": result["pdb_codeview_identity"],
        "analysis_sha256": result["analysis_sha256"],
        "analysis_receipt_sha256": result["analysis_receipt_sha256"],
    }
    if result_version == RESULT_VERSION_V3:
        expected.update(
            {
                **{name: result[name] for name in BYO_BINDING_FIELDS},
                "private_bundle_verified": False,
            }
        )
    if any(raw[name] != value for name, value in expected.items()):
        raise ValueError("real IOCTL labels are not bound to the ranked artifact")
    for name in expected:
        if name.endswith("sha256"):
            _sha(raw[name], name)
    frozen = _timestamp(raw["frozen_at"], "frozen_at")
    issued = _timestamp(raw["issued_at"], "labels.issued_at")
    expires = _timestamp(raw["expires_at"], "labels.expires_at")
    admission_issued = _timestamp(result["admission_issued_at"], "admission_issued_at")
    if frozen > issued or issued > admission_issued:
        raise ValueError("real IOCTL labels were frozen after admission issuance")
    if result_version == RESULT_VERSION_V3 and frozen > _timestamp(
        result["byo_declared_frozen_at"], "byo_declared_frozen_at"
    ):
        raise ValueError("labels must freeze no later than the BYO inventory")
    if expires <= issued or expires - issued > timedelta(hours=24) or admission_issued > expires:
        raise ValueError("real IOCTL label authority window is invalid")
    _integer(raw["rank_cutoff"], "rank_cutoff", 1, 4096)
    _ratio(raw["minimum_recall_at_cutoff"], "minimum_recall_at_cutoff")
    _ratio(raw["minimum_control_suppression"], "minimum_control_suppression")
    _ratio(raw["maximum_emitted_abstention_rate"], "maximum_emitted_abstention_rate")
    sources = raw["provenance_source_sha256s"]
    if (
        not isinstance(sources, list)
        or not sources
        or sources != sorted(set(sources))
        or any(_sha(value, "provenance source") != value for value in sources)
    ):
        raise ValueError("label provenance sources must be sorted unique SHA-256 values")
    policy_sha256, authority_commitment = _strict_policy(policy, identity, "label")
    verify_ssh_signature(
        canonical_signed_material(raw),
        raw["signature_ssh"],
        identity=identity,
        namespace=expected_namespace,
        allowed_signers=policy,
        label="Windows IOCTL real labels",
        require_trusted_policy=require_trusted_policy,
        ssh_keygen=verification_ssh_keygen,
        inherit_environment=verification_inherit_environment,
    )
    _require_policy_unchanged(policy, policy_sha256, "label")
    return identity, authority_commitment


def _candidate_site(result: dict[str, Any], candidate: dict[str, Any]) -> dict[str, object]:
    evidence = _object(candidate["ssa_evidence"], "candidate.ssa_evidence")
    field = _object(evidence["field"], "candidate.ssa_evidence.field")
    record = {
        "ioctl_code": evidence["ioctl_code"],
        "registration_rva": evidence["registration_rva"],
        "handler_name": evidence["handler_name"],
        "handler_rva": evidence["handler_rva"],
        "source": evidence["source"],
        "source_inst_id": evidence["source_inst_id"],
        "field_offset": field["offset"],
        "field_width": field["width"],
        "field_kind": field["kind"],
        "sink_kind": evidence["sink_kind"],
        "sink_function": evidence["sink_function"],
        "sink_address": evidence["sink_address"],
        "sink_inst_id": evidence["sink_inst_id"],
    }
    return {
        "site_id": _site_id(str(result["driver_sha256"]), str(result["analysis_sha256"]), record),
        **record,
    }


def _site_id(driver_sha256: str, analysis_sha256: str, record: dict[str, object]) -> str:
    return ioctl_site_id(driver_sha256, analysis_sha256, record)


def _site_set(raw: object, label: str) -> set[tuple[object, ...]]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    result: set[tuple[object, ...]] = set()
    for index, raw_site in enumerate(raw):
        site = _object(raw_site, f"{label}[{index}]")
        _exact(site, _SITE_FIELDS, f"{label}[{index}]")
        record = _site_tuple(site)
        if record in result:
            raise ValueError(f"{label} contains duplicate sites")
        result.add(record)
    return result


def _site_tuple(site: dict[str, Any]) -> tuple[object, ...]:
    return tuple(site[name] for name in sorted(_SITE_FIELDS))


def _site_records(sites: set[tuple[object, ...]]) -> list[dict[str, object]]:
    names = sorted(_SITE_FIELDS)
    return [dict(zip(names, values, strict=True)) for values in sites]


def _validate_site_ids(sites: set[tuple[object, ...]], result: dict[str, Any]) -> None:
    names = sorted(_SITE_FIELDS)
    for values in sites:
        site = dict(zip(names, values, strict=True))
        claimed = _sha(site.pop("site_id"), "site_id")
        _validate_site_record(site)
        if _site_id(str(result["driver_sha256"]), str(result["analysis_sha256"]), site) != claimed:
            raise ValueError("label site_id does not match its artifact-bound geometry")


def _validate_site_record(site: dict[str, object]) -> None:
    if _IOCTL_CODE.fullmatch(str(site["ioctl_code"])) is None:
        raise ValueError("label site IOCTL code must be canonical 32-bit hexadecimal")
    _rva(site["registration_rva"], "label site registration_rva")
    _text(site["handler_name"], "label site handler_name")
    _rva(site["handler_rva"], "label site handler_rva")
    if str(site["source"]) not in _SOURCES:
        raise ValueError("label site source is unsupported")
    _integer(site["source_inst_id"], "label site source_inst_id", 1, 1 << 63)
    _integer(site["field_offset"], "label site field_offset", 0, 1 << 20)
    _integer(site["field_width"], "label site field_width", 1, 8)
    if str(site["field_kind"]) not in _FIELD_KINDS:
        raise ValueError("label site field kind is unsupported")
    if str(site["sink_kind"]) not in _SINKS:
        raise ValueError("label site sink kind is unsupported")
    _text(site["sink_function"], "label site sink_function")
    _rva(site["sink_address"], "label site sink_address")
    _integer(site["sink_inst_id"], "label site sink_inst_id", 1, 1 << 63)


def _ratio(raw: object, label: str) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError(f"{label} must be a number")
    value = float(raw)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{label} must be between zero and one")
    return value


def _strict_policy(path: Path, identity: str, label: str) -> tuple[str, str]:
    data = _read_bounded(path, 64 * 1024, f"IOCTL {label} authority policy")
    try:
        lines = [
            line
            for line in data.decode().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except UnicodeDecodeError as exc:
        raise ValueError(f"IOCTL {label} authority policy must be UTF-8") from exc
    if len(lines) != 1:
        raise ValueError(f"IOCTL {label} authority policy must contain exactly one signer")
    parts = lines[0].split()
    if len(parts) not in {3, 4} or parts[0] != identity or parts[1] != "ssh-ed25519":
        raise ValueError(
            f"IOCTL {label} authority policy must contain one exact Ed25519 signer"
        )
    try:
        key = base64.b64decode(parts[2], validate=True)
        if not key:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"IOCTL {label} authority key is malformed") from exc
    commitment = hashlib.sha256(
        b"0verse-ssh-authority-key-v1\0ssh-ed25519\0" + key
    ).hexdigest()
    return hashlib.sha256(data).hexdigest(), commitment


def _require_policy_unchanged(path: Path, expected: str, label: str) -> None:
    observed = hashlib.sha256(
        _read_bounded(path, 64 * 1024, f"IOCTL {label} authority policy")
    ).hexdigest()
    if observed != expected:
        raise ValueError(f"IOCTL {label} authority policy changed during verification")


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} fields mismatch")
