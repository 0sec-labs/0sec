"""Verify a one-time, post-evaluation authorization for one opaque BYO tuple.

This module deliberately has no private key, source-index, bundle-store, or path
access.  A later native resolver may consume the verified metadata only after it
durably burns both returned replay identities.
"""

from __future__ import annotations

import base64
import hashlib
import json
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_byo_corpus import (
    BYO_CORPUS_COMMITMENT_SCHEME,
    verify_windows_byo_corpus_manifest,
)
from .windows_byo_private_construction import CONSTRUCTION_PROFILE
from .windows_ioctl_rank import _load_object, _read_bounded, _sha
from .windows_ioctl_real_eval import (
    EVAL_VERSION_V2,
    LABEL_VERSION_V2,
    RANK_RECEIPT_VERSION_V2,
    evaluate_windows_ioctl_real_static,
)
from .windows_ioctl_real_rank import (
    BYO_BINDING_FIELDS,
    RESULT_VERSION_V3,
    _nonce,
    _timestamp,
    _token,
)

SCHEMA_VERSION = "0verse.windows-byo-private-resolution-authorization/v1"
PRODUCER = "zeroverse.windows-byo-private-resolution-authority/v1"
PURPOSE = "one-time-post-evaluation-private-tuple-resolution-only"
SIGNATURE_NAMESPACE = "0verse-windows-byo-private-resolution-authorization-v1"
DEFAULT_ALLOWED_SIGNERS = Path(
    "/etc/0verse/windows-byo-private-resolution-authorization.allowed_signers"
)
DEFAULT_RESOLVER_ALLOWED_SIGNERS = Path(
    "/etc/0verse/windows-byo-private-resolver.allowed_signers"
)
AUTHORIZED_OPERATION = "resolve-one-precommitted-private-bundle"
PROOF_LIMIT = (
    "Authorizes one human-approved attempt to resolve one precommitted opaque private "
    "bundle after a passed blinded static evaluation only. It does not establish HMAC "
    "key entropy or construction correctness, source truth, provenance, label or patch "
    "direction, reachability, vulnerability, impact, novelty, claim or bounty eligibility, "
    "execution authority, redistribution, disclosure, or weaponization."
)

_TUPLE_REPLAY_DOMAIN = b"0verse-windows-byo-private-resolution-tuple-once-v1\0"
_PERMIT_REPLAY_DOMAIN = b"0verse-windows-byo-private-resolution-authorization-once-v1\0"


@dataclass(frozen=True)
class VerifiedPrivateResolutionAuthorization:
    """Opaque authorization metadata safe to hand to a separate resolver boundary."""

    authorization_sha256: str
    inventory_sha256: str
    inventory_signature_sha256: str
    inventory_id: str
    inventory_nonce: str
    item_commitment_sha256: str
    private_bundle_commitment_sha256: str
    rank_result_sha256: str
    rank_receipt_sha256: str
    labels_sha256: str
    evaluation_sha256: str
    request_nonce: str
    issued_at: str
    expires_at: str
    authorizer_principal: str
    authorizer_authority_key_commitment: str
    resolver_principal: str
    resolver_authority_key_commitment: str
    tuple_replay_identity_sha256: str
    authorization_replay_identity_sha256: str
    replay_state_consumed: bool = False
    private_bundle_verified: bool = False
    secret_accessed: bool = False
    zeroization_verified: bool = False

    @property
    def burn_only_replay_identities(self) -> tuple[str, str]:
        return (
            self.tuple_replay_identity_sha256,
            self.authorization_replay_identity_sha256,
        )


def verify_private_resolution_authorization(
    inventory_path: str | Path,
    rank_output_path: str | Path,
    rank_receipt_path: str | Path,
    labels_path: str | Path,
    evaluation_path: str | Path,
    authorization_path: str | Path,
    *,
    label_allowed_signers: str | Path | None = None,
    rank_receipt_allowed_signers: str | Path | None = None,
    authorization_allowed_signers: str | Path | None = None,
    resolver_allowed_signers: str | Path | None = None,
    burned_replay_identities: frozenset[str] = frozenset(),
    now: datetime | None = None,
    verification_ssh_keygen: str | Path = "/usr/bin/ssh-keygen",
) -> VerifiedPrivateResolutionAuthorization:
    """Recompute the public chain and authenticate one still-unconsumed permit."""
    inventory = verify_windows_byo_corpus_manifest(
        inventory_path,
        now=now,
        verification_ssh_keygen=verification_ssh_keygen,
        verification_inherit_environment=False,
    )
    rank_bytes = _read_bounded(Path(rank_output_path), 16 * 1024 * 1024, "rank result")
    receipt_bytes = _read_bounded(Path(rank_receipt_path), 1024 * 1024, "rank receipt")
    labels_bytes = _read_bounded(Path(labels_path), 4 * 1024 * 1024, "blinded labels")
    evaluation_bytes = _read_bounded(
        Path(evaluation_path), 1024 * 1024, "blinded evaluation"
    )
    authorization_bytes = _read_bounded(
        Path(authorization_path), 1024 * 1024, "private resolution authorization"
    )

    result = _load_object(rank_bytes, "rank result")
    receipt = _load_object(receipt_bytes, "rank receipt")
    labels = _load_object(labels_bytes, "blinded labels")
    retained_evaluation = _load_object(evaluation_bytes, "blinded evaluation")
    authorization = _load_object(authorization_bytes, "private resolution authorization")

    if authorization_bytes != _canonical_json(authorization):
        raise ValueError("private resolution authorization must use canonical JSON bytes")
    if (
        result.get("schema_version") != RESULT_VERSION_V3
        or receipt.get("schema_version") != RANK_RECEIPT_VERSION_V2
        or labels.get("schema_version") != LABEL_VERSION_V2
        or retained_evaluation.get("schema_version") != EVAL_VERSION_V2
    ):
        raise ValueError("private resolution requires the exact BYO v3/v2 closure")

    label_policy = Path(label_allowed_signers) if label_allowed_signers else None
    receipt_policy = (
        Path(rank_receipt_allowed_signers) if rank_receipt_allowed_signers else None
    )
    recomputed_evaluation = evaluate_windows_ioctl_real_static(
        rank_output_path,
        rank_receipt_path,
        labels_path,
        label_allowed_signers=label_policy,
        rank_receipt_allowed_signers=receipt_policy,
        now=now,
        verification_ssh_keygen=verification_ssh_keygen,
        verification_inherit_environment=False,
    )
    if evaluation_bytes != _canonical_json(recomputed_evaluation):
        raise ValueError(
            "retained blinded evaluation is not the canonical deterministic recomputation"
        )
    gates = retained_evaluation.get("gates")
    if (
        retained_evaluation.get("passed") is not True
        or not isinstance(gates, dict)
        or not gates
        or any(value is not True for value in gates.values())
    ):
        raise ValueError("private resolution requires a passed blinded evaluation")

    inventory_binding = {
        "byo_inventory_sha256": inventory.inventory_sha256,
        "byo_inventory_signature_sha256": inventory.signature_sha256,
        "byo_inventory_id": inventory.inventory_id,
        "byo_inventory_nonce": inventory.inventory_nonce,
        "byo_curator_principal": inventory.manifest_signer_identity,
        "byo_curator_authority_key_commitment": inventory.authority_key_commitment_sha256,
        "byo_blinding_key_commitment_sha256": inventory.blinding_key_commitment_sha256,
        "byo_source_index_commitment_sha256": (
            inventory.declared_source_index_commitment_sha256
        ),
        "byo_item_commitment_sha256": result["byo_item_commitment_sha256"],
        "byo_private_bundle_commitment_sha256": result[
            "byo_private_bundle_commitment_sha256"
        ],
        "byo_declared_frozen_at": inventory.declared_frozen_at,
    }
    if any(result.get(name) != value for name, value in inventory_binding.items()):
        raise ValueError("rank result does not match the reverified BYO inventory")
    if (
        inventory_binding["byo_item_commitment_sha256"],
        inventory_binding["byo_private_bundle_commitment_sha256"],
    ) not in set(
        zip(
            inventory.item_commitment_sha256s,
            inventory.private_bundle_commitment_sha256s,
            strict=True,
        )
    ):
        raise ValueError("selected opaque tuple is absent from the reverified inventory")

    _validate_exact_authorization_fields(authorization)
    expected = {
        **inventory_binding,
        "construction_profile": CONSTRUCTION_PROFILE,
        "commitment_scheme": BYO_CORPUS_COMMITMENT_SCHEME,
        "campaign_id": result["campaign_id"],
        "campaign_sha256": result["campaign_sha256"],
        "admission_sha256": result["admission_sha256"],
        "analysis_run_id": result["analysis_run_id"],
        "driver_sha256": result["driver_sha256"],
        "pdb_sha256": result["pdb_sha256"],
        "pdb_codeview_identity": result["pdb_codeview_identity"],
        "analysis_sha256": result["analysis_sha256"],
        "analysis_receipt_sha256": result["analysis_receipt_sha256"],
        "rank_contract": RESULT_VERSION_V3,
        "rank_result_sha256": hashlib.sha256(rank_bytes).hexdigest(),
        "rank_receipt_contract": RANK_RECEIPT_VERSION_V2,
        "rank_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "labels_contract": LABEL_VERSION_V2,
        "labels_sha256": hashlib.sha256(labels_bytes).hexdigest(),
        "evaluation_contract": EVAL_VERSION_V2,
        "evaluation_sha256": hashlib.sha256(evaluation_bytes).hexdigest(),
        "evaluation_passed": True,
    }
    if any(authorization.get(name) != value for name, value in expected.items()):
        raise ValueError("private resolution authorization artifact binding mismatch")

    for name in (
        "rank_result_sha256",
        "rank_receipt_sha256",
        "labels_sha256",
        "evaluation_sha256",
        "authorizer_authority_key_commitment",
        "resolver_authority_key_commitment",
        "tuple_replay_identity_sha256",
        "driver_sha256",
        "pdb_sha256",
        "analysis_sha256",
        "analysis_receipt_sha256",
    ):
        _sha(authorization[name], name)
    request_nonce = _nonce(authorization["request_nonce"])
    authorizer = _token(authorization["authorizer_principal"], "authorizer_principal")
    resolver = _token(authorization["resolver_principal"], "resolver_principal")

    authorizer_policy = Path(
        authorization_allowed_signers or DEFAULT_ALLOWED_SIGNERS
    )
    resolver_policy = Path(resolver_allowed_signers or DEFAULT_RESOLVER_ALLOWED_SIGNERS)
    authorizer_policy_sha, authorizer_key = _singleton_policy_authority(
        authorizer_policy,
        authorizer,
        "private resolution authorizer",
        require_trusted=authorization_allowed_signers is None,
    )
    resolver_policy_sha, resolver_key = _singleton_policy_authority(
        resolver_policy,
        resolver,
        "private resolver",
        require_trusted=resolver_allowed_signers is None,
    )
    if (
        authorization["authorizer_authority_key_commitment"] != authorizer_key
        or authorization["resolver_authority_key_commitment"] != resolver_key
    ):
        raise ValueError("private resolution authority policy binding mismatch")

    receipt_signer = _token(
        receipt["receipt_signer_identity"], "rank_receipt_signer_identity"
    )
    label_signer = _token(labels["labeled_by"], "label_signer_identity")
    _, receipt_key = _singleton_policy_authority(
        receipt_policy
        if receipt_policy is not None
        else Path("/etc/0verse/windows-ioctl-rank-result.allowed_signers"),
        receipt_signer,
        "rank receipt",
        require_trusted=rank_receipt_allowed_signers is None,
    )
    _, label_key = _singleton_policy_authority(
        label_policy
        if label_policy is not None
        else Path("/etc/0verse/windows-ioctl-real-labels.allowed_signers"),
        label_signer,
        "blinded label",
        require_trusted=label_allowed_signers is None,
    )
    principals = {
        str(result["byo_curator_principal"]),
        str(result["admission_principal"]),
        receipt_signer,
        label_signer,
        authorizer,
        resolver,
    }
    keys = {
        str(result["byo_curator_authority_key_commitment"]),
        str(result["admission_authority_key_commitment"]),
        receipt_key,
        label_key,
        authorizer_key,
        resolver_key,
    }
    if len(principals) != 6 or len(keys) != 6:
        raise ValueError("all private resolution authorities must use distinct principals and keys")

    issued = _timestamp(authorization["issued_at"], "authorization.issued_at")
    expires = _timestamp(authorization["expires_at"], "authorization.expires_at")
    receipt_issued = _timestamp(receipt["issued_at"], "rank_receipt.issued_at")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    if (
        issued < receipt_issued
        or issued > current + timedelta(minutes=5)
        or expires <= current
        or expires <= issued
        or expires - issued > timedelta(minutes=15)
    ):
        raise ValueError("private resolution authorization chronology is invalid")

    tuple_replay = _tuple_replay_identity(authorization)
    if authorization["tuple_replay_identity_sha256"] != tuple_replay:
        raise ValueError("private resolution tuple replay identity mismatch")
    authorization_sha256 = hashlib.sha256(authorization_bytes).hexdigest()
    authorization_replay = hashlib.sha256(
        _PERMIT_REPLAY_DOMAIN
        + authorization_sha256.encode("ascii")
        + b"\0"
        + request_nonce.encode("ascii")
    ).hexdigest()
    replay = (tuple_replay, authorization_replay)
    if len(set(replay)) != 2 or any(value in burned_replay_identities for value in replay):
        raise ValueError("private resolution authorization replay identity was already burned")

    verify_ssh_signature(
        canonical_signed_material(authorization),
        str(authorization["signature_ssh"]),
        identity=authorizer,
        namespace=SIGNATURE_NAMESPACE,
        allowed_signers=authorizer_policy,
        label="Windows BYO private resolution authorization",
        require_trusted_policy=authorization_allowed_signers is None,
        ssh_keygen=verification_ssh_keygen,
        inherit_environment=False,
    )
    _require_policy_unchanged(authorizer_policy, authorizer_policy_sha, "authorizer")
    _require_policy_unchanged(resolver_policy, resolver_policy_sha, "resolver")

    return VerifiedPrivateResolutionAuthorization(
        authorization_sha256=authorization_sha256,
        inventory_sha256=inventory.inventory_sha256,
        inventory_signature_sha256=inventory.signature_sha256,
        inventory_id=inventory.inventory_id,
        inventory_nonce=inventory.inventory_nonce,
        item_commitment_sha256=str(authorization["byo_item_commitment_sha256"]),
        private_bundle_commitment_sha256=str(
            authorization["byo_private_bundle_commitment_sha256"]
        ),
        rank_result_sha256=str(authorization["rank_result_sha256"]),
        rank_receipt_sha256=str(authorization["rank_receipt_sha256"]),
        labels_sha256=str(authorization["labels_sha256"]),
        evaluation_sha256=str(authorization["evaluation_sha256"]),
        request_nonce=request_nonce,
        issued_at=str(authorization["issued_at"]),
        expires_at=str(authorization["expires_at"]),
        authorizer_principal=authorizer,
        authorizer_authority_key_commitment=authorizer_key,
        resolver_principal=resolver,
        resolver_authority_key_commitment=resolver_key,
        tuple_replay_identity_sha256=tuple_replay,
        authorization_replay_identity_sha256=authorization_replay,
    )


def derive_tuple_replay_identity(raw: dict[str, Any]) -> str:
    """Public construction helper; request nonces intentionally do not affect it."""
    return _tuple_replay_identity(raw)


def _tuple_replay_identity(raw: dict[str, Any]) -> str:
    fields = (
        "byo_inventory_sha256",
        "byo_inventory_signature_sha256",
        "byo_inventory_id",
        "byo_inventory_nonce",
        "byo_item_commitment_sha256",
        "byo_private_bundle_commitment_sha256",
        "rank_result_sha256",
        "rank_receipt_sha256",
        "labels_sha256",
        "evaluation_sha256",
    )
    material = {name: raw[name] for name in fields}
    return hashlib.sha256(_TUPLE_REPLAY_DOMAIN + _canonical_json(material)).hexdigest()


def _validate_exact_authorization_fields(raw: dict[str, Any]) -> None:
    fields = {
        "schema_version",
        "producer",
        "purpose",
        "authorized_operation",
        "construction_profile",
        "commitment_scheme",
        *BYO_BINDING_FIELDS,
        "campaign_id",
        "campaign_sha256",
        "admission_sha256",
        "analysis_run_id",
        "driver_sha256",
        "pdb_sha256",
        "pdb_codeview_identity",
        "analysis_sha256",
        "analysis_receipt_sha256",
        "rank_contract",
        "rank_result_sha256",
        "rank_receipt_contract",
        "rank_receipt_sha256",
        "labels_contract",
        "labels_sha256",
        "evaluation_contract",
        "evaluation_sha256",
        "evaluation_passed",
        "resolver_principal",
        "resolver_authority_key_commitment",
        "max_private_bundle_resolutions",
        "single_use",
        "human_authorized",
        "static_only",
        "runtime_consumable",
        "execution_authorized",
        "network_authorized",
        "redistribution_authorized",
        "disclosure_authorized",
        "weaponization_authorized",
        "private_bundle_verified",
        "secret_accessed",
        "zeroization_verified",
        "issued_at",
        "expires_at",
        "request_nonce",
        "tuple_replay_identity_sha256",
        "proof_limit",
        "authorizer_principal",
        "authorizer_authority_key_commitment",
        "signature_ssh",
    }
    if set(raw) != fields:
        raise ValueError("private resolution authorization fields mismatch")
    if (
        raw["schema_version"] != SCHEMA_VERSION
        or raw["producer"] != PRODUCER
        or raw["purpose"] != PURPOSE
        or raw["authorized_operation"] != AUTHORIZED_OPERATION
        or raw["proof_limit"] != PROOF_LIMIT
        or raw["max_private_bundle_resolutions"] != 1
        or raw["single_use"] is not True
        or raw["human_authorized"] is not True
        or raw["static_only"] is not True
        or raw["evaluation_passed"] is not True
    ):
        raise ValueError("unsupported private resolution authorization contract")
    false_fields = {
        "runtime_consumable",
        "execution_authorized",
        "network_authorized",
        "redistribution_authorized",
        "disclosure_authorized",
        "weaponization_authorized",
        "private_bundle_verified",
        "secret_accessed",
        "zeroization_verified",
    }
    if any(raw[name] is not False for name in false_fields):
        raise ValueError("private resolution authorization safety flags are not fail-closed")


def _singleton_policy_authority(
    path: Path,
    identity: str,
    label: str,
    *,
    require_trusted: bool,
) -> tuple[str, str]:
    data = _read_bounded(path, 64 * 1024, f"{label} allowed-signers policy")
    metadata = path.stat()
    if require_trusted and (
        metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError(f"{label} policy must be root-owned and not group/world writable")
    try:
        lines = [
            line
            for line in data.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} policy must be UTF-8") from exc
    if len(lines) != 1:
        raise ValueError(f"{label} policy must contain exactly one signer")
    parts = lines[0].split()
    if len(parts) not in {3, 4} or parts[0] != identity or parts[1] != "ssh-ed25519":
        raise ValueError(f"{label} policy must contain one exact Ed25519 signer")
    try:
        key = base64.b64decode(parts[2], validate=True)
        if not key:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"{label} authority key is malformed") from exc
    commitment = hashlib.sha256(
        b"0verse-ssh-authority-key-v1\0ssh-ed25519\0" + key
    ).hexdigest()
    return hashlib.sha256(data).hexdigest(), commitment


def _require_policy_unchanged(path: Path, expected: str, label: str) -> None:
    observed = hashlib.sha256(
        _read_bounded(path, 64 * 1024, f"{label} allowed-signers policy")
    ).hexdigest()
    if observed != expected:
        raise ValueError(f"{label} allowed-signers policy changed during verification")


def _canonical_json(raw: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("private resolution artifact is not canonical JSON") from exc
