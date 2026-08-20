"""Stateless verification of a complete Windows token-evidence pack.

The verifier rehashes a digest-addressed closure, verifies the outer pack
signature and every nested 0verse signature, and independently derives the
target/control result. It deliberately does not consume replay state or issue
an acceptance, novelty, claim-eligibility, or disclosure decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, cast

from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import sign_ssh_material, verify_ssh_signature
from .windows_lpac_broker_receipt import (
    derive_burn_only_replay_identities as derive_broker_replay_identities,
)
from .windows_lpac_broker_receipt import (
    load_windows_lpac_broker_receipt,
    require_broker_receipt_binding,
)
from .windows_lpac_launch_receipt import (
    derive_burn_only_replay_identities as derive_launch_replay_identities,
)
from .windows_lpac_launch_receipt import (
    load_windows_lpac_launch_receipt,
    require_launch_receipt_binding,
)
from .windows_scope import load_scope
from .windows_token_capture import LPAC_PROCESS_SCHEMA_VERSION, load_windows_token_capture
from .windows_token_evidence import (
    EVIDENCE_SCHEMA_VERSION,
    derive_windows_token_grant_ledger_entry,
    load_windows_token_evidence_receipt,
    observe_windows_token_evidence,
)
from .windows_token_runner import (
    load_windows_token_campaign,
    load_windows_token_execution_grant,
    load_windows_token_worker_acceptance,
)

PACK_SCHEMA_VERSION = "0sec.windows-token-evidence-pack/v1"
LPAC_PACK_SCHEMA_VERSION = "0sec.windows-token-evidence-pack/v2"
LPAC_LAUNCH_PACK_SCHEMA_VERSION = "0sec.windows-token-evidence-pack/v3"
ENVELOPE_SCHEMA_VERSION = "0sec.windows-token-evidence-pack-envelope/v1"
POLICY_SCHEMA_VERSION = "0sec.windows-token-evidence-acceptance-policy/v1"
LPAC_POLICY_SCHEMA_VERSION = "0sec.windows-token-evidence-acceptance-policy/v2"
LPAC_LAUNCH_POLICY_SCHEMA_VERSION = "0sec.windows-token-evidence-acceptance-policy/v3"
PACK_SIGNATURE_NAMESPACE = "0sec-windows-token-evidence-pack-v1"
LPAC_PACK_SIGNATURE_NAMESPACE = "0sec-windows-token-evidence-pack-v2"
LPAC_LAUNCH_PACK_SIGNATURE_NAMESPACE = "0sec-windows-token-evidence-pack-v3"
PACK_MANIFEST_MEDIA_TYPE = "application/vnd.0sec.windows-token-evidence-pack+json"
PACK_SIGNATURE_MEDIA_TYPE = "application/vnd.openssh.signature"
VERIFICATION_SCHEMA_VERSION = "0verse.windows-token-pack-verification/v3"
BUILD_SCHEMA_VERSION = "0verse.windows-token-pack-build/v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_VISIBLE_ASCII = re.compile(r"^[\x20-\x7e]+$")
_MAX_SAFE_INTEGER = 2**53 - 1
_MAX_JSON_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 128
_MAX_BLOB_BYTES = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES = 64 * 1024 * 1024

_MANIFEST_FIELDS = frozenset(
    {
        "schemaVersion",
        "runId",
        "jobNonce",
        "campaign",
        "scopeManifest",
        "executionGrant",
        "workerAcceptance",
        "aggregateReceipt",
        "matrix",
        "signerPolicies",
        "zeroverseRuntime",
        "packSignerIdentity",
    }
)
_MANIFEST_FIELDS_V5 = _MANIFEST_FIELDS | {"brokerReceipts"}
_MANIFEST_FIELDS_V5_LAUNCH = _MANIFEST_FIELDS_V5 | {"launchReceipts"}
_POLICY_FIELDS = frozenset(
    {
        "schemaVersion",
        "allowedPackSignerIdentities",
        "allowedPackSignerPolicySha256",
        "allowedZeroverseOciDigests",
        "allowedScopeSignerPolicySha256",
        "allowedExecutionGrantSignerPolicySha256",
        "allowedWorkerAcceptanceSignerPolicySha256",
        "allowedCaptureSignerPolicySha256",
        "allowedAggregateReceiptSignerPolicySha256",
        "maxBlobSizeBytes",
        "maxBundleSizeBytes",
    }
)
_POLICY_FIELDS_V5 = _POLICY_FIELDS | {"allowedLpacBrokerReceiptSignerPolicySha256"}
_POLICY_FIELDS_V5_LAUNCH = _POLICY_FIELDS_V5 | {
    "allowedLpacLaunchReceiptSignerPolicySha256",
    "allowedLpacLaunchProfileSha256",
}
_CONTEXT_FIELDS = frozenset(
    {
        "runId",
        "jobNonce",
        "packSignerPolicySha256",
        "campaignSha256",
        "scopeManifestSha256",
        "executionGrantSha256",
        "workerAcceptanceSha256",
    }
)


@dataclass(frozen=True)
class BlobRef:
    sha256: str
    size_bytes: int
    media_type: str

    def to_dict(self) -> dict[str, object]:
        return {
            "sha256": self.sha256,
            "sizeBytes": self.size_bytes,
            "mediaType": self.media_type,
        }


@dataclass(frozen=True)
class BuiltWindowsTokenPack:
    """Deterministic local pack output and its complete content references."""

    pack_id: str
    envelope_ref: BlobRef
    blob_refs: tuple[BlobRef, ...]
    context_commitments: dict[str, str]
    envelope_path: Path
    blob_dir: Path
    refs_path: Path

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": BUILD_SCHEMA_VERSION,
            "pack_id": self.pack_id,
            "envelope": self.envelope_ref.to_dict(),
            "blobs": [ref.to_dict() for ref in self.blob_refs],
            "context_commitments": dict(self.context_commitments),
            "envelope_file": "envelope.json",
            "blob_directory": "blobs",
        }


@dataclass(frozen=True)
class WindowsTokenPackVerification:
    pack_id: str
    run_id: str
    job_nonce: str
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    worker_acceptance_sha256: str
    aggregate_receipt_sha256: str
    target_confirmations: int
    clean_controls: int
    trials: int
    pack_signer_identity: str
    zeroverse_runtime_digest: str
    grant_replay_identity_sha256: str
    ordered_run_replay_identity_sha256: tuple[str, ...]
    campaign_id: str
    worker: str
    build_lab_ex: str
    scope_program: str
    scope_url: str
    latest_build_number: str
    latest_build_source_url: str
    latest_build_verified_at: str
    all_start_tokens_lpac: bool
    eligible_sandbox: str
    launch_app_container_executable_sha256: str
    sandbox_process_executable_sha256: str
    launch_transcript_commitment_sha256: str
    starting_context: str
    finishing_principal: str
    minimum_confirmations: int
    worker_machine_id: str
    runner_executable_sha256: str
    witness_user_sid: str
    witness_session_id: int
    witness_authentication_id: str
    witness_executable_sha256: str
    target_operation_sha256: str
    control_operation_sha256: str
    grant_authorized_by: str
    acceptance_accepted_by: str
    capture_signer_identity: str
    worker_acceptance_replay_identity_sha256: str
    ordered_capture_sha256: tuple[str, ...]
    ordered_process_identity_sha256: tuple[str, ...]
    clean_target_no_transitions: int
    ambiguous_targets: int
    run_id_commitment_sha256: str
    job_nonce_commitment_sha256: str
    execution_grant_nonce_commitment_sha256: str
    worker_acceptance_nonce_commitment_sha256: str
    ordered_capture_nonce_commitment_sha256: tuple[str, ...]
    scope_authorized_by: str
    aggregate_signed_by: str
    scope_authority_key_commitment_sha256: str
    grant_authority_key_commitment_sha256: str
    acceptance_authority_key_commitment_sha256: str
    capture_authority_key_commitment_sha256: str
    aggregate_authority_key_commitment_sha256: str
    pack_authority_key_commitment_sha256: str
    ordered_broker_receipt_replay_identity_sha256: tuple[str, ...] = ()
    ordered_broker_process_replay_identity_sha256: tuple[str, ...] = ()
    ordered_broker_transcript_replay_identity_sha256: tuple[str, ...] = ()
    broker_receipt_authority_key_commitment_sha256: str = ""
    broker_receipt_signer_identity: str = ""
    ordered_launch_receipt_replay_identity_sha256: tuple[str, ...] = ()
    ordered_launch_process_replay_identity_sha256: tuple[str, ...] = ()
    ordered_launch_transcript_replay_identity_sha256: tuple[str, ...] = ()
    launch_receipt_authority_key_commitment_sha256: str = ""
    launch_receipt_signer_identity: str = ""

    def require_legacy_identity_schema(self) -> None:
        broker_fields = (
            bool(self.ordered_broker_receipt_replay_identity_sha256),
            bool(self.ordered_broker_process_replay_identity_sha256),
            bool(self.ordered_broker_transcript_replay_identity_sha256),
            bool(self.broker_receipt_authority_key_commitment_sha256),
            bool(self.broker_receipt_signer_identity),
        )
        launch_fields = (
            bool(self.ordered_launch_receipt_replay_identity_sha256),
            bool(self.ordered_launch_process_replay_identity_sha256),
            bool(self.ordered_launch_transcript_replay_identity_sha256),
            bool(self.launch_receipt_authority_key_commitment_sha256),
            bool(self.launch_receipt_signer_identity),
        )
        if any(broker_fields) and not all(broker_fields):
            raise ValueError("broker-bearing pack verification fields are incoherent")
        if any(launch_fields) and not all(launch_fields):
            raise ValueError("launch-bearing pack verification fields are incoherent")
        if any(launch_fields) and not all(broker_fields):
            raise ValueError("launch-bearing pack verification requires broker identities")
        if all(broker_fields) or all(launch_fields):
            raise ValueError(
                "broker-bearing pack verification output requires an additive acceptance-"
                "witness/measured-process identity schema"
            )

    def to_dict(self) -> dict[str, object]:
        self.require_legacy_identity_schema()
        result: dict[str, object] = {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "status": "ARTIFACT_CLOSURE_VERIFIED",
            "pack_id": self.pack_id,
            "run_id": self.run_id,
            "job_nonce": self.job_nonce,
            "campaign_sha256": self.campaign_sha256,
            "scope_manifest_sha256": self.scope_manifest_sha256,
            "execution_grant_sha256": self.execution_grant_sha256,
            "worker_acceptance_sha256": self.worker_acceptance_sha256,
            "aggregate_receipt_sha256": self.aggregate_receipt_sha256,
            "target_confirmations": self.target_confirmations,
            "clean_controls": self.clean_controls,
            "trials": self.trials,
            "pack_signer_identity": self.pack_signer_identity,
            "zeroverse_runtime_digest": self.zeroverse_runtime_digest,
            "closure_commitment_sha256": self.pack_id,
            "grant_replay_identity_sha256": self.grant_replay_identity_sha256,
            "ordered_run_replay_identity_sha256": list(self.ordered_run_replay_identity_sha256),
            "authority_binding_verified": True,
            "aggregate_semantics_verified": True,
            "runtime_provenance": "outer-signed-allowlisted-not-attested",
            "replay_state_consumed": False,
            "witness_user_sid": self.witness_user_sid,
            "witness_session_id": self.witness_session_id,
            "witness_authentication_id": self.witness_authentication_id,
            "witness_executable_sha256": self.witness_executable_sha256,
            "accepted": False,
            "claim_eligible": False,
            "weaponization": False,
            "auto_disclosure": False,
            "human_report_gate": True,
            "scope_program": self.scope_program,
            "scope_url": self.scope_url,
            "latest_build_number": self.latest_build_number,
            "latest_build_source_url": self.latest_build_source_url,
            "latest_build_verified_at": self.latest_build_verified_at,
            "all_start_tokens_lpac": self.all_start_tokens_lpac,
            "eligible_sandbox": self.eligible_sandbox,
            "launch_app_container_executable_sha256": (self.launch_app_container_executable_sha256),
            "sandbox_process_executable_sha256": self.sandbox_process_executable_sha256,
            "launch_transcript_commitment_sha256": (self.launch_transcript_commitment_sha256),
        }
        return result


class BlobDirectory:
    """Read exact SHA-256 filenames from a caller-owned private CAS directory."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("token pack blob directory must be a regular directory")

    def read(self, ref: BlobRef, *, maximum: int) -> bytes:
        if ref.size_bytes > maximum:
            raise ValueError(f"blob {ref.sha256} exceeds the configured size limit")
        directory = os.open(
            self.root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            descriptor = os.open(
                ref.sha256,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory,
            )
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != ref.size_bytes:
                    raise ValueError(f"blob {ref.sha256} size differs from its content ref")
                with os.fdopen(os.dup(descriptor), "rb") as stream:
                    data = stream.read(ref.size_bytes + 1)
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
        if len(data) != ref.size_bytes or hashlib.sha256(data).hexdigest() != ref.sha256:
            raise ValueError(f"blob {ref.sha256} bytes differ from its content ref")
        return data


def build_windows_token_pack(
    output_dir: str | Path,
    *,
    campaign_path: str | Path,
    scope_manifest_path: str | Path,
    execution_grant_path: str | Path,
    worker_acceptance_path: str | Path,
    aggregate_receipt_path: str | Path,
    capture_paths: Sequence[str | Path],
    scope_allowed_signers_path: str | Path,
    execution_grant_allowed_signers_path: str | Path,
    worker_acceptance_allowed_signers_path: str | Path,
    capture_allowed_signers_path: str | Path,
    aggregate_allowed_signers_path: str | Path,
    run_id: str,
    job_nonce: str,
    zeroverse_runtime_digest: str,
    pack_signer_identity: str,
    pack_signing_key: str | Path,
    broker_receipt_paths: Sequence[str | Path] | None = None,
    broker_receipt_allowed_signers_path: str | Path | None = None,
    launch_receipt_paths: Sequence[str | Path] | None = None,
    launch_receipt_allowed_signers_path: str | Path | None = None,
) -> BuiltWindowsTokenPack:
    """Verify, canonicalize, sign, and atomically retain one token pack.

    The acceptance policy, expected context, and pack-signer policy remain
    service-selected verifier inputs and are intentionally not accepted from
    or embedded by this producer.  ``context_commitments`` in the returned
    build record is informational; an accepter must independently select and
    validate its trusted expected context.
    """
    _safe_text(run_id, "token pack runId")
    if _NONCE.fullmatch(job_nonce) is None:
        raise ValueError("token pack jobNonce is invalid")
    if _OCI_DIGEST.fullmatch(zeroverse_runtime_digest) is None:
        raise ValueError("token pack zeroverse runtime digest is invalid")
    _safe_text(pack_signer_identity, "token pack packSignerIdentity")
    if isinstance(capture_paths, (str, bytes, Path)) or not capture_paths:
        raise ValueError("token pack capture_paths must be a non-empty path sequence")
    if (broker_receipt_paths is None) != (broker_receipt_allowed_signers_path is None):
        raise ValueError("token pack broker receipts and signer policy must be supplied together")
    if (launch_receipt_paths is None) != (launch_receipt_allowed_signers_path is None):
        raise ValueError("token pack launch receipts and signer policy must be supplied together")
    if launch_receipt_paths is not None and broker_receipt_paths is None:
        raise ValueError("token pack launch receipts require LPAC broker receipts")

    policy_source_paths = {
        "scopeAuthorization": scope_allowed_signers_path,
        "executionGrantAuthorization": execution_grant_allowed_signers_path,
        "workerAcceptanceAuthorization": worker_acceptance_allowed_signers_path,
        "capture": capture_allowed_signers_path,
        "aggregateReceipt": aggregate_allowed_signers_path,
    }
    if broker_receipt_allowed_signers_path is not None:
        policy_source_paths["lpacBrokerReceipt"] = broker_receipt_allowed_signers_path
    if launch_receipt_allowed_signers_path is not None:
        policy_source_paths["lpacLaunchReceipt"] = launch_receipt_allowed_signers_path
    policy_bytes = {
        role: _read_regular_path(path, _MAX_JSON_BYTES, f"{role} signer policy")
        for role, path in policy_source_paths.items()
    }
    campaign, campaign_sha256 = load_windows_token_campaign(campaign_path)
    with tempfile.TemporaryDirectory(prefix="0verse-token-pack-builder-policy-") as root:
        staged_policies = {
            role: _stage_blob(Path(root), role, data) for role, data in policy_bytes.items()
        }
        scope, scope_sha256 = load_scope(
            scope_manifest_path,
            allowed_signers=staged_policies["scopeAuthorization"],
            require_authorized=True,
        )
        grant, grant_sha256 = load_windows_token_execution_grant(
            execution_grant_path,
            allowed_signers=staged_policies["executionGrantAuthorization"],
            require_authorized=True,
        )
        acceptance, acceptance_sha256 = load_windows_token_worker_acceptance(
            worker_acceptance_path,
            allowed_signers=staged_policies["workerAcceptanceAuthorization"],
            require_authorized=True,
        )
        resolved_capture_paths = tuple(Path(path) for path in capture_paths)
        capture_models = [
            load_windows_token_capture(
                path,
                allowed_signers=staged_policies["capture"],
                require_verified=True,
            )[0]
            for path in resolved_capture_paths
        ]
        broker_models = []
        broker_sha256s: list[str] = []
        resolved_broker_paths: tuple[Path, ...] = ()
        if broker_receipt_paths is not None:
            if isinstance(broker_receipt_paths, (str, bytes, Path)):
                raise ValueError("token pack broker_receipt_paths must be a path sequence")
            resolved_broker_paths = tuple(Path(path) for path in broker_receipt_paths)
            if len(resolved_broker_paths) != len(capture_models):
                raise ValueError("token pack requires one LPAC broker receipt per capture")
            broker_models_and_sha = [
                load_windows_lpac_broker_receipt(
                    path, allowed_signers=staged_policies["lpacBrokerReceipt"]
                )
                for path in resolved_broker_paths
            ]
            broker_models = [item[0] for item in broker_models_and_sha]
            broker_sha256s = [item[1] for item in broker_models_and_sha]
            broker_signers = {broker.signed_by for broker in broker_models}
            other_signers = {
                scope.authorized_by,
                grant.authorized_by,
                acceptance.accepted_by,
                acceptance.capture_signer,
                pack_signer_identity,
            }
            if len(broker_signers) != 1 or broker_signers & other_signers:
                raise ValueError("LPAC broker signer must be one distinct authority")
            broker_authority = ssh_authority_key_commitment(staged_policies["lpacBrokerReceipt"])
            other_authorities = {
                ssh_authority_key_commitment(path)
                for role, path in staged_policies.items()
                if role != "lpacBrokerReceipt"
            }
            if broker_authority in other_authorities:
                raise ValueError("LPAC broker signer key must be role-distinct")
            if any(
                capture.schema_version != LPAC_PROCESS_SCHEMA_VERSION for capture in capture_models
            ):
                raise ValueError("token pack broker receipts require capture v5 only")
            for capture, broker, broker_sha in zip(
                capture_models, broker_models, broker_sha256s, strict=True
            ):
                require_broker_receipt_binding(
                    broker,
                    receipt_sha256=broker_sha,
                    capture=capture,
                    campaign=campaign,
                    campaign_sha256=campaign_sha256,
                    scope_sha256=scope_sha256,
                    grant_sha256=grant_sha256,
                    acceptance_sha256=acceptance_sha256,
                )
        elif any(
            capture.schema_version == LPAC_PROCESS_SCHEMA_VERSION for capture in capture_models
        ):
            raise ValueError("token pack capture v5 requires LPAC broker receipt blobs")
        launch_models = []
        launch_sha256s: list[str] = []
        resolved_launch_paths: tuple[Path, ...] = ()
        if launch_receipt_paths is not None:
            if isinstance(launch_receipt_paths, (str, bytes, Path)):
                raise ValueError("token pack launch_receipt_paths must be a path sequence")
            resolved_launch_paths = tuple(Path(path) for path in launch_receipt_paths)
            if len(resolved_launch_paths) != len(capture_models):
                raise ValueError("token pack requires one LPAC launch receipt per capture")
            launch_models_and_sha = [
                load_windows_lpac_launch_receipt(
                    path, allowed_signers=staged_policies["lpacLaunchReceipt"]
                )
                for path in resolved_launch_paths
            ]
            launch_models = [item[0] for item in launch_models_and_sha]
            launch_sha256s = [item[1] for item in launch_models_and_sha]
            uniqueness = (
                [row.receipt_nonce for row in launch_models],
                [row.process_locator_identity_sha256 for row in launch_models],
                [row.launch_transcript_sha256 for row in launch_models],
            )
            if any(len(values) != len(set(values)) for values in uniqueness):
                raise ValueError("token pack reuses LPAC launch receipt identities")
            launch_signers = {launch.signed_by for launch in launch_models}
            other_signers = {
                scope.authorized_by,
                grant.authorized_by,
                acceptance.accepted_by,
                acceptance.capture_signer,
                pack_signer_identity,
                *(broker.signed_by for broker in broker_models),
            }
            if len(launch_signers) != 1 or launch_signers & other_signers:
                raise ValueError("LPAC launch signer must be one distinct authority")
            launch_authority = ssh_authority_key_commitment(staged_policies["lpacLaunchReceipt"])
            if any(
                launch_authority == ssh_authority_key_commitment(path)
                for role, path in staged_policies.items()
                if role != "lpacLaunchReceipt"
            ):
                raise ValueError("LPAC launch signer key must be role-distinct")
            for capture, broker, launch, launch_sha in zip(
                capture_models,
                broker_models,
                launch_models,
                launch_sha256s,
                strict=True,
            ):
                require_launch_receipt_binding(
                    launch,
                    receipt_sha256=launch_sha,
                    capture=capture,
                    broker=broker,
                    campaign=campaign,
                    scope=scope,
                    grant=grant,
                    acceptance=acceptance,
                    campaign_sha256=campaign_sha256,
                    scope_sha256=scope_sha256,
                    grant_sha256=grant_sha256,
                    acceptance_sha256=acceptance_sha256,
                )
        observation = observe_windows_token_evidence(
            capture_models,
            campaign,
            campaign_sha256,
            scope,
            scope_sha256,
            grant,
            grant_sha256,
            acceptance,
            acceptance_sha256,
        )
        aggregate, aggregate_sha256 = load_windows_token_evidence_receipt(
            aggregate_receipt_path,
            allowed_signers=staged_policies["aggregateReceipt"],
        )
        if broker_models and cast(str, aggregate["signed_by"]) in {
            broker.signed_by for broker in broker_models
        }:
            raise ValueError("LPAC broker and aggregate signers must be distinct")
        if launch_models and cast(str, aggregate["signed_by"]) in {
            launch.signed_by for launch in launch_models
        }:
            raise ValueError("LPAC launch and aggregate signers must be distinct")
    expected_aggregate = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "status": "AGGREGATED",
        **observation.evidence.to_dict(),
    }
    for name, value in expected_aggregate.items():
        if aggregate.get(name) != value:
            raise ValueError(f"aggregate receipt {name} differs from derived evidence")

    artifact_sources = {
        "campaign": (campaign_path, campaign_sha256),
        "scopeManifest": (scope_manifest_path, scope_sha256),
        "executionGrant": (execution_grant_path, grant_sha256),
        "workerAcceptance": (worker_acceptance_path, acceptance_sha256),
        "aggregateReceipt": (aggregate_receipt_path, aggregate_sha256),
    }
    blob_bytes: dict[str, tuple[bytes, str]] = {}

    def retain(data: bytes, media_type: str, label: str) -> dict[str, object]:
        if not data or len(data) > _MAX_BLOB_BYTES:
            raise ValueError(f"{label} is empty or exceeds the pack blob limit")
        digest = hashlib.sha256(data).hexdigest()
        existing = blob_bytes.get(digest)
        if existing is not None and existing != (data, media_type):
            raise ValueError(f"{label} conflicts with an existing content reference")
        blob_bytes[digest] = (data, media_type)
        return BlobRef(digest, len(data), media_type).to_dict()

    artifact_refs = {
        name: retain(
            _source_bound_bytes(path, digest, name),
            "application/json",
            name,
        )
        for name, (path, digest) in artifact_sources.items()
    }
    capture_by_role = {(capture.case, capture.trial): capture for capture in capture_models}
    capture_path_by_role = {
        (capture.case, capture.trial): path
        for path, capture in zip(resolved_capture_paths, capture_models, strict=True)
    }
    capture_rows: list[dict[str, object]] = []
    broker_by_role = (
        {
            (capture.case, capture.trial): (path, model, digest)
            for capture, path, model, digest in zip(
                capture_models,
                resolved_broker_paths,
                broker_models,
                broker_sha256s,
                strict=True,
            )
        }
        if broker_models
        else {}
    )
    broker_rows: list[dict[str, object]] = []
    launch_by_role = (
        {
            (capture.case, capture.trial): (path, model, digest)
            for capture, path, model, digest in zip(
                capture_models,
                resolved_launch_paths,
                launch_models,
                launch_sha256s,
                strict=True,
            )
        }
        if launch_models
        else {}
    )
    launch_rows: list[dict[str, object]] = []
    for trial in range(1, campaign.trials + 1):
        for case in ("target", "control"):
            capture = capture_by_role[(case, trial)]
            capture_rows.append(
                {
                    "case": case,
                    "trial": trial,
                    "artifact": retain(
                        _source_bound_bytes(
                            capture_path_by_role[(case, trial)],
                            capture.source_sha256,
                            f"{case} capture {trial}",
                        ),
                        "application/json",
                        f"{case} capture {trial}",
                    ),
                }
            )
            if broker_by_role:
                broker_path, _broker, broker_sha = broker_by_role[(case, trial)]
                broker_rows.append(
                    {
                        "case": case,
                        "trial": trial,
                        "artifact": retain(
                            _source_bound_bytes(
                                broker_path, broker_sha, f"{case} LPAC broker receipt {trial}"
                            ),
                            "application/json",
                            f"{case} LPAC broker receipt {trial}",
                        ),
                    }
                )
            if launch_by_role:
                launch_path, _launch, launch_sha = launch_by_role[(case, trial)]
                launch_rows.append(
                    {
                        "case": case,
                        "trial": trial,
                        "artifact": retain(
                            _source_bound_bytes(
                                launch_path,
                                launch_sha,
                                f"{case} LPAC launch receipt {trial}",
                            ),
                            "application/json",
                            f"{case} LPAC launch receipt {trial}",
                        ),
                    }
                )

    policy_refs = {
        role: retain(
            data,
            "text/plain",
            f"{role} signer policy",
        )
        for role, data in policy_bytes.items()
    }
    manifest: dict[str, object] = {
        "schemaVersion": (
            LPAC_LAUNCH_PACK_SCHEMA_VERSION
            if launch_rows
            else LPAC_PACK_SCHEMA_VERSION
            if broker_rows
            else PACK_SCHEMA_VERSION
        ),
        "runId": run_id,
        "jobNonce": job_nonce,
        **artifact_refs,
        "matrix": {"trials": campaign.trials, "captures": capture_rows},
        "signerPolicies": policy_refs,
        "zeroverseRuntime": {
            "kind": "oci-image",
            "digest": zeroverse_runtime_digest,
        },
        "packSignerIdentity": pack_signer_identity,
    }
    if broker_rows:
        manifest["brokerReceipts"] = broker_rows
    if launch_rows:
        manifest["launchReceipts"] = launch_rows
    manifest_bytes = _canonical_json_bytes(manifest)
    _parse_manifest(manifest_bytes)
    manifest_ref = retain(
        manifest_bytes,
        PACK_MANIFEST_MEDIA_TYPE,
        "token pack manifest",
    )
    unsigned_refs = tuple(
        BlobRef(digest, len(data), media_type) for digest, (data, media_type) in blob_bytes.items()
    )
    if _unique_bundle_size(unsigned_refs) >= _MAX_BUNDLE_BYTES:
        raise ValueError("token pack closure leaves no room for its signature")
    signature_bytes = sign_ssh_material(
        manifest_bytes,
        signing_key=pack_signing_key,
        namespace=(
            LPAC_LAUNCH_PACK_SIGNATURE_NAMESPACE
            if launch_rows
            else LPAC_PACK_SIGNATURE_NAMESPACE
            if broker_rows
            else PACK_SIGNATURE_NAMESPACE
        ),
        label="Windows token evidence pack",
    ).encode("utf-8")
    signature_ref = retain(
        signature_bytes,
        PACK_SIGNATURE_MEDIA_TYPE,
        "token pack signature",
    )
    envelope: dict[str, object] = {
        "schemaVersion": ENVELOPE_SCHEMA_VERSION,
        "packId": manifest_ref["sha256"],
        "manifest": manifest_ref,
        "signature": signature_ref,
    }
    _parse_envelope(cast(dict[str, object], json.loads(_canonical_json_bytes(envelope))))
    envelope_bytes = _canonical_json_bytes(envelope)
    envelope_ref = BlobRef(
        hashlib.sha256(envelope_bytes).hexdigest(),
        len(envelope_bytes),
        "application/json",
    )
    refs = tuple(
        BlobRef(digest, len(data), media_type)
        for digest, (data, media_type) in sorted(blob_bytes.items())
    )
    _require_build_bundle_size(refs)
    context_commitments = {
        "runId": run_id,
        "jobNonce": job_nonce,
        "campaignSha256": campaign_sha256,
        "scopeManifestSha256": scope_sha256,
        "executionGrantSha256": grant_sha256,
        "workerAcceptanceSha256": acceptance_sha256,
    }
    requested_destination = Path(output_dir)
    if _SAFE_PATH_COMPONENT.fullmatch(
        requested_destination.name
    ) is None or requested_destination.name in {".", ".."}:
        raise ValueError("token pack output directory name is invalid")
    requested_parent = requested_destination.parent
    absolute_parent = requested_parent.absolute()
    if absolute_parent != requested_parent.resolve():
        raise ValueError("token pack output parent must not traverse a symlink")
    destination = absolute_parent / requested_destination.name
    provisional = BuiltWindowsTokenPack(
        pack_id=cast(str, envelope["packId"]),
        envelope_ref=envelope_ref,
        blob_refs=refs,
        context_commitments=context_commitments,
        envelope_path=destination / "envelope.json",
        blob_dir=destination / "blobs",
        refs_path=destination / "refs.json",
    )
    _publish_pack_directory(
        destination,
        envelope_bytes=envelope_bytes,
        blob_bytes=blob_bytes,
        refs_bytes=_canonical_json_bytes(provisional.to_dict()) + b"\n",
    )
    return provisional


def verify_windows_token_pack(
    envelope_path: str | Path,
    *,
    blob_dir: str | Path,
    acceptance_policy_path: str | Path,
    expected_context_path: str | Path,
    pack_signer_policy_path: str | Path,
) -> WindowsTokenPackVerification:
    """Verify the complete signed closure without mutating replay state."""
    envelope = _parse_envelope(_load_json_path(envelope_path, "token pack envelope"))
    policy = _parse_policy(_load_json_path(acceptance_policy_path, "token pack acceptance policy"))
    expected = _parse_context(_load_json_path(expected_context_path, "token pack expected context"))
    store = BlobDirectory(blob_dir)
    max_blob_size = cast(int, policy["maxBlobSizeBytes"])
    max_bundle_size = cast(int, policy["maxBundleSizeBytes"])

    manifest_ref = envelope["manifest"]
    signature_ref = envelope["signature"]
    assert isinstance(manifest_ref, BlobRef) and isinstance(signature_ref, BlobRef)
    manifest_bytes = store.read(manifest_ref, maximum=max_blob_size)
    manifest = _parse_manifest(manifest_bytes)
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_digest != envelope["packId"] or manifest_digest != manifest_ref.sha256:
        raise ValueError("token pack envelope does not bind the canonical manifest")

    _validate_manifest_policy_context(manifest, policy, expected, manifest_digest)
    inner_refs = _manifest_blob_refs(manifest)
    _validate_complete_size_policy(
        [*inner_refs, manifest_ref, signature_ref],
        max_blob=max_blob_size,
        max_bundle=max_bundle_size,
    )

    pack_policy_bytes = _read_regular_path(
        pack_signer_policy_path, 1024 * 1024, "pack signer allowed-signers policy"
    )
    pack_policy_digest = hashlib.sha256(pack_policy_bytes).hexdigest()
    if pack_policy_digest != expected["packSignerPolicySha256"] or pack_policy_digest not in cast(
        list[str], policy["allowedPackSignerPolicySha256"]
    ):
        raise ValueError("pack signer policy differs from trusted expected context")
    signature = store.read(signature_ref, maximum=max_blob_size)
    try:
        signature_text = signature.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("token pack signature is not UTF-8") from exc
    # Verify against the exact policy bytes that were hashed above. Reopening the
    # caller path here would permit a policy swap between the digest check and
    # ssh-keygen verification.
    with tempfile.TemporaryDirectory(prefix="0verse-pack-policy-") as policy_temp:
        staged_pack_policy = _stage_blob(Path(policy_temp), "allowed-signers", pack_policy_bytes)
        verify_ssh_signature(
            manifest_bytes,
            signature_text,
            identity=cast(str, manifest["packSignerIdentity"]),
            namespace=(
                LPAC_LAUNCH_PACK_SIGNATURE_NAMESPACE
                if manifest["schemaVersion"] == LPAC_LAUNCH_PACK_SCHEMA_VERSION
                else LPAC_PACK_SIGNATURE_NAMESPACE
                if manifest["schemaVersion"] == LPAC_PACK_SCHEMA_VERSION
                else PACK_SIGNATURE_NAMESPACE
            ),
            allowed_signers=staged_pack_policy,
            label="Windows token evidence pack",
            require_trusted_policy=False,
        )
        pack_authority_key_commitment = ssh_authority_key_commitment(staged_pack_policy)

    refs = _named_manifest_refs(manifest)
    policies = manifest["signerPolicies"]
    assert isinstance(policies, dict)
    with tempfile.TemporaryDirectory(prefix="0verse-token-pack-") as temporary:
        staging = Path(temporary)
        paths: dict[str, Path] = {}
        for name, ref in refs.items():
            paths[name] = _stage_blob(staging, name, store.read(ref, maximum=max_blob_size))
        policy_paths: dict[str, Path] = {}
        for name, ref in policies.items():
            assert isinstance(ref, BlobRef)
            policy_paths[name] = _stage_blob(
                staging,
                f"policy-{name}",
                store.read(ref, maximum=max_blob_size),
            )
        role_authority_commitments = {
            name: ssh_authority_key_commitment(path) for name, path in policy_paths.items()
        }

        campaign, campaign_sha = load_windows_token_campaign(paths["campaign"])
        scope, scope_sha = load_scope(
            paths["scopeManifest"],
            allowed_signers=policy_paths["scopeAuthorization"],
            require_authorized=True,
        )
        grant, grant_sha = load_windows_token_execution_grant(
            paths["executionGrant"],
            allowed_signers=policy_paths["executionGrantAuthorization"],
            require_authorized=True,
        )
        acceptance, acceptance_sha = load_windows_token_worker_acceptance(
            paths["workerAcceptance"],
            allowed_signers=policy_paths["workerAcceptanceAuthorization"],
            require_authorized=True,
        )

        capture_models = []
        matrix = manifest["matrix"]
        assert isinstance(matrix, dict)
        captures = matrix["captures"]
        assert isinstance(captures, list)
        for index, capture_ref in enumerate(captures):
            assert isinstance(capture_ref, dict)
            capture, capture_sha = load_windows_token_capture(
                paths[f"capture-{index}"],
                allowed_signers=policy_paths["capture"],
                require_verified=True,
            )
            artifact = capture_ref["artifact"]
            assert isinstance(artifact, BlobRef)
            if (
                capture_sha != artifact.sha256
                or capture.case != capture_ref["case"]
                or capture.trial != capture_ref["trial"]
            ):
                raise ValueError("capture bytes differ from their canonical matrix row")
            capture_models.append(capture)

        broker_models = []
        broker_replay_rows: list[tuple[str, str, str]] = []
        broker_rows = manifest.get("brokerReceipts", [])
        assert isinstance(broker_rows, list)
        if broker_rows:
            if len(broker_rows) != len(capture_models):
                raise ValueError("token pack requires one LPAC broker receipt per capture")
            for index, (broker_ref, capture) in enumerate(
                zip(broker_rows, capture_models, strict=True)
            ):
                assert isinstance(broker_ref, dict)
                broker, broker_sha = load_windows_lpac_broker_receipt(
                    paths[f"broker-receipt-{index}"],
                    allowed_signers=policy_paths["lpacBrokerReceipt"],
                )
                artifact = broker_ref["artifact"]
                assert isinstance(artifact, BlobRef)
                if broker_sha != artifact.sha256:
                    raise ValueError("LPAC broker receipt bytes differ from matrix row")
                require_broker_receipt_binding(
                    broker,
                    receipt_sha256=broker_sha,
                    capture=capture,
                    campaign=campaign,
                    campaign_sha256=campaign_sha,
                    scope_sha256=scope_sha,
                    grant_sha256=grant_sha,
                    acceptance_sha256=acceptance_sha,
                )
                broker_models.append(broker)
                broker_replay_rows.append(derive_broker_replay_identities(broker))
            uniqueness = (
                [row.receipt_nonce for row in broker_models],
                [row.process_identity_sha256 for row in broker_models],
                [row.measurement_transcript_sha256 for row in broker_models],
            )
            if any(len(values) != len(set(values)) for values in uniqueness):
                raise ValueError("token pack reuses LPAC broker receipt identities")
            broker_signers = {broker.signed_by for broker in broker_models}
            if len(broker_signers) != 1 or broker_signers & {
                scope.authorized_by,
                grant.authorized_by,
                acceptance.accepted_by,
                acceptance.capture_signer,
                cast(str, manifest["packSignerIdentity"]),
            }:
                raise ValueError("LPAC broker signer must be one distinct authority")
            broker_authority = role_authority_commitments["lpacBrokerReceipt"]
            if (
                broker_authority
                in {
                    commitment
                    for role, commitment in role_authority_commitments.items()
                    if role != "lpacBrokerReceipt"
                }
                or broker_authority == pack_authority_key_commitment
            ):
                raise ValueError("LPAC broker signer key must be role-distinct")
        elif any(
            capture.schema_version == LPAC_PROCESS_SCHEMA_VERSION for capture in capture_models
        ):
            raise ValueError("token pack capture v5 requires LPAC broker receipt blobs")

        launch_models = []
        launch_replay_rows: list[tuple[str, str, str]] = []
        launch_rows = manifest.get("launchReceipts", [])
        assert isinstance(launch_rows, list)
        if launch_rows:
            if len(launch_rows) != len(capture_models) or len(broker_models) != len(capture_models):
                raise ValueError("token pack requires one launch and broker receipt per capture")
            for index, (launch_ref, capture, broker) in enumerate(
                zip(launch_rows, capture_models, broker_models, strict=True)
            ):
                assert isinstance(launch_ref, dict)
                launch, launch_sha = load_windows_lpac_launch_receipt(
                    paths[f"launch-receipt-{index}"],
                    allowed_signers=policy_paths["lpacLaunchReceipt"],
                )
                artifact = launch_ref["artifact"]
                assert isinstance(artifact, BlobRef)
                if launch_sha != artifact.sha256:
                    raise ValueError("LPAC launch receipt bytes differ from matrix row")
                require_launch_receipt_binding(
                    launch,
                    receipt_sha256=launch_sha,
                    capture=capture,
                    broker=broker,
                    campaign=campaign,
                    scope=scope,
                    grant=grant,
                    acceptance=acceptance,
                    campaign_sha256=campaign_sha,
                    scope_sha256=scope_sha,
                    grant_sha256=grant_sha,
                    acceptance_sha256=acceptance_sha,
                )
                launch_models.append(launch)
                launch_replay_rows.append(derive_launch_replay_identities(launch))
            _require_lpac_launch_profiles_selected(launch_models, policy)
            uniqueness = (
                [row.receipt_nonce for row in launch_models],
                [row.process_locator_identity_sha256 for row in launch_models],
                [row.launch_transcript_sha256 for row in launch_models],
            )
            if any(len(values) != len(set(values)) for values in uniqueness):
                raise ValueError("token pack reuses LPAC launch receipt identities")
            launch_signers = {launch.signed_by for launch in launch_models}
            disallowed_signers = {
                scope.authorized_by,
                grant.authorized_by,
                acceptance.accepted_by,
                acceptance.capture_signer,
                cast(str, manifest["packSignerIdentity"]),
                *(broker.signed_by for broker in broker_models),
            }
            if len(launch_signers) != 1 or launch_signers & disallowed_signers:
                raise ValueError("LPAC launch signer must be one distinct authority")
            launch_authority = role_authority_commitments["lpacLaunchReceipt"]
            if (
                launch_authority
                in {
                    commitment
                    for role, commitment in role_authority_commitments.items()
                    if role != "lpacLaunchReceipt"
                }
                or launch_authority == pack_authority_key_commitment
            ):
                raise ValueError("LPAC launch signer key must be role-distinct")

        receipt, receipt_sha = load_windows_token_evidence_receipt(
            paths["aggregateReceipt"],
            allowed_signers=policy_paths["aggregateReceipt"],
        )
        if broker_models and cast(str, receipt["signed_by"]) in {
            broker.signed_by for broker in broker_models
        }:
            raise ValueError("LPAC broker and aggregate signers must be distinct")
        if launch_models and cast(str, receipt["signed_by"]) in {
            launch.signed_by for launch in launch_models
        }:
            raise ValueError("LPAC launch and aggregate signers must be distinct")
        observation = observe_windows_token_evidence(
            capture_models,
            campaign,
            campaign_sha,
            scope,
            scope_sha,
            grant,
            grant_sha,
            acceptance,
            acceptance_sha,
        )
        derived = observation.evidence

        embedded_launch_rows = [
            capture.lpac_launch for capture in capture_models if capture.lpac_launch is not None
        ]
        if launch_models:
            transcript_ids = [row.launch_transcript_sha256 for row in launch_models]
            launch_transcript_commitment = hashlib.sha256(
                b"0verse-windows-lpac-launch-transcripts-v2\0"
                + b"\0".join(value.encode("ascii") for value in transcript_ids)
            ).hexdigest()
        elif embedded_launch_rows:
            if len(embedded_launch_rows) != len(capture_models):
                raise ValueError("token pack mixes LPAC-aware and legacy captures")
            receipt_ids = [row.launch_receipt_sha256 for row in embedded_launch_rows]
            creation_ids = [row.process_creation_identity_sha256 for row in embedded_launch_rows]
            transcript_ids = [row.launch_transcript_sha256 for row in embedded_launch_rows]
            if (
                len(receipt_ids) != len(set(receipt_ids))
                or len(creation_ids) != len(set(creation_ids))
                or len(transcript_ids) != len(set(transcript_ids))
            ):
                raise ValueError("token pack reuses LPAC launch provenance")
            launch_transcript_commitment = hashlib.sha256(
                b"0verse-windows-lpac-launch-transcripts-v1\0"
                + b"\0".join(value.encode("ascii") for value in transcript_ids)
            ).hexdigest()
        else:
            launch_transcript_commitment = ""

    expected_receipt = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "status": "AGGREGATED",
        **derived.to_dict(),
    }
    for name, value in expected_receipt.items():
        if receipt.get(name) != value:
            raise ValueError(f"aggregate receipt {name} differs from derived evidence")

    return WindowsTokenPackVerification(
        pack_id=manifest_digest,
        run_id=cast(str, manifest["runId"]),
        job_nonce=cast(str, manifest["jobNonce"]),
        campaign_sha256=campaign_sha,
        scope_manifest_sha256=scope_sha,
        execution_grant_sha256=grant_sha,
        worker_acceptance_sha256=acceptance_sha,
        aggregate_receipt_sha256=receipt_sha,
        target_confirmations=derived.target_confirmations,
        clean_controls=derived.clean_controls,
        trials=derived.trials,
        pack_signer_identity=cast(str, manifest["packSignerIdentity"]),
        zeroverse_runtime_digest=cast(dict[str, str], manifest["zeroverseRuntime"])["digest"],
        grant_replay_identity_sha256=derive_windows_token_grant_ledger_entry(
            grant.nonce, campaign_sha
        ),
        ordered_run_replay_identity_sha256=derived.ledger_entry,
        campaign_id=campaign.campaign_id,
        worker=campaign.worker,
        build_lab_ex=scope.preflight_build_lab_ex,
        scope_program=scope.program,
        scope_url=scope.scope_url,
        latest_build_number=scope.latest_build_number,
        latest_build_source_url=scope.latest_build_source_url,
        latest_build_verified_at=scope.latest_build_verified_at,
        all_start_tokens_lpac=bool(capture_models)
        and all(capture.start_token.less_privileged_app_container for capture in capture_models),
        eligible_sandbox=campaign.eligible_sandbox,
        launch_app_container_executable_sha256=(campaign.launch_app_container_executable_sha256),
        sandbox_process_executable_sha256=campaign.sandbox_process_executable_sha256,
        launch_transcript_commitment_sha256=launch_transcript_commitment,
        starting_context=campaign.starting_context,
        finishing_principal=campaign.finishing_principal,
        minimum_confirmations=campaign.minimum_confirmations,
        worker_machine_id=acceptance.worker_machine_id,
        runner_executable_sha256=acceptance.runner_executable_sha256,
        witness_user_sid=derived.witness_user_sid,
        witness_session_id=derived.witness_session_id,
        witness_authentication_id=derived.witness_authentication_id,
        witness_executable_sha256=derived.witness_executable_sha256,
        target_operation_sha256=campaign.target_operation_sha256,
        control_operation_sha256=campaign.control_operation_sha256,
        grant_authorized_by=grant.authorized_by,
        acceptance_accepted_by=acceptance.accepted_by,
        capture_signer_identity=acceptance.capture_signer,
        worker_acceptance_replay_identity_sha256=hashlib.sha256(
            b"0verse-windows-token-acceptance-once-v1\0"
            + acceptance.nonce.encode("ascii")
            + b"\0"
            + acceptance_sha.encode("ascii")
        ).hexdigest(),
        ordered_capture_sha256=derived.capture_sha256,
        ordered_process_identity_sha256=tuple(
            hashlib.sha256(
                b"0verse-windows-token-process-v1\0" + capture.process_instance_id.encode("ascii")
            ).hexdigest()
            for capture in capture_models
        ),
        clean_target_no_transitions=observation.clean_target_no_transitions,
        ambiguous_targets=observation.ambiguous_targets,
        run_id_commitment_sha256=_domain_commitment(
            b"0verse-windows-token-run-id-v1\0", cast(str, manifest["runId"])
        ),
        job_nonce_commitment_sha256=_domain_commitment(
            b"0verse-windows-token-job-nonce-v1\0", cast(str, manifest["jobNonce"])
        ),
        execution_grant_nonce_commitment_sha256=_domain_commitment(
            b"0verse-windows-token-grant-nonce-v1\0", grant.nonce
        ),
        worker_acceptance_nonce_commitment_sha256=_domain_commitment(
            b"0verse-windows-token-acceptance-nonce-v1\0", acceptance.nonce
        ),
        ordered_capture_nonce_commitment_sha256=tuple(
            _domain_commitment(b"0verse-windows-token-capture-nonce-v1\0", capture.capture_nonce)
            for capture in capture_models
        ),
        scope_authorized_by=scope.authorized_by,
        aggregate_signed_by=cast(str, receipt["signed_by"]),
        scope_authority_key_commitment_sha256=role_authority_commitments["scopeAuthorization"],
        grant_authority_key_commitment_sha256=role_authority_commitments[
            "executionGrantAuthorization"
        ],
        acceptance_authority_key_commitment_sha256=role_authority_commitments[
            "workerAcceptanceAuthorization"
        ],
        capture_authority_key_commitment_sha256=role_authority_commitments["capture"],
        aggregate_authority_key_commitment_sha256=role_authority_commitments["aggregateReceipt"],
        pack_authority_key_commitment_sha256=pack_authority_key_commitment,
        ordered_broker_receipt_replay_identity_sha256=tuple(row[0] for row in broker_replay_rows),
        ordered_broker_process_replay_identity_sha256=tuple(row[1] for row in broker_replay_rows),
        ordered_broker_transcript_replay_identity_sha256=tuple(
            row[2] for row in broker_replay_rows
        ),
        broker_receipt_authority_key_commitment_sha256=(
            role_authority_commitments.get("lpacBrokerReceipt", "")
        ),
        broker_receipt_signer_identity=(broker_models[0].signed_by if broker_models else ""),
        ordered_launch_receipt_replay_identity_sha256=tuple(row[0] for row in launch_replay_rows),
        ordered_launch_process_replay_identity_sha256=tuple(row[1] for row in launch_replay_rows),
        ordered_launch_transcript_replay_identity_sha256=tuple(
            row[2] for row in launch_replay_rows
        ),
        launch_receipt_authority_key_commitment_sha256=(
            role_authority_commitments.get("lpacLaunchReceipt", "")
        ),
        launch_receipt_signer_identity=(launch_models[0].signed_by if launch_models else ""),
    )


def _domain_commitment(domain: bytes, value: str) -> str:
    return hashlib.sha256(domain + value.encode("utf-8")).hexdigest()


def _require_lpac_launch_profiles_selected(
    launches: Sequence[object], policy: dict[str, object]
) -> None:
    """Require exact compiled launch-profile bytes to be acceptance-allowlisted.

    A future native service must hash its service-owned compiled registry bytes;
    this verifier only compares those signed digests and activates no profile.
    """
    allowed = cast(list[str], policy.get("allowedLpacLaunchProfileSha256", []))
    if launches and (
        not allowed or any(launch.launch_profile_sha256 not in allowed for launch in launches)  # type: ignore[attr-defined]
    ):
        raise ValueError("LPAC launch profile is not selected by the trusted acceptance policy")


def _parse_manifest(data: bytes) -> dict[str, object]:
    raw = _load_json_bytes(data, "token pack manifest", require_canonical=True)
    launch_v5 = "launchReceipts" in raw
    v5 = "brokerReceipts" in raw
    if launch_v5 and not v5:
        raise ValueError("token pack launch receipts require broker receipts")
    expected_fields = (
        _MANIFEST_FIELDS_V5_LAUNCH if launch_v5 else _MANIFEST_FIELDS_V5 if v5 else _MANIFEST_FIELDS
    )
    _exact(raw, expected_fields, "token pack manifest")
    expected_schema = (
        LPAC_LAUNCH_PACK_SCHEMA_VERSION
        if launch_v5
        else LPAC_PACK_SCHEMA_VERSION
        if v5
        else PACK_SCHEMA_VERSION
    )
    if raw["schemaVersion"] != expected_schema:
        raise ValueError("token pack manifest schema is unsupported")
    for name in ("runId", "packSignerIdentity"):
        _safe_text(raw[name], f"token pack {name}")
    if not isinstance(raw["jobNonce"], str) or _NONCE.fullmatch(raw["jobNonce"]) is None:
        raise ValueError("token pack jobNonce is invalid")

    for name in (
        "campaign",
        "scopeManifest",
        "executionGrant",
        "workerAcceptance",
        "aggregateReceipt",
    ):
        raw[name] = _blob_ref(raw[name], name, media_type="application/json")

    matrix = raw["matrix"]
    if not isinstance(matrix, dict):
        raise ValueError("token pack matrix must be an object")
    _exact(matrix, frozenset({"trials", "captures"}), "token pack matrix")
    trials = _safe_integer(matrix["trials"], "token pack trials", minimum=2, maximum=32)
    captures = matrix["captures"]
    if not isinstance(captures, list) or len(captures) != trials * 2:
        raise ValueError("token pack matrix must contain exact target/control pairs")
    parsed_captures: list[dict[str, object]] = []
    for index, capture in enumerate(captures):
        if not isinstance(capture, dict):
            raise ValueError("token pack capture row must be an object")
        _exact(capture, frozenset({"case", "trial", "artifact"}), "capture row")
        expected_case = "target" if index % 2 == 0 else "control"
        expected_trial = index // 2 + 1
        if capture["case"] != expected_case or capture["trial"] != expected_trial:
            raise ValueError("token pack captures are not in canonical target/control order")
        parsed_captures.append(
            {
                "case": expected_case,
                "trial": expected_trial,
                "artifact": _blob_ref(
                    capture["artifact"], "capture artifact", media_type="application/json"
                ),
            }
        )
    matrix["trials"] = trials
    matrix["captures"] = parsed_captures

    parsed_broker_receipts: list[dict[str, object]] = []
    if v5:
        broker_receipts = raw["brokerReceipts"]
        if not isinstance(broker_receipts, list) or len(broker_receipts) != len(parsed_captures):
            raise ValueError("token pack requires one LPAC broker receipt per capture")
        for index, receipt in enumerate(broker_receipts):
            if not isinstance(receipt, dict):
                raise ValueError("token pack LPAC broker receipt row must be an object")
            _exact(
                receipt,
                frozenset({"case", "trial", "artifact"}),
                "LPAC broker receipt row",
            )
            expected_capture = parsed_captures[index]
            if (
                receipt["case"] != expected_capture["case"]
                or receipt["trial"] != expected_capture["trial"]
            ):
                raise ValueError("LPAC broker receipts are not in capture matrix order")
            parsed_broker_receipts.append(
                {
                    "case": receipt["case"],
                    "trial": receipt["trial"],
                    "artifact": _blob_ref(
                        receipt["artifact"],
                        "LPAC broker receipt artifact",
                        media_type="application/json",
                    ),
                }
            )
        raw["brokerReceipts"] = parsed_broker_receipts

    parsed_launch_receipts: list[dict[str, object]] = []
    if launch_v5:
        launch_receipts = raw["launchReceipts"]
        if not isinstance(launch_receipts, list) or len(launch_receipts) != len(parsed_captures):
            raise ValueError("token pack requires one LPAC launch receipt per capture")
        for index, receipt in enumerate(launch_receipts):
            if not isinstance(receipt, dict):
                raise ValueError("token pack LPAC launch receipt row must be an object")
            _exact(receipt, frozenset({"case", "trial", "artifact"}), "LPAC launch receipt row")
            expected_capture = parsed_captures[index]
            if (
                receipt["case"] != expected_capture["case"]
                or receipt["trial"] != expected_capture["trial"]
            ):
                raise ValueError("LPAC launch receipts are not in capture matrix order")
            parsed_launch_receipts.append(
                {
                    "case": receipt["case"],
                    "trial": receipt["trial"],
                    "artifact": _blob_ref(
                        receipt["artifact"],
                        "LPAC launch receipt artifact",
                        media_type="application/json",
                    ),
                }
            )
        raw["launchReceipts"] = parsed_launch_receipts

    signer_policies = raw["signerPolicies"]
    if not isinstance(signer_policies, dict):
        raise ValueError("token pack signerPolicies must be an object")
    policy_names = frozenset(
        {
            "scopeAuthorization",
            "executionGrantAuthorization",
            "workerAcceptanceAuthorization",
            "capture",
            "aggregateReceipt",
        }
    )
    if v5:
        policy_names = policy_names | {"lpacBrokerReceipt"}
    if launch_v5:
        policy_names = policy_names | {"lpacLaunchReceipt"}
    _exact(signer_policies, policy_names, "token pack signerPolicies")
    for name in policy_names:
        signer_policies[name] = _blob_ref(signer_policies[name], name, media_type="text/plain")
    if len({ref.sha256 for ref in signer_policies.values()}) != len(policy_names):
        raise ValueError("token pack signer policies must be role-separated")

    runtime = raw["zeroverseRuntime"]
    if (
        not isinstance(runtime, dict)
        or set(runtime) != {"kind", "digest"}
        or runtime["kind"] != "oci-image"
        or not isinstance(runtime["digest"], str)
        or _OCI_DIGEST.fullmatch(runtime["digest"]) is None
    ):
        raise ValueError("token pack zeroverseRuntime is invalid")

    signed_refs = [
        raw["campaign"],
        raw["scopeManifest"],
        raw["executionGrant"],
        raw["workerAcceptance"],
        raw["aggregateReceipt"],
        *(capture["artifact"] for capture in parsed_captures),
        *(receipt["artifact"] for receipt in parsed_broker_receipts),
        *(receipt["artifact"] for receipt in parsed_launch_receipts),
    ]
    if len({_as_ref(ref).sha256 for ref in signed_refs}) != len(signed_refs):
        raise ValueError("token pack signed artifact roles must have unique digests")
    _reject_metadata_conflicts(_manifest_blob_refs(raw))
    return raw


def _parse_envelope(raw: dict[str, object]) -> dict[str, object]:
    _exact(raw, frozenset({"schemaVersion", "packId", "manifest", "signature"}), "envelope")
    if raw["schemaVersion"] != ENVELOPE_SCHEMA_VERSION:
        raise ValueError("token pack envelope schema is unsupported")
    if not isinstance(raw["packId"], str) or _SHA256.fullmatch(raw["packId"]) is None:
        raise ValueError("token pack envelope packId is invalid")
    raw["manifest"] = _blob_ref(
        raw["manifest"], "envelope manifest", media_type=PACK_MANIFEST_MEDIA_TYPE
    )
    raw["signature"] = _blob_ref(
        raw["signature"], "envelope signature", media_type=PACK_SIGNATURE_MEDIA_TYPE
    )
    manifest = raw["manifest"]
    signature = raw["signature"]
    assert isinstance(manifest, BlobRef) and isinstance(signature, BlobRef)
    if raw["packId"] != manifest.sha256 or manifest.sha256 == signature.sha256:
        raise ValueError("token pack envelope digest bindings are invalid")
    return raw


def _parse_policy(raw: dict[str, object]) -> dict[str, object]:
    launch_v5 = "allowedLpacLaunchReceiptSignerPolicySha256" in raw
    v5 = "allowedLpacBrokerReceiptSignerPolicySha256" in raw
    if launch_v5 and not v5:
        raise ValueError("LPAC launch policy requires LPAC broker policy")
    expected_fields = (
        _POLICY_FIELDS_V5_LAUNCH if launch_v5 else _POLICY_FIELDS_V5 if v5 else _POLICY_FIELDS
    )
    _exact(raw, expected_fields, "acceptance policy")
    expected_schema = (
        LPAC_LAUNCH_POLICY_SCHEMA_VERSION
        if launch_v5
        else LPAC_POLICY_SCHEMA_VERSION
        if v5
        else POLICY_SCHEMA_VERSION
    )
    if raw["schemaVersion"] != expected_schema:
        raise ValueError("token pack acceptance policy schema is unsupported")
    identity_list = _string_list(raw["allowedPackSignerIdentities"], "pack identities")
    for identity in identity_list:
        _safe_text(identity, "allowed pack signer identity")
    runtime_list = _string_list(raw["allowedZeroverseOciDigests"], "runtime digests")
    if any(_OCI_DIGEST.fullmatch(value) is None for value in runtime_list):
        raise ValueError("token pack runtime allowlist is invalid")
    raw["allowedPackSignerIdentities"] = identity_list
    raw["allowedZeroverseOciDigests"] = runtime_list
    role_names: tuple[str, ...] = (
        "allowedPackSignerPolicySha256",
        "allowedScopeSignerPolicySha256",
        "allowedExecutionGrantSignerPolicySha256",
        "allowedWorkerAcceptanceSignerPolicySha256",
        "allowedCaptureSignerPolicySha256",
        "allowedAggregateReceiptSignerPolicySha256",
    )
    if v5:
        role_names = (*role_names, "allowedLpacBrokerReceiptSignerPolicySha256")
    if launch_v5:
        role_names = (*role_names, "allowedLpacLaunchReceiptSignerPolicySha256")
    seen: set[str] = set()
    for name in role_names:
        values = _string_list(raw[name], name)
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError(f"token pack {name} contains a non-SHA-256 value")
        if seen & set(values):
            raise ValueError("token pack signer-policy allowlists must be role-separated")
        seen.update(values)
        raw[name] = values
    if launch_v5:
        # Activation must hash the exact service-owned compiled registry bytes
        # and select that digest here; this verifier does not load or execute it.
        profiles = _string_list(
            raw["allowedLpacLaunchProfileSha256"],
            "allowedLpacLaunchProfileSha256",
        )
        if any(_SHA256.fullmatch(value) is None for value in profiles):
            raise ValueError(
                "token pack allowedLpacLaunchProfileSha256 contains a non-SHA-256 value"
            )
        raw["allowedLpacLaunchProfileSha256"] = profiles
    max_blob = _safe_integer(
        raw["maxBlobSizeBytes"], "maxBlobSizeBytes", minimum=1, maximum=_MAX_BLOB_BYTES
    )
    max_bundle = _safe_integer(
        raw["maxBundleSizeBytes"],
        "maxBundleSizeBytes",
        minimum=1,
        maximum=_MAX_BUNDLE_BYTES,
    )
    if max_bundle < max_blob:
        raise ValueError("maxBundleSizeBytes must be at least maxBlobSizeBytes")
    raw["maxBlobSizeBytes"] = max_blob
    raw["maxBundleSizeBytes"] = max_bundle
    return raw


def _parse_context(raw: dict[str, object]) -> dict[str, object]:
    _exact(raw, _CONTEXT_FIELDS, "expected context")
    _safe_text(raw["runId"], "expected runId")
    if not isinstance(raw["jobNonce"], str) or _NONCE.fullmatch(raw["jobNonce"]) is None:
        raise ValueError("expected jobNonce is invalid")
    for name in _CONTEXT_FIELDS - {"runId", "jobNonce"}:
        value = raw[name]
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise ValueError(f"expected context {name} is invalid")
    return raw


def _validate_manifest_policy_context(
    manifest: dict[str, object],
    policy: dict[str, object],
    expected: dict[str, object],
    manifest_digest: str,
) -> None:
    del manifest_digest  # The caller binds this through the envelope before entering here.
    bindings = {
        "runId": manifest["runId"],
        "jobNonce": manifest["jobNonce"],
        "campaignSha256": _as_ref(manifest["campaign"]).sha256,
        "scopeManifestSha256": _as_ref(manifest["scopeManifest"]).sha256,
        "executionGrantSha256": _as_ref(manifest["executionGrant"]).sha256,
        "workerAcceptanceSha256": _as_ref(manifest["workerAcceptance"]).sha256,
    }
    for name, value in bindings.items():
        if expected[name] != value:
            raise ValueError(f"token pack {name} differs from expected job context")
    if manifest["packSignerIdentity"] not in cast(list[str], policy["allowedPackSignerIdentities"]):
        raise ValueError("token pack signer identity is not allowlisted")
    runtime = manifest["zeroverseRuntime"]
    assert isinstance(runtime, dict)
    if runtime["digest"] not in cast(list[str], policy["allowedZeroverseOciDigests"]):
        raise ValueError("token pack 0verse runtime digest is not allowlisted")
    signer_policies = manifest["signerPolicies"]
    assert isinstance(signer_policies, dict)
    role_bindings = {
        "scopeAuthorization": "allowedScopeSignerPolicySha256",
        "executionGrantAuthorization": "allowedExecutionGrantSignerPolicySha256",
        "workerAcceptanceAuthorization": "allowedWorkerAcceptanceSignerPolicySha256",
        "capture": "allowedCaptureSignerPolicySha256",
        "aggregateReceipt": "allowedAggregateReceiptSignerPolicySha256",
    }
    if "lpacBrokerReceipt" in signer_policies:
        if "allowedLpacBrokerReceiptSignerPolicySha256" not in policy:
            raise ValueError("token pack policy lacks LPAC broker receipt authority")
        role_bindings["lpacBrokerReceipt"] = "allowedLpacBrokerReceiptSignerPolicySha256"
    elif "allowedLpacBrokerReceiptSignerPolicySha256" in policy:
        raise ValueError("legacy token pack cannot select an LPAC broker receipt authority")
    if "lpacLaunchReceipt" in signer_policies:
        if "allowedLpacLaunchReceiptSignerPolicySha256" not in policy:
            raise ValueError("token pack policy lacks LPAC launch receipt authority")
        role_bindings["lpacLaunchReceipt"] = "allowedLpacLaunchReceiptSignerPolicySha256"
    elif "allowedLpacLaunchReceiptSignerPolicySha256" in policy:
        raise ValueError("token pack cannot omit its LPAC launch receipt authority")
    for role, allowlist in role_bindings.items():
        if _as_ref(signer_policies[role]).sha256 not in cast(list[str], policy[allowlist]):
            raise ValueError(f"token pack {role} signer policy is not allowlisted")


def _named_manifest_refs(manifest: dict[str, object]) -> dict[str, BlobRef]:
    refs = {
        name: _as_ref(manifest[name])
        for name in (
            "campaign",
            "scopeManifest",
            "executionGrant",
            "workerAcceptance",
            "aggregateReceipt",
        )
    }
    matrix = manifest["matrix"]
    assert isinstance(matrix, dict) and isinstance(matrix["captures"], list)
    for index, capture in enumerate(matrix["captures"]):
        assert isinstance(capture, dict)
        refs[f"capture-{index}"] = _as_ref(capture["artifact"])
    broker_receipts = manifest.get("brokerReceipts", [])
    assert isinstance(broker_receipts, list)
    for index, receipt in enumerate(broker_receipts):
        assert isinstance(receipt, dict)
        refs[f"broker-receipt-{index}"] = _as_ref(receipt["artifact"])
    launch_receipts = manifest.get("launchReceipts", [])
    assert isinstance(launch_receipts, list)
    for index, receipt in enumerate(launch_receipts):
        assert isinstance(receipt, dict)
        refs[f"launch-receipt-{index}"] = _as_ref(receipt["artifact"])
    return refs


def _manifest_blob_refs(manifest: dict[str, object]) -> list[BlobRef]:
    refs = list(_named_manifest_refs(manifest).values())
    policies = manifest["signerPolicies"]
    assert isinstance(policies, dict)
    refs.extend(_as_ref(value) for value in policies.values())
    return refs


def _validate_complete_size_policy(refs: list[BlobRef], *, max_blob: int, max_bundle: int) -> None:
    _reject_metadata_conflicts(refs)
    if any(ref.size_bytes > max_blob for ref in refs):
        raise ValueError("token pack contains a blob larger than maxBlobSizeBytes")
    unique = {ref.sha256: ref for ref in refs}
    total = sum(ref.size_bytes for ref in unique.values())
    if total > _MAX_SAFE_INTEGER or total > max_bundle:
        raise ValueError("token pack closure exceeds maxBundleSizeBytes")


def _blob_ref(value: object, label: str, *, media_type: str) -> BlobRef:
    if not isinstance(value, dict):
        raise ValueError(f"{label} content ref must be an object")
    _exact(value, frozenset({"sha256", "sizeBytes", "mediaType"}), f"{label} ref")
    digest = value["sha256"]
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ValueError(f"{label} SHA-256 is invalid")
    size = _safe_integer(
        value["sizeBytes"], f"{label} sizeBytes", minimum=1, maximum=_MAX_SAFE_INTEGER
    )
    if value["mediaType"] != media_type:
        raise ValueError(f"{label} media type is invalid")
    return BlobRef(digest, size, media_type)


def _reject_metadata_conflicts(refs: list[BlobRef]) -> None:
    metadata: dict[str, tuple[int, str]] = {}
    for ref in refs:
        current = (ref.size_bytes, ref.media_type)
        if ref.sha256 in metadata and metadata[ref.sha256] != current:
            raise ValueError(f"blob {ref.sha256} declares conflicting metadata")
        metadata[ref.sha256] = current


def _load_json_path(path: str | Path, label: str) -> dict[str, object]:
    return _load_json_bytes(_read_regular_path(path, _MAX_JSON_BYTES, label), label)


def _load_json_bytes(
    data: bytes, label: str, *, require_canonical: bool = False
) -> dict[str, object]:
    if not data or len(data) > _MAX_JSON_BYTES or data.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{label} must be non-empty bounded UTF-8 without a BOM")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not strict UTF-8") from exc
    _validate_json_depth(text, label)

    def reject_float(value: str) -> NoReturn:
        raise ValueError(f"{label} contains a non-integer JSON number: {value}")

    def reject_constant(value: str) -> NoReturn:
        raise ValueError(f"{label} contains an invalid JSON constant: {value}")

    try:
        raw = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    if require_canonical:
        canonical = json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if data != canonical:
            raise ValueError(f"{label} bytes are not canonical")
    return raw


def _validate_json_depth(text: str, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "{[":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise ValueError(f"{label} exceeds the JSON nesting limit")
        elif character in "}]":
            depth -= 1
            if depth < 0:
                raise ValueError(f"{label} JSON nesting is invalid")


def _read_regular_path(path: str | Path, maximum: int, label: str) -> bytes:
    source = Path(path)
    if source.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError(f"{label} must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(maximum + 1)
    finally:
        os.close(descriptor)
    if not data or len(data) > maximum:
        raise ValueError(f"{label} is empty or exceeds its size limit")
    return data


def _source_bound_bytes(path: str | Path, expected_sha256: str, label: str) -> bytes:
    if _SHA256.fullmatch(expected_sha256) is None:
        raise ValueError(f"{label} source digest is invalid")
    data = _read_regular_path(path, _MAX_BLOB_BYTES, label)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError(f"{label} changed after verification")
    return data


def _unique_bundle_size(refs: Sequence[BlobRef]) -> int:
    _reject_metadata_conflicts(list(refs))
    return sum({ref.sha256: ref.size_bytes for ref in refs}.values())


def _require_build_bundle_size(refs: Sequence[BlobRef]) -> None:
    if _unique_bundle_size(refs) > _MAX_BUNDLE_BYTES:
        raise ValueError("token pack closure exceeds the producer bundle limit")


def _canonical_json_bytes(raw: dict[str, object]) -> bytes:
    return json.dumps(
        raw,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _publish_pack_directory(
    destination: Path,
    *,
    envelope_bytes: bytes,
    blob_bytes: dict[str, tuple[bytes, str]],
    refs_bytes: bytes,
) -> None:
    """Publish below one stable, private parent-directory descriptor.

    Portable POSIX rename has no universal no-replace flag for directories, so
    the parent is an explicit trust boundary: it must be owned by this process
    and inaccessible to group/other users.  Within that boundary, all staging,
    existence checks, cleanup, and rename operations are descriptor-relative.
    """
    if os.name == "nt" or not all(
        operation in os.supports_dir_fd
        for operation in (os.mkdir, os.open, os.rename, os.stat, os.unlink, os.rmdir)
    ):
        raise ValueError("secure token pack publication requires POSIX dirfd support")
    parent = destination.parent
    _require_stable_output_ancestry(parent)
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    staging_name = f".{destination.name}.{secrets.token_hex(16)}"
    staging_descriptor: int | None = None
    blobs_descriptor: int | None = None
    staging_created = False
    blobs_created = False
    published = False
    try:
        parent_metadata = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or parent_metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise ValueError(
                "token pack output parent must be owner-only and owned by the publisher"
            )
        _require_same_directory_inode(parent, parent_metadata)
        _require_missing_entry(parent_descriptor, destination.name)
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_descriptor)
        staging_created = True
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        os.mkdir("blobs", mode=0o700, dir_fd=staging_descriptor)
        blobs_created = True
        blobs_descriptor = os.open(
            "blobs",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=staging_descriptor,
        )
        _write_new_file_at(staging_descriptor, "envelope.json", envelope_bytes)
        for digest, (data, _media_type) in blob_bytes.items():
            _write_new_file_at(blobs_descriptor, digest, data)
        _write_new_file_at(staging_descriptor, "refs.json", refs_bytes)
        os.fsync(blobs_descriptor)
        os.fsync(staging_descriptor)
        _require_same_directory_inode(parent, parent_metadata)
        _require_missing_entry(parent_descriptor, destination.name)
        os.rename(
            staging_name,
            destination.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        published = True
        try:
            os.fsync(parent_descriptor)
        except OSError as exc:
            raise RuntimeError(
                "token pack was published but parent durability is unconfirmed; "
                "inspect the destination before retrying"
            ) from exc
    finally:
        if not published:
            if blobs_descriptor is not None:
                for digest in blob_bytes:
                    _unlink_missing_ok(blobs_descriptor, digest)
            if staging_descriptor is not None:
                _unlink_missing_ok(staging_descriptor, "envelope.json")
                _unlink_missing_ok(staging_descriptor, "refs.json")
        if blobs_descriptor is not None:
            os.close(blobs_descriptor)
        if not published and blobs_created and staging_descriptor is not None:
            _rmdir_missing_ok(staging_descriptor, "blobs")
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if not published and staging_created:
            _rmdir_missing_ok(parent_descriptor, staging_name)
        os.close(parent_descriptor)


def _require_stable_output_ancestry(parent: Path) -> None:
    """Reject ancestry that another uid could rename below the returned path."""
    if not parent.is_absolute():
        raise ValueError("token pack output parent must be absolute")
    publisher_uid = os.geteuid()
    current = Path(parent.anchor)
    try:
        current_metadata = current.lstat()
    except OSError as exc:
        raise ValueError("token pack output ancestry is unavailable") from exc
    if not stat.S_ISDIR(current_metadata.st_mode):
        raise ValueError("token pack output ancestry must contain only directories")
    for component in parent.parts[1:]:
        child = current / component
        try:
            child_metadata = child.lstat()
        except OSError as exc:
            raise ValueError("token pack output ancestry is unavailable") from exc
        if not stat.S_ISDIR(child_metadata.st_mode):
            raise ValueError(
                "token pack output ancestry must contain no symlinks or non-directories"
            )
        if current_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            if not current_metadata.st_mode & stat.S_ISVTX:
                raise ValueError(
                    "token pack output ancestry contains a non-sticky writable directory"
                )
            if child_metadata.st_uid != publisher_uid:
                raise ValueError(
                    "token pack output sticky ancestry does not protect a publisher-owned entry"
                )
        current = child
        current_metadata = child_metadata


def _require_same_directory_inode(parent: Path, expected: os.stat_result) -> None:
    try:
        current = parent.lstat()
    except OSError as exc:
        raise ValueError("token pack output parent changed during publication") from exc
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise ValueError("token pack output parent changed during publication")


def _require_missing_entry(directory_descriptor: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise FileExistsError("token pack output directory already exists")


def _write_new_file_at(directory_descriptor: int, name: str, data: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory_descriptor,
    )
    try:
        with os.fdopen(os.dup(descriptor), "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def _unlink_missing_ok(directory_descriptor: int, name: str) -> None:
    if _SAFE_PATH_COMPONENT.fullmatch(name) is None or name in {".", ".."}:
        raise AssertionError("internal token pack cleanup name is invalid")
    with suppress(FileNotFoundError):
        # Descriptor-relative, single-component names are either fixed literals,
        # SHA-256 digests, or the validated random staging name above.
        os.unlink(name, dir_fd=directory_descriptor)  # foxguard: ignore[py/no-path-traversal]


def _rmdir_missing_ok(directory_descriptor: int, name: str) -> None:
    if _SAFE_PATH_COMPONENT.fullmatch(name) is None or name in {".", ".."}:
        raise AssertionError("internal token pack cleanup name is invalid")
    with suppress(FileNotFoundError):
        os.rmdir(name, dir_fd=directory_descriptor)


def _stage_blob(root: Path, name: str, data: bytes) -> Path:
    path = root / name
    with path.open("xb") as output:
        output.write(data)
    path.chmod(0o600)
    return path


def _safe_integer(value: object, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")
    return value


def _safe_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or _VISIBLE_ASCII.fullmatch(value) is None
    ):
        raise ValueError(f"{label} must be bounded visible ASCII")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 256
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError(f"{label} must be a non-empty unique string list")
    return value


def _exact(raw: dict[str, object], fields: frozenset[str], label: str) -> None:
    missing = sorted(fields - raw.keys())
    unknown = sorted(raw.keys() - fields)
    if missing or unknown:
        raise ValueError(f"{label} fields are invalid: missing={missing}, unknown={unknown}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _as_ref(value: object) -> BlobRef:
    if not isinstance(value, BlobRef):
        raise AssertionError("validated token pack ref lost its type")
    return value
