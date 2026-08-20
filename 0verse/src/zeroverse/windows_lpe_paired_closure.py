"""Fail-closed differential closure for candidate/fixed Windows LPE observations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_lpe_opaque_content import load_windows_lpe_opaque_content
from .windows_lpe_paired_observation import derive_windows_lpe_paired_observation
from .windows_pair_plan import VerifiedWindowsPairPlan, verify_windows_pair_plan
from .windows_servicing import (
    WindowsServicingReceipt,
    verify_windows_servicing_receipt,
    verify_windows_servicing_receipt_against_plan,
)
from .windows_token_pack import WindowsTokenPackVerification, verify_windows_token_pack

SCHEMA_VERSION = "0verse.windows-lpe-paired-closure/v2"
EXPERIMENT_SCHEMA_VERSION = "0verse.windows-lpe-experiment/v1"
EXPERIMENT_SIGNATURE_NAMESPACE = "0verse-windows-lpe-experiment-v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class WindowsServicingInputs:
    artifact_path: Path
    receipt_path: Path
    allowed_signers_path: Path


@dataclass(frozen=True)
class WindowsTokenPackInputs:
    envelope_path: Path
    blob_dir: Path
    acceptance_policy_path: Path
    expected_context_path: Path
    pack_signer_policy_path: Path


@dataclass(frozen=True)
class VerifiedWindowsLpeExperiment:
    source_sha256: str
    pair_plan_sha256: str
    component: str
    candidate_artifact_sha256: str
    control_artifact_sha256: str
    target_operation_sha256: str
    control_operation_sha256: str
    runner_executable_sha256: str
    authorized_by: str
    authority_key_commitment_sha256: str


@dataclass(frozen=True)
class WindowsLpePairedClosure:
    pair_plan_sha256: str
    experiment_sha256: str
    component: str
    architecture: str
    candidate_servicing_receipt_sha256: str
    candidate_artifact_sha256: str
    candidate_build_lab_ex: str
    candidate_pack_id: str
    candidate_target_confirmations: int
    candidate_clean_target_no_transitions: int
    candidate_clean_controls: int
    fixed_servicing_receipt_sha256: str
    fixed_artifact_sha256: str
    fixed_build_lab_ex: str
    fixed_pack_id: str
    fixed_clean_target_no_transitions: int
    fixed_clean_controls: int
    trials: int
    minimum_confirmations: int
    target_operation_sha256: str
    control_operation_sha256: str
    runner_executable_sha256: str
    candidate_worker_machine_id: str
    fixed_worker_machine_id: str
    candidate_witness_user_sid: str
    candidate_witness_session_id: int
    candidate_witness_authentication_id: str
    candidate_witness_executable_sha256: str
    fixed_witness_user_sid: str
    fixed_witness_session_id: int
    fixed_witness_authentication_id: str
    fixed_witness_executable_sha256: str
    candidate_run_id_commitment_sha256: str
    candidate_job_nonce_commitment_sha256: str
    candidate_grant_nonce_commitment_sha256: str
    candidate_acceptance_nonce_commitment_sha256: str
    candidate_ordered_capture_nonce_commitment_sha256: tuple[str, ...]
    fixed_run_id_commitment_sha256: str
    fixed_job_nonce_commitment_sha256: str
    fixed_grant_nonce_commitment_sha256: str
    fixed_acceptance_nonce_commitment_sha256: str
    fixed_ordered_capture_nonce_commitment_sha256: tuple[str, ...]
    authority_key_commitments: tuple[tuple[str, str], ...]
    closure_commitment_sha256: str
    pair_replay_identity_sha256: str
    ordered_replay_identity_sha256: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "PAIRED_DIFFERENTIAL_OBSERVED",
            "pair_plan_sha256": self.pair_plan_sha256,
            "experiment_sha256": self.experiment_sha256,
            "component": self.component,
            "architecture": self.architecture,
            "candidate": {
                "servicing_receipt_sha256": self.candidate_servicing_receipt_sha256,
                "artifact_sha256": self.candidate_artifact_sha256,
                "build_lab_ex": self.candidate_build_lab_ex,
                "token_pack_id": self.candidate_pack_id,
                "target_confirmations": self.candidate_target_confirmations,
                "clean_target_no_transitions": (
                    self.candidate_clean_target_no_transitions
                ),
                "clean_controls": self.candidate_clean_controls,
                "worker_machine_id": self.candidate_worker_machine_id,
                "witness": {
                    "user_sid": self.candidate_witness_user_sid,
                    "session_id": self.candidate_witness_session_id,
                    "authentication_id": self.candidate_witness_authentication_id,
                    "executable_sha256": self.candidate_witness_executable_sha256,
                },
                "identity_commitments": {
                    "run_id_sha256": self.candidate_run_id_commitment_sha256,
                    "job_nonce_sha256": self.candidate_job_nonce_commitment_sha256,
                    "grant_nonce_sha256": self.candidate_grant_nonce_commitment_sha256,
                    "acceptance_nonce_sha256": (
                        self.candidate_acceptance_nonce_commitment_sha256
                    ),
                    "ordered_capture_nonce_sha256": list(
                        self.candidate_ordered_capture_nonce_commitment_sha256
                    ),
                },
            },
            "fixed": {
                "plan_role": "control",
                "servicing_receipt_sha256": self.fixed_servicing_receipt_sha256,
                "artifact_sha256": self.fixed_artifact_sha256,
                "build_lab_ex": self.fixed_build_lab_ex,
                "token_pack_id": self.fixed_pack_id,
                "target_confirmations": 0,
                "clean_target_no_transitions": self.fixed_clean_target_no_transitions,
                "clean_controls": self.fixed_clean_controls,
                "worker_machine_id": self.fixed_worker_machine_id,
                "witness": {
                    "user_sid": self.fixed_witness_user_sid,
                    "session_id": self.fixed_witness_session_id,
                    "authentication_id": self.fixed_witness_authentication_id,
                    "executable_sha256": self.fixed_witness_executable_sha256,
                },
                "identity_commitments": {
                    "run_id_sha256": self.fixed_run_id_commitment_sha256,
                    "job_nonce_sha256": self.fixed_job_nonce_commitment_sha256,
                    "grant_nonce_sha256": self.fixed_grant_nonce_commitment_sha256,
                    "acceptance_nonce_sha256": (
                        self.fixed_acceptance_nonce_commitment_sha256
                    ),
                    "ordered_capture_nonce_sha256": list(
                        self.fixed_ordered_capture_nonce_commitment_sha256
                    ),
                },
            },
            "trials": self.trials,
            "minimum_confirmations": self.minimum_confirmations,
            "target_operation_sha256": self.target_operation_sha256,
            "control_operation_sha256": self.control_operation_sha256,
            "runner_executable_sha256": self.runner_executable_sha256,
            "closure_commitment_sha256": self.closure_commitment_sha256,
            "pair_replay_identity_sha256": self.pair_replay_identity_sha256,
            "ordered_replay_identity_sha256": list(
                self.ordered_replay_identity_sha256
            ),
            "authority_key_commitments": dict(self.authority_key_commitments),
            "servicing_provenance_verified": True,
            "neutral_observations_rederived": True,
            "replay_state_consumed": False,
            "accepted": False,
            "claim_eligible": False,
            "bounty_eligible": False,
            "weaponization": False,
            "auto_disclosure": False,
            "human_report_gate": True,
            "proof_limit": (
                "A signed, internally consistent candidate/fixed token differential was "
                "observed on the bound builds and machines. Vulnerability causality, "
                "novelty, exploitability, affected population, CVE identity, bounty "
                "eligibility, and disclosure readiness remain unproven."
            ),
        }


def verify_windows_lpe_paired_closure(
    pair_plan_path: str | Path,
    *,
    experiment_path: str | Path,
    experiment_allowed_signers_path: str | Path,
    candidate_servicing: WindowsServicingInputs,
    candidate_token_pack: WindowsTokenPackInputs,
    fixed_servicing: WindowsServicingInputs,
    fixed_token_pack: WindowsTokenPackInputs,
) -> WindowsLpePairedClosure:
    """Re-verify every nested artifact, then derive the differential verdict."""
    plan = verify_windows_pair_plan(pair_plan_path)
    experiment = verify_windows_lpe_experiment(
        experiment_path, experiment_allowed_signers_path
    )
    candidate_receipt = verify_windows_servicing_receipt(
        pair_plan_path,
        candidate_servicing.artifact_path,
        candidate_servicing.receipt_path,
        candidate_servicing.allowed_signers_path,
    )
    fixed_receipt = verify_windows_servicing_receipt(
        pair_plan_path,
        fixed_servicing.artifact_path,
        fixed_servicing.receipt_path,
        fixed_servicing.allowed_signers_path,
    )
    candidate_pack = _verify_pack(candidate_token_pack)
    fixed_pack = _verify_pack(fixed_token_pack)
    return derive_windows_lpe_paired_closure(
        plan,
        experiment,
        candidate_receipt,
        candidate_pack,
        fixed_receipt,
        fixed_pack,
    )


def verify_windows_lpe_paired_closure_cas(
    pair_plan_path: str | Path,
    *,
    opaque_content_path: str | Path,
    experiment_path: str | Path,
    experiment_allowed_signers_path: str | Path,
    candidate_servicing: WindowsServicingInputs,
    candidate_token_pack: WindowsTokenPackInputs,
    fixed_servicing: WindowsServicingInputs,
    fixed_token_pack: WindowsTokenPackInputs,
) -> WindowsLpePairedClosure:
    """Verify a CAS snapshot while retaining every semantic/signature check.

    The opaque manifest may replace only bodies which the legacy verifier used
    solely for SHA-256/size comparison. The component PEs, structured receipts,
    detached signatures, signer policies, and token packs are still read and
    independently verified inside this process.
    """
    opaque = load_windows_lpe_opaque_content(opaque_content_path)
    plan_path = Path(pair_plan_path).resolve()
    plan = verify_windows_pair_plan(plan_path, opaque_content=opaque)
    experiment = verify_windows_lpe_experiment(
        experiment_path, experiment_allowed_signers_path
    )
    candidate_receipt = verify_windows_servicing_receipt_against_plan(
        plan,
        candidate_servicing.artifact_path,
        candidate_servicing.receipt_path,
        candidate_servicing.allowed_signers_path,
        opaque_content=opaque,
        opaque_root=plan_path.parent,
    )
    fixed_receipt = verify_windows_servicing_receipt_against_plan(
        plan,
        fixed_servicing.artifact_path,
        fixed_servicing.receipt_path,
        fixed_servicing.allowed_signers_path,
        opaque_content=opaque,
        opaque_root=plan_path.parent,
    )
    candidate_pack = _verify_pack(candidate_token_pack)
    fixed_pack = _verify_pack(fixed_token_pack)
    opaque.require_all_consumed()
    return derive_windows_lpe_paired_closure(
        plan,
        experiment,
        candidate_receipt,
        candidate_pack,
        fixed_receipt,
        fixed_pack,
    )


def verify_windows_lpe_experiment(
    experiment_path: str | Path, allowed_signers_path: str | Path
) -> VerifiedWindowsLpeExperiment:
    """Verify the signed precommitment joining the plan to runner operations."""
    data = _read_bounded_regular(experiment_path, "Windows LPE experiment")
    raw = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("Windows LPE experiment must be an object")
    expected = {
        "schema_version",
        "pair_plan_sha256",
        "component",
        "candidate",
        "control",
        "target_operation_sha256",
        "control_operation_sha256",
        "runner_executable_sha256",
        "authorized_by",
        "signature_ssh",
    }
    if set(raw) != expected or raw["schema_version"] != EXPERIMENT_SCHEMA_VERSION:
        raise ValueError("Windows LPE experiment fields or schema are invalid")
    sides: dict[str, str] = {}
    for role in ("candidate", "control"):
        side = raw[role]
        if not isinstance(side, dict) or set(side) != {"role", "artifact_sha256"}:
            raise ValueError(f"Windows LPE experiment {role} fields are invalid")
        if side["role"] != role:
            raise ValueError("Windows LPE experiment role binding is invalid")
        sides[role] = _sha256(side["artifact_sha256"], f"{role} artifact")
    hashes = {
        name: _sha256(raw[name], name)
        for name in (
            "pair_plan_sha256",
            "target_operation_sha256",
            "control_operation_sha256",
            "runner_executable_sha256",
        )
    }
    if sides["candidate"] == sides["control"]:
        raise ValueError("Windows LPE experiment artifacts must differ")
    if hashes["target_operation_sha256"] == hashes["control_operation_sha256"]:
        raise ValueError("Windows LPE experiment operations must differ")
    component = raw["component"]
    authorized_by = raw["authorized_by"]
    signature = raw["signature_ssh"]
    if (
        not isinstance(component, str)
        or not component
        or Path(component).name != component
        or "\\" in component
        or "\x00" in component
        or not isinstance(authorized_by, str)
        or not authorized_by
        or authorized_by != authorized_by.strip()
        or len(authorized_by) > 256
        or any(ord(character) < 0x20 for character in authorized_by)
        or not isinstance(signature, str)
        or not signature
    ):
        raise ValueError("Windows LPE experiment identity fields are invalid")
    policy_bytes = _read_bounded_regular(
        allowed_signers_path, "Windows LPE experiment allowed-signers policy"
    )
    with tempfile.TemporaryDirectory(prefix="0verse-lpe-experiment-policy-") as temporary:
        policy_snapshot = Path(temporary) / "allowed-signers"
        policy_snapshot.write_bytes(policy_bytes)
        verify_ssh_signature(
            canonical_signed_material(raw),
            signature,
            identity=authorized_by,
            namespace=EXPERIMENT_SIGNATURE_NAMESPACE,
            allowed_signers=policy_snapshot,
            label="Windows LPE experiment",
            require_trusted_policy=False,
        )
        authority_key_commitment = ssh_authority_key_commitment(policy_snapshot)
    return VerifiedWindowsLpeExperiment(
        source_sha256=hashlib.sha256(data).hexdigest(),
        pair_plan_sha256=hashes["pair_plan_sha256"],
        component=component,
        candidate_artifact_sha256=sides["candidate"],
        control_artifact_sha256=sides["control"],
        target_operation_sha256=hashes["target_operation_sha256"],
        control_operation_sha256=hashes["control_operation_sha256"],
        runner_executable_sha256=hashes["runner_executable_sha256"],
        authorized_by=authorized_by,
        authority_key_commitment_sha256=authority_key_commitment,
    )


def _verify_pack(inputs: WindowsTokenPackInputs) -> WindowsTokenPackVerification:
    return verify_windows_token_pack(
        inputs.envelope_path,
        blob_dir=inputs.blob_dir,
        acceptance_policy_path=inputs.acceptance_policy_path,
        expected_context_path=inputs.expected_context_path,
        pack_signer_policy_path=inputs.pack_signer_policy_path,
    )


def derive_windows_lpe_paired_closure(
    plan: VerifiedWindowsPairPlan,
    experiment: VerifiedWindowsLpeExperiment,
    candidate_receipt: WindowsServicingReceipt,
    candidate_pack: WindowsTokenPackVerification,
    fixed_receipt: WindowsServicingReceipt,
    fixed_pack: WindowsTokenPackVerification,
) -> WindowsLpePairedClosure:
    """Join already verified nested artifacts without trusting producer labels."""
    candidate_pack.require_legacy_identity_schema()
    fixed_pack.require_legacy_identity_schema()
    if (
        experiment.pair_plan_sha256 != plan.plan_sha256
        or experiment.component != plan.component
        or experiment.candidate_artifact_sha256 != plan.candidate_sha256
        or experiment.control_artifact_sha256 != plan.control_sha256
    ):
        raise ValueError("paired closure experiment differs from the frozen pair plan")
    _verify_servicing_side(
        plan,
        candidate_receipt,
        candidate_pack,
        role="candidate",
        artifact_sha256=plan.candidate_sha256,
        build_lab_ex=plan.candidate_build_lab_ex,
    )
    _verify_servicing_side(
        plan,
        fixed_receipt,
        fixed_pack,
        role="control",
        artifact_sha256=plan.control_sha256,
        build_lab_ex=plan.control_build_lab_ex,
    )
    if (
        experiment.target_operation_sha256 != candidate_pack.target_operation_sha256
        or experiment.control_operation_sha256 != candidate_pack.control_operation_sha256
        or experiment.runner_executable_sha256 != candidate_pack.runner_executable_sha256
    ):
        raise ValueError("paired closure execution differs from the signed experiment")
    if candidate_pack.target_confirmations < candidate_pack.minimum_confirmations:
        raise ValueError("paired closure candidate lacks required target confirmations")
    if candidate_pack.ambiguous_targets:
        raise ValueError("paired closure candidate contains ambiguous target outcomes")
    if fixed_pack.target_confirmations != 0:
        raise ValueError("paired closure fixed build contains a target transition")
    if (
        fixed_pack.clean_target_no_transitions != fixed_pack.trials
        or fixed_pack.ambiguous_targets
    ):
        raise ValueError("paired closure fixed target outcomes are not all clean")
    if (
        candidate_pack.clean_controls != candidate_pack.trials
        or fixed_pack.clean_controls != fixed_pack.trials
    ):
        raise ValueError("paired closure operation controls are not all clean")
    observation = derive_windows_lpe_paired_observation(candidate_pack, fixed_pack)
    if observation.status != "SUBJECT_ONLY_TRANSITION":
        raise ValueError("paired closure requires a subject-only token transition")

    signer_identities = (
        experiment.authorized_by,
        candidate_pack.scope_authorized_by,
        candidate_pack.grant_authorized_by,
        candidate_pack.acceptance_accepted_by,
        candidate_pack.capture_signer_identity,
        candidate_pack.pack_signer_identity,
        candidate_pack.aggregate_signed_by,
        candidate_receipt.receipt_signer_identity,
        fixed_pack.scope_authorized_by,
        fixed_pack.grant_authorized_by,
        fixed_pack.acceptance_accepted_by,
        fixed_pack.capture_signer_identity,
        fixed_pack.pack_signer_identity,
        fixed_pack.aggregate_signed_by,
        fixed_receipt.receipt_signer_identity,
    )
    if len(signer_identities) != len(set(signer_identities)):
        raise ValueError("paired closure signer roles must be independently authorized")
    authority_key_commitments = (
        ("experiment", experiment.authority_key_commitment_sha256),
        ("candidate.scope", candidate_pack.scope_authority_key_commitment_sha256),
        ("candidate.grant", candidate_pack.grant_authority_key_commitment_sha256),
        (
            "candidate.acceptance",
            candidate_pack.acceptance_authority_key_commitment_sha256,
        ),
        ("candidate.capture", candidate_pack.capture_authority_key_commitment_sha256),
        (
            "candidate.aggregate",
            candidate_pack.aggregate_authority_key_commitment_sha256,
        ),
        ("candidate.pack", candidate_pack.pack_authority_key_commitment_sha256),
        (
            "candidate.servicing",
            candidate_receipt.receipt_signer_authority_commitment_sha256,
        ),
        ("fixed.scope", fixed_pack.scope_authority_key_commitment_sha256),
        ("fixed.grant", fixed_pack.grant_authority_key_commitment_sha256),
        ("fixed.acceptance", fixed_pack.acceptance_authority_key_commitment_sha256),
        ("fixed.capture", fixed_pack.capture_authority_key_commitment_sha256),
        ("fixed.aggregate", fixed_pack.aggregate_authority_key_commitment_sha256),
        ("fixed.pack", fixed_pack.pack_authority_key_commitment_sha256),
        (
            "fixed.servicing",
            fixed_receipt.receipt_signer_authority_commitment_sha256,
        ),
    )
    key_commitments = tuple(commitment for _, commitment in authority_key_commitments)
    if len(key_commitments) != len(set(key_commitments)):
        raise ValueError("paired closure authority roles must use independent SSH keys")
    per_run_identities = (
        *candidate_pack.ordered_run_replay_identity_sha256,
        *fixed_pack.ordered_run_replay_identity_sha256,
        *candidate_pack.ordered_capture_sha256,
        *fixed_pack.ordered_capture_sha256,
        *candidate_pack.ordered_process_identity_sha256,
        *fixed_pack.ordered_process_identity_sha256,
    )
    commitment_material = {
        "schema_version": SCHEMA_VERSION,
        "pair_plan_sha256": plan.plan_sha256,
        "experiment_sha256": experiment.source_sha256,
        "candidate_servicing_receipt_sha256": candidate_receipt.receipt_sha256,
        "fixed_servicing_receipt_sha256": fixed_receipt.receipt_sha256,
        "candidate_pack_id": candidate_pack.pack_id,
        "fixed_pack_id": fixed_pack.pack_id,
        "target_operation_sha256": candidate_pack.target_operation_sha256,
        "control_operation_sha256": candidate_pack.control_operation_sha256,
        "runner_executable_sha256": candidate_pack.runner_executable_sha256,
        "candidate_witness": {
            "user_sid": candidate_pack.witness_user_sid,
            "session_id": candidate_pack.witness_session_id,
            "authentication_id": candidate_pack.witness_authentication_id,
            "executable_sha256": candidate_pack.witness_executable_sha256,
        },
        "fixed_witness": {
            "user_sid": fixed_pack.witness_user_sid,
            "session_id": fixed_pack.witness_session_id,
            "authentication_id": fixed_pack.witness_authentication_id,
            "executable_sha256": fixed_pack.witness_executable_sha256,
        },
        "authority_key_commitments": dict(authority_key_commitments),
        "per_run_identities": list(per_run_identities),
    }
    commitment = hashlib.sha256(
        json.dumps(
            commitment_material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    pair_replay = hashlib.sha256(
        b"0verse-windows-lpe-paired-replay-v1\0" + commitment.encode("ascii")
    ).hexdigest()
    replay = (
        pair_replay,
        candidate_pack.run_id_commitment_sha256,
        candidate_pack.job_nonce_commitment_sha256,
        candidate_pack.execution_grant_nonce_commitment_sha256,
        candidate_pack.worker_acceptance_nonce_commitment_sha256,
        candidate_pack.grant_replay_identity_sha256,
        candidate_pack.worker_acceptance_replay_identity_sha256,
        *candidate_pack.ordered_capture_nonce_commitment_sha256,
        *candidate_pack.ordered_run_replay_identity_sha256,
        fixed_pack.run_id_commitment_sha256,
        fixed_pack.job_nonce_commitment_sha256,
        fixed_pack.execution_grant_nonce_commitment_sha256,
        fixed_pack.worker_acceptance_nonce_commitment_sha256,
        fixed_pack.grant_replay_identity_sha256,
        fixed_pack.worker_acceptance_replay_identity_sha256,
        *fixed_pack.ordered_capture_nonce_commitment_sha256,
        *fixed_pack.ordered_run_replay_identity_sha256,
    )
    if len(replay) != len(set(replay)):
        raise ValueError("paired closure replay identities are not globally unique")
    return WindowsLpePairedClosure(
        pair_plan_sha256=plan.plan_sha256,
        experiment_sha256=experiment.source_sha256,
        component=plan.component,
        architecture=plan.architecture,
        candidate_servicing_receipt_sha256=candidate_receipt.receipt_sha256,
        candidate_artifact_sha256=candidate_receipt.artifact_sha256,
        candidate_build_lab_ex=candidate_receipt.build_lab_ex,
        candidate_pack_id=candidate_pack.pack_id,
        candidate_target_confirmations=candidate_pack.target_confirmations,
        candidate_clean_target_no_transitions=(
            candidate_pack.clean_target_no_transitions
        ),
        candidate_clean_controls=candidate_pack.clean_controls,
        fixed_servicing_receipt_sha256=fixed_receipt.receipt_sha256,
        fixed_artifact_sha256=fixed_receipt.artifact_sha256,
        fixed_build_lab_ex=fixed_receipt.build_lab_ex,
        fixed_pack_id=fixed_pack.pack_id,
        fixed_clean_target_no_transitions=fixed_pack.clean_target_no_transitions,
        fixed_clean_controls=fixed_pack.clean_controls,
        trials=candidate_pack.trials,
        minimum_confirmations=candidate_pack.minimum_confirmations,
        target_operation_sha256=candidate_pack.target_operation_sha256,
        control_operation_sha256=candidate_pack.control_operation_sha256,
        runner_executable_sha256=candidate_pack.runner_executable_sha256,
        candidate_worker_machine_id=candidate_pack.worker_machine_id,
        fixed_worker_machine_id=fixed_pack.worker_machine_id,
        candidate_witness_user_sid=candidate_pack.witness_user_sid,
        candidate_witness_session_id=candidate_pack.witness_session_id,
        candidate_witness_authentication_id=(
            candidate_pack.witness_authentication_id
        ),
        candidate_witness_executable_sha256=(
            candidate_pack.witness_executable_sha256
        ),
        fixed_witness_user_sid=fixed_pack.witness_user_sid,
        fixed_witness_session_id=fixed_pack.witness_session_id,
        fixed_witness_authentication_id=fixed_pack.witness_authentication_id,
        fixed_witness_executable_sha256=fixed_pack.witness_executable_sha256,
        candidate_run_id_commitment_sha256=candidate_pack.run_id_commitment_sha256,
        candidate_job_nonce_commitment_sha256=candidate_pack.job_nonce_commitment_sha256,
        candidate_grant_nonce_commitment_sha256=(
            candidate_pack.execution_grant_nonce_commitment_sha256
        ),
        candidate_acceptance_nonce_commitment_sha256=(
            candidate_pack.worker_acceptance_nonce_commitment_sha256
        ),
        candidate_ordered_capture_nonce_commitment_sha256=(
            candidate_pack.ordered_capture_nonce_commitment_sha256
        ),
        fixed_run_id_commitment_sha256=fixed_pack.run_id_commitment_sha256,
        fixed_job_nonce_commitment_sha256=fixed_pack.job_nonce_commitment_sha256,
        fixed_grant_nonce_commitment_sha256=(
            fixed_pack.execution_grant_nonce_commitment_sha256
        ),
        fixed_acceptance_nonce_commitment_sha256=(
            fixed_pack.worker_acceptance_nonce_commitment_sha256
        ),
        fixed_ordered_capture_nonce_commitment_sha256=(
            fixed_pack.ordered_capture_nonce_commitment_sha256
        ),
        authority_key_commitments=authority_key_commitments,
        closure_commitment_sha256=commitment,
        pair_replay_identity_sha256=pair_replay,
        ordered_replay_identity_sha256=replay,
    )


def _verify_servicing_side(
    plan: VerifiedWindowsPairPlan,
    receipt: WindowsServicingReceipt,
    pack: WindowsTokenPackVerification,
    *,
    role: str,
    artifact_sha256: str,
    build_lab_ex: str,
) -> None:
    if (
        receipt.pair_plan_sha256 != plan.plan_sha256
        or receipt.role != role
        or receipt.artifact_sha256 != artifact_sha256
        or receipt.build_lab_ex != build_lab_ex
        or pack.build_lab_ex != build_lab_ex
        or receipt.worker_machine_id != pack.worker_machine_id
    ):
        raise ValueError(f"paired closure {role} servicing/build/machine binding mismatch")


def _sha256(raw: object, label: str) -> str:
    if not isinstance(raw, str) or _SHA256.fullmatch(raw) is None:
        raise ValueError(f"Windows LPE experiment {label} is invalid")
    return raw


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_bounded_regular(path: str | Path, label: str) -> bytes:
    descriptor = os.open(
        Path(path),
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise ValueError(f"{label} must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(data) > 1024 * 1024:
        raise ValueError(f"{label} exceeds the size limit")
    return data
