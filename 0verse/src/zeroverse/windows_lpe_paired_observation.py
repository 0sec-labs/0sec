"""Neutral comparison of two independently verified Windows token packs.

This module deliberately stops at an observed token differential.  It does not
bind a component artifact, servicing history, CVE, KB, vulnerability, novelty,
or bounty claim.  The stricter paired-closure verifier adds those independent
inputs after reusing this comparison boundary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from .windows_token_pack import WindowsTokenPackVerification

SCHEMA_VERSION = "0verse.windows-lpe-paired-observation/v1"

ObservationStatus = Literal[
    "SUBJECT_ONLY_TRANSITION",
    "REFERENCE_ONLY_TRANSITION",
    "BOTH_TRANSITION",
    "NO_TRANSITION",
    "INCONCLUSIVE",
]

PROOF_LIMIT = (
    "Two independently verified Windows token-pack observations were compared under "
    "matching declared runtime parameters. Component identity, retained PE artifact "
    "hashes, Microsoft provenance, CVE or KB mapping, vulnerable or fixed status, "
    "vulnerability causality, novelty, exploitability, impact, bounty eligibility, and "
    "disclosure readiness remain unproven."
)


@dataclass(frozen=True)
class WindowsLpePairedObservation:
    status: ObservationStatus
    subject: WindowsTokenPackVerification
    reference: WindowsTokenPackVerification
    authority_key_commitments: tuple[tuple[str, str], ...]
    observation_commitment_sha256: str
    pair_replay_identity_sha256: str
    ordered_replay_identity_sha256: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        self.subject.require_legacy_identity_schema()
        self.reference.require_legacy_identity_schema()
        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "subject": _side_to_dict(self.subject, role="subject"),
            "reference": _side_to_dict(self.reference, role="reference"),
            "trials": self.subject.trials,
            "minimum_confirmations": self.subject.minimum_confirmations,
            "starting_context": self.subject.starting_context,
            "finishing_principal": self.subject.finishing_principal,
            "target_operation_sha256": self.subject.target_operation_sha256,
            "control_operation_sha256": self.subject.control_operation_sha256,
            "runner_executable_sha256": self.subject.runner_executable_sha256,
            "witness_executable_sha256": self.subject.witness_executable_sha256,
            "zeroverse_runtime_digest": self.subject.zeroverse_runtime_digest,
            "authority_key_commitments": dict(self.authority_key_commitments),
            "observation_commitment_sha256": self.observation_commitment_sha256,
            "pair_replay_identity_sha256": self.pair_replay_identity_sha256,
            "ordered_replay_identity_sha256": list(self.ordered_replay_identity_sha256),
            "neutral_observations_rederived": True,
            "replay_state_consumed": False,
            "accepted": False,
            "claim_eligible": False,
            "bounty_eligible": False,
            "weaponization": False,
            "auto_disclosure": False,
            "human_report_gate": True,
            "proof_limit": PROOF_LIMIT,
        }


def derive_windows_lpe_paired_observation(
    subject: WindowsTokenPackVerification,
    reference: WindowsTokenPackVerification,
) -> WindowsLpePairedObservation:
    """Compare two already verified packs without promoting a security claim."""
    subject.require_legacy_identity_schema()
    reference.require_legacy_identity_schema()
    _verify_comparable(subject, reference)
    _verify_counts(subject, reference)
    authority_key_commitments = _verify_authorities(subject, reference)
    _verify_unique_identities(subject, reference)

    status = _derive_status(subject, reference)
    material = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "subject": _side_to_dict(subject, role="subject"),
        "reference": _side_to_dict(reference, role="reference"),
        "trials": subject.trials,
        "minimum_confirmations": subject.minimum_confirmations,
        "starting_context": subject.starting_context,
        "finishing_principal": subject.finishing_principal,
        "target_operation_sha256": subject.target_operation_sha256,
        "control_operation_sha256": subject.control_operation_sha256,
        "runner_executable_sha256": subject.runner_executable_sha256,
        "witness_executable_sha256": subject.witness_executable_sha256,
        "zeroverse_runtime_digest": subject.zeroverse_runtime_digest,
        "authority_key_commitments": dict(authority_key_commitments),
    }
    canonical_material = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    commitment = hashlib.sha256(
        b"0verse-windows-lpe-paired-observation-v1\0" + canonical_material
    ).hexdigest()
    pair_replay = hashlib.sha256(
        b"0verse-windows-lpe-paired-observation-replay-v1\0" + commitment.encode("ascii")
    ).hexdigest()
    replay = (
        pair_replay,
        *_side_replay_identities(subject),
        *_side_replay_identities(reference),
    )
    if len(replay) != len(set(replay)):
        raise ValueError("paired observation replay identities are not globally unique")

    return WindowsLpePairedObservation(
        status=status,
        subject=subject,
        reference=reference,
        authority_key_commitments=authority_key_commitments,
        observation_commitment_sha256=commitment,
        pair_replay_identity_sha256=pair_replay,
        ordered_replay_identity_sha256=replay,
    )


def _verify_comparable(
    subject: WindowsTokenPackVerification,
    reference: WindowsTokenPackVerification,
) -> None:
    if (
        subject.trials != reference.trials
        or subject.minimum_confirmations != reference.minimum_confirmations
        or subject.starting_context != reference.starting_context
        or subject.finishing_principal != reference.finishing_principal
    ):
        raise ValueError("paired observation experiment parameters differ across builds")
    if (
        subject.target_operation_sha256 != reference.target_operation_sha256
        or subject.control_operation_sha256 != reference.control_operation_sha256
    ):
        raise ValueError("paired observation operation identities differ across builds")
    if (
        subject.runner_executable_sha256 != reference.runner_executable_sha256
        or subject.witness_executable_sha256 != reference.witness_executable_sha256
    ):
        raise ValueError(
            "paired observation runner, witness, or operation identities differ across builds"
        )
    if subject.zeroverse_runtime_digest != reference.zeroverse_runtime_digest:
        raise ValueError("paired observation runtime digests differ across builds")
    subject_architecture = "amd64" if ".amd64fre." in subject.build_lab_ex else "arm64"
    reference_architecture = "amd64" if ".amd64fre." in reference.build_lab_ex else "arm64"
    if subject_architecture != reference_architecture:
        raise ValueError("paired observation subject/reference architectures differ")
    if subject.worker_machine_id == reference.worker_machine_id:
        raise ValueError("paired observation requires distinct subject/reference machines")


def _verify_counts(
    subject: WindowsTokenPackVerification,
    reference: WindowsTokenPackVerification,
) -> None:
    for label, pack in (("subject", subject), ("reference", reference)):
        target_counts = (
            pack.target_confirmations,
            pack.clean_target_no_transitions,
            pack.ambiguous_targets,
        )
        if (
            any(value < 0 or value > pack.trials for value in target_counts)
            or sum(target_counts) != pack.trials
            or not 0 <= pack.clean_controls <= pack.trials
            or len(pack.ordered_capture_nonce_commitment_sha256) != pack.trials * 2
        ):
            raise ValueError(f"paired observation {label} counts or identities are invalid")


def _verify_authorities(
    subject: WindowsTokenPackVerification,
    reference: WindowsTokenPackVerification,
) -> tuple[tuple[str, str], ...]:
    signer_identities = (
        subject.scope_authorized_by,
        subject.grant_authorized_by,
        subject.acceptance_accepted_by,
        subject.capture_signer_identity,
        subject.aggregate_signed_by,
        subject.pack_signer_identity,
        reference.scope_authorized_by,
        reference.grant_authorized_by,
        reference.acceptance_accepted_by,
        reference.capture_signer_identity,
        reference.aggregate_signed_by,
        reference.pack_signer_identity,
    )
    if len(signer_identities) != len(set(signer_identities)):
        raise ValueError("paired observation signer roles must be independently authorized")

    commitments = (
        ("subject.scope", subject.scope_authority_key_commitment_sha256),
        ("subject.grant", subject.grant_authority_key_commitment_sha256),
        ("subject.acceptance", subject.acceptance_authority_key_commitment_sha256),
        ("subject.capture", subject.capture_authority_key_commitment_sha256),
        ("subject.aggregate", subject.aggregate_authority_key_commitment_sha256),
        ("subject.pack", subject.pack_authority_key_commitment_sha256),
        ("reference.scope", reference.scope_authority_key_commitment_sha256),
        ("reference.grant", reference.grant_authority_key_commitment_sha256),
        (
            "reference.acceptance",
            reference.acceptance_authority_key_commitment_sha256,
        ),
        ("reference.capture", reference.capture_authority_key_commitment_sha256),
        ("reference.aggregate", reference.aggregate_authority_key_commitment_sha256),
        ("reference.pack", reference.pack_authority_key_commitment_sha256),
    )
    values = tuple(value for _, value in commitments)
    if len(values) != len(set(values)):
        raise ValueError("paired observation authority roles must use independent SSH keys")
    return commitments


def _verify_unique_identities(
    subject: WindowsTokenPackVerification,
    reference: WindowsTokenPackVerification,
) -> None:
    singleton_identities = (
        subject.pack_id,
        reference.pack_id,
        subject.campaign_sha256,
        reference.campaign_sha256,
        subject.scope_manifest_sha256,
        reference.scope_manifest_sha256,
        subject.execution_grant_sha256,
        reference.execution_grant_sha256,
        subject.worker_acceptance_sha256,
        reference.worker_acceptance_sha256,
        subject.grant_replay_identity_sha256,
        reference.grant_replay_identity_sha256,
        subject.worker_acceptance_replay_identity_sha256,
        reference.worker_acceptance_replay_identity_sha256,
    )
    if len(singleton_identities) != len(set(singleton_identities)):
        raise ValueError("paired observation reuses a cross-build authority identity")

    same_kind_nonces = (
        (subject.run_id_commitment_sha256, reference.run_id_commitment_sha256),
        (subject.job_nonce_commitment_sha256, reference.job_nonce_commitment_sha256),
        (
            subject.execution_grant_nonce_commitment_sha256,
            reference.execution_grant_nonce_commitment_sha256,
        ),
        (
            subject.worker_acceptance_nonce_commitment_sha256,
            reference.worker_acceptance_nonce_commitment_sha256,
        ),
    )
    if any(left == right for left, right in same_kind_nonces):
        raise ValueError("paired observation reuses a cross-build authority nonce")

    expected_per_kind = subject.trials * 2 + reference.trials * 2
    for identities in (
        (
            *subject.ordered_run_replay_identity_sha256,
            *reference.ordered_run_replay_identity_sha256,
        ),
        (*subject.ordered_capture_sha256, *reference.ordered_capture_sha256),
        (
            *subject.ordered_process_identity_sha256,
            *reference.ordered_process_identity_sha256,
        ),
        (
            *subject.ordered_capture_nonce_commitment_sha256,
            *reference.ordered_capture_nonce_commitment_sha256,
        ),
    ):
        if len(identities) != expected_per_kind or len(identities) != len(set(identities)):
            raise ValueError("paired observation reuses or omits a per-run identity")


def _derive_status(
    subject: WindowsTokenPackVerification,
    reference: WindowsTokenPackVerification,
) -> ObservationStatus:
    if subject.clean_controls != subject.trials or reference.clean_controls != reference.trials:
        return "INCONCLUSIVE"
    subject_state = _target_state(subject)
    reference_state = _target_state(reference)
    if subject_state == "transition" and reference_state == "no-transition":
        return "SUBJECT_ONLY_TRANSITION"
    if subject_state == "no-transition" and reference_state == "transition":
        return "REFERENCE_ONLY_TRANSITION"
    if subject_state == reference_state == "transition":
        return "BOTH_TRANSITION"
    if subject_state == reference_state == "no-transition":
        return "NO_TRANSITION"
    return "INCONCLUSIVE"


def _target_state(pack: WindowsTokenPackVerification) -> str:
    if pack.ambiguous_targets:
        return "inconclusive"
    if pack.target_confirmations >= pack.minimum_confirmations:
        return "transition"
    if pack.target_confirmations == 0 and pack.clean_target_no_transitions == pack.trials:
        return "no-transition"
    return "inconclusive"


def _side_to_dict(
    pack: WindowsTokenPackVerification, *, role: Literal["subject", "reference"]
) -> dict[str, object]:
    return {
        "role": role,
        "token_pack_id": pack.pack_id,
        "build_lab_ex": pack.build_lab_ex,
        "target_confirmations": pack.target_confirmations,
        "clean_target_no_transitions": pack.clean_target_no_transitions,
        "ambiguous_targets": pack.ambiguous_targets,
        "clean_controls": pack.clean_controls,
        "worker_machine_id": pack.worker_machine_id,
        "witness": {
            "user_sid": pack.witness_user_sid,
            "session_id": pack.witness_session_id,
            "authentication_id": pack.witness_authentication_id,
            "executable_sha256": pack.witness_executable_sha256,
        },
        "identity_commitments": {
            "run_id_sha256": pack.run_id_commitment_sha256,
            "job_nonce_sha256": pack.job_nonce_commitment_sha256,
            "grant_nonce_sha256": pack.execution_grant_nonce_commitment_sha256,
            "acceptance_nonce_sha256": (pack.worker_acceptance_nonce_commitment_sha256),
            "ordered_capture_nonce_sha256": list(pack.ordered_capture_nonce_commitment_sha256),
        },
    }


def _side_replay_identities(
    pack: WindowsTokenPackVerification,
) -> tuple[str, ...]:
    return (
        pack.run_id_commitment_sha256,
        pack.job_nonce_commitment_sha256,
        pack.execution_grant_nonce_commitment_sha256,
        pack.worker_acceptance_nonce_commitment_sha256,
        pack.grant_replay_identity_sha256,
        pack.worker_acceptance_replay_identity_sha256,
        *pack.ordered_capture_nonce_commitment_sha256,
        *pack.ordered_run_replay_identity_sha256,
    )
