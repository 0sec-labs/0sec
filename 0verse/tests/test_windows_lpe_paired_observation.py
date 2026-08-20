from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from test_windows_lpe_paired_closure import _digest, _paired_fixture

from zeroverse.windows_lpe_paired_observation import (
    SCHEMA_VERSION,
    derive_windows_lpe_paired_observation,
)


def _packs(tmp_path):
    fixture = _paired_fixture(tmp_path)
    return fixture[3], fixture[5]


def test_derives_neutral_subject_only_observation(tmp_path) -> None:
    subject, reference = _packs(tmp_path)
    observation = derive_windows_lpe_paired_observation(subject, reference)
    raw = observation.to_dict()

    assert raw["schema_version"] == SCHEMA_VERSION
    assert raw["status"] == "SUBJECT_ONLY_TRANSITION"
    assert raw["subject"]["role"] == "subject"
    assert raw["reference"]["role"] == "reference"
    assert raw["subject"]["token_pack_id"] == subject.pack_id
    assert raw["reference"]["token_pack_id"] == reference.pack_id
    assert raw["witness_executable_sha256"] == raw["subject"]["witness"]["executable_sha256"]
    assert raw["witness_executable_sha256"] == raw["reference"]["witness"]["executable_sha256"]
    assert raw["zeroverse_runtime_digest"] == subject.zeroverse_runtime_digest
    assert len(raw["authority_key_commitments"]) == 12
    assert set(raw) == {
        "schema_version",
        "status",
        "subject",
        "reference",
        "trials",
        "minimum_confirmations",
        "starting_context",
        "finishing_principal",
        "target_operation_sha256",
        "control_operation_sha256",
        "runner_executable_sha256",
        "witness_executable_sha256",
        "zeroverse_runtime_digest",
        "authority_key_commitments",
        "observation_commitment_sha256",
        "pair_replay_identity_sha256",
        "ordered_replay_identity_sha256",
        "neutral_observations_rederived",
        "replay_state_consumed",
        "accepted",
        "claim_eligible",
        "bounty_eligible",
        "weaponization",
        "auto_disclosure",
        "human_report_gate",
        "proof_limit",
    }
    for side in (raw["subject"], raw["reference"]):
        assert set(side) == {
            "role",
            "token_pack_id",
            "build_lab_ex",
            "target_confirmations",
            "clean_target_no_transitions",
            "ambiguous_targets",
            "clean_controls",
            "worker_machine_id",
            "witness",
            "identity_commitments",
        }
        assert set(side["identity_commitments"]) == {
            "run_id_sha256",
            "job_nonce_sha256",
            "grant_nonce_sha256",
            "acceptance_nonce_sha256",
            "ordered_capture_nonce_sha256",
        }
    assert len(raw["ordered_replay_identity_sha256"]) == 29
    assert len(set(raw["ordered_replay_identity_sha256"])) == 29
    assert raw["accepted"] is False
    assert raw["claim_eligible"] is False
    assert raw["bounty_eligible"] is False
    assert raw["weaponization"] is False
    assert raw["auto_disclosure"] is False
    assert raw["human_report_gate"] is True
    assert raw["neutral_observations_rederived"] is True

    def keys(value):
        if isinstance(value, dict):
            return set(value) | {key for child in value.values() for key in keys(child)}
        if isinstance(value, list):
            return {key for child in value for key in keys(child)}
        return set()

    output_keys = keys(raw)
    for forbidden in ("cve_id", "kb_id", "component", "artifact_sha256"):
        assert forbidden not in output_keys


@pytest.mark.parametrize(
    ("subject_changes", "reference_changes", "expected"),
    [
        ({"target_confirmations": 0, "clean_target_no_transitions": 2}, {}, "NO_TRANSITION"),
        (
            {},
            {"target_confirmations": 2, "clean_target_no_transitions": 0},
            "BOTH_TRANSITION",
        ),
        (
            {"target_confirmations": 0, "clean_target_no_transitions": 2},
            {"target_confirmations": 2, "clean_target_no_transitions": 0},
            "REFERENCE_ONLY_TRANSITION",
        ),
        (
            {"target_confirmations": 1, "clean_target_no_transitions": 0, "ambiguous_targets": 1},
            {},
            "INCONCLUSIVE",
        ),
        ({"clean_controls": 1}, {}, "INCONCLUSIVE"),
    ],
)
def test_derives_all_neutral_statuses_from_counts(
    tmp_path, subject_changes, reference_changes, expected
) -> None:
    subject, reference = _packs(tmp_path)
    observation = derive_windows_lpe_paired_observation(
        replace(subject, **subject_changes),
        replace(reference, **reference_changes),
    )
    assert observation.status == expected


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"zeroverse_runtime_digest": "sha256:" + "f" * 64}, "runtime digests differ"),
        ({"worker_machine_id": "worker-01"}, "distinct.*machines"),
        ({"pack_id": "subject-pack"}, "authority identity"),
    ],
)
def test_rejects_noncomparable_or_reused_cross_pack_state(tmp_path, changes, message) -> None:
    subject, reference = _packs(tmp_path)
    if changes.get("pack_id") == "subject-pack":
        changes = {"pack_id": subject.pack_id}
    with pytest.raises(ValueError, match=message):
        derive_windows_lpe_paired_observation(subject, replace(reference, **changes))


def test_observation_commitment_is_domain_separated_and_binds_witness(tmp_path) -> None:
    subject, reference = _packs(tmp_path)
    subject = replace(subject, pack_id=_digest("subject-pack"))
    baseline = derive_windows_lpe_paired_observation(subject, reference)
    changed = derive_windows_lpe_paired_observation(
        replace(subject, witness_session_id=subject.witness_session_id + 10), reference
    )
    assert baseline.observation_commitment_sha256 != (changed.observation_commitment_sha256)
    assert (
        baseline.observation_commitment_sha256
        == "a3a23b731f1137992dd30b49290d5ec48741b9141c2e776c2aed5aa0ea54d6c9"
    )
    expected_replay = hashlib.sha256(
        b"0verse-windows-lpe-paired-observation-replay-v1\0"
        + baseline.observation_commitment_sha256.encode("ascii")
    ).hexdigest()
    assert baseline.pair_replay_identity_sha256 == expected_replay


def test_strict_closure_rejects_non_subject_only_base_status(tmp_path) -> None:
    from zeroverse.windows_lpe_paired_closure import derive_windows_lpe_paired_closure

    plan, experiment, candidate_receipt, subject, fixed_receipt, reference = _paired_fixture(
        tmp_path
    )
    subject = replace(subject, target_confirmations=0, clean_target_no_transitions=subject.trials)
    with pytest.raises(ValueError, match=r"lacks required|subject-only"):
        derive_windows_lpe_paired_closure(
            plan,
            experiment,
            candidate_receipt,
            subject,
            fixed_receipt,
            reference,
        )


def test_rejects_broker_pack_until_identity_separation_schema_exists(tmp_path) -> None:
    subject, reference = _packs(tmp_path)
    subject = replace(
        subject,
        ordered_broker_receipt_replay_identity_sha256=("a" * 64,),
        ordered_broker_process_replay_identity_sha256=("b" * 64,),
        ordered_broker_transcript_replay_identity_sha256=("c" * 64,),
        broker_receipt_authority_key_commitment_sha256="d" * 64,
        broker_receipt_signer_identity="broker@example.test",
    )
    with pytest.raises(ValueError, match="acceptance-witness/measured-process"):
        derive_windows_lpe_paired_observation(subject, reference)


def test_rejects_partial_broker_pack_before_paired_output(tmp_path) -> None:
    subject, reference = _packs(tmp_path)
    subject = replace(subject, broker_receipt_signer_identity="broker@example.test")
    with pytest.raises(ValueError, match="fields are incoherent"):
        derive_windows_lpe_paired_observation(subject, reference)


def test_direct_observation_serialization_rejects_partial_broker_model(tmp_path) -> None:
    subject, reference = _packs(tmp_path)
    observation = derive_windows_lpe_paired_observation(subject, reference)
    partial = replace(subject, broker_receipt_signer_identity="broker@example.test")
    with pytest.raises(ValueError, match="fields are incoherent"):
        replace(observation, subject=partial).to_dict()


def test_direct_observation_serialization_rejects_complete_broker_model(tmp_path) -> None:
    subject, reference = _packs(tmp_path)
    observation = derive_windows_lpe_paired_observation(subject, reference)
    broker = replace(
        subject,
        ordered_broker_receipt_replay_identity_sha256=("a" * 64,),
        ordered_broker_process_replay_identity_sha256=("b" * 64,),
        ordered_broker_transcript_replay_identity_sha256=("c" * 64,),
        broker_receipt_authority_key_commitment_sha256="d" * 64,
        broker_receipt_signer_identity="broker@example.test",
    )
    with pytest.raises(ValueError, match="acceptance-witness/measured-process"):
        replace(observation, subject=broker).to_dict()
