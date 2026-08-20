from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from authorization_helpers import authorization_policy, sign_document
from test_windows_lpac_capture import (
    APP_CONTAINER_SID,
    SANDBOX,
    SANDBOX_PROCESS_SHA256,
    _lpac_campaign,
    _lpac_capture,
)
from test_windows_token_capture import _authority_bundle

from zeroverse.ssh_authorization import canonical_signed_material, sign_ssh_material
from zeroverse.windows_lpac_broker_receipt import (
    OBSERVATION_LOCUS,
    SCHEMA_VERSION,
    SIGNATURE_NAMESPACE,
    derive_burn_only_replay_identities,
    derive_process_identity,
    derive_token_profile_sha256,
    load_windows_lpac_broker_receipt,
    require_broker_receipt_binding,
)
from zeroverse.windows_token_capture import (
    LPAC_PROCESS_SCHEMA_VERSION,
    ProductionWindowsTokenSnapshot,
    load_windows_token_capture,
)
from zeroverse.windows_token_capture import (
    SIGNATURE_NAMESPACE as CAPTURE_SIGNATURE_NAMESPACE,
)
from zeroverse.windows_token_pack import build_windows_token_pack


def _v5_fixture(tmp_path: Path):
    worker_machine_id = hashlib.sha256(b"owned-canary-machine-001").hexdigest()
    authorities = _authority_bundle(
        tmp_path,
        campaign_overrides=_lpac_campaign(),
        acceptance_overrides={"worker_machine_id": worker_machine_id},
    )
    _v4, _ = _lpac_capture(tmp_path, authorities)
    capture_path = tmp_path / "capture-control-1.json"
    capture_raw = json.loads(capture_path.read_text(encoding="utf-8"))
    capture_raw["worker_machine_id"] = worker_machine_id
    launch_receipt_sha256 = capture_raw["lpac_launch"]["launch_receipt_sha256"]
    capture_raw.pop("lpac_launch")
    capture_raw.pop("thread_id_before")
    capture_raw.pop("thread_id_after")
    capture_raw["schema_version"] = LPAC_PROCESS_SCHEMA_VERSION
    for phase in ("start_token", "finish_token"):
        capture_raw[phase]["token_source"] = OBSERVATION_LOCUS
        capture_raw[phase]["user_sid"] = "S-1-5-21-1-2-3-1002"
        capture_raw[phase]["session_id"] = 2
        capture_raw[phase]["authentication_id"] = "0000000000001002"

    start = capture_raw["start_token"]
    finish = capture_raw["finish_token"]
    campaign, campaign_sha, _scope, scope_sha, _grant, grant_sha, _acceptance, acceptance_sha = (
        authorities
    )
    process_identity = derive_process_identity(
        worker_machine_id=capture_raw["worker_machine_id"],
        measured_pid=4242,
        measured_creation_filetime=133700000000000000,
        image_volume_serial_number="0123456789abcdef",
        image_file_id="0123456789abcdef0123456789abcdef",
        image_sha256=SANDBOX_PROCESS_SHA256,
        package_full_name="Microsoft.SecHealthUI_1.0.0.0_x64__cw5n1h2txyewy",
        package_family_name="Microsoft.SecHealthUI_cw5n1h2txyewy",
        app_container_sid=APP_CONTAINER_SID,
    )
    broker_raw: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "observation_locus": OBSERVATION_LOCUS,
        "locator_pid": 4242,
        "locator_creation_filetime": 133700000000000000,
        "measured_pid": 4242,
        "measured_creation_filetime": 133700000000000000,
        "measured_started_at": capture_raw["started_at"],
        "measured_completed_at": capture_raw["completed_at"],
        "process_alive_before": True,
        "process_alive_after": True,
        "image_file_handle_held_before_after": True,
        "image_volume_serial_number": "0123456789abcdef",
        "image_file_id": "0123456789abcdef0123456789abcdef",
        "image_sha256": SANDBOX_PROCESS_SHA256,
        "package_full_name": "Microsoft.SecHealthUI_1.0.0.0_x64__cw5n1h2txyewy",
        "package_family_name": "Microsoft.SecHealthUI_cw5n1h2txyewy",
        "eligible_sandbox": SANDBOX,
        "app_container_sid": APP_CONTAINER_SID,
        "less_privileged_app_container": True,
        "start_token_id": start["token_id"],
        "finish_token_id": finish["token_id"],
        "start_user_sid": start["user_sid"],
        "finish_user_sid": finish["user_sid"],
        "start_session_id": start["session_id"],
        "finish_session_id": finish["session_id"],
        "start_authentication_id": start["authentication_id"],
        "finish_authentication_id": finish["authentication_id"],
        "start_token_profile_sha256": derive_token_profile_sha256(start),
        "finish_token_profile_sha256": derive_token_profile_sha256(finish),
        "start_statistics_token_id": start["statistics_token_id_before"],
        "finish_statistics_token_id": finish["statistics_token_id_before"],
        "start_modified_id": start["modified_id_before"],
        "finish_modified_id": finish["modified_id_before"],
        "process_identity_sha256": process_identity,
        "measurement_transcript_sha256": hashlib.sha256(b"measurement-a").hexdigest(),
        "receipt_nonce": "broker_receipt_nonce_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "fixed_adapter_operation_sha256": campaign.control_operation_sha256,
        "launch_receipt_sha256": launch_receipt_sha256,
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "execution_grant_sha256": grant_sha,
        "worker_acceptance_sha256": acceptance_sha,
        "case": "control",
        "trial": 1,
        "run_nonce": capture_raw["run_nonce"],
        "process_instance_id": capture_raw["process_instance_id"],
        "worker": capture_raw["worker"],
        "worker_machine_id": capture_raw["worker_machine_id"],
        "build_lab_ex": capture_raw["build_lab_ex"],
        "signed_by": "operator@example.test",
        "signature_ssh": "",
    }
    broker_path = tmp_path / "broker-control-1.json"
    broker_key = tmp_path / "broker-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(broker_key)],
        check=True,
    )
    broker_policy = tmp_path / "broker.allowed-signers"
    broker_policy.write_text(
        "broker@example.test "
        + broker_key.with_suffix(".pub").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    broker_raw["signed_by"] = "broker@example.test"
    broker_raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(broker_raw),
        signing_key=broker_key,
        namespace=SIGNATURE_NAMESPACE,
        label="test LPAC broker receipt",
    )
    broker_path.write_text(json.dumps(broker_raw), encoding="utf-8")
    broker, broker_sha = load_windows_lpac_broker_receipt(
        broker_path, allowed_signers=broker_policy
    )
    capture_raw["lpac_broker_receipt_sha256"] = broker_sha
    capture_raw["lpac_launch_receipt_sha256"] = launch_receipt_sha256
    capture_path.write_text(
        json.dumps(sign_document(capture_raw, CAPTURE_SIGNATURE_NAMESPACE)), encoding="utf-8"
    )
    capture, _ = load_windows_token_capture(
        capture_path, allowed_signers=authorization_policy(), require_verified=True
    )
    return authorities, capture, capture_path, broker, broker_path, broker_raw, broker_policy


def test_v5_receipt_cross_binds_os_facts_authority_and_capture(tmp_path: Path) -> None:
    authorities, capture, _capture_path, broker, _broker_path, _raw, _policy = _v5_fixture(
        tmp_path
    )
    campaign, campaign_sha, _scope, scope_sha, _grant, grant_sha, _acceptance, acceptance_sha = (
        authorities
    )
    require_broker_receipt_binding(
        broker,
        receipt_sha256=capture.lpac_broker_receipt_sha256,
        capture=capture,
        campaign=campaign,
        campaign_sha256=campaign_sha,
        scope_sha256=scope_sha,
        grant_sha256=grant_sha,
        acceptance_sha256=acceptance_sha,
    )
    replay = derive_burn_only_replay_identities(broker)
    assert len(replay) == 3
    assert len(set(replay)) == 3
    assert capture.start_token.token_source == "process-primary"
    assert broker.start_user_sid == capture.start_token.user_sid
    assert broker.start_session_id == capture.start_token.session_id
    assert broker.start_authentication_id == capture.start_token.authentication_id
    assert broker.start_user_sid != capture.witness_user_sid
    assert broker.start_session_id != capture.witness_session_id
    assert broker.start_authentication_id != capture.witness_authentication_id
    assert capture.thread_id_before == capture.thread_id_after == 0
    assert "thread_id_before" not in capture.to_dict()
    assert "thread_id_after" not in capture.to_dict()

    wrong_locus = replace(
        capture,
        finish_token=replace(capture.finish_token, token_source="thread"),
    )
    with pytest.raises(ValueError, match="authority/capture-bound"):
        require_broker_receipt_binding(
            broker,
            receipt_sha256=capture.lpac_broker_receipt_sha256,
            capture=wrong_locus,
            campaign=campaign,
            campaign_sha256=campaign_sha,
            scope_sha256=scope_sha,
            grant_sha256=grant_sha,
            acceptance_sha256=acceptance_sha,
        )


def test_v5_capture_rejects_serialized_or_internal_thread_locus(tmp_path: Path) -> None:
    _authorities, capture, capture_path, _broker, _broker_path, _raw, _policy = _v5_fixture(
        tmp_path
    )
    serialized = json.loads(capture_path.read_text(encoding="utf-8"))
    serialized["thread_id_before"] = 4242
    serialized["thread_id_after"] = 4242
    capture_path.write_text(json.dumps(serialized), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown thread_id_after, thread_id_before"):
        load_windows_token_capture(
            capture_path, allowed_signers=authorization_policy(), require_verified=True
        )
    with pytest.raises(ValueError, match="cannot contain thread-locus evidence"):
        replace(capture, thread_id_before=4242, thread_id_after=4242).validate()


def test_broker_measurement_interval_is_fresh_signed_and_capture_bound(
    tmp_path: Path,
) -> None:
    authorities, capture, _capture_path, _broker, broker_path, raw, policy = _v5_fixture(
        tmp_path
    )
    campaign, campaign_sha, _scope, scope_sha, _grant, grant_sha, _acceptance, acceptance_sha = (
        authorities
    )
    shifted = json.loads(json.dumps(raw))
    shifted["measured_started_at"] = (
        datetime.fromisoformat(capture.started_at) - timedelta(seconds=1)
    ).isoformat()
    shifted["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(shifted),
        signing_key=tmp_path / "broker-key",
        namespace=SIGNATURE_NAMESPACE,
        label="shifted LPAC broker receipt",
    )
    shifted_path = tmp_path / "broker-shifted.json"
    shifted_path.write_text(json.dumps(shifted), encoding="utf-8")
    shifted_broker, shifted_sha = load_windows_lpac_broker_receipt(
        shifted_path, allowed_signers=policy
    )
    shifted_capture = replace(capture, lpac_broker_receipt_sha256=shifted_sha)
    with pytest.raises(ValueError, match="authority/capture-bound"):
        require_broker_receipt_binding(
            shifted_broker,
            receipt_sha256=shifted_sha,
            capture=shifted_capture,
            campaign=campaign,
            campaign_sha256=campaign_sha,
            scope_sha256=scope_sha,
            grant_sha256=grant_sha,
            acceptance_sha256=acceptance_sha,
        )

    stale = json.loads(json.dumps(raw))
    stale_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
    stale["measured_started_at"] = stale_time
    stale["measured_completed_at"] = stale_time
    stale["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(stale),
        signing_key=tmp_path / "broker-key",
        namespace=SIGNATURE_NAMESPACE,
        label="stale LPAC broker receipt",
    )
    broker_path.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(ValueError, match="outside the 24-hour evidence window"):
        load_windows_lpac_broker_receipt(broker_path, allowed_signers=policy)


def test_process_once_identity_survives_token_remeasurement_but_not_object_change(
    tmp_path: Path,
) -> None:
    (
        _authorities,
        _capture,
        _capture_path,
        original,
        _broker_path,
        original_raw,
        policy,
    ) = _v5_fixture(tmp_path)

    def load_resigned(name: str, changes: dict[str, object]):
        raw = json.loads(json.dumps(original_raw))
        raw.update(changes)
        raw["signature_ssh"] = sign_ssh_material(
            canonical_signed_material(raw),
            signing_key=tmp_path / "broker-key",
            namespace=SIGNATURE_NAMESPACE,
            label=f"re-measured LPAC broker receipt {name}",
        )
        path = tmp_path / f"broker-{name}.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        return load_windows_lpac_broker_receipt(path, allowed_signers=policy)[0]

    token_remeasurement = load_resigned(
        "token-remeasurement",
        {
            "start_token_id": "remeasured_start_token_aaaaaaaa",
            "finish_token_id": "remeasured_finish_token_bbbbbbb",
            "start_statistics_token_id": 0x2001,
            "finish_statistics_token_id": 0x2002,
            "start_modified_id": 0x3001,
            "finish_modified_id": 0x3002,
            "receipt_nonce": "broker_receipt_nonce_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "measurement_transcript_sha256": "e" * 64,
        },
    )
    original_ids = derive_burn_only_replay_identities(original)
    remeasured_ids = derive_burn_only_replay_identities(token_remeasurement)
    assert original_ids[0] != remeasured_ids[0]
    assert original_ids[1] == remeasured_ids[1]
    assert original_ids[2] != remeasured_ids[2]

    reissued_acceptance = load_resigned(
        "reissued-acceptance",
        {
            "worker_acceptance_sha256": "f" * 64,
            "receipt_nonce": "broker_receipt_nonce_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        },
    )
    assert derive_burn_only_replay_identities(reissued_acceptance)[1] == original_ids[1]

    creation_identity = derive_process_identity(
        worker_machine_id=original.worker_machine_id,
        measured_pid=original.measured_pid,
        measured_creation_filetime=original.measured_creation_filetime + 1,
        image_volume_serial_number=original.image_volume_serial_number,
        image_file_id=original.image_file_id,
        image_sha256=original.image_sha256,
        package_full_name=original.package_full_name,
        package_family_name=original.package_family_name,
        app_container_sid=original.app_container_sid,
    )
    changed_creation = load_resigned(
        "changed-creation",
        {
            "locator_creation_filetime": original.locator_creation_filetime + 1,
            "measured_creation_filetime": original.measured_creation_filetime + 1,
            "process_identity_sha256": creation_identity,
            "receipt_nonce": "broker_receipt_nonce_cccccccccccccccccccccccccccccccc",
        },
    )
    assert derive_burn_only_replay_identities(changed_creation)[1] != original_ids[1]

    changed_file_id = "fedcba9876543210fedcba9876543210"
    file_identity = derive_process_identity(
        worker_machine_id=original.worker_machine_id,
        measured_pid=original.measured_pid,
        measured_creation_filetime=original.measured_creation_filetime,
        image_volume_serial_number=original.image_volume_serial_number,
        image_file_id=changed_file_id,
        image_sha256=original.image_sha256,
        package_full_name=original.package_full_name,
        package_family_name=original.package_family_name,
        app_container_sid=original.app_container_sid,
    )
    changed_file = load_resigned(
        "changed-file",
        {
            "image_file_id": changed_file_id,
            "process_identity_sha256": file_identity,
            "receipt_nonce": "broker_receipt_nonce_dddddddddddddddddddddddddddddddd",
        },
    )
    assert derive_burn_only_replay_identities(changed_file)[1] != original_ids[1]

    changed_machine_id = "9" * 64
    machine_identity = derive_process_identity(
        worker_machine_id=changed_machine_id,
        measured_pid=original.measured_pid,
        measured_creation_filetime=original.measured_creation_filetime,
        image_volume_serial_number=original.image_volume_serial_number,
        image_file_id=original.image_file_id,
        image_sha256=original.image_sha256,
        package_full_name=original.package_full_name,
        package_family_name=original.package_family_name,
        app_container_sid=original.app_container_sid,
    )
    changed_machine = load_resigned(
        "changed-machine",
        {
            "worker_machine_id": changed_machine_id,
            "process_identity_sha256": machine_identity,
            "receipt_nonce": "broker_receipt_nonce_ffffffffffffffffffffffffffffffff",
        },
    )
    assert derive_burn_only_replay_identities(changed_machine)[1] != original_ids[1]

    rotated_key = tmp_path / "rotated-broker-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(rotated_key)],
        check=True,
    )
    rotated_policy = tmp_path / "rotated-broker.allowed-signers"
    rotated_policy.write_text(
        "rotated-broker@example.test "
        + rotated_key.with_suffix(".pub").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    rotated_raw = json.loads(json.dumps(original_raw))
    rotated_raw["signed_by"] = "rotated-broker@example.test"
    rotated_raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(rotated_raw),
        signing_key=rotated_key,
        namespace=SIGNATURE_NAMESPACE,
        label="rotated broker authority receipt",
    )
    rotated_path = tmp_path / "broker-rotated-authority.json"
    rotated_path.write_text(json.dumps(rotated_raw), encoding="utf-8")
    rotated = load_windows_lpac_broker_receipt(
        rotated_path, allowed_signers=rotated_policy
    )[0]
    assert derive_burn_only_replay_identities(rotated) == original_ids


@pytest.mark.parametrize(
    "changes",
    [
        {"token_id": "mutated_evidence_token_aaaa"},
        {"user_sid": "S-1-5-18"},
        {"integrity_rid": 0x3000},
        {"elevation_type": "full"},
        {"elevated": True},
        {"admin_group": "enabled"},
        {"app_container": False},
        {"app_container_sid": "S-1-15-2-9-3-4-5-6-7-8-9"},
        {"restricted_sid_count": 2},
        {"enabled_privileges": ["SeDebugPrivilege"]},
        {"token_source": "thread"},
        {"statistics_token_id_before": 0x2001, "statistics_token_id_after": 0x2001},
        {"modified_id_before": 0x3001, "modified_id_after": 0x3001},
        {"less_privileged_app_container": False},
        {"session_id": 7},
        {"authentication_id": "0000000000001003"},
    ],
)
def test_broker_profile_rejects_every_mutated_capture_security_fact(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    authorities, capture, _path, broker, _broker_path, _raw, _policy = _v5_fixture(
        tmp_path
    )
    campaign, campaign_sha, _scope, scope_sha, _grant, grant_sha, _acceptance, acceptance_sha = (
        authorities
    )
    for phase in ("start", "finish"):
        original = capture.start_token if phase == "start" else capture.finish_token
        mapping = original.to_dict()
        mapping.update(changes)
        mutated_snapshot = ProductionWindowsTokenSnapshot.from_mapping(
            mapping, f"mutated_{phase}", require_app_container_sid=True
        )
        mutated_capture = replace(capture, **{f"{phase}_token": mutated_snapshot})
        with pytest.raises(ValueError, match="authority/capture-bound"):
            require_broker_receipt_binding(
                broker,
                receipt_sha256=capture.lpac_broker_receipt_sha256,
                capture=mutated_capture,
                campaign=campaign,
                campaign_sha256=campaign_sha,
                scope_sha256=scope_sha,
                grant_sha256=grant_sha,
                acceptance_sha256=acceptance_sha,
            )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("observation_locus", "thread", "process-primary"),
        ("measured_pid", 4243, "locator"),
        ("less_privileged_app_container", False, "record LPAC"),
        ("image_file_id", "0" * 31, "file identity"),
        ("worker_machine_id", "NOT-A-SHA256", "must be a SHA-256"),
    ],
)
def test_receipt_rejects_untrusted_locator_and_incomplete_os_measurement(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    _authorities, _capture, _capture_path, _broker, broker_path, raw, policy = _v5_fixture(
        tmp_path
    )
    raw[field] = value
    broker_path.write_text(json.dumps(sign_document(raw, SIGNATURE_NAMESPACE)), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_windows_lpac_broker_receipt(broker_path, allowed_signers=policy)


def test_receipt_rejects_tamper_and_authority_swap(tmp_path: Path) -> None:
    authorities, capture, _capture_path, broker, broker_path, _raw, policy = _v5_fixture(
        tmp_path
    )
    tampered = json.loads(broker_path.read_text(encoding="utf-8"))
    tampered["measurement_transcript_sha256"] = "f" * 64
    broker_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="signature"):
        load_windows_lpac_broker_receipt(broker_path, allowed_signers=policy)

    campaign, campaign_sha, _scope, _scope_sha, _grant, grant_sha, _acceptance, acceptance_sha = (
        authorities
    )
    with pytest.raises(ValueError, match="authority/capture-bound"):
        require_broker_receipt_binding(
            broker,
            receipt_sha256=capture.lpac_broker_receipt_sha256,
            capture=capture,
            campaign=campaign,
            campaign_sha256=campaign_sha,
            scope_sha256="f" * 64,
            grant_sha256=grant_sha,
            acceptance_sha256=acceptance_sha,
        )


def test_pack_builder_loads_and_reverifies_receipt_before_aggregation_kill_switch(
    tmp_path: Path,
) -> None:
    (
        _authorities,
        _capture,
        capture_path,
        _broker,
        broker_path,
        _raw,
        broker_policy,
    ) = _v5_fixture(tmp_path)
    with pytest.raises(ValueError, match="complete target/control matrix"):
        build_windows_token_pack(
            tmp_path / "pack",
            campaign_path=tmp_path / "campaign.json",
            scope_manifest_path=tmp_path / "scope.json",
            execution_grant_path=tmp_path / "grant.json",
            worker_acceptance_path=tmp_path / "acceptance.json",
            aggregate_receipt_path=tmp_path / "campaign.json",
            capture_paths=[capture_path],
            scope_allowed_signers_path=authorization_policy(),
            execution_grant_allowed_signers_path=authorization_policy(),
            worker_acceptance_allowed_signers_path=authorization_policy(),
            capture_allowed_signers_path=authorization_policy(),
            aggregate_allowed_signers_path=authorization_policy(),
            broker_receipt_paths=[broker_path],
            broker_receipt_allowed_signers_path=broker_policy,
            run_id="windows-token-v5-test",
            job_nonce="job_nonce_00000000000000000000001",
            zeroverse_runtime_digest=f"sha256:{'1' * 64}",
            pack_signer_identity="operator@example.test",
            pack_signing_key=authorization_policy(),
        )

    original, _ = load_windows_lpac_broker_receipt(
        broker_path, allowed_signers=broker_policy
    )
    raw = json.loads(broker_path.read_text(encoding="utf-8"))
    raw["measurement_transcript_sha256"] = "e" * 64
    raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(raw),
        signing_key=tmp_path / "broker-key",
        namespace=SIGNATURE_NAMESPACE,
        label="re-signed LPAC broker receipt",
    )
    broker_path.write_text(json.dumps(raw), encoding="utf-8")
    resigned, _ = load_windows_lpac_broker_receipt(
        broker_path, allowed_signers=broker_policy
    )
    assert derive_burn_only_replay_identities(original)[0] == (
        derive_burn_only_replay_identities(resigned)[0]
    )
    assert derive_burn_only_replay_identities(original)[2] != (
        derive_burn_only_replay_identities(resigned)[2]
    )
    with pytest.raises(ValueError, match="authority/capture-bound"):
        build_windows_token_pack(
            tmp_path / "pack-resigned",
            campaign_path=tmp_path / "campaign.json",
            scope_manifest_path=tmp_path / "scope.json",
            execution_grant_path=tmp_path / "grant.json",
            worker_acceptance_path=tmp_path / "acceptance.json",
            aggregate_receipt_path=tmp_path / "campaign.json",
            capture_paths=[capture_path],
            scope_allowed_signers_path=authorization_policy(),
            execution_grant_allowed_signers_path=authorization_policy(),
            worker_acceptance_allowed_signers_path=authorization_policy(),
            capture_allowed_signers_path=authorization_policy(),
            aggregate_allowed_signers_path=authorization_policy(),
            broker_receipt_paths=[broker_path],
            broker_receipt_allowed_signers_path=broker_policy,
            run_id="windows-token-v5-resigned-test",
            job_nonce="job_nonce_00000000000000000000002",
            zeroverse_runtime_digest=f"sha256:{'1' * 64}",
            pack_signer_identity="operator@example.test",
            pack_signing_key=authorization_policy(),
        )
