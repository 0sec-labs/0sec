from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from authorization_helpers import authorization_policy, sign_document
from test_windows_lpac_broker_receipt import _v5_fixture
from test_windows_token_pack import (
    _canonical as _pack_canonical,
)
from test_windows_token_pack import _closure, _put, _ref, _verify

from zeroverse import windows_token_pack as token_pack_module
from zeroverse.ssh_authorization import canonical_signed_material, sign_ssh_material
from zeroverse.windows_lpac_broker_receipt import (
    SIGNATURE_NAMESPACE as BROKER_SIGNATURE_NAMESPACE,
)
from zeroverse.windows_lpac_broker_receipt import load_windows_lpac_broker_receipt
from zeroverse.windows_lpac_launch_receipt import (
    LAUNCH_METHOD,
    SCHEMA_VERSION,
    SIGNATURE_NAMESPACE,
    derive_burn_only_replay_identities,
    derive_process_instance_id,
    derive_process_locator_identity,
    load_windows_lpac_launch_receipt,
    require_launch_receipt_binding,
)
from zeroverse.windows_token_capture import (
    SIGNATURE_NAMESPACE as CAPTURE_SIGNATURE_NAMESPACE,
)
from zeroverse.windows_token_capture import load_windows_token_capture
from zeroverse.windows_token_pack import build_windows_token_pack


def _canonical_source(raw: dict[str, object]) -> bytes:
    return (
        json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    )


def _launch_fixture(tmp_path: Path):
    (
        authorities,
        _capture,
        capture_path,
        _broker,
        broker_path,
        broker_raw,
        broker_policy,
    ) = _v5_fixture(tmp_path)
    (
        campaign,
        campaign_sha,
        _scope,
        scope_sha,
        _grant,
        grant_sha,
        _acceptance,
        acceptance_sha,
    ) = authorities
    capture_raw = json.loads(capture_path.read_text(encoding="utf-8"))
    pid = int(broker_raw["measured_pid"])
    creation = int(broker_raw["measured_creation_filetime"])
    machine = str(broker_raw["worker_machine_id"])
    process_instance_id = derive_process_instance_id(
        worker_machine_id=machine,
        process_id=pid,
        process_creation_filetime=creation,
    )
    measured_started = datetime.fromisoformat(str(broker_raw["measured_started_at"]))
    authority_issued = max(
        datetime.fromisoformat(authorities[2].issued_at),
        datetime.fromisoformat(authorities[4].issued_at),
        datetime.fromisoformat(authorities[6].issued_at),
    )
    launch_completed = measured_started - timedelta(microseconds=1)
    launch_started = max(authority_issued, launch_completed - timedelta(milliseconds=1))
    launch_raw: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "launch_method": LAUNCH_METHOD,
        "launch_profile_id": "windows-defender-msengcp.control.v1",
        "launch_profile_sha256": hashlib.sha256(b"compile-time-launch-profile").hexdigest(),
        "eligible_sandbox": broker_raw["eligible_sandbox"],
        "launch_app_container_executable_sha256": (campaign.launch_app_container_executable_sha256),
        "sandbox_process_executable_sha256": broker_raw["image_sha256"],
        "package_full_name": broker_raw["package_full_name"],
        "package_family_name": broker_raw["package_family_name"],
        "app_container_sid": broker_raw["app_container_sid"],
        "less_privileged_app_container": True,
        "created_suspended": True,
        "process_id": pid,
        "thread_id": 4343,
        "process_creation_filetime": creation,
        "process_instance_id": process_instance_id,
        "process_locator_identity_sha256": derive_process_locator_identity(
            worker_machine_id=machine,
            process_id=pid,
            process_creation_filetime=creation,
        ),
        "launch_started_at": launch_started.isoformat(),
        "launch_completed_at": launch_completed.isoformat(),
        "process_alive_at_handoff": True,
        "process_handle_held": True,
        "thread_handle_held": True,
        "launch_transcript_sha256": hashlib.sha256(b"launch transcript a").hexdigest(),
        "receipt_nonce": "launch_receipt_nonce_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "fixed_adapter_operation_sha256": campaign.control_operation_sha256,
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "execution_grant_sha256": grant_sha,
        "worker_acceptance_sha256": acceptance_sha,
        "campaign_id": capture_raw["campaign_id"],
        "case": "control",
        "trial": 1,
        "run_nonce": capture_raw["run_nonce"],
        "worker": capture_raw["worker"],
        "worker_machine_id": machine,
        "build_lab_ex": capture_raw["build_lab_ex"],
        "signed_by": "launch@example.test",
        "signature_ssh": "",
    }
    launch_key = tmp_path / "launch-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(launch_key)],
        check=True,
    )
    launch_policy = tmp_path / "launch.allowed-signers"
    launch_policy.write_text(
        "launch@example.test " + launch_key.with_suffix(".pub").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    launch_raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(launch_raw),
        signing_key=launch_key,
        namespace=SIGNATURE_NAMESPACE,
        label="test LPAC launch receipt",
    )
    launch_path = tmp_path / "launch-control-1.json"
    launch_path.write_bytes(_canonical_source(launch_raw))
    launch, launch_sha = load_windows_lpac_launch_receipt(
        launch_path, allowed_signers=launch_policy
    )

    broker_raw["launch_receipt_sha256"] = launch_sha
    broker_raw["process_instance_id"] = process_instance_id
    broker_raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(broker_raw),
        signing_key=tmp_path / "broker-key",
        namespace=BROKER_SIGNATURE_NAMESPACE,
        label="launch-bound LPAC broker receipt",
    )
    broker_path.write_text(json.dumps(broker_raw), encoding="utf-8")
    broker, broker_sha = load_windows_lpac_broker_receipt(
        broker_path, allowed_signers=broker_policy
    )

    capture_raw["process_instance_id"] = process_instance_id
    capture_raw["lpac_launch_receipt_sha256"] = launch_sha
    capture_raw["lpac_broker_receipt_sha256"] = broker_sha
    capture_path.write_text(
        json.dumps(sign_document(capture_raw, CAPTURE_SIGNATURE_NAMESPACE)), encoding="utf-8"
    )
    capture, _ = load_windows_token_capture(
        capture_path, allowed_signers=authorization_policy(), require_verified=True
    )
    return (
        authorities,
        capture,
        capture_path,
        broker,
        broker_path,
        broker_policy,
        launch,
        launch_path,
        launch_raw,
        launch_policy,
    )


def _resign_bound_launch(
    tmp_path: Path,
    fixture: tuple[object, ...],
    changes: dict[str, object],
):
    (
        authorities,
        _capture,
        capture_path,
        _broker,
        broker_path,
        broker_policy,
        _launch,
        launch_path,
        launch_raw,
        launch_policy,
    ) = fixture
    assert isinstance(capture_path, Path)
    assert isinstance(broker_path, Path)
    assert isinstance(broker_policy, Path)
    assert isinstance(launch_path, Path)
    assert isinstance(launch_raw, dict)
    assert isinstance(launch_policy, Path)

    resigned_launch_raw = json.loads(json.dumps(launch_raw))
    resigned_launch_raw.update(changes)
    resigned_launch_raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(resigned_launch_raw),
        signing_key=tmp_path / "launch-key",
        namespace=SIGNATURE_NAMESPACE,
        label="re-signed LPAC launch receipt",
    )
    launch_path.write_bytes(_canonical_source(resigned_launch_raw))
    launch, launch_sha = load_windows_lpac_launch_receipt(
        launch_path, allowed_signers=launch_policy
    )

    broker_raw = json.loads(broker_path.read_text(encoding="utf-8"))
    broker_raw["launch_receipt_sha256"] = launch_sha
    broker_raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(broker_raw),
        signing_key=tmp_path / "broker-key",
        namespace=BROKER_SIGNATURE_NAMESPACE,
        label="re-signed launch-bound broker receipt",
    )
    broker_path.write_text(json.dumps(broker_raw), encoding="utf-8")
    broker, broker_sha = load_windows_lpac_broker_receipt(
        broker_path, allowed_signers=broker_policy
    )

    capture_raw = json.loads(capture_path.read_text(encoding="utf-8"))
    capture_raw["lpac_launch_receipt_sha256"] = launch_sha
    capture_raw["lpac_broker_receipt_sha256"] = broker_sha
    capture_path.write_text(
        json.dumps(sign_document(capture_raw, CAPTURE_SIGNATURE_NAMESPACE)), encoding="utf-8"
    )
    capture, _ = load_windows_token_capture(
        capture_path, allowed_signers=authorization_policy(), require_verified=True
    )
    return authorities, capture, broker, launch


def _require_fixture_binding(authorities, capture, broker, launch) -> None:
    campaign, campaign_sha, scope, scope_sha, grant, grant_sha, acceptance, acceptance_sha = (
        authorities
    )
    require_launch_receipt_binding(
        launch,
        receipt_sha256=capture.lpac_launch_receipt_sha256,
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


def test_launch_receipt_cross_binds_exact_process_authority_and_run(tmp_path: Path) -> None:
    (
        authorities,
        capture,
        _capture_path,
        broker,
        _broker_path,
        _broker_policy,
        launch,
        _launch_path,
        _raw,
        _launch_policy,
    ) = _launch_fixture(tmp_path)
    _require_fixture_binding(authorities, capture, broker, launch)
    identities = derive_burn_only_replay_identities(launch)
    assert len(identities) == len(set(identities)) == 3


@pytest.mark.parametrize(
    "changes",
    [
        {"worker": "different-worker"},
        {"campaign_id": "different-campaign"},
        {"fixed_adapter_operation_sha256": "f" * 64},
        {"package_full_name": "Different.Package_1.0.0.0_x64__publisher"},
    ],
)
def test_resigned_launch_cross_binding_mutations_fail(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    fixture = _launch_fixture(tmp_path)
    authorities, capture, broker, launch = _resign_bound_launch(tmp_path, fixture, changes)
    with pytest.raises(ValueError, match="authority/capture/broker-bound"):
        _require_fixture_binding(authorities, capture, broker, launch)


def test_launch_profile_requires_exact_trusted_policy_selection(tmp_path: Path) -> None:
    (*_rest, launch, _launch_path, _raw, _policy) = _launch_fixture(tmp_path)
    token_pack_module._require_lpac_launch_profiles_selected(
        [launch], {"allowedLpacLaunchProfileSha256": [launch.launch_profile_sha256]}
    )
    with pytest.raises(ValueError, match="not selected by the trusted acceptance policy"):
        token_pack_module._require_lpac_launch_profiles_selected(
            [launch], {"allowedLpacLaunchProfileSha256": ["f" * 64]}
        )


def test_resigned_launch_cannot_predate_current_authority(tmp_path: Path) -> None:
    fixture = _launch_fixture(tmp_path)
    authorities = fixture[0]
    assert isinstance(authorities, tuple)
    scope, grant, acceptance = authorities[2], authorities[4], authorities[6]
    issued = max(
        datetime.fromisoformat(scope.issued_at),
        datetime.fromisoformat(grant.issued_at),
        datetime.fromisoformat(acceptance.issued_at),
    )
    replaced = _resign_bound_launch(
        tmp_path,
        fixture,
        {
            "launch_started_at": (issued - timedelta(seconds=2)).isoformat(),
            "launch_completed_at": (issued - timedelta(seconds=1)).isoformat(),
        },
    )
    with pytest.raises(ValueError, match="authority/capture/broker-bound"):
        _require_fixture_binding(*replaced)


def test_resigned_launch_handoff_is_bounded_to_five_minutes(tmp_path: Path) -> None:
    fixture = _launch_fixture(tmp_path)
    broker = fixture[3]
    measured = datetime.fromisoformat(broker.measured_started_at)
    replaced = _resign_bound_launch(
        tmp_path,
        fixture,
        {
            "launch_started_at": (measured - timedelta(minutes=6, seconds=1)).isoformat(),
            "launch_completed_at": (measured - timedelta(minutes=6)).isoformat(),
        },
    )
    with pytest.raises(ValueError, match="authority/capture/broker-bound"):
        _require_fixture_binding(*replaced)


def test_launch_must_complete_before_current_authority_expiry(tmp_path: Path) -> None:
    authorities, capture, _capture_path, broker, *_middle, launch, _path, _raw, _policy = (
        _launch_fixture(tmp_path)
    )
    campaign, campaign_sha, scope, scope_sha, grant, grant_sha, acceptance, acceptance_sha = (
        authorities
    )
    expired_acceptance = replace(acceptance, expires_at=launch.launch_completed_at)
    with pytest.raises(ValueError, match="authority/capture/broker-bound"):
        require_launch_receipt_binding(
            launch,
            receipt_sha256=capture.lpac_launch_receipt_sha256,
            capture=capture,
            broker=broker,
            campaign=campaign,
            scope=scope,
            grant=grant,
            acceptance=expired_acceptance,
            campaign_sha256=campaign_sha,
            scope_sha256=scope_sha,
            grant_sha256=grant_sha,
            acceptance_sha256=acceptance_sha,
        )


def test_launch_receipt_requires_exact_canonical_final_lf_and_nofollow(tmp_path: Path) -> None:
    (*_rest, launch_path, raw, policy) = _launch_fixture(tmp_path)
    canonical = launch_path.read_bytes()
    launch_path.write_bytes(canonical.rstrip(b"\n"))
    with pytest.raises(ValueError, match="not canonical"):
        load_windows_lpac_launch_receipt(launch_path, allowed_signers=policy)
    launch_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not canonical"):
        load_windows_lpac_launch_receipt(launch_path, allowed_signers=policy)
    launch_path.write_bytes(canonical + b"\n")
    with pytest.raises(ValueError, match="not canonical"):
        load_windows_lpac_launch_receipt(launch_path, allowed_signers=policy)
    launch_path.write_bytes(canonical)
    link = tmp_path / "launch-link.json"
    link.symlink_to(launch_path)
    with pytest.raises(ValueError, match="symlink"):
        load_windows_lpac_launch_receipt(link, allowed_signers=policy)


def test_launch_replay_process_identity_survives_signer_rotation(tmp_path: Path) -> None:
    (*_rest, launch, launch_path, raw, _policy) = _launch_fixture(tmp_path)
    rotated_key = tmp_path / "rotated-launch-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(rotated_key)],
        check=True,
    )
    rotated_policy = tmp_path / "rotated-launch.allowed-signers"
    rotated_policy.write_text(
        "rotated-launch@example.test "
        + rotated_key.with_suffix(".pub").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    raw["signed_by"] = "rotated-launch@example.test"
    raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(raw),
        signing_key=rotated_key,
        namespace=SIGNATURE_NAMESPACE,
        label="rotated LPAC launch receipt",
    )
    launch_path.write_bytes(_canonical_source(raw))
    rotated, _ = load_windows_lpac_launch_receipt(launch_path, allowed_signers=rotated_policy)
    assert derive_burn_only_replay_identities(rotated) == derive_burn_only_replay_identities(launch)


def test_pack_builder_reverifies_launch_before_aggregation_kill_switch(tmp_path: Path) -> None:
    (
        _authorities,
        _capture,
        capture_path,
        _broker,
        broker_path,
        broker_policy,
        _launch,
        launch_path,
        _raw,
        launch_policy,
    ) = _launch_fixture(tmp_path)
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
            launch_receipt_paths=[launch_path],
            launch_receipt_allowed_signers_path=launch_policy,
            run_id="windows-token-v5-launch-test",
            job_nonce="job_nonce_00000000000000000000001",
            zeroverse_runtime_digest=f"sha256:{'1' * 64}",
            pack_signer_identity="operator@example.test",
            pack_signing_key=authorization_policy(),
        )

    tampered = bytearray(launch_path.read_bytes())
    tampered[-2] ^= 1
    launch_path.write_bytes(tampered)
    with pytest.raises((ValueError, json.JSONDecodeError)):
        load_windows_lpac_launch_receipt(launch_path, allowed_signers=launch_policy)


def test_pack_v3_manifest_and_policy_are_strict_additive_schemas(tmp_path: Path) -> None:
    bundle = _closure(tmp_path)
    blobs = bundle["blobs"]
    envelope = bundle["envelope_raw"]
    assert isinstance(blobs, Path) and isinstance(envelope, dict)
    manifest_ref = envelope["manifest"]
    assert isinstance(manifest_ref, dict)
    manifest = json.loads((blobs / str(manifest_ref["sha256"])).read_text())
    broker_rows = []
    launch_rows = []
    for index, capture_row in enumerate(manifest["matrix"]["captures"]):
        broker_rows.append(
            {
                "case": capture_row["case"],
                "trial": capture_row["trial"],
                "artifact": _put(blobs, json.dumps({"broker": index}).encode()),
            }
        )
        launch_rows.append(
            {
                "case": capture_row["case"],
                "trial": capture_row["trial"],
                "artifact": _put(blobs, json.dumps({"launch": index}).encode()),
            }
        )
    broker_policy = b"broker@example.test ssh-ed25519 AAAABROKER broker\n"
    launch_policy = b"launch@example.test ssh-ed25519 AAAALAUNCH launch\n"
    broker_policy_ref = _ref(broker_policy, "text/plain")
    launch_policy_ref = _ref(launch_policy, "text/plain")
    (blobs / str(broker_policy_ref["sha256"])).write_bytes(broker_policy)
    (blobs / str(launch_policy_ref["sha256"])).write_bytes(launch_policy)
    manifest["schemaVersion"] = token_pack_module.LPAC_LAUNCH_PACK_SCHEMA_VERSION
    manifest["brokerReceipts"] = broker_rows
    manifest["launchReceipts"] = launch_rows
    manifest["signerPolicies"]["lpacBrokerReceipt"] = broker_policy_ref
    manifest["signerPolicies"]["lpacLaunchReceipt"] = launch_policy_ref
    parsed = token_pack_module._parse_manifest(_pack_canonical(manifest))
    assert parsed["schemaVersion"] == "0sec.windows-token-evidence-pack/v3"

    missing_launch = json.loads(json.dumps(manifest))
    missing_launch.pop("launchReceipts")
    with pytest.raises(ValueError, match="schema is unsupported"):
        token_pack_module._parse_manifest(_pack_canonical(missing_launch))

    policy = json.loads(Path(bundle["policy"]).read_text())
    policy["schemaVersion"] = token_pack_module.LPAC_LAUNCH_POLICY_SCHEMA_VERSION
    policy["allowedLpacBrokerReceiptSignerPolicySha256"] = [str(broker_policy_ref["sha256"])]
    policy["allowedLpacLaunchReceiptSignerPolicySha256"] = [str(launch_policy_ref["sha256"])]
    policy["allowedLpacLaunchProfileSha256"] = ["a" * 64]
    parsed_policy = token_pack_module._parse_policy(policy)
    assert parsed_policy["schemaVersion"] == "0sec.windows-token-evidence-acceptance-policy/v3"
    policy.pop("allowedLpacLaunchReceiptSignerPolicySha256")
    policy.pop("allowedLpacLaunchProfileSha256")
    with pytest.raises(ValueError, match="schema is unsupported"):
        token_pack_module._parse_policy(policy)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ordered_launch_receipt_replay_identity_sha256", ("a" * 64,)),
        ("ordered_launch_process_replay_identity_sha256", ("b" * 64,)),
        ("ordered_launch_transcript_replay_identity_sha256", ("c" * 64,)),
        ("launch_receipt_authority_key_commitment_sha256", "d" * 64),
        ("launch_receipt_signer_identity", "launch@example.test"),
    ],
)
def test_partial_launch_verification_model_is_incoherent(
    tmp_path: Path, field: str, value: object
) -> None:
    verification = _verify(_closure(tmp_path))
    with pytest.raises(ValueError, match="launch-bearing pack verification fields are incoherent"):
        replace(verification, **{field: value}).to_dict()


def test_complete_launch_verification_model_requires_broker_identity_schema(
    tmp_path: Path,
) -> None:
    verification = _verify(_closure(tmp_path))
    launch_model = replace(
        verification,
        ordered_launch_receipt_replay_identity_sha256=("a" * 64,),
        ordered_launch_process_replay_identity_sha256=("b" * 64,),
        ordered_launch_transcript_replay_identity_sha256=("c" * 64,),
        launch_receipt_authority_key_commitment_sha256="d" * 64,
        launch_receipt_signer_identity="launch@example.test",
    )
    with pytest.raises(ValueError, match="requires broker identities"):
        launch_model.to_dict()
