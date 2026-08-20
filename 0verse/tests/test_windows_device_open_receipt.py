from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zeroverse.cli import main
from zeroverse.ssh_authorization import canonical_signed_material, sign_ssh_material
from zeroverse.windows_device_open_receipt import (
    CREATE_FILE_API,
    ENUMERATION_API,
    EVIDENCE_CLASS,
    OBSERVATION_KIND,
    PRODUCER_AUTHORITY,
    SCHEMA_VERSION,
    SIGNATURE_NAMESPACE,
    derive_burn_only_replay_identities,
    load_windows_device_open_receipt,
    require_device_open_receipt_binding,
)


def _canonical(raw: dict[str, object]) -> bytes:
    return (
        json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        + b"\n"
    )


def _fixture(tmp_path: Path) -> tuple[dict[str, object], Path, Path, Path]:
    key = tmp_path / "device-open-authority-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    policy = tmp_path / "device-open-authority.allowed-signers"
    policy.write_text(
        "device-open-authority@example.test "
        + key.with_suffix(".pub").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    completed = datetime.now(UTC) - timedelta(seconds=1)
    raw: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "observation_kind": OBSERVATION_KIND,
        "evidence_class": EVIDENCE_CLASS,
        "producer_authority": PRODUCER_AUTHORITY,
        "broker_duplicate_handle_held_during_signing": True,
        "broker_revalidated_primary_token": True,
        "broker_reenumerated_interface": True,
        "worker": "worker-01.example.test",
        "worker_machine_id": hashlib.sha256(b"fixture-machine").hexdigest(),
        "worker_acceptance_sha256": hashlib.sha256(b"worker acceptance").hexdigest(),
        "windows_build_lab_ex": "26100.1.amd64fre.ge_release.240331-1435",
        "windows_ubr": 4652,
        "boot_id": "d86b4d2e-75f1-44d4-aa53-0ea81f034876",
        "boundary_manifest_sha256": hashlib.sha256(b"boundary manifest").hexdigest(),
        "collector_id": "0verse.device-open.fixture.v1",
        "collector_sha256": hashlib.sha256(b"collector exe").hexdigest(),
        "collector_registry_sha256": hashlib.sha256(b"compile-time registry").hexdigest(),
        "driver_id": "0verse-fixture-buffered",
        "driver_service_name": "ZeroverseFixtureBuffered",
        "driver_image_sha256": hashlib.sha256(b"fixture driver sys").hexdigest(),
        "interface_class_guid": "{4d36e97d-e325-11ce-bfc1-08002be10318}",
        "interface_instance_id": "ROOT\\ZEROVERSEFIXTURE\\0000",
        "interface_path_sha256": hashlib.sha256(b"opaque device path").hexdigest(),
        "enumeration_api": ENUMERATION_API,
        "enumeration_flags": 0x12,
        "interface_count": 1,
        "selected_interface_index": 0,
        "create_file_api": CREATE_FILE_API,
        "desired_access": 0,
        "share_mode": 3,
        "security_attributes_null": True,
        "creation_disposition": 3,
        "flags_and_attributes": 0x80,
        "template_file_null": True,
        "process_id": 4242,
        "process_creation_filetime": 133700000000000000,
        "primary_token_id": 65536,
        "primary_token_modified_id": 131072,
        "token_type": "TokenPrimary",
        "thread_token_present": False,
        "impersonation_active": False,
        "elevation_type": "TokenElevationTypeDefault",
        "elevated": False,
        "integrity_rid": 8192,
        "admin_group_present": False,
        "linked_token_present": False,
        "token_restricted": False,
        "restricted_sid_count": 0,
        "enabled_privileges": ["SeChangeNotifyPrivilege"],
        "app_container": False,
        "debug_privilege_present": False,
        "user_sid": "S-1-5-21-111111111-222222222-333333333-1001",
        "authentication_id": "00000000000abcde",
        "session_id": 1,
        "observation_started_at": (completed - timedelta(milliseconds=25)).isoformat(),
        "observation_completed_at": completed.isoformat(),
        "create_file_succeeded": True,
        "handle_held_during_observation": True,
        "handle_closed_cleanly": True,
        "device_io_control_call_count": 0,
        "driver_load_call_count": 0,
        "device_handle_read_call_count": 0,
        "device_handle_write_call_count": 0,
        "observation_transcript_sha256": hashlib.sha256(b"observation transcript").hexdigest(),
        "receipt_nonce": "device_open_receipt_nonce_aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "signed_by": "device-open-authority@example.test",
        "signature_ssh": "",
    }
    _sign(raw, key)
    path = tmp_path / "device-open-receipt.json"
    path.write_bytes(_canonical(raw))
    return raw, path, policy, key


def _sign(raw: dict[str, object], key: Path) -> None:
    raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(raw),
        signing_key=key,
        namespace=SIGNATURE_NAMESPACE,
        label="test Windows device-open boundary receipt",
    )


def test_signed_device_open_receipt_is_capability_only_and_source_bound(
    tmp_path: Path,
) -> None:
    raw, path, policy, _key = _fixture(tmp_path)
    receipt, digest = load_windows_device_open_receipt(path, allowed_signers=policy)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert receipt.source_sha256 == digest
    assert receipt.evidence_class == "candidate-capability-only"
    assert receipt.desired_access == 0
    assert receipt.device_io_control_call_count == 0
    assert receipt.device_handle_read_call_count == 0
    assert receipt.device_handle_write_call_count == 0
    identities = require_device_open_receipt_binding(
        receipt,
        receipt_sha256=digest,
        boundary_manifest_sha256=str(raw["boundary_manifest_sha256"]),
        worker_acceptance_sha256=str(raw["worker_acceptance_sha256"]),
        worker=str(raw["worker"]),
        worker_machine_id=str(raw["worker_machine_id"]),
        windows_build_lab_ex=str(raw["windows_build_lab_ex"]),
        windows_ubr=int(raw["windows_ubr"]),
        boot_id=str(raw["boot_id"]),
        collector_id=str(raw["collector_id"]),
        collector_sha256=str(raw["collector_sha256"]),
        collector_registry_sha256=str(raw["collector_registry_sha256"]),
        driver_id=str(raw["driver_id"]),
        driver_service_name=str(raw["driver_service_name"]),
        driver_image_sha256=str(raw["driver_image_sha256"]),
        interface_class_guid=str(raw["interface_class_guid"]),
        interface_instance_id=str(raw["interface_instance_id"]),
        observation_transcript=b"observation transcript",
    )
    assert identities == derive_burn_only_replay_identities(receipt)
    with pytest.raises(ValueError, match="already burned"):
        require_device_open_receipt_binding(
            receipt,
            receipt_sha256=digest,
            boundary_manifest_sha256=str(raw["boundary_manifest_sha256"]),
            worker_acceptance_sha256=str(raw["worker_acceptance_sha256"]),
            worker=str(raw["worker"]),
            worker_machine_id=str(raw["worker_machine_id"]),
            windows_build_lab_ex=str(raw["windows_build_lab_ex"]),
            windows_ubr=int(raw["windows_ubr"]),
            boot_id=str(raw["boot_id"]),
            collector_id=str(raw["collector_id"]),
            collector_sha256=str(raw["collector_sha256"]),
            collector_registry_sha256=str(raw["collector_registry_sha256"]),
            driver_id=str(raw["driver_id"]),
            driver_service_name=str(raw["driver_service_name"]),
            driver_image_sha256=str(raw["driver_image_sha256"]),
            interface_class_guid=str(raw["interface_class_guid"]),
            interface_instance_id=str(raw["interface_instance_id"]),
            observation_transcript=b"observation transcript",
            burned_replay_identities=frozenset({identities[1]}),
        )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("desired_access", 0x80000000, "query-only"),
        ("broker_duplicate_handle_held_during_signing", False, "broker-held authority"),
        ("broker_revalidated_primary_token", False, "broker-held authority"),
        ("broker_reenumerated_interface", False, "broker-held authority"),
        ("share_mode", 1, "query-only"),
        ("primary_token_id", 0, "process identity"),
        ("primary_token_modified_id", 0, "process identity"),
        ("thread_token_present", True, "natural standard-user"),
        ("impersonation_active", True, "natural standard-user"),
        ("elevation_type", "TokenElevationTypeLimited", "natural standard-user"),
        ("elevated", True, "natural standard-user"),
        ("integrity_rid", 12288, "natural standard-user"),
        ("admin_group_present", True, "natural standard-user"),
        ("linked_token_present", True, "natural standard-user"),
        ("token_restricted", True, "natural standard-user"),
        ("restricted_sid_count", 1, "natural standard-user"),
        ("user_sid", "S-1-5-18", "canonical account SID"),
        ("user_sid", "S-1-5-21-1-2-3-500", "canonical account SID"),
        ("authentication_id", "00000000000003e7", "token identity"),
        ("enabled_privileges", ["SeImpersonatePrivilege"], "incomplete or unsafe"),
        (
            "enabled_privileges",
            ["SeChangeNotifyPrivilege", "SeChangeNotifyPrivilege"],
            "incomplete or unsafe",
        ),
        (
            "enabled_privileges",
            ["SeUndockPrivilege", "SeChangeNotifyPrivilege"],
            "incomplete or unsafe",
        ),
        ("app_container", True, "natural standard-user"),
        ("debug_privilege_present", True, "natural standard-user"),
        ("create_file_succeeded", False, "held-handle"),
        ("handle_held_during_observation", False, "held-handle"),
        ("device_io_control_call_count", 1, "capability-only"),
        ("driver_load_call_count", 1, "capability-only"),
        ("device_handle_read_call_count", 1, "capability-only"),
        ("device_handle_write_call_count", 1, "capability-only"),
    ],
)
def test_resigned_unsafe_or_non_natural_observations_fail_closed(
    tmp_path: Path, field: str, value: object, error: str
) -> None:
    raw, path, policy, key = _fixture(tmp_path)
    raw[field] = value
    _sign(raw, key)
    path.write_bytes(_canonical(raw))
    with pytest.raises(ValueError, match=error):
        load_windows_device_open_receipt(path, allowed_signers=policy)


def test_unknown_duplicate_tampered_noncanonical_and_symlink_sources_fail(
    tmp_path: Path,
) -> None:
    raw, path, policy, _key = _fixture(tmp_path)
    raw["unknown"] = "rejected"
    path.write_bytes(_canonical(raw))
    with pytest.raises(ValueError, match="exact fields"):
        load_windows_device_open_receipt(path, allowed_signers=policy)

    raw.pop("unknown")
    canonical = _canonical(raw)
    path.write_bytes(canonical.replace(b'"windows_ubr":4652', b'"windows_ubr":4653'))
    with pytest.raises(ValueError, match="SSH signature is invalid"):
        load_windows_device_open_receipt(path, allowed_signers=policy)

    path.write_bytes(canonical[:-1])
    with pytest.raises(ValueError, match="not canonical"):
        load_windows_device_open_receipt(path, allowed_signers=policy)

    duplicate = canonical.replace(
        b'{"admin_group_present":false,',
        b'{"admin_group_present":false,"admin_group_present":false,',
    )
    path.write_bytes(duplicate)
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_windows_device_open_receipt(path, allowed_signers=policy)

    path.write_bytes(canonical)
    link = tmp_path / "device-open-link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="symlink"):
        load_windows_device_open_receipt(link, allowed_signers=policy)


def test_wrong_role_policy_and_external_binding_fail_closed(tmp_path: Path) -> None:
    raw, path, policy, _key = _fixture(tmp_path)
    wrong_key = tmp_path / "wrong-role-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(wrong_key)],
        check=True,
    )
    wrong_policy = tmp_path / "wrong-role.allowed-signers"
    wrong_policy.write_text(
        "other-role@example.test "
        + wrong_key.with_suffix(".pub").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="SSH signature is invalid"):
        load_windows_device_open_receipt(path, allowed_signers=wrong_policy)

    receipt, digest = load_windows_device_open_receipt(path, allowed_signers=policy)
    with pytest.raises(ValueError, match="driver_image_sha256 binding does not match"):
        require_device_open_receipt_binding(
            receipt,
            receipt_sha256=digest,
            boundary_manifest_sha256=str(raw["boundary_manifest_sha256"]),
            worker_acceptance_sha256=str(raw["worker_acceptance_sha256"]),
            worker=str(raw["worker"]),
            worker_machine_id=str(raw["worker_machine_id"]),
            windows_build_lab_ex=str(raw["windows_build_lab_ex"]),
            windows_ubr=int(raw["windows_ubr"]),
            boot_id=str(raw["boot_id"]),
            collector_id=str(raw["collector_id"]),
            collector_sha256=str(raw["collector_sha256"]),
            collector_registry_sha256=str(raw["collector_registry_sha256"]),
            driver_id=str(raw["driver_id"]),
            driver_service_name=str(raw["driver_service_name"]),
            driver_image_sha256="f" * 64,
            interface_class_guid=str(raw["interface_class_guid"]),
            interface_instance_id=str(raw["interface_instance_id"]),
            observation_transcript=b"observation transcript",
        )

    with pytest.raises(ValueError, match="retained transcript hash does not match"):
        require_device_open_receipt_binding(
            receipt,
            receipt_sha256=digest,
            boundary_manifest_sha256=str(raw["boundary_manifest_sha256"]),
            worker_acceptance_sha256=str(raw["worker_acceptance_sha256"]),
            worker=str(raw["worker"]),
            worker_machine_id=str(raw["worker_machine_id"]),
            windows_build_lab_ex=str(raw["windows_build_lab_ex"]),
            windows_ubr=int(raw["windows_ubr"]),
            boot_id=str(raw["boot_id"]),
            collector_id=str(raw["collector_id"]),
            collector_sha256=str(raw["collector_sha256"]),
            collector_registry_sha256=str(raw["collector_registry_sha256"]),
            driver_id=str(raw["driver_id"]),
            driver_service_name=str(raw["driver_service_name"]),
            driver_image_sha256=str(raw["driver_image_sha256"]),
            interface_class_guid=str(raw["interface_class_guid"]),
            interface_instance_id=str(raw["interface_instance_id"]),
            observation_transcript=b"wrong retained transcript",
        )


def test_cli_reports_signature_only_not_producer_authority(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _raw, path, policy, _key = _fixture(tmp_path)
    assert main(
        ["windows-device-open-verify", str(path), "--allowed-signers", str(policy)]
    ) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "SIGNATURE_VERIFIED"
    assert output["producer_authority"] == "system-held-device-open-broker"
    assert output["producer_authority_assertion_signed"] is True
    assert output["producer_authority_verified"] is False
    assert output["system_key_custody_verified"] is False
    assert output["external_binding_verified"] is False
    assert output["device_io_control_call_count"] == 0
    assert output["device_handle_read_call_count"] == 0
    assert output["device_handle_write_call_count"] == 0
