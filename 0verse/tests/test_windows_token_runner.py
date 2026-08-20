from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from authorization_helpers import authorization_policy, sign_document

from zeroverse.windows_scope import AUTHORIZATION_NAMESPACE, load_scope
from zeroverse.windows_token_runner import (
    ACCEPTANCE_SIGNATURE_NAMESPACE,
    GRANT_SIGNATURE_NAMESPACE,
    WindowsTokenCampaign,
    WindowsTokenWorkerAcceptance,
    derive_windows_worker_machine_id,
    load_windows_token_campaign,
    load_windows_token_execution_grant,
    load_windows_token_worker_acceptance,
    validate_windows_witness_user_sid,
)


def test_worker_machine_id_derivation_is_canonical_and_domain_separated() -> None:
    expected = "7605d7cee78c7386fdb6eb5cf8a57d4af9ffd699cb1fc45ef80d131b5a6d3af8"
    assert (
        derive_windows_worker_machine_id("00112233-4455-6677-8899-AABBCCDDEEFF")
        == expected
    )
    assert (
        derive_windows_worker_machine_id("00112233-4455-6677-8899-aabbccddeeff")
        == expected
    )
    for invalid in (
        "{00112233-4455-6677-8899-aabbccddeeff}",
        "00112233445566778899aabbccddeeff",
        "not-a-guid",
    ):
        with pytest.raises(ValueError, match="canonical UUID"):
            derive_windows_worker_machine_id(invalid)


def test_witness_provenance_is_exact_and_rejects_builtin_accounts() -> None:
    validate_windows_witness_user_sid("S-1-5-21-1-2-3-1001")
    for invalid in (
        "S-1-5-18",
        "S-1-5-32-545",
        "S-1-5-21-1-2-3-500",
        "S-1-5-21-01-2-3-1001",
    ):
        with pytest.raises(ValueError, match="witness user SID"):
            validate_windows_witness_user_sid(invalid)


def campaign() -> dict[str, object]:
    return {
        "schema_version": "0verse.windows-token-campaign/v1",
        "campaign_id": "canary-lpe-001",
        "worker": "canary-worker-1",
        "starting_context": "standard-user",
        "finishing_principal": "local-system",
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "trials": 2,
        "minimum_confirmations": 2,
    }


def scope() -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "schema_version": "0verse.windows-scope/v2",
        "campaign_id": "canary-lpe-001",
        "program": "windows-canary",
        "scope_url": "https://www.microsoft.com/en-us/msrc/bounty-windows-insider-preview",
        "target_feature": "Windows local privilege boundary",
        "reachability": "owned Canary VM",
        "authorization": "published scope; owned worker",
        "worker": "canary-worker-1",
        "latest_build_verified_at": now.isoformat(),
        "latest_build_number": "29000.1",
        "latest_build_source_url": "https://learn.microsoft.com/en-us/windows-insider/flight-hub/",
        "preflight": {
            "ok": True,
            "program": "windows-canary",
            "checked_at": now.isoformat(),
            "build_lab_ex": "29000.1.amd64fre.rs_prerelease",
            "product_name": "Windows 11 Pro",
            "hyperv_available": False,
            "insider": {
                "ring": "Experimental Future Platforms",
                "content_type": "Mainline",
                "branch_name": "rs_prerelease",
                "channel_family": "experimental-future-platforms",
            },
        },
        "authorized_by": "operator@example.test",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "scope_authorization_nonce_000000001",
        "signature_ssh": "",
    }


def grant(campaign_sha: str, scope_sha: str) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "schema_version": "0verse.windows-token-execution-grant/v1",
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "campaign_id": "canary-lpe-001",
        "worker": "canary-worker-1",
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "execution_grant_nonce_0000000001",
        "authorized_by": "operator@example.test",
        "signature_ssh": "",
    }


def acceptance(
    campaign_sha: str, scope_sha: str, grant_sha: str
) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "schema_version": "0verse.windows-token-worker-acceptance/v2",
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "execution_grant_sha256": grant_sha,
        "execution_grant_nonce": "execution_grant_nonce_0000000001",
        "campaign_id": "canary-lpe-001",
        "worker": "canary-worker-1",
        "build_lab_ex": "29000.1.amd64fre.rs_prerelease",
        "worker_machine_id": "owned-canary-machine-001",
        "runner_executable_sha256": "c" * 64,
        "witness_user_sid": "S-1-5-21-1-2-3-1001",
        "witness_session_id": 1,
        "witness_authentication_id": "0000000000001001",
        "witness_executable_sha256": "d" * 64,
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "worker_acceptance_nonce_00000001",
        "accepted_by": "operator@example.test",
        "capture_signer": "canary-worker@example.test",
        "signature_ssh": "",
    }


def write_json(path: Path, raw: dict[str, object]) -> str:
    path.write_text(json.dumps(raw), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def authority_bundle(tmp_path: Path):
    campaign_path = tmp_path / "campaign.json"
    campaign_sha = write_json(campaign_path, campaign())
    loaded_campaign, _ = load_windows_token_campaign(campaign_path)

    scope_path = tmp_path / "scope.json"
    scope_sha = write_json(scope_path, sign_document(scope(), AUTHORIZATION_NAMESPACE))
    loaded_scope, _ = load_scope(
        scope_path,
        allowed_signers=authorization_policy(),
        require_authorized=True,
    )

    grant_path = tmp_path / "grant.json"
    grant_sha = write_json(
        grant_path,
        sign_document(grant(campaign_sha, scope_sha), GRANT_SIGNATURE_NAMESPACE),
    )
    loaded_grant, _ = load_windows_token_execution_grant(
        grant_path,
        allowed_signers=authorization_policy(),
        require_authorized=True,
    )

    acceptance_path = tmp_path / "acceptance.json"
    acceptance_sha = write_json(
        acceptance_path,
        sign_document(
            acceptance(campaign_sha, scope_sha, grant_sha),
            ACCEPTANCE_SIGNATURE_NAMESPACE,
        ),
    )
    loaded_acceptance, _ = load_windows_token_worker_acceptance(
        acceptance_path,
        allowed_signers=authorization_policy(),
        require_authorized=True,
    )
    return (
        loaded_campaign,
        campaign_sha,
        loaded_scope,
        scope_sha,
        loaded_grant,
        grant_sha,
        loaded_acceptance,
        acceptance_sha,
    )


def test_signed_campaign_grant_and_acceptance_bind_exact_authority(tmp_path: Path) -> None:
    (
        loaded_campaign,
        campaign_sha,
        loaded_scope,
        scope_sha,
        loaded_grant,
        grant_sha,
        loaded_acceptance,
        acceptance_sha,
    ) = authority_bundle(tmp_path)
    loaded_grant.require_binding(
        loaded_campaign, campaign_sha, loaded_scope, scope_sha, grant_sha
    )
    loaded_acceptance.require_binding(
        loaded_campaign,
        campaign_sha,
        loaded_scope,
        scope_sha,
        loaded_grant,
        grant_sha,
        acceptance_sha,
    )
    assert len(acceptance_sha) == 64


def test_campaign_has_no_argv_path_or_payload_surface(tmp_path: Path) -> None:
    raw = campaign()
    raw["argv"] = ["cmd.exe"]
    path = tmp_path / "campaign.json"
    write_json(path, raw)
    with pytest.raises(ValueError, match="unknown argv"):
        load_windows_token_campaign(path)

    raw = campaign()
    raw["target_operation_sha256"] = raw["control_operation_sha256"]
    with pytest.raises(ValueError, match="must differ"):
        WindowsTokenCampaign.from_mapping(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("witness_user_sid", "S-1-5-18"),
        ("witness_session_id", -1),
        ("witness_session_id", True),
        ("witness_session_id", 2**32),
        ("witness_authentication_id", "00000000000003e7"),
        ("witness_executable_sha256", "A" * 64),
    ],
)
def test_worker_acceptance_rejects_unbound_witness_identity(
    field: str, value: object
) -> None:
    raw = acceptance("a" * 64, "b" * 64, "c" * 64)
    raw["signature_ssh"] = "test-signature"
    raw[field] = value
    with pytest.raises(ValueError, match=r"witness|SHA-256"):
        WindowsTokenWorkerAcceptance.from_mapping(raw)


def test_worker_acceptance_v1_is_not_backwards_compatible() -> None:
    raw = acceptance("a" * 64, "b" * 64, "c" * 64)
    raw["schema_version"] = "0verse.windows-token-worker-acceptance/v1"
    raw["signature_ssh"] = "test-signature"
    with pytest.raises(ValueError, match="unsupported Windows token worker acceptance schema"):
        WindowsTokenWorkerAcceptance.from_mapping(raw)


def test_worker_acceptance_allows_non_admin_session_zero() -> None:
    raw = acceptance("a" * 64, "b" * 64, "c" * 64)
    raw["witness_session_id"] = 0
    raw["signature_ssh"] = "test-signature"
    loaded = WindowsTokenWorkerAcceptance.from_mapping(raw)
    assert loaded.witness_session_id == 0
    with pytest.raises(ValueError, match="witness_session_id"):
        replace(loaded, witness_session_id=False).validate()


def test_wrong_signature_namespace_and_duplicate_keys_fail(tmp_path: Path) -> None:
    campaign_path = tmp_path / "campaign.json"
    campaign_sha = write_json(campaign_path, campaign())
    scope_sha = "d" * 64
    wrong = sign_document(grant(campaign_sha, scope_sha), ACCEPTANCE_SIGNATURE_NAMESPACE)
    path = tmp_path / "grant.json"
    write_json(path, wrong)
    with pytest.raises(ValueError, match="signature is invalid"):
        load_windows_token_execution_grant(path, allowed_signers=authorization_policy())

    path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_windows_token_execution_grant(path, allowed_signers=authorization_policy())


def test_live_objects_cannot_drift_after_signature_verification(tmp_path: Path) -> None:
    bundle = authority_bundle(tmp_path)
    loaded_campaign, campaign_sha, loaded_scope, scope_sha = bundle[:4]
    loaded_grant, grant_sha, loaded_acceptance = bundle[4:7]
    with pytest.raises(ValueError, match="differ from signed material"):
        replace(loaded_grant, worker="other-worker").require_signed_authorization()
    with pytest.raises(ValueError, match="differ from signed material"):
        replace(
            loaded_acceptance, build_lab_ex="different-build"
        ).require_signed_authorization()
    with pytest.raises(ValueError, match="differ from signed material"):
        replace(
            loaded_acceptance, execution_grant_sha256="f" * 64
        ).require_binding(
            loaded_campaign,
            campaign_sha,
            loaded_scope,
            scope_sha,
            loaded_grant,
            grant_sha,
            bundle[7],
        )
    with pytest.raises(ValueError, match="grant SHA-256 differs"):
        replace(loaded_grant, _source_sha256="f" * 64).require_source_binding(grant_sha)
    with pytest.raises(ValueError, match="acceptance SHA-256 differs"):
        replace(loaded_acceptance, _source_sha256="f" * 64).require_source_binding(
            bundle[7]
        )


def test_symlink_and_expiry_fail_closed(tmp_path: Path) -> None:
    campaign_path = tmp_path / "campaign.json"
    write_json(campaign_path, campaign())
    link = tmp_path / "campaign-link.json"
    link.symlink_to(campaign_path)
    with pytest.raises(ValueError, match="symlinks"):
        load_windows_token_campaign(link)

    now = datetime.now(UTC)
    expired = grant("a" * 64, "b" * 64)
    expired["issued_at"] = (now - timedelta(hours=2)).isoformat()
    expired["expires_at"] = (now - timedelta(hours=1)).isoformat()
    expired_path = tmp_path / "expired.json"
    write_json(
        expired_path,
        sign_document(expired, GRANT_SIGNATURE_NAMESPACE),
    )
    with pytest.raises(ValueError, match="expired"):
        load_windows_token_execution_grant(
            expired_path, allowed_signers=authorization_policy()
        )
