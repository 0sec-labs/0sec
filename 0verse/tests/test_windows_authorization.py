from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from authorization_helpers import (
    authorization_key,
    authorization_policy,
    authorized_grant,
    authorized_scope,
    sign_document,
)

from zeroverse.hyperv_prover import (
    GRANT_AUTHORIZATION_NAMESPACE,
    HyperVExecutionGrant,
    load_execution_grant,
)
from zeroverse.ssh_authorization import canonical_signed_material
from zeroverse.windows_authorization import issue_windows_authorization
from zeroverse.windows_oracle import WindowsWorker
from zeroverse.windows_scope import AUTHORIZATION_NAMESPACE, load_scope


def _scope_v2(**updates: object) -> dict[str, object]:
    now = datetime.now(UTC)
    raw: dict[str, object] = {
        "schema_version": "0verse.windows-scope/v2",
        "campaign_id": "signed-scope-001",
        "program": "hyperv-insider",
        "scope_url": "https://www.microsoft.com/msrc/hyperv-scope",
        "target_feature": "Hyper-V vmswitch",
        "reachability": "stock child partition",
        "authorization": "published scope; owned host and guest",
        "worker": "worker-01.example.test",
        "latest_build_verified_at": now.isoformat(),
        "latest_build_number": "",
        "latest_build_source_url": "",
        "preflight": {
            "ok": True,
            "program": "hyperv-insider",
            "checked_at": now.isoformat(),
            "build_lab_ex": "28020.1.amd64fre.rs_prerelease",
            "product_name": "Windows 11 Pro",
            "hyperv_available": True,
            "insider": {
                "ring": "External",
                "content_type": "Mainline",
                "branch_name": "rs_prerelease",
                "channel_family": "experimental-26h1",
            },
        },
        "authorized_by": "operator@example.test",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "scope-authorization-000000000000000001",
        "signature_ssh": "",
    }
    raw.update(updates)
    return raw


def _grant_v2(**updates: object) -> dict[str, object]:
    now = datetime.now(UTC)
    raw: dict[str, object] = {
        "schema_version": "0verse.hyperv-execution-grant/v2",
        "campaign_sha256": "a" * 64,
        "scope_manifest_sha256": "b" * 64,
        "campaign_id": "signed-scope-001",
        "worker": "worker-01.example.test",
        "guest_worker": "attacker-insider",
        "vm_name": "attacker",
        "checkpoint_name": "clean",
        "dump_path": "C:\\dumps\\MEMORY.DMP",
        "trigger_executable_sha256": "c" * 64,
        "control_executable_sha256": "d" * 64,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "grant-authorization-000000000000000001",
        "authorized_by": "operator@example.test",
        "signature_ssh": "",
    }
    raw.update(updates)
    return raw


def test_canonical_material_excludes_only_signature_and_is_order_stable() -> None:
    first = {"z": [2, 1], "signature_ssh": "ignored", "a": {"b": True}}
    second = {"a": {"b": True}, "z": [2, 1], "signature_ssh": "different"}
    expected = b'{"a":{"b":true},"z":[2,1]}'
    assert canonical_signed_material(first) == expected
    assert canonical_signed_material(second) == expected


def test_operator_issuer_self_verifies_scope_and_grant(tmp_path: Path) -> None:
    scope_template = tmp_path / "scope-template.json"
    scope_output = tmp_path / "scope.json"
    scope_template.write_text(json.dumps(_scope_v2()), encoding="utf-8")
    scope_result = issue_windows_authorization(
        scope_template,
        scope_output,
        kind="scope",
        signing_key=authorization_key(),
        allowed_signers=authorization_policy(),
    )
    scope, scope_digest = load_scope(
        scope_output,
        allowed_signers=authorization_policy(),
        require_authorized=True,
    )
    assert scope_result.sha256 == scope_digest
    assert scope.authorized_by == "operator@example.test"

    grant_template = tmp_path / "grant-template.json"
    grant_output = tmp_path / "grant.json"
    grant_template.write_text(json.dumps(_grant_v2()), encoding="utf-8")
    grant_result = issue_windows_authorization(
        grant_template,
        grant_output,
        kind="grant",
        signing_key=authorization_key(),
        allowed_signers=authorization_policy(),
    )
    grant, grant_digest = load_execution_grant(
        grant_output,
        allowed_signers=authorization_policy(),
        require_authorized=True,
    )
    assert grant_result.sha256 == grant_digest
    assert grant.nonce == "grant-authorization-000000000000000001"


def test_nested_scope_tamper_and_wrong_namespace_fail(tmp_path: Path) -> None:
    signed = sign_document(_scope_v2(), AUTHORIZATION_NAMESPACE)
    preflight = signed["preflight"]
    assert isinstance(preflight, dict)
    insider = preflight["insider"]
    assert isinstance(insider, dict)
    insider["content_type"] = "tampered"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    with pytest.raises(ValueError, match="signature is invalid"):
        load_scope(path, allowed_signers=authorization_policy())

    wrong_namespace = sign_document(_scope_v2(), GRANT_AUTHORIZATION_NAMESPACE)
    path.write_text(json.dumps(wrong_namespace), encoding="utf-8")
    with pytest.raises(ValueError, match="signature is invalid"):
        load_scope(path, allowed_signers=authorization_policy())


def test_v1_is_inspection_only_and_worker_requires_explicit_mode(tmp_path: Path) -> None:
    raw = _scope_v2()
    for field in ("authorized_by", "issued_at", "expires_at", "nonce", "signature_ssh"):
        raw.pop(field)
    raw["schema_version"] = "0verse.windows-scope/v1"
    path = tmp_path / "scope-v1.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    scope, _ = load_scope(path)
    with pytest.raises(ValueError, match="verified signed scope v2"):
        scope.require_signed_authorization()

    grant_raw = _grant_v2()
    grant_raw.pop("signature_ssh")
    grant_raw["schema_version"] = "0verse.hyperv-execution-grant/v1"
    grant_path = tmp_path / "grant-v1.json"
    grant_path.write_text(json.dumps(grant_raw), encoding="utf-8")
    grant, _ = load_execution_grant(grant_path)
    with pytest.raises(ValueError, match="verified signed grant v2"):
        grant.require_signed_authorization()

    with pytest.raises(ValueError, match="signed scope authorization or lab_only"):
        WindowsWorker("worker-01.example.test")
    assert WindowsWorker("worker-01.example.test", lab_only=True).lab_only


def test_duplicate_keys_and_strict_signed_scalar_types_fail(tmp_path: Path) -> None:
    signed = sign_document(_scope_v2(), AUTHORIZATION_NAMESPACE)
    text = json.dumps(signed).replace(
        '"campaign_id":', '"campaign_id": "duplicate", "campaign_id":', 1
    )
    path = tmp_path / "duplicate.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key: campaign_id"):
        load_scope(path, allowed_signers=authorization_policy())

    malformed = _grant_v2(campaign_id=123)
    malformed = sign_document(malformed, GRANT_AUTHORIZATION_NAMESPACE)
    grant_path = tmp_path / "bad-grant.json"
    grant_path.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ValueError, match="campaign_id must be a string"):
        load_execution_grant(grant_path, allowed_signers=authorization_policy())


def test_issuer_requires_env_key_and_never_publishes_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ZEROVERSE_WINDOWS_AUTHORIZATION_SIGNING_KEY", raising=False)
    template = tmp_path / "scope-template.json"
    output = tmp_path / "scope.json"
    template.write_text(json.dumps(_scope_v2()), encoding="utf-8")
    with pytest.raises(ValueError, match="ZEROVERSE_WINDOWS_AUTHORIZATION_SIGNING_KEY"):
        issue_windows_authorization(template, output, kind="scope")
    assert not output.exists()


def test_expired_signed_scope_and_grant_are_rejected(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    expired_scope = _scope_v2(
        issued_at=(now - timedelta(hours=2)).isoformat(),
        expires_at=(now - timedelta(hours=1)).isoformat(),
    )
    scope_path = tmp_path / "expired-scope.json"
    scope_path.write_text(
        json.dumps(sign_document(expired_scope, AUTHORIZATION_NAMESPACE)), encoding="utf-8"
    )
    with pytest.raises(ValueError, match=r"outside the 24-hour window|expired"):
        load_scope(scope_path, allowed_signers=authorization_policy())

    expired_grant = _grant_v2(
        issued_at=(now - timedelta(hours=2)).isoformat(),
        expires_at=(now - timedelta(hours=1)).isoformat(),
    )
    grant_path = tmp_path / "expired-grant.json"
    grant_path.write_text(
        json.dumps(sign_document(expired_grant, GRANT_AUTHORIZATION_NAMESPACE)),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="expired"):
        load_execution_grant(grant_path, allowed_signers=authorization_policy())


def test_raw_v1_grant_object_cannot_be_promoted_programmatically() -> None:
    raw = _grant_v2()
    raw.pop("signature_ssh")
    raw["schema_version"] = "0verse.hyperv-execution-grant/v1"
    grant = HyperVExecutionGrant.from_mapping(raw)
    with pytest.raises(ValueError, match="verified signed grant v2"):
        grant.require_signed_authorization()


def test_verified_objects_cannot_diverge_from_their_signed_material() -> None:
    signed_scope = authorized_scope(_scope_v2())
    with pytest.raises(ValueError, match="differ from signed material"):
        replace(signed_scope, worker="evil-host").require_signed_authorization()

    signed_grant = authorized_grant(_grant_v2())
    with pytest.raises(ValueError, match="differ from signed material"):
        replace(signed_grant, vm_name="evil-vm").require_signed_authorization()
    with pytest.raises(ValueError, match="differ from signed material"):
        replace(
            signed_grant, trigger_executable_sha256="e" * 64
        ).require_signed_authorization()
