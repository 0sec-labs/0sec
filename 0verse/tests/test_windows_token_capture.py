from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from authorization_helpers import authorization_key, authorization_policy, sign_document

from zeroverse.cli import main
from zeroverse.ssh_authorization import (
    canonical_signed_material,
    sign_ssh_material,
    verify_ssh_signature,
)
from zeroverse.windows_scope import AUTHORIZATION_NAMESPACE, load_scope
from zeroverse.windows_token_capture import (
    SIGNATURE_NAMESPACE,
    ExclusiveFileNonceLedger,
    derive_token_id,
    load_windows_token_capture,
)
from zeroverse.windows_token_evidence import (
    EVIDENCE_SIGNATURE_NAMESPACE,
    aggregate_windows_token_evidence,
    aggregate_windows_token_observation,
    derive_windows_token_evidence,
    derive_windows_token_grant_ledger_entry,
    load_windows_token_evidence_receipt,
    observe_windows_token_evidence,
)
from zeroverse.windows_token_runner import (
    ACCEPTANCE_SIGNATURE_NAMESPACE,
    GRANT_SIGNATURE_NAMESPACE,
    load_windows_token_campaign,
    load_windows_token_execution_grant,
    load_windows_token_worker_acceptance,
)

CANONICAL_V3_FIXTURE = (
    Path(__file__).parent / "fixtures" / "windows-token-capture-v3-canonical.json"
)
SSHSIG_VECTOR = Path(__file__).parent / "fixtures" / "windows-token-sshsig"
AUTHORITY_VECTOR = (
    Path(__file__).parent / "fixtures" / "windows-token-authority-v1"
)


def test_native_capture_v3_canonical_material_matches_python_contract() -> None:
    raw = json.loads(CANONICAL_V3_FIXTURE.read_text(encoding="utf-8"))
    material = canonical_signed_material(raw)
    assert (
        hashlib.sha256(material).hexdigest()
        == "e07af9d8777cc5f4a2707dcd0c5a47fc73cfcca264dfbbf3ccb5771dbf58323e"
    )
    assert b'"signature_ssh"' not in material
    assert material.startswith(b'{"build_lab_ex":')


def test_native_sshsig_vector_is_openssh_compatible() -> None:
    verify_ssh_signature(
        (SSHSIG_VECTOR / "material.json").read_bytes(),
        (SSHSIG_VECTOR / "material.json.sig").read_text(encoding="utf-8"),
        identity="capture@example.test",
        namespace=SIGNATURE_NAMESPACE,
        allowed_signers=SSHSIG_VECTOR / "allowed_signers",
        label="native SSHSIG vector",
        require_trusted_policy=False,
    )


def test_native_authority_vector_matches_python_contract() -> None:
    expected = json.loads((AUTHORITY_VECTOR / "expected.json").read_text())
    documents = {
        name: json.loads((AUTHORITY_VECTOR / f"{name}.json").read_text())
        for name in ("campaign", "scope", "grant", "acceptance")
    }

    for name, raw in documents.items():
        source = (AUTHORITY_VECTOR / f"{name}.json").read_bytes()
        assert hashlib.sha256(source).hexdigest() == expected[f"{name}_sha256"]
        material = (
            json.dumps(
                raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
            if name == "campaign"
            else canonical_signed_material(raw)
        )
        assert (
            hashlib.sha256(material).hexdigest()
            == expected[f"{name}_canonical_sha256"]
        )

    for name, namespace, identity_field in (
        ("scope", AUTHORIZATION_NAMESPACE, "authorized_by"),
        ("grant", GRANT_SIGNATURE_NAMESPACE, "authorized_by"),
        ("acceptance", ACCEPTANCE_SIGNATURE_NAMESPACE, "accepted_by"),
    ):
        raw = documents[name]
        verify_ssh_signature(
            canonical_signed_material(raw),
            raw["signature_ssh"],
            identity=raw[identity_field],
            namespace=namespace,
            allowed_signers=SSHSIG_VECTOR / "allowed_signers",
            label=f"native {name} authority vector",
            require_trusted_policy=False,
        )


def _write(path: Path, raw: dict[str, object]) -> str:
    path.write_text(json.dumps(raw), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sign_with_key(
    raw: dict[str, object], namespace: str, signing_key: Path | None
) -> dict[str, object]:
    if signing_key is None:
        return sign_document(raw, namespace)
    signed = json.loads(json.dumps(raw))
    signed["signature_ssh"] = ""
    signed["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(signed),
        signing_key=signing_key,
        namespace=namespace,
        label="test role document",
    )
    return signed


def _campaign() -> dict[str, object]:
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


def _scope() -> dict[str, object]:
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


def _grant(campaign_sha: str, scope_sha: str) -> dict[str, object]:
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


def _acceptance(
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
        "capture_signer": "operator@example.test",
        "signature_ssh": "",
    }


def _token(
    token_seed: str,
    *,
    system: bool = False,
    app_container: bool = False,
    restricted_sid_count: int = 0,
    run_nonce: str = "per_run_nonce_00000000000000000001",
    phase: str | None = None,
    session_id: int = 1,
) -> dict[str, object]:
    counter = int(hashlib.sha256(token_seed.encode()).hexdigest()[:12], 16)
    snapshot_phase = phase or ("start" if token_seed.startswith("start") else "finish")
    return {
        "token_id": derive_token_id(run_nonce, snapshot_phase, counter),
        "user_sid": "S-1-5-18" if system else "S-1-5-21-1-2-3-1001",
        "integrity_rid": 0x4000 if system else 0x2000,
        "elevation_type": "default",
        "elevated": system,
        "admin_group": "enabled" if system else "absent",
        "app_container": app_container,
        "restricted_sid_count": restricted_sid_count,
        "enabled_privileges": ["SeDebugPrivilege"] if system else ["SeChangeNotifyPrivilege"],
        "token_source": (
            "thread" if system else "process-fallback-no-thread-token"
        ),
        "statistics_token_id_before": counter,
        "statistics_token_id_after": counter,
        "modified_id_before": counter + 1,
        "modified_id_after": counter + 1,
        "lpac_supported": True,
        "less_privileged_app_container": False,
        "session_id": session_id,
        "authentication_id": (
            "00000000000003e7" if system else "0000000000001001"
        ),
    }


def _capture(
    campaign_sha: str,
    scope_sha: str,
    grant_sha: str,
    acceptance_sha: str,
) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "schema_version": "0verse.windows-token-capture/v3",
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "execution_grant_sha256": grant_sha,
        "execution_grant_nonce": "execution_grant_nonce_0000000001",
        "worker_acceptance_sha256": acceptance_sha,
        "worker_acceptance_nonce": "worker_acceptance_nonce_00000001",
        "campaign_id": "canary-lpe-001",
        "worker": "canary-worker-1",
        "build_lab_ex": "29000.1.amd64fre.rs_prerelease",
        "worker_machine_id": "owned-canary-machine-001",
        "runner_executable_sha256": "c" * 64,
        "witness_user_sid": "S-1-5-21-1-2-3-1001",
        "witness_session_id": 1,
        "witness_authentication_id": "0000000000001001",
        "witness_executable_sha256": "d" * 64,
        "operation_sha256": "a" * 64,
        "case": "target",
        "trial": 1,
        "run_nonce": "per_run_nonce_00000000000000000001",
        "capture_nonce": "capture_nonce_0000000000000000001",
        "process_instance_id": "process_instance_00000001",
        "thread_id_before": 4242,
        "thread_id_after": 4242,
        "started_at": now.isoformat(),
        "completed_at": now.isoformat(),
        "start_token": _token("start_token_00000001"),
        "finish_token": _token("finish_token_0000001", system=True),
        "signed_by": "operator@example.test",
        "signature_ssh": "",
    }


def _authority_bundle(
    tmp_path: Path,
    campaign_overrides: dict[str, object] | None = None,
    *,
    scope_overrides: dict[str, object] | None = None,
    grant_overrides: dict[str, object] | None = None,
    acceptance_overrides: dict[str, object] | None = None,
    role_policies: dict[str, Path] | None = None,
    role_signing_keys: dict[str, Path] | None = None,
):
    campaign_path = tmp_path / "campaign.json"
    campaign_raw = {**_campaign(), **(campaign_overrides or {})}
    campaign_sha = _write(campaign_path, campaign_raw)
    campaign, _ = load_windows_token_campaign(campaign_path)

    scope_path = tmp_path / "scope.json"
    scope_raw = {**_scope(), **(scope_overrides or {})}
    scope_sha = _write(
        scope_path,
        _sign_with_key(
            scope_raw, AUTHORIZATION_NAMESPACE, (role_signing_keys or {}).get("scope")
        ),
    )
    scope, _ = load_scope(
        scope_path,
        allowed_signers=(role_policies or {}).get("scope", authorization_policy()),
        require_authorized=True,
    )

    grant_path = tmp_path / "grant.json"
    grant_sha = _write(
        grant_path,
        _sign_with_key(
            {**_grant(campaign_sha, scope_sha), **(grant_overrides or {})},
            GRANT_SIGNATURE_NAMESPACE,
            (role_signing_keys or {}).get("grant"),
        ),
    )
    grant, _ = load_windows_token_execution_grant(
        grant_path,
        allowed_signers=(role_policies or {}).get("grant", authorization_policy()),
        require_authorized=True,
    )

    acceptance_path = tmp_path / "acceptance.json"
    acceptance_sha = _write(
        acceptance_path,
        _sign_with_key(
            {
                **_acceptance(campaign_sha, scope_sha, grant_sha),
                **(acceptance_overrides or {}),
            },
            ACCEPTANCE_SIGNATURE_NAMESPACE,
            (role_signing_keys or {}).get("acceptance"),
        ),
    )
    acceptance, _ = load_windows_token_worker_acceptance(
        acceptance_path,
        allowed_signers=(role_policies or {}).get("acceptance", authorization_policy()),
        require_authorized=True,
    )
    return (
        campaign,
        campaign_sha,
        scope,
        scope_sha,
        grant,
        grant_sha,
        acceptance,
        acceptance_sha,
    )


def _signed_capture(tmp_path: Path):
    authorities = _authority_bundle(tmp_path)
    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    path = tmp_path / "capture.json"
    digest = _write(path, sign_document(raw, SIGNATURE_NAMESPACE))
    capture, loaded_digest = load_windows_token_capture(
        path, allowed_signers=authorization_policy(), require_verified=True
    )
    return authorities, capture, path, digest, loaded_digest


def _capture_matrix(
    tmp_path: Path,
    authorities,
    *,
    dirty_control: bool = False,
    escape_control: bool = False,
    target_transition: bool = True,
    capture_policy: Path | None = None,
    nonce_tag: str = "",
    capture_signing_key: Path | None = None,
):
    captures = []
    sandboxed = authorities[0].starting_context == "appcontainer"
    for trial in (1, 2):
        for case in ("target", "control"):
            raw = _capture(
                authorities[1], authorities[3], authorities[5], authorities[7]
            )
            suffix = f"{trial:02d}{'01' if case == 'target' else '02'}"
            run_nonce = (
                f"{nonce_tag}_run_nonce_00000000000000{suffix}"
                if nonce_tag
                else f"per_run_nonce_0000000000000000{suffix}"
            )
            raw.update(
                {
                    "campaign_id": authorities[0].campaign_id,
                    "worker": authorities[0].worker,
                    "build_lab_ex": authorities[2].preflight_build_lab_ex,
                    "worker_machine_id": authorities[6].worker_machine_id,
                    "runner_executable_sha256": authorities[6].runner_executable_sha256,
                    "witness_user_sid": authorities[6].witness_user_sid,
                    "witness_session_id": authorities[6].witness_session_id,
                    "witness_authentication_id": authorities[6].witness_authentication_id,
                    "witness_executable_sha256": authorities[6].witness_executable_sha256,
                    "execution_grant_nonce": authorities[4].nonce,
                    "worker_acceptance_nonce": authorities[6].nonce,
                    "signed_by": authorities[6].capture_signer,
                    "case": case,
                    "trial": trial,
                    "operation_sha256": "a" * 64 if case == "target" else "b" * 64,
                    "run_nonce": run_nonce,
                    "capture_nonce": (
                        f"{nonce_tag}_capture_nonce_0000000000{suffix}"
                        if nonce_tag
                        else f"capture_nonce_00000000000000000{suffix}"
                    ),
                    "process_instance_id": (
                        f"{nonce_tag}_process_instance_0000{suffix}"
                        if nonce_tag
                        else f"process_instance_0000{suffix}"
                    ),
                    "start_token": _token(
                        f"start_token_000000{suffix}",
                        app_container=sandboxed,
                        run_nonce=run_nonce,
                        session_id=authorities[6].witness_session_id,
                    ),
                    "finish_token": _token(
                        f"finish_token_00000{suffix}",
                        system=case == "target" and target_transition,
                        app_container=sandboxed and case == "control",
                        run_nonce=run_nonce,
                        session_id=authorities[6].witness_session_id,
                    ),
                }
            )
            if dirty_control and case == "control" and trial == 2:
                raw["finish_token"] = _token(
                    f"finish_token_00000{suffix}",
                    system=True,
                    run_nonce=run_nonce,
                    session_id=authorities[6].witness_session_id,
                )
            if escape_control and case == "control" and trial == 2:
                raw["finish_token"] = _token(
                    f"finish_token_00000{suffix}",
                    run_nonce=run_nonce,
                    session_id=authorities[6].witness_session_id,
                )
            path = tmp_path / f"capture-{case}-{trial}.json"
            _write(path, _sign_with_key(raw, SIGNATURE_NAMESPACE, capture_signing_key))
            capture, _ = load_windows_token_capture(
                path,
                allowed_signers=capture_policy or authorization_policy(),
                require_verified=True,
            )
            captures.append(capture)
    return captures


def test_signed_capture_binds_to_all_authority_and_source(tmp_path: Path) -> None:
    authorities, capture, path, digest, loaded_digest = _signed_capture(tmp_path)
    (
        campaign,
        campaign_sha,
        scope,
        scope_sha,
        grant,
        grant_sha,
        acceptance,
        acceptance_sha,
    ) = authorities

    capture.require_binding(
        campaign,
        campaign_sha,
        scope,
        scope_sha,
        grant,
        grant_sha,
        acceptance,
        acceptance_sha,
        expected_case="target",
        expected_trial=1,
        expected_run_nonce="per_run_nonce_00000000000000000001",
    )
    assert capture.source_sha256 == digest == loaded_digest
    assert capture.source_name == path.name


def test_wrong_namespace_tamper_and_binding_drift_fail(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path)
    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    path = tmp_path / "capture.json"
    _write(path, sign_document(raw, GRANT_SIGNATURE_NAMESPACE))
    with pytest.raises(ValueError, match="signature is invalid"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())

    signed = sign_document(raw, SIGNATURE_NAMESPACE)
    signed["campaign_id"] = "tampered-campaign"
    _write(path, signed)
    with pytest.raises(ValueError, match="signature is invalid"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())

    _, capture, _, _, _ = _signed_capture(tmp_path)
    with pytest.raises(ValueError, match="differs from signed material"):
        replace(capture, trial=2).require_signature()

    with pytest.raises(ValueError, match="not bound to authorized execution"):
        capture.require_binding(
            *authorities,
            expected_case="target",
            expected_trial=2,
            expected_run_nonce="per_run_nonce_00000000000000000001",
        )
    with pytest.raises(ValueError, match="capture SHA-256 differs"):
        replace(capture, _source_sha256="f" * 64).require_binding(
            *authorities,
            expected_case="target",
            expected_trial=1,
            expected_run_nonce="per_run_nonce_00000000000000000001",
        )


def test_duplicate_unknown_and_symlink_sources_fail(tmp_path: Path) -> None:
    path = tmp_path / "capture.json"
    path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())

    authorities = _authority_bundle(tmp_path)
    legacy = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    legacy["schema_version"] = "0verse.windows-token-capture/v2"
    _write(path, legacy)
    with pytest.raises(ValueError, match="unsupported Windows token capture schema"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())

    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    raw["argv"] = ["cmd.exe"]
    _write(path, sign_document(raw, SIGNATURE_NAMESPACE))
    with pytest.raises(ValueError, match="unknown argv"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())

    real = tmp_path / "real.json"
    _write(
        real,
        sign_document(
            _capture(authorities[1], authorities[3], authorities[5], authorities[7]),
            SIGNATURE_NAMESPACE,
        ),
    )
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="cannot be a symlink"):
        load_windows_token_capture(link, allowed_signers=authorization_policy())


def test_nonce_domains_must_be_distinct(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path)
    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    raw["run_nonce"] = raw["execution_grant_nonce"]
    path = tmp_path / "capture.json"
    _write(path, sign_document(raw, SIGNATURE_NAMESPACE))
    with pytest.raises(ValueError, match="nonce domains must be distinct"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())


def test_snapshot_id_has_cross_language_reference_vector() -> None:
    assert derive_token_id(
        "per_run_nonce_00000000000000000001", "start", 0x0123456789ABCDEF
    ) == "gKIIAtvLD0aQPeH50jftFhe9SgR6ubLeF9KFCTEo-bE"
    assert derive_token_id(
        "per_run_nonce_00000000000000000001", "finish", 0x0123456789ABCDEF
    ) == "_zlR6AYfi4bXd33NtpuQ49HJMGPwD5lHOCydcSoi8EU"
    with pytest.raises(ValueError, match="phase must be start or finish"):
        derive_token_id("per_run_nonce_00000000000000000001", "other", 1)


def test_capture_requires_stable_non_lpac_token_and_authority_window(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path)
    base = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    path = tmp_path / "capture.json"

    unstable = json.loads(json.dumps(base))
    unstable["start_token"]["modified_id_after"] += 1
    _write(path, sign_document(unstable, SIGNATURE_NAMESPACE))
    with pytest.raises(ValueError, match="changed while token facts were captured"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())

    thread_drift = json.loads(json.dumps(base))
    thread_drift["thread_id_after"] += 1
    _write(path, sign_document(thread_drift, SIGNATURE_NAMESPACE))
    with pytest.raises(ValueError, match="remain on one valid OS thread"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())

    lpac = json.loads(json.dumps(base))
    lpac["start_token"]["less_privileged_app_container"] = True
    _write(path, sign_document(lpac, SIGNATURE_NAMESPACE))
    capture, _ = load_windows_token_capture(
        path, allowed_signers=authorization_policy(), require_verified=True
    )
    with pytest.raises(ValueError, match="rejects LPAC"):
        capture.require_binding(
            *authorities,
            expected_case="target",
            expected_trial=1,
            expected_run_nonce=base["run_nonce"],
        )

    outside = json.loads(json.dumps(base))
    outside["started_at"] = (
        datetime.fromisoformat(authorities[6].issued_at) - timedelta(seconds=1)
    ).isoformat()
    _write(path, sign_document(outside, SIGNATURE_NAMESPACE))
    capture, _ = load_windows_token_capture(
        path, allowed_signers=authorization_policy(), require_verified=True
    )
    with pytest.raises(ValueError, match="outside its authorization window"):
        capture.require_binding(
            *authorities,
            expected_case="target",
            expected_trial=1,
            expected_run_nonce=base["run_nonce"],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("witness_user_sid", "S-1-5-21-1-2-3-1002"),
        ("witness_session_id", 2),
        ("witness_authentication_id", "0000000000001002"),
        ("witness_executable_sha256", "e" * 64),
    ],
)
def test_capture_witness_provenance_must_match_signed_acceptance(
    tmp_path: Path, field: str, value: object
) -> None:
    authorities = _authority_bundle(tmp_path)
    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    raw[field] = value
    if field == "witness_user_sid":
        raw["start_token"]["user_sid"] = value
    elif field == "witness_session_id":
        raw["start_token"]["session_id"] = value
        raw["finish_token"]["session_id"] = value
    elif field == "witness_authentication_id":
        raw["start_token"]["authentication_id"] = value
    path = tmp_path / f"capture-{field}.json"
    _write(path, sign_document(raw, SIGNATURE_NAMESPACE))
    capture, _ = load_windows_token_capture(
        path, allowed_signers=authorization_policy(), require_verified=True
    )
    with pytest.raises(ValueError, match="not bound to authorized execution"):
        capture.require_binding(
            *authorities,
            expected_case="target",
            expected_trial=1,
            expected_run_nonce=raw["run_nonce"],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("integrity_rid", 0x4000),
        ("elevation_type", "limited"),
        ("elevated", True),
        ("admin_group", "deny-only"),
        ("app_container", True),
        ("restricted_sid_count", 1),
        ("enabled_privileges", ["SeDebugPrivilege"]),
        ("token_source", "thread"),
    ],
)
def test_capture_rejects_non_natural_standard_user_start(
    tmp_path: Path, field: str, value: object
) -> None:
    authorities = _authority_bundle(tmp_path)
    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    raw["start_token"][field] = value
    path = tmp_path / f"capture-start-{field}.json"
    _write(path, sign_document(raw, SIGNATURE_NAMESPACE))
    capture, _ = load_windows_token_capture(
        path, allowed_signers=authorization_policy(), require_verified=True
    )
    with pytest.raises(ValueError, match="not the bound standard user"):
        capture.require_binding(
            *authorities,
            expected_case="target",
            expected_trial=1,
            expected_run_nonce=raw["run_nonce"],
        )


def test_capture_allows_bound_standard_user_in_session_zero(tmp_path: Path) -> None:
    authorities = _authority_bundle(
        tmp_path, acceptance_overrides={"witness_session_id": 0}
    )
    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    raw["witness_session_id"] = 0
    raw["start_token"]["session_id"] = 0
    raw["finish_token"]["session_id"] = 0
    path = tmp_path / "capture-session-zero.json"
    _write(path, sign_document(raw, SIGNATURE_NAMESPACE))
    capture, _ = load_windows_token_capture(
        path, allowed_signers=authorization_policy(), require_verified=True
    )
    capture.require_binding(
        *authorities,
        expected_case="target",
        expected_trial=1,
        expected_run_nonce=raw["run_nonce"],
    )
    with pytest.raises(ValueError, match="witness_session_id"):
        replace(capture, witness_session_id=False).validate()


@pytest.mark.parametrize("invalid_session", [-1, True, 2**32])
def test_capture_rejects_invalid_witness_session_bounds(
    tmp_path: Path, invalid_session: object
) -> None:
    authorities = _authority_bundle(tmp_path)
    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    raw["witness_session_id"] = invalid_session
    raw["start_token"]["session_id"] = invalid_session
    raw["finish_token"]["session_id"] = invalid_session
    path = tmp_path / "capture-invalid-session.json"
    _write(path, sign_document(raw, SIGNATURE_NAMESPACE))
    with pytest.raises(ValueError, match="session_id"):
        load_windows_token_capture(
            path,
            allowed_signers=authorization_policy(),
            require_verified=True,
        )


def test_unchanged_control_token_has_distinct_phase_snapshot_ids(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path)
    raw = _capture(authorities[1], authorities[3], authorities[5], authorities[7])
    raw["case"] = "control"
    raw["operation_sha256"] = "b" * 64
    start = _token("same_underlying_token", phase="start")
    finish = _token("same_underlying_token", phase="finish")
    raw["start_token"] = start
    raw["finish_token"] = finish
    path = tmp_path / "unchanged-control.json"
    _write(path, sign_document(raw, SIGNATURE_NAMESPACE))
    capture, _ = load_windows_token_capture(
        path, allowed_signers=authorization_policy(), require_verified=True
    )
    assert capture.start_token.statistics_token_id_before == (
        capture.finish_token.statistics_token_id_before
    )
    assert capture.start_token.token_id != capture.finish_token.token_id
    capture.require_binding(
        *authorities,
        expected_case="control",
        expected_trial=1,
        expected_run_nonce=raw["run_nonce"],
    )

def test_exclusive_nonce_ledger_consumes_once_and_rejects_permissions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "ledger"
    ledger = ExclusiveFileNonceLedger(root)
    identity = ledger.consume(
        "execution_grant_nonce_0000000001",
        "per_run_nonce_00000000000000000001",
    )
    assert (root / f"{identity}.used").read_text(encoding="ascii") == identity + "\n"
    with pytest.raises(FileExistsError):
        ledger.consume(
            "execution_grant_nonce_0000000001",
            "per_run_nonce_00000000000000000001",
        )
    unconsumed = "per_run_nonce_00000000000000000002"
    with pytest.raises(FileExistsError):
        ledger.consume_batch(
            "execution_grant_nonce_0000000001",
            (unconsumed, "per_run_nonce_00000000000000000001"),
        )
    assert ledger.consume("execution_grant_nonce_0000000001", unconsumed)

    single_use = ExclusiveFileNonceLedger(tmp_path / "single-use-ledger")
    single_use.consume_batch(
        "execution_grant_nonce_0000000001",
        ("per_run_nonce_00000000000000000003",),
        campaign_sha256="a" * 64,
    )
    grant_marker = derive_windows_token_grant_ledger_entry(
        "execution_grant_nonce_0000000001", "a" * 64
    )
    assert (tmp_path / "single-use-ledger" / f"{grant_marker}.used").is_file()
    with pytest.raises(FileExistsError):
        single_use.consume_batch(
            "execution_grant_nonce_0000000001",
            ("per_run_nonce_00000000000000000004",),
            campaign_sha256="a" * 64,
        )

    if os.name != "nt":
        broad = tmp_path / "broad-ledger"
        broad.mkdir(mode=0o755)
        broad.chmod(0o755)
        with pytest.raises(ValueError, match="permissions are too broad"):
            ExclusiveFileNonceLedger(broad)


def test_aggregation_derives_semantics_and_rejects_replay(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path)
    captures = _capture_matrix(tmp_path, authorities)
    ledger = ExclusiveFileNonceLedger(tmp_path / "aggregate-ledger")
    evidence = aggregate_windows_token_evidence(
        captures,
        *authorities,
        ledger,
    )
    assert evidence.target_confirmations == 2
    assert evidence.clean_controls == 2
    assert evidence.witness_user_sid == authorities[6].witness_user_sid
    assert evidence.witness_session_id == authorities[6].witness_session_id
    assert evidence.witness_authentication_id == (
        authorities[6].witness_authentication_id
    )
    assert evidence.witness_executable_sha256 == (
        authorities[6].witness_executable_sha256
    )
    assert evidence.to_dict()["human_report_gate"] is True
    assert evidence.to_dict()["weaponization"] is False

    with pytest.raises(FileExistsError):
        aggregate_windows_token_evidence(captures, *authorities, ledger)


def test_aggregation_requires_complete_clean_matrix(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path)
    captures = _capture_matrix(tmp_path, authorities, dirty_control=True)
    ledger = ExclusiveFileNonceLedger(tmp_path / "dirty-ledger")
    with pytest.raises(ValueError, match="control is not clean"):
        aggregate_windows_token_evidence(captures, *authorities, ledger)
    assert not list((tmp_path / "dirty-ledger").glob("*.used"))

    with pytest.raises(ValueError, match="complete target/control matrix"):
        aggregate_windows_token_evidence(
            captures[:-1],
            *authorities,
            ExclusiveFileNonceLedger(tmp_path / "incomplete-ledger"),
        )


def test_appcontainer_control_cannot_escape_sandbox(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path, {"starting_context": "appcontainer"})
    captures = _capture_matrix(tmp_path, authorities, escape_control=True)
    with pytest.raises(ValueError, match="control is not clean"):
        aggregate_windows_token_evidence(
            captures,
            *authorities,
            ExclusiveFileNonceLedger(tmp_path / "sandbox-ledger"),
        )


def test_neutral_observation_accepts_clean_fixed_matrix_but_strict_wrapper_rejects(
    tmp_path: Path,
) -> None:
    authorities = _authority_bundle(tmp_path)
    captures = _capture_matrix(tmp_path, authorities, target_transition=False)
    observation = observe_windows_token_evidence(captures, *authorities)
    assert observation.target_confirmations == 0
    assert observation.clean_target_no_transitions == 2
    assert observation.ambiguous_targets == 0
    assert observation.clean_controls == 2
    ledger = ExclusiveFileNonceLedger(tmp_path / "neutral-observation-ledger")
    consumed = aggregate_windows_token_observation(captures, *authorities, ledger)
    assert consumed == observation
    with pytest.raises(FileExistsError, match="consumed"):
        aggregate_windows_token_observation(captures, *authorities, ledger)
    with pytest.raises(ValueError, match="required target confirmations"):
        derive_windows_token_evidence(captures, *authorities)


def test_cli_validation_and_offline_aggregation(tmp_path: Path, capsys, monkeypatch) -> None:
    authorities = _authority_bundle(tmp_path)
    policy = authorization_policy()
    monkeypatch.setattr(
        "zeroverse.windows_scope.load_scope",
        lambda path, **kwargs: load_scope(
            path, allowed_signers=policy, require_authorized=kwargs["require_authorized"]
        ),
    )
    monkeypatch.setattr(
        "zeroverse.windows_token_runner.load_windows_token_execution_grant",
        lambda path, **kwargs: load_windows_token_execution_grant(
            path, allowed_signers=policy, require_authorized=kwargs["require_authorized"]
        ),
    )
    monkeypatch.setattr(
        "zeroverse.windows_token_runner.load_windows_token_worker_acceptance",
        lambda path, **kwargs: load_windows_token_worker_acceptance(
            path, allowed_signers=policy, require_authorized=kwargs["require_authorized"]
        ),
    )
    monkeypatch.setattr(
        "zeroverse.windows_token_capture.load_windows_token_capture",
        lambda path, **kwargs: load_windows_token_capture(
            path, allowed_signers=policy, require_verified=kwargs["require_verified"]
        ),
    )
    common = [
        str(tmp_path / "campaign.json"),
        "--scope-manifest",
        str(tmp_path / "scope.json"),
        "--execution-grant",
        str(tmp_path / "grant.json"),
        "--worker-acceptance",
        str(tmp_path / "acceptance.json"),
    ]
    assert main(["windows-token-validate", *common]) == 0
    assert json.loads(capsys.readouterr().out)["execution"] is False

    captures = _capture_matrix(tmp_path, authorities)
    assert main(
        ["windows-token-capture-verify", str(tmp_path / "capture-target-1.json")]
    ) == 0
    capture_verification = json.loads(capsys.readouterr().out)
    assert capture_verification["status"] == "SIGNATURE_VERIFIED"
    assert capture_verification["authority_binding_verified"] is False
    capture_args = [item for capture in captures for item in ("--capture", str(
        tmp_path / f"capture-{capture.case}-{capture.trial}.json"
    ))]
    assert main(
        [
            "windows-token-aggregate",
            *common,
            *capture_args,
            "--nonce-ledger",
            str(tmp_path / "cli-ledger"),
            "--signing-key",
            str(authorization_key()),
            "--signed-by",
            "operator@example.test",
        ]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "AGGREGATED"
    assert payload["target_confirmations"] == 2
    verify_ssh_signature(
        canonical_signed_material(payload),
        payload["signature_ssh"],
        identity=payload["signed_by"],
        namespace=EVIDENCE_SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows token evidence receipt",
        require_trusted_policy=False,
    )
    receipt_path = tmp_path / "evidence.json"
    _write(receipt_path, payload)
    loaded, digest = load_windows_token_evidence_receipt(
        receipt_path, allowed_signers=policy
    )
    assert loaded["campaign_sha256"] == authorities[1]
    assert loaded["witness_user_sid"] == authorities[6].witness_user_sid
    assert loaded["witness_session_id"] == authorities[6].witness_session_id
    assert loaded["witness_authentication_id"] == (
        authorities[6].witness_authentication_id
    )
    assert loaded["witness_executable_sha256"] == (
        authorities[6].witness_executable_sha256
    )
    assert digest == hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    session_zero = json.loads(json.dumps(payload))
    session_zero["witness_session_id"] = 0
    session_zero["signature_ssh"] = ""
    session_zero["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(session_zero),
        signing_key=authorization_key(),
        namespace=EVIDENCE_SIGNATURE_NAMESPACE,
        label="test Session 0 Windows token evidence receipt",
    )
    _write(receipt_path, session_zero)
    loaded_zero, _ = load_windows_token_evidence_receipt(
        receipt_path, allowed_signers=policy
    )
    assert loaded_zero["witness_session_id"] == 0

    for field, value in [
        ("witness_session_id", -1),
        ("witness_session_id", True),
        ("witness_session_id", 2**32),
        ("witness_authentication_id", "00000000000003e7"),
    ]:
        invalid = json.loads(json.dumps(payload))
        invalid[field] = value
        invalid["signature_ssh"] = ""
        invalid["signature_ssh"] = sign_ssh_material(
            canonical_signed_material(invalid),
            signing_key=authorization_key(),
            namespace=EVIDENCE_SIGNATURE_NAMESPACE,
            label="test invalid Windows token evidence receipt",
        )
        _write(receipt_path, invalid)
        with pytest.raises(ValueError, match=field):
            load_windows_token_evidence_receipt(receipt_path, allowed_signers=policy)

    fixed_root = tmp_path / "fixed"
    fixed_root.mkdir()
    fixed_authorities = _authority_bundle(fixed_root)
    fixed_captures = _capture_matrix(
        fixed_root,
        fixed_authorities,
        target_transition=False,
    )
    fixed_common = [
        str(fixed_root / "campaign.json"),
        "--scope-manifest",
        str(fixed_root / "scope.json"),
        "--execution-grant",
        str(fixed_root / "grant.json"),
        "--worker-acceptance",
        str(fixed_root / "acceptance.json"),
    ]
    fixed_capture_args = [
        item
        for capture in fixed_captures
        for item in (
            "--capture",
            str(fixed_root / f"capture-{capture.case}-{capture.trial}.json"),
        )
    ]
    assert main(
        [
            "windows-token-aggregate-neutral",
            *fixed_common,
            *fixed_capture_args,
            "--nonce-ledger",
            str(fixed_root / "neutral-cli-ledger"),
            "--signing-key",
            str(authorization_key()),
            "--signed-by",
            "operator@example.test",
        ]
    ) == 0
    fixed_payload = json.loads(capsys.readouterr().out)
    assert fixed_payload["target_confirmations"] == 0
    assert fixed_payload["clean_controls"] == 2
    assert main(
        [
            "windows-token-aggregate",
            *fixed_common,
            *fixed_capture_args,
            "--nonce-ledger",
            str(fixed_root / "strict-cli-ledger"),
            "--signing-key",
            str(authorization_key()),
            "--signed-by",
            "operator@example.test",
        ]
    ) == 2
    assert "required target confirmations" in capsys.readouterr().err

    payload["target_confirmations"] = 1
    _write(receipt_path, payload)
    with pytest.raises(ValueError, match="signature is invalid"):
        load_windows_token_evidence_receipt(receipt_path, allowed_signers=policy)
