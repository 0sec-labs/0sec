from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from authorization_helpers import authorization_policy, sign_document
from test_windows_token_capture import _authority_bundle, _capture

from zeroverse.windows_token_capture import (
    LPAC_LAUNCH_SIGNATURE_NAMESPACE,
    SIGNATURE_NAMESPACE,
    derive_token_id,
    load_windows_token_capture,
)
from zeroverse.windows_token_evidence import observe_windows_token_evidence
from zeroverse.windows_token_runner import load_windows_token_campaign

APP_CONTAINER_SID = "S-1-15-2-1-2-3-4-5-6-7-8"
SANDBOX = "windows-defender-msengcp"
LAUNCHER_SHA256 = "1" * 64
SANDBOX_PROCESS_SHA256 = "2" * 64


def _lpac_campaign() -> dict[str, object]:
    return {
        "schema_version": "0verse.windows-token-campaign/v2",
        "starting_context": "eligible-sandbox",
        "eligible_sandbox": SANDBOX,
        "launch_app_container_executable_sha256": LAUNCHER_SHA256,
        "sandbox_process_executable_sha256": SANDBOX_PROCESS_SHA256,
        "app_container_sid": APP_CONTAINER_SID,
    }


def _lpac_capture(
    tmp_path: Path,
    authorities,
    *,
    case: str = "control",
    trial: int = 1,
    tag: str = "a",
    target_transition: bool = False,
) -> tuple[object, str]:
    campaign, campaign_sha, _scope, scope_sha, _grant, grant_sha, _acceptance, acceptance_sha = (
        authorities
    )
    raw = _capture(campaign_sha, scope_sha, grant_sha, acceptance_sha)
    run_nonce = f"lpac_run_nonce_{tag * 32}"
    raw.update(
        {
            "schema_version": "0verse.windows-token-capture/v4",
            "case": case,
            "trial": trial,
            "run_nonce": run_nonce,
            "capture_nonce": f"lpac_capture_nonce_{tag * 28}",
            "process_instance_id": f"lpac_process_instance_{tag * 16}",
            "operation_sha256": (
                campaign.target_operation_sha256
                if case == "target"
                else campaign.control_operation_sha256
            ),
        }
    )
    if not target_transition:
        raw["finish_token"] = json.loads(json.dumps(raw["start_token"]))
    for phase in ("start", "finish"):
        token = raw[f"{phase}_token"]
        assert isinstance(token, dict)
        token["token_id"] = derive_token_id(
            run_nonce, phase, int(token["statistics_token_id_before"])
        )
        token["app_container_sid"] = APP_CONTAINER_SID
        token["app_container"] = True
        token["restricted_sid_count"] = 1
        token["less_privileged_app_container"] = True
    if target_transition:
        finish = raw["finish_token"]
        assert isinstance(finish, dict)
        finish.update(
            {
                "user_sid": "S-1-5-18",
                "integrity_rid": 0x4000,
                "elevated": True,
                "admin_group": "enabled",
                "app_container": False,
                "app_container_sid": "",
                "restricted_sid_count": 0,
                "less_privileged_app_container": False,
                "enabled_privileges": ["SeDebugPrivilege"],
                "token_source": "thread",
                "authentication_id": "00000000000003e7",
            }
        )
    provenance: dict[str, object] = {
        "schema_version": "0verse.windows-lpac-launch-provenance/v1",
        "eligible_sandbox": SANDBOX,
        "launch_app_container_executable_sha256": LAUNCHER_SHA256,
        "sandbox_process_executable_sha256": SANDBOX_PROCESS_SHA256,
        "app_container_sid": APP_CONTAINER_SID,
        "process_creation_identity_sha256": hashlib.sha256(
            f"process-{tag}".encode()
        ).hexdigest(),
        "launch_receipt_sha256": hashlib.sha256(f"receipt-{tag}".encode()).hexdigest(),
        "launch_transcript_sha256": hashlib.sha256(
            f"transcript-{tag}".encode()
        ).hexdigest(),
        "lpac_flag": True,
        "fixed_adapter_operation_sha256": raw["operation_sha256"],
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "execution_grant_sha256": grant_sha,
        "worker_acceptance_sha256": acceptance_sha,
        "case": case,
        "trial": trial,
        "run_nonce": run_nonce,
        "process_instance_id": raw["process_instance_id"],
        "worker": raw["worker"],
        "build_lab_ex": raw["build_lab_ex"],
        "signed_by": raw["signed_by"],
        "signature_ssh": "",
    }
    raw["lpac_launch"] = sign_document(
        provenance, LPAC_LAUNCH_SIGNATURE_NAMESPACE
    )
    path = tmp_path / f"capture-{case}-{trial}.json"
    path.write_text(json.dumps(sign_document(raw, SIGNATURE_NAMESPACE)), encoding="utf-8")
    return load_windows_token_capture(
        path, allowed_signers=authorization_policy(), require_verified=True
    )


def test_eligible_sandbox_requires_additive_campaign_v2(tmp_path: Path) -> None:
    raw = {
        "schema_version": "0verse.windows-token-campaign/v1",
        "campaign_id": "canary-lpe-001",
        "worker": "canary-worker-1",
        "starting_context": "eligible-sandbox",
        "finishing_principal": "local-system",
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "trials": 2,
        "minimum_confirmations": 2,
    }
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="campaign v2"):
        load_windows_token_campaign(path)


def test_campaign_rejects_well_known_app_packages_group_sid(tmp_path: Path) -> None:
    raw = {
        **_lpac_campaign(),
        "campaign_id": "canary-lpe-001",
        "worker": "canary-worker-1",
        "finishing_principal": "local-system",
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "trials": 2,
        "minimum_confirmations": 2,
        "app_container_sid": "S-1-15-2-1",
    }
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="AppContainer SID"):
        load_windows_token_campaign(path)


def test_campaign_cleanly_rejects_overlong_app_container_rid(tmp_path: Path) -> None:
    raw = {
        **_lpac_campaign(),
        "campaign_id": "canary-lpe-001",
        "worker": "canary-worker-1",
        "finishing_principal": "local-system",
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "trials": 2,
        "minimum_confirmations": 2,
        "app_container_sid": "S-1-15-2-" + "9" * 5000 + "-2-3-4-5-6-7-8",
    }
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="AppContainer SID"):
        load_windows_token_campaign(path)


def test_signed_v4_lpac_capture_is_exactly_authority_bound(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path, campaign_overrides=_lpac_campaign())
    capture, digest = _lpac_capture(tmp_path, authorities)
    capture.require_binding(
        authorities[0],
        authorities[1],
        authorities[2],
        authorities[3],
        authorities[4],
        authorities[5],
        authorities[6],
        authorities[7],
        expected_case="control",
        expected_trial=1,
        expected_run_nonce=capture.run_nonce,
    )
    assert len(digest) == 64
    assert capture.start_token.app_container is True
    assert capture.start_token.less_privileged_app_container is True
    assert capture.lpac_launch is not None
    capture.lpac_launch.require_signature()


def test_v4_rejects_logical_lpac_without_appcontainer(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path, campaign_overrides=_lpac_campaign())
    _capture_model, _ = _lpac_capture(tmp_path, authorities)
    path = tmp_path / "capture-control-1.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["start_token"]["app_container"] = False
    path.write_text(json.dumps(sign_document(raw, SIGNATURE_NAMESPACE)), encoding="utf-8")
    with pytest.raises(ValueError, match="LPAC AppContainer start"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())


def test_v4_rejects_logical_finish_lpac_without_appcontainer(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path, campaign_overrides=_lpac_campaign())
    _capture_model, _ = _lpac_capture(
        tmp_path, authorities, case="target", target_transition=True
    )
    path = tmp_path / "capture-target-1.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["finish_token"]["less_privileged_app_container"] = True
    path.write_text(json.dumps(sign_document(raw, SIGNATURE_NAMESPACE)), encoding="utf-8")
    with pytest.raises(ValueError, match="finish AppContainer facts are inconsistent"):
        load_windows_token_capture(path, allowed_signers=authorization_policy())


def test_v4_rejects_post_verification_launch_provenance_mutation(tmp_path: Path) -> None:
    authorities = _authority_bundle(tmp_path, campaign_overrides=_lpac_campaign())
    capture, _ = _lpac_capture(tmp_path, authorities)
    assert capture.lpac_launch is not None
    capture = replace(
        capture,
        lpac_launch=replace(
            capture.lpac_launch, eligible_sandbox="edge-chromium-renderer"
        ),
    )
    with pytest.raises(ValueError, match="differs from signed material"):
        capture.require_binding(
            authorities[0],
            authorities[1],
            authorities[2],
            authorities[3],
            authorities[4],
            authorities[5],
            authorities[6],
            authorities[7],
            expected_case="control",
            expected_trial=1,
            expected_run_nonce=capture.run_nonce,
        )


def test_verified_v4_matrix_remains_disabled_without_native_lpac_capability(
    tmp_path: Path,
) -> None:
    authorities = _authority_bundle(tmp_path, campaign_overrides=_lpac_campaign())
    captures = []
    for trial, target_tag, control_tag in ((1, "a", "b"), (2, "c", "d")):
        captures.append(
            _lpac_capture(
                tmp_path,
                authorities,
                case="target",
                trial=trial,
                tag=target_tag,
                target_transition=True,
            )[0]
        )
        captures.append(
            _lpac_capture(
                tmp_path,
                authorities,
                case="control",
                trial=trial,
                tag=control_tag,
            )[0]
        )
    with pytest.raises(ValueError, match="native authenticated external LPAC witness"):
        observe_windows_token_evidence(captures, *authorities)
