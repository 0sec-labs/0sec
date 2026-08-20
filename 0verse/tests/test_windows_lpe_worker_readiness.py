from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zeroverse.cli import main
from zeroverse.ssh_authority_commitment import ssh_authority_key_commitment
from zeroverse.ssh_authorization import canonical_signed_material, verify_ssh_signature
from zeroverse.windows_lpe_worker_readiness import (
    SIGNATURE_NAMESPACE,
    WindowsLpeWorkerPlan,
    WindowsLpeWorkerReadiness,
    verify_windows_lpe_worker_readiness,
)
from zeroverse.windows_scope import AUTHORIZATION_NAMESPACE
from zeroverse.windows_token_runner import (
    ACCEPTANCE_SIGNATURE_NAMESPACE,
    GRANT_SIGNATURE_NAMESPACE,
)


def _authority(root: Path, name: str) -> tuple[Path, Path, str]:
    key = root / f"{name}-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    identity = f"{name}@example.test"
    policy = root / f"{name}.allowed-signers"
    policy.write_text(
        f"{identity} {key.with_suffix('.pub').read_text(encoding='utf-8').strip()}\n",
        encoding="utf-8",
    )
    return key, policy, identity


def _sign(raw: dict[str, object], key: Path, namespace: str) -> dict[str, object]:
    signed = dict(raw)
    signed["signature_ssh"] = ""
    material = key.parent / f"{key.name}-{namespace}.json"
    material.write_bytes(canonical_signed_material(signed))
    subprocess.run(
        ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", namespace, str(material)],
        check=True,
        capture_output=True,
    )
    signed["signature_ssh"] = Path(f"{material}.sig").read_text(encoding="utf-8")
    material.unlink()
    Path(f"{material}.sig").unlink()
    return signed


def _write(path: Path, raw: dict[str, object]) -> str:
    path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bundle(tmp_path: Path) -> dict[str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    scope_key, scope_policy, scope_identity = _authority(tmp_path, "scope")
    grant_key, grant_policy, grant_identity = _authority(tmp_path, "grant")
    acceptance_key, acceptance_policy, acceptance_identity = _authority(
        tmp_path, "acceptance"
    )
    readiness_key, readiness_policy, readiness_identity = _authority(tmp_path, "readiness")
    campaign_path = tmp_path / "campaign.json"
    campaign = {
        "schema_version": "0verse.windows-token-campaign/v1",
        "campaign_id": "canary-lpe-readiness-001",
        "worker": "canary-worker-1",
        "starting_context": "standard-user",
        "finishing_principal": "local-system",
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "trials": 3,
        "minimum_confirmations": 3,
    }
    campaign_sha = _write(campaign_path, campaign)
    scope_path = tmp_path / "scope.json"
    scope = {
        "schema_version": "0verse.windows-scope/v2",
        "campaign_id": campaign["campaign_id"],
        "program": "windows-canary",
        "scope_url": "https://www.microsoft.com/en-us/msrc/bounty-windows-insider-preview",
        "target_feature": "Windows local privilege boundary",
        "reachability": "owned isolated Canary VM",
        "authorization": "published scope; owned worker; operator controlled",
        "worker": campaign["worker"],
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
        "authorized_by": scope_identity,
        "issued_at": (now - timedelta(minutes=10)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "scope_authorization_nonce_000000001",
        "signature_ssh": "",
    }
    scope_sha = _write(scope_path, _sign(scope, scope_key, AUTHORIZATION_NAMESPACE))
    grant_path = tmp_path / "grant.json"
    grant = {
        "schema_version": "0verse.windows-token-execution-grant/v1",
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "campaign_id": campaign["campaign_id"],
        "worker": campaign["worker"],
        "target_operation_sha256": campaign["target_operation_sha256"],
        "control_operation_sha256": campaign["control_operation_sha256"],
        "issued_at": (now - timedelta(minutes=9)).isoformat(),
        "expires_at": (now + timedelta(minutes=55)).isoformat(),
        "nonce": "execution_grant_nonce_0000000001",
        "authorized_by": grant_identity,
        "signature_ssh": "",
    }
    grant_sha = _write(grant_path, _sign(grant, grant_key, GRANT_SIGNATURE_NAMESPACE))
    acceptance_path = tmp_path / "acceptance.json"
    acceptance = {
        "schema_version": "0verse.windows-token-worker-acceptance/v2",
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "execution_grant_sha256": grant_sha,
        "execution_grant_nonce": grant["nonce"],
        "campaign_id": campaign["campaign_id"],
        "worker": campaign["worker"],
        "build_lab_ex": scope["preflight"]["build_lab_ex"],  # type: ignore[index]
        "worker_machine_id": "owned-isolated-canary-worker",
        "runner_executable_sha256": "c" * 64,
        "witness_user_sid": "S-1-5-21-1-2-3-1001",
        "witness_session_id": 1,
        "witness_authentication_id": "0000000000001001",
        "witness_executable_sha256": "d" * 64,
        "target_operation_sha256": campaign["target_operation_sha256"],
        "control_operation_sha256": campaign["control_operation_sha256"],
        "issued_at": (now - timedelta(minutes=8)).isoformat(),
        "expires_at": (now + timedelta(minutes=50)).isoformat(),
        "nonce": "worker_acceptance_nonce_00000001",
        "accepted_by": acceptance_identity,
        "capture_signer": "capture@example.test",
        "signature_ssh": "",
    }
    acceptance_sha = _write(
        acceptance_path,
        _sign(acceptance, acceptance_key, ACCEPTANCE_SIGNATURE_NAMESPACE),
    )
    artifacts = {
        "checkpoint-before.bin": b"baseline-probe",
        "checkpoint-dirty.bin": b"dirty-probe",
        "checkpoint-after.bin": b"baseline-probe",
        "benign.dmp": b"owned-benign-complete-dump",
        "benign-cdb.txt": b"benign debugger smoke completed\n",
    }
    for filename, data in artifacts.items():
        (tmp_path / filename).write_bytes(data)
    readiness_path = tmp_path / "readiness.json"
    readiness: dict[str, object] = {
        "schema_version": "0verse.windows-lpe-worker-readiness/v1",
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "execution_grant_sha256": grant_sha,
        "worker_acceptance_sha256": acceptance_sha,
        "campaign_id": campaign["campaign_id"],
        "worker": campaign["worker"],
        "build_lab_ex": acceptance["build_lab_ex"],
        "worker_machine_id": acceptance["worker_machine_id"],
        "runner_executable_sha256": acceptance["runner_executable_sha256"],
        "target_vm_name": "isolated-canary-target",
        "checkpoint_name": "clean",
        "checkpoint_identity_sha256": "e" * 64,
        "debugger_executable_sha256": "f" * 64,
        "dump_configuration_sha256": "1" * 64,
        "checkpoint_before_sha256": hashlib.sha256(artifacts["checkpoint-before.bin"]).hexdigest(),
        "checkpoint_dirty_sha256": hashlib.sha256(artifacts["checkpoint-dirty.bin"]).hexdigest(),
        "checkpoint_after_sha256": hashlib.sha256(artifacts["checkpoint-after.bin"]).hexdigest(),
        "benign_dump_sha256": hashlib.sha256(artifacts["benign.dmp"]).hexdigest(),
        "benign_dump_analysis_sha256": hashlib.sha256(artifacts["benign-cdb.txt"]).hexdigest(),
        "drill_started_at": (now - timedelta(minutes=5)).isoformat(),
        "drill_completed_at": (now - timedelta(minutes=2)).isoformat(),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=45)).isoformat(),
        "nonce": "readiness_acceptance_nonce_00000001",
        "accepted_by": readiness_identity,
        "checkpoint_restore_confirmed": True,
        "debugger_smoke_confirmed": True,
        "complete_dump_confirmed": True,
        "network_isolated": True,
        "compile_time_adapter_registry_only": True,
        "arbitrary_command_allowed": False,
        "device_io_control_allowed": False,
        "candidate_execution_authorized": False,
        "human_start_gate": True,
        "signature_ssh": "",
    }
    _write(readiness_path, _sign(readiness, readiness_key, SIGNATURE_NAMESPACE))
    return {
        "campaign": campaign_path,
        "scope": scope_path,
        "grant": grant_path,
        "acceptance": acceptance_path,
        "readiness": readiness_path,
        "scope_policy": scope_policy,
        "grant_policy": grant_policy,
        "acceptance_policy": acceptance_policy,
        "readiness_policy": readiness_policy,
        "readiness_key": readiness_key,
    }


def _verify(paths: dict[str, Path]) -> WindowsLpeWorkerPlan:
    return verify_windows_lpe_worker_readiness(
        campaign_path=paths["campaign"],
        scope_path=paths["scope"],
        execution_grant_path=paths["grant"],
        worker_acceptance_path=paths["acceptance"],
        readiness_path=paths["readiness"],
        scope_allowed_signers=paths["scope_policy"],
        grant_allowed_signers=paths["grant_policy"],
        acceptance_allowed_signers=paths["acceptance_policy"],
        readiness_allowed_signers=paths["readiness_policy"],
    )


def test_verified_readiness_emits_control_first_nonexecuting_plan(tmp_path: Path) -> None:
    paths = _bundle(tmp_path)
    plan = _verify(paths)
    assert plan.status == "UNTRUSTED_POLICY_REVIEW_ONLY"
    assert plan.trusted_policy is False
    assert plan.production_ready is False
    assert plan.artifact_semantics_verified is False
    assert plan.checkpoint_restore_semantics_verified is False
    assert plan.debugger_smoke_semantics_verified is False
    assert plan.complete_dump_semantics_verified is False
    assert plan.opaque_artifact_receipt_only is True
    assert plan.worker_machine_id == "owned-isolated-canary-worker"
    assert plan.target_vm_name == "isolated-canary-target"
    assert plan.checkpoint_identity_sha256 == "e" * 64
    assert plan.debugger_executable_sha256 == "f" * 64
    assert plan.dump_configuration_sha256 == "1" * 64
    assert plan.authority_key_commitments == {
        "scope": ssh_authority_key_commitment(paths["scope_policy"]),
        "execution_grant": ssh_authority_key_commitment(paths["grant_policy"]),
        "worker_acceptance": ssh_authority_key_commitment(paths["acceptance_policy"]),
        "readiness": ssh_authority_key_commitment(paths["readiness_policy"]),
    }
    assert {item["path"] for item in plan.opaque_artifacts} == {
        "checkpoint-before.bin",
        "checkpoint-dirty.bin",
        "checkpoint-after.bin",
        "benign.dmp",
        "benign-cdb.txt",
    }
    assert all(item["semantics_verified"] is False for item in plan.opaque_artifacts)
    assert plan.execution_authorized is False
    assert plan.device_io_control_authorized is False
    adapter_steps = [step for step in plan.steps if step["action"] == "operator-gated-adapter"]
    assert [(step["trial"], step["case"]) for step in adapter_steps] == [
        (1, "control"),
        (1, "target"),
        (2, "control"),
        (2, "target"),
        (3, "control"),
        (3, "target"),
    ]
    assert all(step["execution_authorized"] is False for step in adapter_steps)
    for adapter_index in [
        index for index, step in enumerate(plan.steps) if step["action"] == "operator-gated-adapter"
    ]:
        assert plan.steps[adapter_index - 2]["action"] == "restore-checkpoint"
        assert plan.steps[adapter_index - 1]["action"] == "verify-baseline-probe"
    gates = [step for step in plan.steps if step["action"] == "require-clean-control"]
    assert len(gates) == 3
    assert all(step["on_failure"] == "abort-and-quarantine" for step in gates)
    assert plan.steps[-2]["action"] == "restore-checkpoint"
    assert plan.steps[-1]["action"] == "verify-baseline-probe"


def test_cli_has_no_execute_surface_and_emits_canonical_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = _bundle(tmp_path)
    argv = [
        "windows-lpe-worker-readiness",
        str(paths["readiness"]),
        "--campaign",
        str(paths["campaign"]),
        "--scope-manifest",
        str(paths["scope"]),
        "--execution-grant",
        str(paths["grant"]),
        "--worker-acceptance",
        str(paths["acceptance"]),
        "--scope-allowed-signers",
        str(paths["scope_policy"]),
        "--execution-grant-allowed-signers",
        str(paths["grant_policy"]),
        "--worker-acceptance-allowed-signers",
        str(paths["acceptance_policy"]),
        "--readiness-allowed-signers",
        str(paths["readiness_policy"]),
    ]
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert output == json.dumps(
        json.loads(output), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ) + "\n"
    assert json.loads(output)["execution_authorized"] is False
    assert json.loads(output)["production_ready"] is False
    with pytest.raises(SystemExit):
        main([*argv, "--execute"])


def test_reset_and_fail_closed_safety_are_mandatory() -> None:
    raw: dict[str, object] = {
        name: "x"
        for name in WindowsLpeWorkerReadiness.__dataclass_fields__
        if not name.startswith("_")
    }
    raw.update(
        schema_version="0verse.windows-lpe-worker-readiness/v1",
        **{name: "a" * 64 for name in raw if name.endswith("_sha256")},
        campaign_id="campaign",
        worker="worker",
        target_vm_name="target",
        checkpoint_name="clean",
        nonce="readiness_nonce_000000000000000001",
        drill_started_at="2026-01-01T00:00:00+00:00",
        drill_completed_at="2026-01-01T00:01:00+00:00",
        issued_at="2026-01-01T00:02:00+00:00",
        expires_at="2026-01-01T01:00:00+00:00",
        checkpoint_restore_confirmed=True,
        debugger_smoke_confirmed=True,
        complete_dump_confirmed=True,
        network_isolated=True,
        compile_time_adapter_registry_only=True,
        arbitrary_command_allowed=False,
        device_io_control_allowed=False,
        candidate_execution_authorized=False,
        human_start_gate=True,
    )
    raw["checkpoint_dirty_sha256"] = raw["checkpoint_before_sha256"]
    with pytest.raises(ValueError, match="dirty state"):
        WindowsLpeWorkerReadiness.from_mapping(raw)
    raw["checkpoint_dirty_sha256"] = "b" * 64
    raw["candidate_execution_authorized"] = True
    with pytest.raises(ValueError, match="fail-closed"):
        WindowsLpeWorkerReadiness.from_mapping(raw)


def test_tampered_artifact_and_authority_binding_fail(tmp_path: Path) -> None:
    paths = _bundle(tmp_path)
    (tmp_path / "benign-cdb.txt").write_bytes(b"changed")
    with pytest.raises(ValueError, match="artifact SHA-256 mismatch"):
        _verify(paths)

    paths = _bundle(tmp_path / "other")
    raw = json.loads(paths["readiness"].read_text(encoding="utf-8"))
    raw["build_lab_ex"] = "different-build"
    paths["readiness"].write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="signature"):
        _verify(paths)


def test_readiness_authority_must_be_independent(tmp_path: Path) -> None:
    paths = _bundle(tmp_path)
    paths["readiness_policy"].write_bytes(paths["acceptance_policy"].read_bytes())
    with pytest.raises(ValueError, match=r"signature|independent SSH authorities"):
        _verify(paths)


def test_caller_policy_overrides_can_never_emit_production_ready(tmp_path: Path) -> None:
    plan = _verify(_bundle(tmp_path))
    assert plan.status != "READY_FOR_OPERATOR_REVIEW"
    assert plan.trusted_policy is False
    assert plan.production_ready is False


def test_fixed_default_policies_are_the_only_production_ready_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _bundle(tmp_path)
    defaults = {
        "DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS": paths["scope_policy"],
        "DEFAULT_GRANT_ALLOWED_SIGNERS": paths["grant_policy"],
        "DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS": paths["acceptance_policy"],
        "DEFAULT_ALLOWED_SIGNERS": paths["readiness_policy"],
    }
    for name, value in defaults.items():
        monkeypatch.setattr(
            f"zeroverse.windows_lpe_worker_readiness.{name}", value
        )
    monkeypatch.setattr(
        "zeroverse.windows_scope.DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS",
        paths["scope_policy"],
    )
    monkeypatch.setattr(
        "zeroverse.windows_token_runner.DEFAULT_GRANT_ALLOWED_SIGNERS",
        paths["grant_policy"],
    )
    monkeypatch.setattr(
        "zeroverse.windows_token_runner.DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS",
        paths["acceptance_policy"],
    )

    def verify_as_root_owned(*args: object, **kwargs: object) -> None:
        kwargs["require_trusted_policy"] = False
        verify_ssh_signature(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        "zeroverse.ssh_authorization.verify_ssh_signature", verify_as_root_owned
    )
    monkeypatch.setattr(
        "zeroverse.windows_lpe_worker_readiness.verify_ssh_signature",
        verify_as_root_owned,
    )
    monkeypatch.setattr(
        "zeroverse.windows_token_runner.verify_ssh_signature", verify_as_root_owned
    )
    plan = verify_windows_lpe_worker_readiness(
        campaign_path=paths["campaign"],
        scope_path=paths["scope"],
        execution_grant_path=paths["grant"],
        worker_acceptance_path=paths["acceptance"],
        readiness_path=paths["readiness"],
    )
    assert plan.status == "READY_FOR_OPERATOR_REVIEW"
    assert plan.trusted_policy is True
    assert plan.production_ready is True


def test_drill_must_begin_after_every_authority_is_issued(tmp_path: Path) -> None:
    paths = _bundle(tmp_path)
    acceptance = json.loads(paths["acceptance"].read_text(encoding="utf-8"))
    readiness = json.loads(paths["readiness"].read_text(encoding="utf-8"))
    readiness["drill_started_at"] = (
        datetime.fromisoformat(acceptance["issued_at"]) - timedelta(seconds=1)
    ).isoformat()
    _write(
        paths["readiness"],
        _sign(readiness, paths["readiness_key"], SIGNATURE_NAMESPACE),
    )
    with pytest.raises(ValueError, match="drill predates its authority"):
        _verify(paths)


def test_readiness_and_artifact_symlinks_are_rejected(tmp_path: Path) -> None:
    paths = _bundle(tmp_path)
    readiness_link = tmp_path / "readiness-link.json"
    readiness_link.symlink_to(paths["readiness"])
    with pytest.raises(ValueError, match="missing or unsafe"):
        verify_windows_lpe_worker_readiness(
            campaign_path=paths["campaign"],
            scope_path=paths["scope"],
            execution_grant_path=paths["grant"],
            worker_acceptance_path=paths["acceptance"],
            readiness_path=readiness_link,
            scope_allowed_signers=paths["scope_policy"],
            grant_allowed_signers=paths["grant_policy"],
            acceptance_allowed_signers=paths["acceptance_policy"],
            readiness_allowed_signers=paths["readiness_policy"],
        )

    paths = _bundle(tmp_path / "artifact-link")
    dump = paths["readiness"].parent / "benign.dmp"
    retained = paths["readiness"].parent / "retained.dmp"
    dump.rename(retained)
    dump.symlink_to(retained)
    with pytest.raises(ValueError, match="missing or unsafe"):
        _verify(paths)
