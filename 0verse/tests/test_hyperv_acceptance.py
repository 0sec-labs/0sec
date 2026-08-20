from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

import pytest
from authorization_helpers import authorized_grant, authorized_scope

from zeroverse.hyperv_acceptance import (
    SIGNATURE_NAMESPACE,
    HyperVWorkerAcceptance,
    issue_worker_acceptance,
    load_worker_acceptance,
)
from zeroverse.hyperv_prover import HyperVExecutionGrant, HyperVProverManifest
from zeroverse.hyperv_transport import GuestAcceptanceState, HostAcceptanceState
from zeroverse.windows_scope import WindowsScope

_CAMPAIGN_RAW: dict[str, object] = {
    "campaign_id": "hyperv-acceptance-001",
    "worker": "worker-01.example.test",
    "guest_worker": "attacker-insider",
    "vm_name": "attacker",
    "checkpoint_name": "clean",
    "trigger_argv": ["/root/harness/trigger"],
    "control_argv": ["/root/harness/control"],
    "trials": 2,
    "minimum_confirmations": 2,
}
_CAMPAIGN_BYTES = json.dumps(_CAMPAIGN_RAW, sort_keys=True).encode()
_CAMPAIGN_SHA256 = hashlib.sha256(_CAMPAIGN_BYTES).hexdigest()


def campaign() -> HyperVProverManifest:
    return replace(
        HyperVProverManifest.from_mapping(_CAMPAIGN_RAW),
        _source_material=_CAMPAIGN_BYTES,
        _source_sha256=_CAMPAIGN_SHA256,
    )


@lru_cache(maxsize=1)
def scope() -> WindowsScope:
    now = datetime.now(UTC).isoformat()
    return authorized_scope(
        {
            "campaign_id": "hyperv-acceptance-001", "program": "hyperv-insider",
            "scope_url": "https://example.test/msrc-hyperv-scope",
            "target_feature": "Hyper-V", "reachability": "stock child partition",
            "authorization": "published scope; owned host and guest",
            "worker": "worker-01.example.test", "latest_build_verified_at": now,
            "preflight": {
                "ok": True, "program": "hyperv-insider", "checked_at": now,
                "build_lab_ex": "28020.1.amd64fre.rs_prerelease",
                "product_name": "Windows 11 Pro", "hyperv_available": True,
                "insider": {"ring": "External", "branch_name": "rs_prerelease"},
            },
        }
    )


def grant() -> HyperVExecutionGrant:
    manifest = campaign()
    now = datetime.now(UTC)
    return authorized_grant(
        {
            "campaign_sha256": _CAMPAIGN_SHA256,
            "scope_manifest_sha256": scope()._source_sha256,
            "campaign_id": manifest.campaign_id, "worker": manifest.worker,
            "guest_worker": manifest.guest_worker, "vm_name": manifest.vm_name,
            "checkpoint_name": manifest.checkpoint_name, "dump_path": manifest.dump_path,
            "trigger_executable_sha256": "c" * 64,
            "control_executable_sha256": "d" * 64, "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "nonce": "acceptance-grant-0000000000000001",
            "authorized_by": "operator@example.test",
        }
    )


def _write_signed_bundle(tmp_path: Path, **receipt_updates: object) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    common: dict[str, object] = {
        "campaign_sha256": _CAMPAIGN_SHA256,
        "scope_manifest_sha256": scope()._source_sha256,
        "campaign_id": "hyperv-acceptance-001", "worker": "worker-01.example.test",
        "guest_worker": "attacker-insider", "vm_name": "attacker",
        "checkpoint_name": "clean", "dump_path": "C:\\dumps\\MEMORY.DMP",
        "build_lab_ex": "28020.1.amd64fre.rs_prerelease",
        "checkpoint_identity_sha256": "1" * 64,
        "debugger_executable_sha256": "2" * 64,
        "trigger_executable_sha256": "c" * 64,
        "control_executable_sha256": "d" * 64,
    }
    recovery_artifacts = {
        "benign_dump_sha256": ("recovery-benign.dmp", b"PAGEDU64sanitized-benign-dump"),
        "benign_dump_analysis_sha256": (
            "recovery-benign-cdb.txt",
            b"BugCheck 0, benign debugger smoke\n",
        ),
        "guest_challenge_sha256": (
            "recovery-guest-challenge.json",
            b'{"challenge":"nonce-bound","ok":true}',
        ),
    }
    recovery_hashes: dict[str, str] = {}
    for field_name, (filename, content) in recovery_artifacts.items():
        (tmp_path / filename).write_bytes(content)
        recovery_hashes[field_name] = hashlib.sha256(content).hexdigest()
    drill = {
        "schema_version": "0verse.hyperv-recovery-drill/v1", **common,
        "worker_machine_id": "worker-machine-guid", "guest_machine_id": "guest-machine-id",
        "worker_ssh_host_key_sha256": "4" * 64, "guest_ssh_host_key_sha256": "5" * 64,
        "recovery_nonce": "recovery-drill-00000000000000000001",
        "pre_host_boot_id": "boot-before", "post_host_boot_id": "boot-after",
        "started_at": (now - timedelta(minutes=6)).isoformat(),
        "host_unavailable_observed_at": (now - timedelta(minutes=5)).isoformat(),
        "host_recovered_at": (now - timedelta(minutes=4)).isoformat(),
        "guest_recovered_at": (now - timedelta(minutes=3)).isoformat(),
        "completed_at": (now - timedelta(minutes=2)).isoformat(),
        **recovery_hashes, "out_of_band_controller": "provider-console",
        "host_unavailable_observed": True, "checkpoint_restore_confirmed": True,
        "guest_challenge_confirmed": True, "debugger_smoke_confirmed": True,
    }
    drill_path = tmp_path / "recovery-drill.json"
    drill_path.write_text(json.dumps(drill, sort_keys=True), encoding="utf-8")
    receipt: dict[str, object] = {
        "schema_version": "0verse.hyperv-worker-acceptance/v1", **common,
        "recovery_drill_path": drill_path.name,
        "recovery_drill_sha256": hashlib.sha256(drill_path.read_bytes()).hexdigest(),
        "execution_grant_sha256": "9" * 64,
        "execution_grant_nonce": "acceptance-grant-0000000000000001",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "worker-acceptance-0000000000000001",
        "accepted_by": "lab-acceptance", "signature_ssh": "pending",
    }
    receipt.update(receipt_updates)
    parsed = HyperVWorkerAcceptance.from_mapping(receipt)
    material = tmp_path / "acceptance-material.json"
    material.write_bytes(parsed.signed_material())
    key = tmp_path / "acceptance-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    subprocess.run(
        ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n",
         SIGNATURE_NAMESPACE, str(material)], check=True, capture_output=True,
    )
    receipt["signature_ssh"] = Path(f"{material}.sig").read_text(encoding="utf-8")
    receipt_path = tmp_path / "worker-acceptance.json"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(f"lab-acceptance {key.with_suffix('.pub').read_text()}", encoding="utf-8")
    return receipt_path, allowed


def test_signed_recovery_evidence_binds_campaign_scope_and_toolchain(tmp_path: Path) -> None:
    path, allowed = _write_signed_bundle(tmp_path)
    accepted, digest = load_worker_acceptance(path, allowed_signers=allowed)
    accepted.validate_binding(
        campaign(), _CAMPAIGN_SHA256, scope(), scope()._source_sha256, grant(), "9" * 64
    )
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()


def test_verified_acceptance_cannot_diverge_from_retained_drill_bytes(tmp_path: Path) -> None:
    path, allowed = _write_signed_bundle(tmp_path)
    accepted, _ = load_worker_acceptance(path, allowed_signers=allowed)
    mutated = replace(
        accepted,
        drill=replace(accepted.drill, worker_machine_id="different-worker"),
    )
    with pytest.raises(ValueError, match="differs from retained drill bytes"):
        mutated.validate_binding(
            campaign(), _CAMPAIGN_SHA256, scope(), scope()._source_sha256, grant(), "9" * 64
        )


def test_tampered_receipt_or_recovery_sidecar_is_rejected(tmp_path: Path) -> None:
    path, allowed = _write_signed_bundle(tmp_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["build_lab_ex"] = "different-build"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="signature"):
        load_worker_acceptance(path, allowed_signers=allowed)

    other = tmp_path / "other"
    other.mkdir()
    path, allowed = _write_signed_bundle(other)
    (other / "recovery-drill.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_worker_acceptance(path, allowed_signers=allowed)


def test_recovery_drill_requires_real_transition_and_all_confirmations(tmp_path: Path) -> None:
    path, allowed = _write_signed_bundle(tmp_path)
    drill_path = tmp_path / "recovery-drill.json"
    raw = json.loads(drill_path.read_text(encoding="utf-8"))
    raw["post_host_boot_id"] = raw["pre_host_boot_id"]
    drill_path.write_text(json.dumps(raw), encoding="utf-8")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["recovery_drill_sha256"] = hashlib.sha256(drill_path.read_bytes()).hexdigest()
    path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(ValueError, match=r"boot transition|signature"):
        load_worker_acceptance(path, allowed_signers=allowed)


def test_unknown_fields_and_unsafe_drill_paths_fail_closed(tmp_path: Path) -> None:
    path, _ = _write_signed_bundle(tmp_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["claimed_ready"] = "true"
    with pytest.raises(ValueError, match="unknown"):
        HyperVWorkerAcceptance.from_mapping(raw)
    raw.pop("claimed_ready")
    raw["recovery_drill_path"] = "../outside.json"
    with pytest.raises(ValueError, match="sibling filename"):
        HyperVWorkerAcceptance.from_mapping(raw)


def test_acceptance_must_follow_drill_and_not_outlive_grant(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    path, allowed = _write_signed_bundle(
        tmp_path / "early",
        issued_at=(now - timedelta(minutes=3)).isoformat(),
    )
    accepted, _ = load_worker_acceptance(path, allowed_signers=allowed)
    with pytest.raises(ValueError, match="issued_at"):
        accepted.validate_binding(
            campaign(), _CAMPAIGN_SHA256, scope(), scope()._source_sha256, grant(), "9" * 64
        )

    path, allowed = _write_signed_bundle(
        tmp_path / "late",
        expires_at=(now + timedelta(hours=2)).isoformat(),
    )
    accepted, _ = load_worker_acceptance(path, allowed_signers=allowed)
    with pytest.raises(ValueError, match="expires_at"):
        accepted.validate_binding(
            campaign(), _CAMPAIGN_SHA256, scope(), scope()._source_sha256, grant(), "9" * 64
        )


def test_execution_policy_cannot_be_redirected_by_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, allowed = _write_signed_bundle(tmp_path)
    monkeypatch.setenv("ZEROVERSE_HYPERV_ACCEPTANCE_ALLOWED_SIGNERS", str(allowed))
    with pytest.raises(ValueError, match="allowed-signers"):
        load_worker_acceptance(path)


class IssuerControl:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def host_acceptance_state(self, manifest: HyperVProverManifest) -> HostAcceptanceState:
        self.calls.append("host")
        return HostAcceptanceState(
            "28020.1.amd64fre.rs_prerelease",
            "1" * 64,
            "2" * 64,
            "worker-machine-guid",
            "boot-after",
        )

    def restore_checkpoint(self, manifest: HyperVProverManifest) -> None:
        self.calls.append("restore")

    def wait_guest(self, manifest: HyperVProverManifest) -> None:
        self.calls.append("wait_guest")

    def guest_acceptance_state(self, manifest: HyperVProverManifest) -> GuestAcceptanceState:
        self.calls.append("guest")
        return GuestAcceptanceState("guest-machine-id", "c" * 64, "d" * 64)


def test_independent_issuer_derives_signs_and_self_verifies_bundle(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _, allowed = _write_signed_bundle(source)
    control = IssuerControl()
    receipt_path, digest = issue_worker_acceptance(
        campaign(),
        _CAMPAIGN_SHA256,
        scope(),
        scope()._source_sha256,
        grant(),
        "9" * 64,
        source / "recovery-drill.json",
        tmp_path / "accepted",
        "lab-acceptance",
        control,  # type: ignore[arg-type]
        signing_key=source / "acceptance-key",
        allowed_signers=allowed,
    )
    accepted, loaded_digest = load_worker_acceptance(receipt_path, allowed_signers=allowed)
    accepted.validate_binding(
        campaign(), _CAMPAIGN_SHA256, scope(), scope()._source_sha256, grant(), "9" * 64
    )
    assert digest == loaded_digest
    assert control.calls == ["host", "restore", "wait_guest", "guest"]


def test_issuer_rejects_tampered_recovery_artifact_before_remote_action(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _, allowed = _write_signed_bundle(source)
    (source / "recovery-guest-challenge.json").write_text("tampered", encoding="utf-8")
    control = IssuerControl()
    with pytest.raises(ValueError, match="artifact SHA-256 mismatch"):
        issue_worker_acceptance(
            campaign(), _CAMPAIGN_SHA256, scope(), scope()._source_sha256, grant(), "9" * 64,
            source / "recovery-drill.json", tmp_path / "accepted", "lab-acceptance",
            control,  # type: ignore[arg-type]
            signing_key=source / "acceptance-key", allowed_signers=allowed,
        )
    assert control.calls == []
