from __future__ import annotations

import base64
import hashlib
import json
import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from authorization_helpers import (
    authorization_policy,
    authorized_grant,
    authorized_scope,
    write_signed_grant,
    write_signed_scope,
)

from zeroverse.cli import _retain_verified_sidecar, main
from zeroverse.hyperv_acceptance import VerifiedHyperVWorkerAcceptance
from zeroverse.hyperv_prover import HyperVExecutionGrant, HyperVProverManifest
from zeroverse.hyperv_transport import (
    DumpEvidence,
    DumpPreparation,
    GuestAcceptanceState,
    GuestRun,
    HostAcceptanceState,
    HostState,
    HyperVTransportWorker,
    SshHyperVControlPlane,
    crash_signature,
)
from zeroverse.windows_scope import WindowsScope


def manifest(**updates: object) -> HyperVProverManifest:
    raw: dict[str, object] = {
        "campaign_id": "vmswitch-transport-001",
        "worker": "worker-01.example.test",
        "guest_worker": "attacker-insider",
        "vm_name": "attacker",
        "checkpoint_name": "clean",
        "trigger_argv": ["/root/harness/send-oid", "candidate"],
        "control_argv": ["/root/harness/send-oid", "control"],
        "trials": 2,
        "minimum_confirmations": 2,
    }
    raw.update(updates)
    source = json.dumps(raw, sort_keys=True).encode()
    return replace(
        HyperVProverManifest.from_mapping(raw),
        _source_material=source,
        _source_sha256=hashlib.sha256(source).hexdigest(),
    )


def grant(
    campaign: HyperVProverManifest | None = None,
    *,
    scope_sha256: str = "b" * 64,
) -> HyperVExecutionGrant:
    campaign = campaign or manifest()
    now = datetime.now(UTC)
    return authorized_grant(
        {
            "campaign_sha256": campaign._source_sha256,
            "scope_manifest_sha256": scope_sha256,
            "campaign_id": campaign.campaign_id,
            "worker": campaign.worker,
            "guest_worker": campaign.guest_worker,
            "vm_name": campaign.vm_name,
            "checkpoint_name": campaign.checkpoint_name,
            "dump_path": campaign.dump_path,
            "trigger_executable_sha256": "c" * 64,
            "control_executable_sha256": "c" * 64,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "nonce": "transport-grant-00000000000000001",
            "authorized_by": "operator@example.test",
        }
    )


def scope(campaign: HyperVProverManifest | None = None) -> WindowsScope:
    campaign = campaign or manifest()
    now = datetime.now(UTC)
    return authorized_scope(
        {
            "campaign_id": campaign.campaign_id,
            "program": "hyperv-insider",
            "scope_url": "https://example.test/msrc-hyperv-scope",
            "target_feature": "Hyper-V vmswitch",
            "reachability": "stock child partition RNDIS message",
            "authorization": "published bounty scope; owned host and guest",
            "worker": campaign.worker,
            "latest_build_verified_at": now.isoformat(),
            "preflight": {
                "ok": True,
                "program": "hyperv-insider",
                "checked_at": now.isoformat(),
                "build_lab_ex": "28020.1.amd64fre.rs_prerelease",
                "product_name": "Windows 11 Pro",
                "hyperv_available": True,
                "insider": {"ring": "External", "branch_name": "rs_prerelease"},
            },
        }
    )


class Control:
    def __init__(
        self,
        *,
        after_identity: str = "missing",
        guest: GuestRun | None = None,
        dump: DumpEvidence | None = None,
        acceptance_boot_ids: Sequence[str] = ("boot", "boot"),
        after_identities: Sequence[str] | None = None,
    ) -> None:
        identities = after_identities or (after_identity,)
        self.states = iter([
            state
            for identity in identities
            for state in (
                HostState("28020.1.amd64fre.rs_prerelease", "Running", "old"),
                HostState("28020.1.amd64fre.rs_prerelease", "Running", identity),
            )
        ])
        self.guest = guest or GuestRun(0, "sent", "")
        self.dump = dump or DumpEvidence("d" * 64, "new|artifact", "C:\\dump.dmp", "")
        self.calls: list[str] = []
        self.acceptance_boot_ids = iter(acceptance_boot_ids)

    def host_acceptance_state(self, campaign: HyperVProverManifest) -> HostAcceptanceState:
        self.calls.append("host_acceptance_state")
        return HostAcceptanceState(
            "build", "1" * 64, "2" * 64, "worker", next(self.acceptance_boot_ids)
        )

    def guest_acceptance_state(self, campaign: HyperVProverManifest) -> GuestAcceptanceState:
        self.calls.append("guest_acceptance_state")
        return GuestAcceptanceState("guest", "c" * 64, "c" * 64)

    def host_state(self, campaign: HyperVProverManifest) -> HostState:
        self.calls.append("host_state")
        return next(self.states)

    def restore_checkpoint(self, campaign: HyperVProverManifest) -> None:
        self.calls.append("restore")

    def wait_guest(self, campaign: HyperVProverManifest) -> None:
        self.calls.append("wait_guest")

    def prepare_dump(
        self,
        campaign: HyperVProverManifest,
        *,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> DumpPreparation:
        self.calls.append("prepare_dump")
        return DumpPreparation(1)

    def invoke_guest(
        self,
        campaign: HyperVProverManifest,
        argv: Sequence[str],
        *,
        expected_executable_sha256: str,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> GuestRun:
        self.calls.append("invoke_guest")
        argv_sha = hashlib.sha256(
            json.dumps(list(argv), separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        return GuestRun(
            returncode=self.guest.returncode,
            stdout=self.guest.stdout,
            stderr=self.guest.stderr,
            timed_out=self.guest.timed_out,
            run_nonce=run_nonce,
            case=case,
            trial=trial,
            argv_sha256=argv_sha,
            started=True,
            finished=True,
        )

    def wait_host(self, campaign: HyperVProverManifest) -> None:
        self.calls.append("wait_host")

    def collect_dump(
        self,
        campaign: HyperVProverManifest,
        *,
        expected_identity: str,
        preparation: DumpPreparation,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> DumpEvidence:
        self.calls.append("collect_dump")
        return self.dump

    def retain_dump(
        self,
        campaign: HyperVProverManifest,
        evidence: DumpEvidence,
        destination: Path,
    ) -> None:
        self.calls.append("retain_dump")
        destination.write_bytes(b"sanitized dump\n")


class Acceptance:
    def validate_binding(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def validate_live_host(
        self, state: dict[str, str], *, expected_host_boot_id: str | None = None
    ) -> None:
        assert state["checkpoint_identity_sha256"] == "1" * 64
        if state["host_boot_id"] != expected_host_boot_id:
            raise ValueError("live Hyper-V host acceptance drift: host_boot_id")

    def validate_live_guest(self, state: dict[str, str]) -> None:
        assert state["trigger_executable_sha256"] == "c" * 64


def transport_worker(
    control: Control,
    acceptance: Acceptance | None = None,
    *,
    artifact_dir: Path | None = None,
) -> HyperVTransportWorker:
    campaign = manifest()
    return HyperVTransportWorker(
        control,
        grant(campaign),
        acceptance or Acceptance(),  # type: ignore[arg-type]
        scope(campaign),
        campaign._source_sha256,
        "b" * 64,
        "e" * 64,
        artifact_dir=artifact_dir,
    )


def ssh_plane(
    runner: object | None = None,
    *,
    sleeper: object | None = None,
    campaign: HyperVProverManifest | None = None,
) -> SshHyperVControlPlane:
    kwargs: dict[str, object] = {}
    if runner is not None:
        kwargs["runner"] = runner
    if sleeper is not None:
        kwargs["sleeper"] = sleeper
    campaign = campaign or manifest()
    scope_manifest = scope(campaign)
    execution_grant = grant(campaign, scope_sha256=scope_manifest._source_sha256)
    acceptance = Mock(spec=VerifiedHyperVWorkerAcceptance)
    return SshHyperVControlPlane(
        scope_manifest,
        execution_grant,
        campaign._source_sha256,
        scope_manifest._source_sha256,
        acceptance,
        "e" * 64,
        **kwargs,
    )  # type: ignore[arg-type]


def test_clean_trial_has_no_crash_authority(tmp_path: Path) -> None:
    control = Control()
    row = transport_worker(control, artifact_dir=tmp_path).run_case(
        manifest(), case="control", trial=1, argv=("/root/harness/send-oid", "control")
    )
    assert row.status == "CLEAN"
    assert row.crash_signature == ""
    assert row.guest_transcript_sha256
    transcript_bytes = Path(row.guest_transcript_path).read_bytes()
    assert hashlib.sha256(transcript_bytes).hexdigest() == row.guest_transcript_sha256
    transcript = json.loads(transcript_bytes)
    assert transcript["run_nonce"] == row.run_nonce
    assert transcript["case"] == "control"
    assert transcript["trial"] == 1
    assert control.calls == [
        "host_acceptance_state",
        "host_state",
        "restore",
        "wait_guest",
        "guest_acceptance_state",
        "prepare_dump",
        "invoke_guest",
        "wait_host",
        "host_state",
        "host_acceptance_state",
    ]


def test_live_acceptance_drift_stops_before_checkpoint_restore() -> None:
    control = Control()

    class Drift(Acceptance):
        def validate_live_host(
            self, state: dict[str, str], *, expected_host_boot_id: str | None = None
        ) -> None:
            raise ValueError("live Hyper-V host acceptance drift: checkpoint")

    row = transport_worker(control, Drift()).run_case(
        manifest(), case="control", trial=1, argv=("/root/harness/send-oid", "control")
    )
    assert row.status == "ERROR"
    assert "acceptance drift" in row.error
    assert control.calls == ["host_acceptance_state"]


def test_new_dump_and_cdb_signature_are_required_for_crash(tmp_path: Path) -> None:
    analysis = "BugCheck 133, {0, 1}\nFAILURE_BUCKET_ID: 0x133_DPC_vmswitch!ParseOid\n"
    control = Control(
        after_identity="new",
        acceptance_boot_ids=("boot", "boot-after-crash"),
        dump=DumpEvidence(
            hashlib.sha256(b"sanitized dump\n").hexdigest(),
            "new|artifact",
            "C:\\artifact.dmp",
            analysis,
        ),
    )
    row = transport_worker(control, artifact_dir=tmp_path).run_case(
        manifest(), case="target", trial=1, argv=("/root/harness/send-oid", "candidate")
    )
    assert row.status == "CRASH"
    assert row.crash_signature == "bugcheck-133:0x133_dpc_vmswitch!parseoid"
    assert row.dump_sha256 == hashlib.sha256(b"sanitized dump\n").hexdigest()
    assert Path(row.dump_analysis_path).read_text() == analysis
    assert row.dump_analysis_sha256 == hashlib.sha256(analysis.encode()).hexdigest()
    assert row.dump_identity == "new|artifact"
    assert control.calls[-2:] == ["collect_dump", "retain_dump"]


def test_dump_backed_boot_transition_allows_the_next_confirmation(tmp_path: Path) -> None:
    analysis = "BugCheck 133, {0, 1}\nFAILURE_BUCKET_ID: vmswitch!ParseOid\n"
    control = Control(
        after_identities=("new", "missing"),
        acceptance_boot_ids=("boot", "boot-after-crash", "boot-after-crash", "boot-after-crash"),
        dump=DumpEvidence(
            hashlib.sha256(b"sanitized dump\n").hexdigest(),
            "new|artifact",
            "C:\\artifact.dmp",
            analysis,
        ),
    )
    worker = transport_worker(control, artifact_dir=tmp_path)
    crash = worker.run_case(
        manifest(), case="target", trial=1, argv=("/root/harness/send-oid", "candidate")
    )
    clean = worker.run_case(
        manifest(), case="control", trial=2, argv=("/root/harness/send-oid", "control")
    )
    assert crash.status == "CRASH"
    assert clean.status == "CLEAN"


def test_unexplained_boot_transition_quarantines_worker() -> None:
    control = Control(acceptance_boot_ids=("boot", "unexpected-boot"))
    worker = transport_worker(control)
    first = worker.run_case(
        manifest(), case="control", trial=1, argv=("/root/harness/send-oid", "control")
    )
    second = worker.run_case(
        manifest(), case="target", trial=1, argv=("/root/harness/send-oid", "candidate")
    )
    assert first.status == "ERROR"
    assert "host_boot_id" in first.error
    assert second.status == "ERROR"
    assert "quarantined" in second.error


def test_sidecar_retention_never_overwrites_existing_evidence(tmp_path: Path) -> None:
    worker = transport_worker(Control(), artifact_dir=tmp_path)
    path = Path(worker._write_artifact("fixed-sidecar.json", b"first"))
    with pytest.raises(FileExistsError):
        worker._write_artifact("fixed-sidecar.json", b"second")
    assert path.read_bytes() == b"first"


def test_guest_failure_without_new_dump_is_error() -> None:
    control = Control(guest=GuestRun(255, "", "connection lost"))
    row = transport_worker(control).run_case(
        manifest(), case="target", trial=1, argv=("/root/harness/send-oid", "candidate")
    )
    assert row.status == "ERROR"
    assert "no new crash dump" in row.error


def test_new_dump_without_stable_signature_is_error() -> None:
    control = Control(
        after_identity="new",
        acceptance_boot_ids=("boot", "boot-after-crash"),
        dump=DumpEvidence(
            "a" * 64,
            "new|artifact",
            "C:\\artifact.dmp",
            "cdb loaded a dump but emitted no bucket",
        ),
    )
    row = transport_worker(control).run_case(
        manifest(), case="target", trial=1, argv=("/root/harness/send-oid", "candidate")
    )
    assert row.status == "ERROR"
    assert "stable cdb" in row.error


def test_new_dump_without_guest_start_record_is_error() -> None:
    analysis = "BugCheck 133, {0, 1}\nFAILURE_BUCKET_ID: vmswitch!ParseOid\n"
    control = Control(
        after_identity="new",
        guest=GuestRun(255, "", "connection lost"),
        dump=DumpEvidence("a" * 64, "new|artifact", "C:\\artifact.dmp", analysis),
    )

    class NoStart(Control):
        def invoke_guest(
            self,
            campaign: HyperVProverManifest,
            argv: Sequence[str],
            **kwargs: object,
        ) -> GuestRun:
            self.calls.append("invoke_guest")
            return self.guest

    no_start = NoStart(after_identity="new", guest=control.guest, dump=control.dump)
    row = transport_worker(no_start).run_case(
        manifest(), case="target", trial=1, argv=("/root/harness/send-oid", "candidate")
    )
    assert row.status == "ERROR"
    assert "requested run" in row.error or "start record" in row.error


def test_signature_needs_bugcheck_and_bucket() -> None:
    assert crash_signature("BugCheck 7E, {0}\nFAILURE_BUCKET_ID: AV_vmswitch!Foo")
    assert crash_signature("BugCheck 7E, {0}") == ""
    assert crash_signature("FAILURE_BUCKET_ID: AV_vmswitch!Foo") == ""


def test_ssh_host_state_uses_marked_json() -> None:
    seen: list[Sequence[str]] = []

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(
            argv,
            0,
            '0VERSE-HYPERV-JSON:{"build_lab_ex":"test-build","vm_state":"Running",'
            '"dump_identity":"1:2:3"}\n',
            "",
        )

    state = ssh_plane(runner).host_state(manifest())
    assert state == HostState("test-build", "Running", "1:2:3")
    assert seen[0][:10] == [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "NumberOfPasswordPrompts=0",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=8",
        "--",
    ]
    assert seen[0][10] == "worker-01.example.test"


def test_raw_control_plane_rechecks_signed_capability_before_commands() -> None:
    seen: list[Sequence[str]] = []

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    campaign = manifest()
    scope_manifest = scope(campaign)
    signed_grant = grant(campaign, scope_sha256=scope_manifest._source_sha256)
    plane = SshHyperVControlPlane(
        scope_manifest,
        replace(signed_grant, vm_name="unauthorized-vm"),
        campaign._source_sha256,
        scope_manifest._source_sha256,
        acceptance_probe_only=True,
        runner=runner,
    )
    with pytest.raises(ValueError, match="differ from signed material"):
        plane.restore_checkpoint(manifest())
    assert seen == []


def test_retained_sidecar_hash_is_checked_after_copy(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    destination = tmp_path / "retained.json"
    source.write_bytes(b"replaced bytes")
    with pytest.raises(ValueError, match="retained sidecar SHA-256 mismatch"):
        _retain_verified_sidecar(source, destination, "0" * 64)
    assert not destination.exists()


def test_ssh_acceptance_state_collects_host_and_guest_identities() -> None:
    calls = 0

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(
                argv,
                0,
                '0VERSE-HYPERV-JSON:{"build_lab_ex":"build","checkpoint_identity_sha256":"'
                + "1" * 64
                + '","debugger_executable_sha256":"'
                + "2" * 64
                + '","worker_machine_id":"worker-guid","host_boot_id":"boot-id"}\n',
                "",
            )
        return subprocess.CompletedProcess(
            argv,
            0,
            "0VERSE-HYPERV-GUEST-STATE:guest-machine\n"
            + "c" * 64
            + "  /root/harness/send-oid\n"
            + "c" * 64
            + "  /root/harness/send-oid-control\n",
            "",
        )

    plane = ssh_plane(runner)
    host = plane.host_acceptance_state(manifest())
    guest = plane.guest_acceptance_state(manifest())
    assert host.checkpoint_identity_sha256 == "1" * 64
    assert host.debugger_executable_sha256 == "2" * 64
    assert guest == GuestAcceptanceState("guest-machine", "c" * 64, "c" * 64)


def test_wait_host_polls_until_external_host_recovers() -> None:
    returns = iter([255, 0])
    sleeps: list[float] = []

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, next(returns), "", "offline")

    campaign = manifest(settle_seconds=1, poll_interval_seconds=2)
    control = ssh_plane(runner, sleeper=sleeps.append, campaign=campaign)
    control.wait_host(campaign)
    assert sleeps == [1, 2]


def test_wait_host_treats_probe_timeout_as_a_failed_poll() -> None:
    calls = 0
    sleeps: list[float] = []

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise subprocess.TimeoutExpired(argv, timeout)
        return subprocess.CompletedProcess(argv, 0, "", "")

    campaign = manifest(settle_seconds=1, poll_interval_seconds=2)
    control = ssh_plane(runner, sleeper=sleeps.append, campaign=campaign)
    control.wait_host(campaign)
    assert calls == 2
    assert sleeps == [1, 2]


def test_guest_runner_is_remote_bounded_hash_bound_and_shell_quoted() -> None:
    seen: list[tuple[Sequence[str], int]] = []
    nonce = "case-nonce-0000000000000000000001"

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        seen.append((argv, timeout))
        return subprocess.CompletedProcess(
            argv,
            0,
            f"0VERSE-HYPERV-GUEST-START:{nonce}:target:1\n"
            f"0VERSE-HYPERV-GUEST-FINISH:{nonce}:0\n",
            "",
        )

    argv = ("/root/harness/send-oid", "; touch /tmp/should-not-run", "$(id)")
    campaign = manifest(guest_timeout_seconds=7, trigger_argv=list(argv))
    row = ssh_plane(runner, campaign=campaign).invoke_guest(
        campaign,
        argv,
        expected_executable_sha256="c" * 64,
        run_nonce=nonce,
        case="target",
        trial=1,
    )
    assert row.started and row.finished and not row.timed_out
    command, timeout = seen[0]
    assert timeout == 30
    remote = command[-1]
    parsed = shlex.split(remote)
    assert parsed[-3:] == list(argv)
    assert parsed[0] == "/usr/local/sbin/0verse-hyperv-guest-runner"
    assert "StrictHostKeyChecking=yes" in command


def test_guest_local_timeout_preserves_start_and_never_claims_clean() -> None:
    nonce = "case-nonce-0000000000000000000002"

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            argv,
            timeout,
            output=f"0VERSE-HYPERV-GUEST-START:{nonce}:target:1\n",
        )

    row = ssh_plane(runner).invoke_guest(
        manifest(),
        ("/root/harness/send-oid", "candidate"),
        expected_executable_sha256="c" * 64,
        run_nonce=nonce,
        case="target",
        trial=1,
    )
    assert row.timed_out and row.started and not row.finished


def test_raw_guest_invocation_is_bound_to_campaign_argv_and_grant_hash() -> None:
    seen: list[Sequence[str]] = []

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    plane = ssh_plane(runner)
    with pytest.raises(ValueError, match="argv differs"):
        plane.invoke_guest(
            manifest(),
            ("/root/harness/send-oid", "unsigned"),
            expected_executable_sha256="c" * 64,
            run_nonce="case-nonce-0000000000000000000003",
            case="target",
            trial=1,
        )
    with pytest.raises(ValueError, match="hash differs"):
        plane.invoke_guest(
            manifest(),
            manifest().trigger_argv,
            expected_executable_sha256="f" * 64,
            run_nonce="case-nonce-0000000000000000000004",
            case="target",
            trial=1,
        )
    assert seen == []


def test_dump_collection_binds_snapshot_and_checks_cdb_exit() -> None:
    captured_script = ""

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        nonlocal captured_script
        encoded = argv[-1].rsplit(" ", 1)[-1]
        captured_script = base64.b64decode(encoded).decode("utf-16le")
        return subprocess.CompletedProcess(
            argv,
            0,
            "BugCheck 133, {0}\nFAILURE_BUCKET_ID: vmswitch!ParseOid\n"
            '0VERSE-HYPERV-DUMP-JSON:{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity":"1:2:3|nonce|target|1|a",'
            '"artifact_path":"C:\\\\dumps\\\\0verse-evidence\\\\case.dmp"}\n',
            "",
        )

    evidence = ssh_plane(runner).collect_dump(
        manifest(),
        expected_identity="1:2:3",
        preparation=DumpPreparation(42),
        run_nonce="nonce",
        case="target",
        trial=1,
    )
    assert evidence.sha256 == "a" * 64
    assert evidence.identity.startswith("1:2:3|")
    assert "$LASTEXITCODE" in captured_script
    assert "dump changed while snapshotting" in captured_script
    assert "dump artifact changed during analysis" in captured_script


def test_dump_retention_uses_strict_scp_and_refuses_bad_remote_paths(tmp_path: Path) -> None:
    captured: list[str] = []

    def runner(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        captured.extend(argv)
        Path(argv[-1]).write_bytes(b"retained dump")
        return subprocess.CompletedProcess(argv, 0, "", "")

    plane = ssh_plane(runner)
    destination = tmp_path / "retained.dmp"
    plane.retain_dump(
        manifest(),
        DumpEvidence("a" * 64, "identity", "C:\\dumps\\0verse-evidence\\case.dmp", ""),
        destination,
    )
    assert destination.read_bytes() == b"retained dump"
    assert captured[0] == "scp"
    assert "StrictHostKeyChecking=yes" in captured

    with pytest.raises(RuntimeError, match="invalid retained dump path"):
        plane.retain_dump(
            manifest(),
            DumpEvidence("a" * 64, "identity", "..\\case.dmp", ""),
            tmp_path / "bad.dmp",
        )


def test_cli_defaults_to_validation_without_transport(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = datetime.now(UTC).isoformat()
    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(
        json.dumps(manifest().to_dict()),
        encoding="utf-8",
    )
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-scope/v1",
                "campaign_id": "vmswitch-transport-001",
                "program": "hyperv-insider",
                "scope_url": "https://example.test/msrc-hyperv-scope",
                "target_feature": "Hyper-V vmswitch",
                "reachability": "stock child partition RNDIS message",
                "authorization": "published bounty scope; owned host and guest",
                "worker": "worker-01.example.test",
                "latest_build_verified_at": now,
                "preflight": {
                    "ok": True,
                    "program": "hyperv-insider",
                    "checked_at": now,
                    "build_lab_ex": "28020.1.amd64fre.rs_prerelease",
                    "product_name": "Windows 11 Pro",
                    "hyperv_available": True,
                    "insider": {"ring": "External", "branch_name": "rs_prerelease"},
                },
            }
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "hyperv-prove",
                str(campaign_path),
                "--scope-manifest",
                str(scope_path),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "VALIDATED"
    assert output["execution_required"] is True
    assert output["execution_grant_required"] is True
    assert output["worker_acceptance_required"] is True

    assert (
        main(
            [
                "hyperv-prove",
                str(campaign_path),
                "--scope-manifest",
                str(scope_path),
                "--execute",
            ]
        )
        == 2
    )
    assert "--execution-grant" in capsys.readouterr().err


def test_cli_execute_requires_artifact_retention(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zeroverse.hyperv_prover as hyperv_prover_module
    import zeroverse.ssh_authorization as ssh_authorization_module
    import zeroverse.windows_scope as windows_scope_module

    policy = authorization_policy()
    monkeypatch.setattr(
        windows_scope_module, "DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS", policy
    )
    monkeypatch.setattr(
        hyperv_prover_module, "DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS", policy
    )
    real_verify = ssh_authorization_module.verify_ssh_signature

    def verify_test_policy(*args: object, **kwargs: object) -> None:
        kwargs["require_trusted_policy"] = False
        real_verify(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        ssh_authorization_module, "verify_ssh_signature", verify_test_policy
    )
    now = datetime.now(UTC).isoformat()
    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(json.dumps(manifest().to_dict()), encoding="utf-8")
    scope_path = tmp_path / "scope.json"
    scope_payload: dict[str, object] = {
        "campaign_id": "vmswitch-transport-001",
        "program": "hyperv-insider",
        "scope_url": "https://example.test/scope",
        "target_feature": "vmswitch",
        "reachability": "stock child partition",
        "authorization": "published scope; owned host",
        "worker": "worker-01.example.test",
        "latest_build_verified_at": now,
        "preflight": {
            "ok": True,
            "program": "hyperv-insider",
            "checked_at": now,
            "build_lab_ex": "28020.1.amd64fre.rs_prerelease",
            "product_name": "Windows 11 Pro",
            "hyperv_available": True,
            "insider": {"ring": "External", "branch_name": "rs_prerelease"},
        },
    }
    scope_digest = write_signed_scope(scope_payload, scope_path)
    grant_payload = grant().to_dict()
    grant_payload["campaign_sha256"] = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
    grant_payload["scope_manifest_sha256"] = scope_digest
    grant_path = tmp_path / "execution-grant.json"
    write_signed_grant(grant_payload, grant_path)
    assert (
        main(
            [
                "hyperv-prove",
                str(campaign_path),
                "--scope-manifest",
                str(scope_path),
                "--execute",
                "--execution-grant",
                str(grant_path),
            ]
        )
        == 2
    )
    assert "--artifact-dir" in capsys.readouterr().err

    assert (
        main(
            [
                "hyperv-prove",
                str(campaign_path),
                "--scope-manifest",
                str(scope_path),
                "--execute",
                "--execution-grant",
                str(grant_path),
                "--artifact-dir",
                str(tmp_path / "evidence"),
            ]
        )
        == 2
    )
    assert "--worker-acceptance" in capsys.readouterr().err
