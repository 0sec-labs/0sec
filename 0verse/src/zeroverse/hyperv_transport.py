"""External control-plane transport for the Hyper-V deterministic prover.

This module never infers a vulnerability from a dropped SSH connection or a
non-zero guest exit.  A crash exists only when the host produces a new dump and
cdb yields a stable bugcheck/failure-bucket signature.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shlex
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, Protocol

from .hyperv_prover import (
    HyperVExecutionGrant,
    HyperVObservation,
    HyperVProverManifest,
    validate_campaign_scope,
)
from .windows_scope import WindowsScope

if TYPE_CHECKING:
    from .hyperv_acceptance import VerifiedHyperVWorkerAcceptance

_JSON_MARKER = "0VERSE-HYPERV-JSON:"
_DUMP_MARKER = "0VERSE-HYPERV-DUMP-JSON:"
_GUEST_START_MARKER = "0VERSE-HYPERV-GUEST-START:"
_GUEST_FINISH_MARKER = "0VERSE-HYPERV-GUEST-FINISH:"
_GUEST_STATE_MARKER = "0VERSE-HYPERV-GUEST-STATE:"
_GUEST_RUNNER = "/usr/local/sbin/0verse-hyperv-guest-runner"
_DEBUGGER = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe"
_BUCKET_RE = re.compile(r"^\s*FAILURE_BUCKET_ID:\s*(\S.+?)\s*$", re.IGNORECASE | re.MULTILINE)
# Accepts both "BugCheck 50, {...}" (kd live / older cdb) and the newer cdb -z
# "Bugcheck code 00000050" banner (measured on Win Kits 10.0.26100 cdb).
_BUGCHECK_RE = re.compile(r"^\s*Bug[Cc]heck(?:\s+code)?\s+([0-9A-Fa-f]+)(?:,|\s|$)", re.MULTILINE)


@dataclass(frozen=True)
class HostState:
    build_lab_ex: str
    vm_state: str
    dump_identity: str


@dataclass(frozen=True)
class DumpPreparation:
    prepared_at_utc_ticks: int
    archived_path: str = ""


@dataclass(frozen=True)
class GuestRun:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    run_nonce: str = ""
    case: str = ""
    trial: int = 0
    argv_sha256: str = ""
    started: bool = False
    finished: bool = False

    @property
    def transcript_bytes(self) -> bytes:
        return json.dumps(
            {
                "returncode": self.returncode,
                "stdout": self.stdout,
                "stderr": self.stderr,
                "timed_out": self.timed_out,
                "run_nonce": self.run_nonce,
                "case": self.case,
                "trial": self.trial,
                "argv_sha256": self.argv_sha256,
                "started": self.started,
                "finished": self.finished,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def transcript_sha256(self) -> str:
        return hashlib.sha256(self.transcript_bytes).hexdigest()


@dataclass(frozen=True)
class DumpEvidence:
    sha256: str
    identity: str
    artifact_path: str
    analysis: str


@dataclass(frozen=True)
class HostAcceptanceState:
    build_lab_ex: str
    checkpoint_identity_sha256: str
    debugger_executable_sha256: str
    worker_machine_id: str
    host_boot_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "build_lab_ex": self.build_lab_ex,
            "checkpoint_identity_sha256": self.checkpoint_identity_sha256,
            "debugger_executable_sha256": self.debugger_executable_sha256,
            "worker_machine_id": self.worker_machine_id,
            "host_boot_id": self.host_boot_id,
        }


@dataclass(frozen=True)
class GuestAcceptanceState:
    guest_machine_id: str
    trigger_executable_sha256: str
    control_executable_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "guest_machine_id": self.guest_machine_id,
            "trigger_executable_sha256": self.trigger_executable_sha256,
            "control_executable_sha256": self.control_executable_sha256,
        }


class HyperVControlPlane(Protocol):
    def host_acceptance_state(self, manifest: HyperVProverManifest) -> HostAcceptanceState: ...

    def guest_acceptance_state(self, manifest: HyperVProverManifest) -> GuestAcceptanceState: ...

    def host_state(self, manifest: HyperVProverManifest) -> HostState: ...

    def restore_checkpoint(self, manifest: HyperVProverManifest) -> None: ...

    def wait_guest(self, manifest: HyperVProverManifest) -> None: ...

    def prepare_dump(
        self,
        manifest: HyperVProverManifest,
        *,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> DumpPreparation: ...

    def invoke_guest(
        self,
        manifest: HyperVProverManifest,
        argv: Sequence[str],
        *,
        expected_executable_sha256: str,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> GuestRun: ...

    def wait_host(self, manifest: HyperVProverManifest) -> None: ...

    def collect_dump(
        self,
        manifest: HyperVProverManifest,
        *,
        expected_identity: str,
        preparation: DumpPreparation,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> DumpEvidence: ...

    def retain_dump(
        self,
        manifest: HyperVProverManifest,
        evidence: DumpEvidence,
        destination: Path,
    ) -> None: ...


@dataclass
class HyperVTransportWorker:
    control: HyperVControlPlane
    execution_grant: HyperVExecutionGrant
    worker_acceptance: VerifiedHyperVWorkerAcceptance
    scope: WindowsScope
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    artifact_dir: Path | None = None
    _expected_host_boot_id: str = field(default="", init=False, repr=False)
    _quarantined: bool = field(default=False, init=False, repr=False)

    def run_case(
        self,
        manifest: HyperVProverManifest,
        *,
        case: str,
        trial: int,
        argv: Sequence[str],
    ) -> HyperVObservation:
        self.scope.require_signed_authorization()
        self.execution_grant.require_signed_authorization()
        self.execution_grant.validate_binding(
            manifest, self.campaign_sha256, self.scope_manifest_sha256
        )
        self.worker_acceptance.validate_binding(
            manifest,
            self.campaign_sha256,
            self.scope,
            self.scope_manifest_sha256,
            self.execution_grant,
            self.execution_grant_sha256,
        )
        build = ""
        transcript = ""
        transcript_path = ""
        run_nonce = secrets.token_urlsafe(24)
        argv_sha256 = _argv_sha256(argv)
        try:
            if self._quarantined:
                raise RuntimeError("Hyper-V worker is quarantined after uncertain state")
            accepted_host = self.control.host_acceptance_state(manifest)
            expected_boot = self._expected_host_boot_id or accepted_host.host_boot_id
            self.worker_acceptance.validate_live_host(
                accepted_host.to_dict(), expected_host_boot_id=expected_boot
            )
            if not self._expected_host_boot_id:
                self._expected_host_boot_id = accepted_host.host_boot_id
            before = self.control.host_state(manifest)
            build = before.build_lab_ex
            self.control.restore_checkpoint(manifest)
            self.control.wait_guest(manifest)
            accepted_guest = self.control.guest_acceptance_state(manifest)
            self.worker_acceptance.validate_live_guest(accepted_guest.to_dict())
            preparation = self.control.prepare_dump(
                manifest, run_nonce=run_nonce, case=case, trial=trial
            )
            expected_hash = (
                self.execution_grant.trigger_executable_sha256
                if case == "target"
                else self.execution_grant.control_executable_sha256
            )
            guest = self.control.invoke_guest(
                manifest,
                argv,
                expected_executable_sha256=expected_hash,
                run_nonce=run_nonce,
                case=case,
                trial=trial,
            )
            if (
                guest.run_nonce != run_nonce
                or guest.case != case
                or guest.trial != trial
                or guest.argv_sha256 != argv_sha256
            ):
                raise RuntimeError("guest evidence was not bound to the requested run")
            transcript = guest.transcript_sha256
            transcript_path = self._write_artifact(
                f"{run_nonce}-trial-{trial:02d}-{case}-guest.json",
                guest.transcript_bytes,
            )
            self.control.wait_host(manifest)
            after = self.control.host_state(manifest)
            recovered_host = self.control.host_acceptance_state(manifest)
            if after.build_lab_ex != before.build_lab_ex:
                raise RuntimeError(
                    "Windows build changed during Hyper-V trial: "
                    f"{before.build_lab_ex!r} -> {after.build_lab_ex!r}"
                )
            if after.dump_identity != "missing":
                if recovered_host.host_boot_id == self._expected_host_boot_id:
                    raise RuntimeError("dump-backed crash did not produce a host boot transition")
                self.worker_acceptance.validate_live_host(
                    recovered_host.to_dict(),
                    expected_host_boot_id=recovered_host.host_boot_id,
                )
                self._expected_host_boot_id = recovered_host.host_boot_id
                if not guest.started:
                    raise RuntimeError("new host dump lacked a nonce-bound guest start record")
                dump = self.control.collect_dump(
                    manifest,
                    expected_identity=after.dump_identity,
                    preparation=preparation,
                    run_nonce=run_nonce,
                    case=case,
                    trial=trial,
                )
                signature = crash_signature(dump.analysis)
                if not signature:
                    raise RuntimeError("new host dump had no stable cdb crash signature")
                if not re.fullmatch(r"[0-9a-f]{64}", dump.sha256):
                    raise RuntimeError("new host dump had no valid SHA-256")
                if not dump.identity.startswith(f"{after.dump_identity}|"):
                    raise RuntimeError("dump artifact was not bound to the observed host dump")
                if self.artifact_dir is None:
                    raise RuntimeError("crash dump cannot be retained without artifact_dir")
                dump_path = self.artifact_dir.resolve() / (
                    f"{run_nonce}-trial-{trial:02d}-{case}.dmp"
                )
                self.control.retain_dump(manifest, dump, dump_path)
                if not dump_path.is_file() or _sha256_path(dump_path) != dump.sha256:
                    raise RuntimeError("retained crash dump did not match worker SHA-256")
                analysis_bytes = dump.analysis.encode()
                analysis_path = self._write_artifact(
                    f"{run_nonce}-trial-{trial:02d}-{case}-cdb.txt",
                    analysis_bytes,
                )
                return HyperVObservation(
                    case=case,
                    trial=trial,
                    build_lab_ex=build,
                    status="CRASH",
                    crash_signature=signature,
                    dump_sha256=dump.sha256,
                    dump_identity=dump.identity,
                    dump_artifact_path=str(dump_path),
                    guest_transcript_sha256=transcript,
                    guest_transcript_path=transcript_path,
                    dump_analysis_path=analysis_path,
                    dump_analysis_sha256=hashlib.sha256(analysis_bytes).hexdigest(),
                    run_nonce=run_nonce,
                    argv_sha256=argv_sha256,
                )
            if after.vm_state.lower() != "running":
                raise RuntimeError(
                    f"VM was {after.vm_state!r} after a no-dump trial; refusing clean evidence"
                )
            self.worker_acceptance.validate_live_host(
                recovered_host.to_dict(), expected_host_boot_id=self._expected_host_boot_id
            )
            if not guest.started or not guest.finished:
                raise RuntimeError("guest runner did not complete its nonce-bound execution")
            if guest.timed_out or guest.returncode != 0:
                detail = (
                    "guest timed out"
                    if guest.timed_out
                    else f"guest exited {guest.returncode}"
                )
                raise RuntimeError(f"{detail}, but the host produced no new crash dump")
            return HyperVObservation(
                case=case,
                trial=trial,
                build_lab_ex=build,
                status="CLEAN",
                guest_transcript_sha256=transcript,
                guest_transcript_path=transcript_path,
                run_nonce=run_nonce,
                argv_sha256=argv_sha256,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
            self._quarantined = True
            return HyperVObservation(
                case=case,
                trial=trial,
                build_lab_ex=build,
                status="ERROR",
                guest_transcript_sha256=transcript,
                guest_transcript_path=transcript_path,
                run_nonce=run_nonce,
                argv_sha256=argv_sha256,
                error=str(exc),
            )

    def _write_artifact(self, name: str, data: bytes) -> str:
        if self.artifact_dir is None:
            return ""
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        path = self.artifact_dir / name
        with path.open("xb") as output:
            output.write(data)
        return str(path.resolve())


def crash_signature(analysis: str) -> str:
    """Return a normalized bugcheck + failure bucket; never use raw exit state."""
    bugcheck = _BUGCHECK_RE.search(analysis)
    bucket = _BUCKET_RE.search(analysis)
    if not bugcheck or not bucket:
        return ""
    normalized_bucket = re.sub(r"\s+", " ", bucket.group(1).strip()).lower()
    # The newer cdb zero-pads the code ("Bugcheck code 00000050"); normalize so the
    # signature is a stable dedup key across debugger versions.
    code = bugcheck.group(1).lower().lstrip("0") or "0"
    return f"bugcheck-{code}:{normalized_bucket}"


CommandRunner = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class SshHyperVControlPlane:
    """SSH implementation that remains outside the crashable Windows host."""

    scope: WindowsScope
    execution_grant: HyperVExecutionGrant
    campaign_sha256: str
    scope_manifest_sha256: str
    worker_acceptance: VerifiedHyperVWorkerAcceptance | None = None
    execution_grant_sha256: str = ""
    acceptance_probe_only: bool = False
    runner: CommandRunner | None = None
    sleeper: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        from .hyperv_acceptance import VerifiedHyperVWorkerAcceptance

        if self.acceptance_probe_only:
            if self.worker_acceptance is not None or self.execution_grant_sha256:
                raise ValueError("acceptance probe control cannot carry execution acceptance")
        elif (
            not isinstance(self.worker_acceptance, VerifiedHyperVWorkerAcceptance)
            or not re.fullmatch(r"[0-9a-f]{64}", self.execution_grant_sha256)
        ):
            raise ValueError(
                "Hyper-V execution control requires verified worker acceptance and grant digest"
            )

    def _require_authorized(
        self, manifest: HyperVProverManifest, *, allow_acceptance_probe: bool = False
    ) -> None:
        self.scope.require_source_binding(self.scope_manifest_sha256)
        self.execution_grant.require_signed_authorization()
        validate_campaign_scope(manifest, self.scope)
        self.execution_grant.validate_binding(
            manifest, self.campaign_sha256, self.scope_manifest_sha256
        )
        if self.acceptance_probe_only:
            if not allow_acceptance_probe:
                raise ValueError("acceptance probe control cannot execute campaign operations")
            return
        assert self.worker_acceptance is not None
        self.worker_acceptance.validate_binding(
            manifest,
            self.campaign_sha256,
            self.scope,
            self.scope_manifest_sha256,
            self.execution_grant,
            self.execution_grant_sha256,
        )

    def host_acceptance_state(self, manifest: HyperVProverManifest) -> HostAcceptanceState:
        self._require_authorized(manifest, allow_acceptance_probe=True)
        script = (
            "$ErrorActionPreference='Stop';"
            "$cv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
            f"$vm=Get-VM -Name {_ps_quote(manifest.vm_name)};"
            f"$cp=Get-VMSnapshot -VMName {_ps_quote(manifest.vm_name)} "
            f"-Name {_ps_quote(manifest.checkpoint_name)} -ErrorAction Stop;"
            f"$debugger={_ps_quote(_DEBUGGER)};"
            "if(-not(Test-Path -LiteralPath $debugger)){throw 'cdb is missing'};"
            "$checkpointMaterial='{0}|{1}|{2}' -f $vm.Id,$cp.Id,"
            "$cp.CreationTime.ToUniversalTime().Ticks;"
            "$checkpointBytes=[Text.Encoding]::UTF8.GetBytes($checkpointMaterial);"
            "$sha=[Security.Cryptography.SHA256]::Create();"
            "$checkpointHash=($sha.ComputeHash($checkpointBytes)|ForEach-Object "
            "{$_.ToString('x2')}) -join '';"
            "$sha.Dispose();"
            "$debuggerHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $debugger).Hash."
            "ToLowerInvariant();"
            "$machine=(Get-CimInstance Win32_ComputerSystemProduct).UUID;"
            "$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime."
            "ToUniversalTime().Ticks.ToString();"
            "$row=[ordered]@{build_lab_ex=$cv.BuildLabEx;"
            "checkpoint_identity_sha256=$checkpointHash;"
            "debugger_executable_sha256=$debuggerHash;worker_machine_id=$machine;"
            "host_boot_id=$boot};"
            f"Write-Output ('{_JSON_MARKER}'+($row|ConvertTo-Json -Compress))"
        )
        row = _marked_json(
            self._host(manifest, script, manifest.connect_timeout_seconds + 30)
        )
        values = {name: str(row.get(name, "")) for name in (
            "build_lab_ex", "checkpoint_identity_sha256", "debugger_executable_sha256",
            "worker_machine_id", "host_boot_id",
        )}
        if any(not value for value in values.values()):
            raise RuntimeError("Hyper-V host acceptance state was incomplete")
        return HostAcceptanceState(**values)

    def guest_acceptance_state(self, manifest: HyperVProverManifest) -> GuestAcceptanceState:
        self._require_authorized(manifest, allow_acceptance_probe=True)
        remote = (
            f"printf '{_GUEST_STATE_MARKER}%s\\n' \"$(cat /etc/machine-id)\" && "
            + shlex.join(["sha256sum", "--", manifest.trigger_argv[0], manifest.control_argv[0]])
        )
        result = self._run(
            self._ssh_argv(manifest, manifest.guest_worker, remote),
            manifest.connect_timeout_seconds + 15,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-500:]
            raise RuntimeError(f"Hyper-V guest acceptance probe failed: {detail}")
        lines = result.stdout.splitlines()
        machine = next(
            (line.removeprefix(_GUEST_STATE_MARKER) for line in lines
             if line.startswith(_GUEST_STATE_MARKER)), ""
        )
        hashes = [
            line.split()[0].lower()
            for line in lines
            if re.match(r"^[0-9A-Fa-f]{64}\s", line)
        ]
        if not machine or len(hashes) != 2:
            raise RuntimeError("Hyper-V guest acceptance state was incomplete")
        return GuestAcceptanceState(machine, hashes[0], hashes[1])

    def host_state(self, manifest: HyperVProverManifest) -> HostState:
        self._require_authorized(manifest)
        script = (
            "$ErrorActionPreference='Stop';"
            "$cv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
            f"$vm=Get-VM -Name {_ps_quote(manifest.vm_name)};"
            f"$cp=Get-VMSnapshot -VMName {_ps_quote(manifest.vm_name)} "
            f"-Name {_ps_quote(manifest.checkpoint_name)} -ErrorAction SilentlyContinue;"
            f"$dump=Get-Item -LiteralPath {_ps_quote(manifest.dump_path)} "
            "-ErrorAction SilentlyContinue;"
            "if($null -eq $cp){throw 'required checkpoint is missing'};"
            "$cs=Get-CimInstance Win32_ComputerSystem;"
            "if(-not $cs.HypervisorPresent){throw 'Hyper-V is unavailable'};"
            "$identity=if($null -eq $dump){'missing'}else{"
            "'{0}:{1}:{2}' -f $dump.Length,$dump.CreationTimeUtc.Ticks,"
            "$dump.LastWriteTimeUtc.Ticks};"
            "$row=[ordered]@{build_lab_ex=$cv.BuildLabEx;"
            "vm_state=$vm.State.ToString();dump_identity=$identity};"
            f"Write-Output ('{_JSON_MARKER}'+($row|ConvertTo-Json -Compress))"
        )
        result = self._host(manifest, script, manifest.connect_timeout_seconds + 15)
        row = _marked_json(result)
        build = str(row.get("build_lab_ex", ""))
        vm_state = str(row.get("vm_state", ""))
        identity = str(row.get("dump_identity", ""))
        if not build or not vm_state or not identity:
            raise RuntimeError("Hyper-V host state omitted build, VM state, or dump identity")
        return HostState(build, vm_state, identity)

    def restore_checkpoint(self, manifest: HyperVProverManifest) -> None:
        self._require_authorized(manifest, allow_acceptance_probe=True)
        script = (
            "$ErrorActionPreference='Stop';"
            f"$vm=Get-VM -Name {_ps_quote(manifest.vm_name)};"
            "if($vm.State -ne 'Off'){Stop-VM -VM $vm -TurnOff -Force};"
            f"$cp=Get-VMSnapshot -VMName {_ps_quote(manifest.vm_name)} "
            f"-Name {_ps_quote(manifest.checkpoint_name)};"
            "Restore-VMSnapshot -VMSnapshot $cp -Confirm:$false;"
            f"Start-VM -Name {_ps_quote(manifest.vm_name)} | Out-Null;"
            f"$vm=Get-VM -Name {_ps_quote(manifest.vm_name)};"
            "if($vm.State -ne 'Running'){throw 'VM did not enter Running state'}"
        )
        self._host(manifest, script, manifest.connect_timeout_seconds + 120)

    def wait_guest(self, manifest: HyperVProverManifest) -> None:
        self._require_authorized(manifest, allow_acceptance_probe=True)
        deadline = time.monotonic() + manifest.guest_ready_timeout_seconds
        last = "guest did not become reachable"
        while time.monotonic() < deadline:
            try:
                result = self._run(
                    self._ssh_argv(manifest, manifest.guest_worker, "true"),
                    manifest.connect_timeout_seconds + 5,
                )
            except subprocess.TimeoutExpired:
                last = "guest SSH readiness probe timed out"
                self.sleeper(manifest.poll_interval_seconds)
                continue
            if result.returncode == 0:
                return
            last = (result.stderr or result.stdout).strip()[-300:] or last
            self.sleeper(manifest.poll_interval_seconds)
        raise RuntimeError(last)

    def prepare_dump(
        self,
        manifest: HyperVProverManifest,
        *,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> DumpPreparation:
        self._require_authorized(manifest)
        script = (
            "$ErrorActionPreference='Stop';"
            f"$dump={_ps_quote(manifest.dump_path)};"
            "$dir=Split-Path -Parent $dump;"
            "$archive=Join-Path $dir '0verse-archive';"
            "$archived='';"
            "if(Test-Path -LiteralPath $dump){"
            "New-Item -ItemType Directory -Force -Path $archive|Out-Null;"
            f"$archived=Join-Path $archive {_ps_quote(f'{run_nonce}-{case}-{trial}-previous.dmp')};"
            "Move-Item -LiteralPath $dump -Destination $archived -ErrorAction Stop};"
            "if(Test-Path -LiteralPath $dump){throw 'dump baseline was not cleared'};"
            "$row=[ordered]@{prepared_at_utc_ticks=[DateTime]::UtcNow.Ticks;"
            "archived_path=$archived};"
            f"Write-Output ('{_JSON_MARKER}'+($row|ConvertTo-Json -Compress))"
        )
        result = self._host(manifest, script, manifest.connect_timeout_seconds + 60)
        row = _marked_json(result)
        prepared_raw = row.get("prepared_at_utc_ticks", 0)
        try:
            if isinstance(prepared_raw, bool) or not isinstance(prepared_raw, (int, str)):
                raise TypeError
            prepared = int(prepared_raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("dump preparation returned an invalid timestamp") from exc
        if prepared <= 0:
            raise RuntimeError("dump preparation omitted its timestamp")
        return DumpPreparation(prepared, str(row.get("archived_path", "")))

    def invoke_guest(
        self,
        manifest: HyperVProverManifest,
        argv: Sequence[str],
        *,
        expected_executable_sha256: str,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> GuestRun:
        self._require_authorized(manifest)
        if case not in {"control", "target"} or not 1 <= trial <= manifest.trials:
            raise ValueError("guest invocation case/trial is outside the signed campaign")
        authorized_argv = (
            manifest.trigger_argv if case == "target" else manifest.control_argv
        )
        authorized_hash = (
            self.execution_grant.trigger_executable_sha256
            if case == "target"
            else self.execution_grant.control_executable_sha256
        )
        if tuple(argv) != authorized_argv:
            raise ValueError("guest invocation argv differs from the signed campaign")
        if expected_executable_sha256 != authorized_hash:
            raise ValueError("guest invocation executable hash differs from the signed grant")
        remote = shlex.join(
            [
                _GUEST_RUNNER,
                "run",
                run_nonce,
                str(manifest.guest_timeout_seconds),
                expected_executable_sha256,
                case,
                str(trial),
                "--",
                *argv,
            ]
        )
        command = self._ssh_argv(manifest, manifest.guest_worker, remote)
        argv_hash = _argv_sha256(argv)
        try:
            result = self._run(
                command,
                manifest.guest_timeout_seconds + manifest.connect_timeout_seconds + 15,
            )
            start = f"{_GUEST_START_MARKER}{run_nonce}:{case}:{trial}"
            finish = f"{_GUEST_FINISH_MARKER}{run_nonce}:"
            return GuestRun(
                result.returncode,
                result.stdout,
                result.stderr,
                run_nonce=run_nonce,
                case=case,
                trial=trial,
                argv_sha256=argv_hash,
                started=start in result.stdout,
                finished=finish in result.stdout,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _text(exc.stdout)
            return GuestRun(
                None,
                stdout,
                _text(exc.stderr),
                timed_out=True,
                run_nonce=run_nonce,
                case=case,
                trial=trial,
                argv_sha256=argv_hash,
                started=f"{_GUEST_START_MARKER}{run_nonce}:{case}:{trial}" in stdout,
                finished=f"{_GUEST_FINISH_MARKER}{run_nonce}:" in stdout,
            )

    def wait_host(self, manifest: HyperVProverManifest) -> None:
        self._require_authorized(manifest)
        self.sleeper(manifest.settle_seconds)
        deadline = time.monotonic() + manifest.recovery_timeout_seconds
        last = "Hyper-V host did not recover"
        while time.monotonic() < deadline:
            try:
                result = self._run(
                    self._ssh_argv(manifest, manifest.worker, "exit 0"),
                    manifest.connect_timeout_seconds + 5,
                )
            except subprocess.TimeoutExpired:
                last = "Hyper-V host SSH recovery probe timed out"
                self.sleeper(manifest.poll_interval_seconds)
                continue
            if result.returncode == 0:
                return
            last = (result.stderr or result.stdout).strip()[-300:] or last
            self.sleeper(manifest.poll_interval_seconds)
        raise RuntimeError(last)

    def collect_dump(
        self,
        manifest: HyperVProverManifest,
        *,
        expected_identity: str,
        preparation: DumpPreparation,
        run_nonce: str,
        case: str,
        trial: int,
    ) -> DumpEvidence:
        self._require_authorized(manifest)
        script = (
            "$ErrorActionPreference='Stop';"
            f"$dump={_ps_quote(manifest.dump_path)};"
            "if(-not (Test-Path -LiteralPath $dump)){throw 'host dump is missing'};"
            "$source=Get-Item -LiteralPath $dump;"
            "$identity='{0}:{1}:{2}' -f $source.Length,$source.CreationTimeUtc.Ticks,"
            "$source.LastWriteTimeUtc.Ticks;"
            f"if($identity -ne {_ps_quote(expected_identity)})"
            "{throw 'dump identity changed before collection'};"
            f"if($source.CreationTimeUtc.Ticks -lt {preparation.prepared_at_utc_ticks})"
            "{throw 'dump predates case preparation'};"
            "$hashBefore=(Get-FileHash -Algorithm SHA256 -LiteralPath $dump).Hash."
            "ToLowerInvariant();"
            "$evidenceDir=Join-Path (Split-Path -Parent $dump) '0verse-evidence';"
            "New-Item -ItemType Directory -Force -Path $evidenceDir|Out-Null;"
            f"$artifact=Join-Path $evidenceDir {_ps_quote(f'{run_nonce}-{case}-{trial}.dmp')};"
            "Copy-Item -LiteralPath $dump -Destination $artifact -ErrorAction Stop;"
            "$artifactHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash."
            "ToLowerInvariant();"
            "$sourceAfter=Get-Item -LiteralPath $dump;"
            "$identityAfter='{0}:{1}:{2}' -f $sourceAfter.Length,"
            "$sourceAfter.CreationTimeUtc.Ticks,$sourceAfter.LastWriteTimeUtc.Ticks;"
            "$hashAfter=(Get-FileHash -Algorithm SHA256 -LiteralPath $dump).Hash."
            "ToLowerInvariant();"
            "if($identityAfter -ne $identity -or $hashBefore -ne $hashAfter -or "
            "$artifactHash -ne $hashBefore){throw 'dump changed while snapshotting'};"
            f"& {_ps_quote(_DEBUGGER)} -z $artifact -c '.bugcheck;!analyze -v;q';"
            "$cdbExit=$LASTEXITCODE;"
            "if($cdbExit -ne 0){throw \"cdb failed with exit $cdbExit\"};"
            "$artifactHashAfter=(Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash."
            "ToLowerInvariant();"
            "if($artifactHashAfter -ne $artifactHash)"
            "{throw 'dump artifact changed during analysis'};"
            f"$artifactIdentity='{expected_identity}|{run_nonce}|{case}|{trial}|'+$artifactHash;"
            "$row=[ordered]@{sha256=$artifactHash;identity=$artifactIdentity;"
            "artifact_path=$artifact};"
            f"Write-Output ('{_DUMP_MARKER}'+($row|ConvertTo-Json -Compress))"
        )
        result = self._host(manifest, script, manifest.dump_timeout_seconds)
        row = _marked_json(result, marker=_DUMP_MARKER)
        sha256 = str(row.get("sha256", ""))
        identity = str(row.get("identity", ""))
        artifact_path = str(row.get("artifact_path", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", sha256) or not identity or not artifact_path:
            raise RuntimeError("dump collection omitted immutable provenance")
        return DumpEvidence(sha256, identity, artifact_path, f"{result.stdout}\n{result.stderr}")

    def retain_dump(
        self,
        manifest: HyperVProverManifest,
        evidence: DumpEvidence,
        destination: Path,
    ) -> None:
        self._require_authorized(manifest)
        remote = PureWindowsPath(evidence.artifact_path)
        if (
            not remote.is_absolute()
            or remote.suffix.lower() != ".dmp"
            or any(part in {".", ".."} for part in remote.parts)
            or any(ord(char) < 32 for char in evidence.artifact_path)
        ):
            raise RuntimeError("worker returned an invalid retained dump path")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise RuntimeError("retained dump destination already exists")
        argv = [
            "scp", "-q", "-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0",
            "-o", "StrictHostKeyChecking=yes", "-o",
            f"ConnectTimeout={manifest.connect_timeout_seconds}", "--",
            f"{manifest.worker}:{evidence.artifact_path}", str(destination),
        ]
        result = self._run(argv, manifest.dump_timeout_seconds)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-500:]
            raise RuntimeError(f"Hyper-V dump retention failed ({result.returncode}): {detail}")

    def _host(
        self,
        manifest: HyperVProverManifest,
        script: str,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        result = self._run(
            self._ssh_argv(manifest, manifest.worker, _encoded_powershell(script)), timeout
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-500:]
            raise RuntimeError(f"Hyper-V host command failed ({result.returncode}): {detail}")
        return result

    def _run(self, argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
        invoke = self.runner or _run_command
        return invoke(argv, timeout)

    @staticmethod
    def _ssh_argv(
        manifest: HyperVProverManifest, host: str, remote_command: str
    ) -> list[str]:
        return [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"ConnectTimeout={manifest.connect_timeout_seconds}",
            "--",
            host,
            remote_command,
        ]


def _marked_json(
    result: subprocess.CompletedProcess[str], *, marker: str = _JSON_MARKER
) -> dict[str, object]:
    for line in result.stdout.splitlines():
        if line.startswith(marker):
            parsed = json.loads(line.removeprefix(marker))
            if isinstance(parsed, dict):
                return parsed
    raise RuntimeError("Hyper-V host response omitted its JSON evidence marker")


def _argv_sha256(argv: Sequence[str]) -> str:
    material = json.dumps(list(argv), separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(material).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _encoded_powershell(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _run_command(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    if not argv or argv[0] not in {"ssh", "scp"} or any("\x00" in item for item in argv):
        raise ValueError("Hyper-V transport accepts only NUL-free ssh/scp argv")
    return subprocess.run(  # foxguard: ignore[py/no-command-injection]
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
