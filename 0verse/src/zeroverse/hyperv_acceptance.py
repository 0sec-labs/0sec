"""Independently signed, evidence-backed Hyper-V worker acceptance."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from .hyperv_prover import HyperVExecutionGrant, HyperVProverManifest
from .windows_scope import WindowsScope

if TYPE_CHECKING:
    from .hyperv_transport import HyperVControlPlane

SCHEMA_VERSION = "0verse.hyperv-worker-acceptance/v1"
DRILL_SCHEMA_VERSION = "0verse.hyperv-recovery-drill/v1"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/hyperv-acceptance.allowed_signers")
SIGNING_KEY_ENV = "ZEROVERSE_HYPERV_ACCEPTANCE_SIGNING_KEY"
SIGNATURE_NAMESPACE = "0verse-hyperv-worker-acceptance"
RECOVERY_ARTIFACTS = {
    "benign_dump_sha256": "recovery-benign.dmp",
    "benign_dump_analysis_sha256": "recovery-benign-cdb.txt",
    "guest_challenge_sha256": "recovery-guest-challenge.json",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version", "campaign_sha256", "scope_manifest_sha256", "campaign_id",
        "worker", "guest_worker", "vm_name", "checkpoint_name", "dump_path",
        "build_lab_ex", "checkpoint_identity_sha256", "debugger_executable_sha256",
        "trigger_executable_sha256", "control_executable_sha256", "recovery_drill_path",
        "recovery_drill_sha256", "execution_grant_sha256", "execution_grant_nonce",
        "issued_at", "expires_at", "nonce", "accepted_by",
        "signature_ssh",
    }
)
_DRILL_STRING_FIELDS = frozenset(
    {
        "schema_version", "campaign_sha256", "scope_manifest_sha256", "campaign_id",
        "worker", "guest_worker", "vm_name", "checkpoint_name", "dump_path",
        "build_lab_ex", "checkpoint_identity_sha256", "debugger_executable_sha256",
        "trigger_executable_sha256", "control_executable_sha256", "worker_machine_id",
        "guest_machine_id", "worker_ssh_host_key_sha256", "guest_ssh_host_key_sha256",
        "recovery_nonce", "pre_host_boot_id", "post_host_boot_id", "started_at",
        "host_unavailable_observed_at", "host_recovered_at", "guest_recovered_at",
        "completed_at", "benign_dump_sha256", "benign_dump_analysis_sha256",
        "guest_challenge_sha256", "out_of_band_controller",
    }
)
_DRILL_BOOL_FIELDS = frozenset(
    {
        "host_unavailable_observed", "checkpoint_restore_confirmed",
        "guest_challenge_confirmed", "debugger_smoke_confirmed",
    }
)


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"worker acceptance {name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"worker acceptance {name} must include a timezone")
    return parsed.astimezone(UTC)


def _exact_strings(raw: Mapping[str, object], fields: frozenset[str], label: str) -> None:
    unknown = sorted(raw.keys() - fields)
    missing = sorted(fields - raw.keys())
    if unknown:
        raise ValueError(f"unknown {label} fields: {', '.join(unknown)}")
    if missing:
        raise ValueError(f"missing {label} fields: {', '.join(missing)}")
    non_strings = sorted(name for name in fields if not isinstance(raw[name], str))
    if non_strings:
        raise ValueError(f"{label} fields must be strings: {', '.join(non_strings)}")


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_recovery_artifacts(base: Path, drill: HyperVRecoveryDrill) -> None:
    for digest_field, filename in RECOVERY_ARTIFACTS.items():
        path = base / filename
        if not path.is_file() or path.is_symlink() or path.parent != base:
            raise ValueError(
                f"worker acceptance recovery artifact is missing or unsafe: {filename}"
            )
        if _sha256_path(path) != getattr(drill, digest_field):
            raise ValueError(f"worker acceptance recovery artifact SHA-256 mismatch: {filename}")


@dataclass(frozen=True)
class HyperVRecoveryDrill:
    campaign_sha256: str
    scope_manifest_sha256: str
    campaign_id: str
    worker: str
    guest_worker: str
    vm_name: str
    checkpoint_name: str
    dump_path: str
    build_lab_ex: str
    checkpoint_identity_sha256: str
    debugger_executable_sha256: str
    trigger_executable_sha256: str
    control_executable_sha256: str
    worker_machine_id: str
    guest_machine_id: str
    worker_ssh_host_key_sha256: str
    guest_ssh_host_key_sha256: str
    recovery_nonce: str
    pre_host_boot_id: str
    post_host_boot_id: str
    started_at: str
    host_unavailable_observed_at: str
    host_recovered_at: str
    guest_recovered_at: str
    completed_at: str
    benign_dump_sha256: str
    benign_dump_analysis_sha256: str
    guest_challenge_sha256: str
    out_of_band_controller: str
    host_unavailable_observed: bool
    checkpoint_restore_confirmed: bool
    guest_challenge_confirmed: bool
    debugger_smoke_confirmed: bool
    schema_version: str = DRILL_SCHEMA_VERSION

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> HyperVRecoveryDrill:
        fields = _DRILL_STRING_FIELDS | _DRILL_BOOL_FIELDS
        unknown = sorted(raw.keys() - fields)
        missing = sorted(fields - raw.keys())
        if unknown:
            raise ValueError(f"unknown Hyper-V recovery drill fields: {', '.join(unknown)}")
        if missing:
            raise ValueError(f"missing Hyper-V recovery drill fields: {', '.join(missing)}")
        if any(not isinstance(raw[name], str) for name in _DRILL_STRING_FIELDS):
            raise ValueError("Hyper-V recovery drill string fields have invalid types")
        if any(not isinstance(raw[name], bool) for name in _DRILL_BOOL_FIELDS):
            raise ValueError("Hyper-V recovery drill boolean fields have invalid types")
        drill = cls(**dict(raw))  # type: ignore[arg-type]
        drill.validate()
        return drill

    def validate(self) -> None:
        if self.schema_version != DRILL_SCHEMA_VERSION:
            raise ValueError(f"unsupported Hyper-V recovery drill schema: {self.schema_version}")
        for name in (
            "campaign_sha256", "scope_manifest_sha256", "checkpoint_identity_sha256",
            "debugger_executable_sha256", "trigger_executable_sha256",
            "control_executable_sha256", "worker_ssh_host_key_sha256",
            "guest_ssh_host_key_sha256", "benign_dump_sha256",
            "benign_dump_analysis_sha256", "guest_challenge_sha256",
        ):
            if not _SHA256_RE.fullmatch(getattr(self, name)):
                raise ValueError(f"recovery drill {name} must be a lowercase SHA-256")
        if not _NONCE_RE.fullmatch(self.recovery_nonce):
            raise ValueError("recovery drill nonce must be 32-128 URL-safe characters")
        for name in _DRILL_STRING_FIELDS - {"schema_version"}:
            value = getattr(self, name)
            if not value.strip() or "\x00" in value:
                raise ValueError(f"recovery drill {name} is empty or contains NUL")
        if not all(getattr(self, name) for name in _DRILL_BOOL_FIELDS):
            raise ValueError("recovery drill did not confirm every required observation")
        if self.pre_host_boot_id == self.post_host_boot_id:
            raise ValueError("recovery drill did not observe a host boot transition")
        timeline = [
            _timestamp(self.started_at, "started_at"),
            _timestamp(self.host_unavailable_observed_at, "host_unavailable_observed_at"),
            _timestamp(self.host_recovered_at, "host_recovered_at"),
            _timestamp(self.guest_recovered_at, "guest_recovered_at"),
            _timestamp(self.completed_at, "completed_at"),
        ]
        if timeline != sorted(timeline):
            raise ValueError("recovery drill timestamps are out of order")
        now = datetime.now(UTC)
        if timeline[-1] > now + timedelta(minutes=5):
            raise ValueError("recovery drill completed in the future")
        if now - timeline[-1] > timedelta(hours=24):
            raise ValueError("recovery drill is older than 24 hours")
        if timeline[-1] - timeline[0] > timedelta(hours=4):
            raise ValueError("recovery drill duration exceeds four hours")


@dataclass(frozen=True)
class HyperVWorkerAcceptance:
    campaign_sha256: str
    scope_manifest_sha256: str
    campaign_id: str
    worker: str
    guest_worker: str
    vm_name: str
    checkpoint_name: str
    dump_path: str
    build_lab_ex: str
    checkpoint_identity_sha256: str
    debugger_executable_sha256: str
    trigger_executable_sha256: str
    control_executable_sha256: str
    recovery_drill_path: str
    recovery_drill_sha256: str
    execution_grant_sha256: str
    execution_grant_nonce: str
    issued_at: str
    expires_at: str
    nonce: str
    accepted_by: str
    signature_ssh: str
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> HyperVWorkerAcceptance:
        _exact_strings(raw, _RECEIPT_FIELDS, "Hyper-V worker acceptance")
        receipt = cls(**dict(raw))  # type: ignore[arg-type]
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported Hyper-V worker acceptance schema: {self.schema_version}")
        for name in (
            "campaign_sha256", "scope_manifest_sha256", "checkpoint_identity_sha256",
            "debugger_executable_sha256", "trigger_executable_sha256",
            "control_executable_sha256", "recovery_drill_sha256",
            "execution_grant_sha256",
        ):
            if not _SHA256_RE.fullmatch(getattr(self, name)):
                raise ValueError(f"worker acceptance {name} must be a lowercase SHA-256")
        if not _NONCE_RE.fullmatch(self.nonce):
            raise ValueError("worker acceptance nonce must be 32-128 URL-safe characters")
        if not _NONCE_RE.fullmatch(self.execution_grant_nonce):
            raise ValueError("worker acceptance execution grant nonce is invalid")
        for name in _RECEIPT_FIELDS - {"schema_version"}:
            value = getattr(self, name)
            if not value.strip() or "\x00" in value:
                raise ValueError(f"worker acceptance {name} is empty or contains NUL")
        path = PurePosixPath(self.recovery_drill_path)
        if path.is_absolute() or len(path.parts) != 1 or path.name in {".", ".."}:
            raise ValueError("worker acceptance recovery drill path must be a sibling filename")
        now = datetime.now(UTC)
        issued = _timestamp(self.issued_at, "issued_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if issued > now + timedelta(minutes=5) or now - issued > timedelta(hours=24):
            raise ValueError("worker acceptance issued_at is outside the 24-hour window")
        if expires <= now or expires <= issued or expires - issued > timedelta(hours=24):
            raise ValueError("worker acceptance expiry is invalid")

    def unsigned_dict(self) -> dict[str, object]:
        row: dict[str, object] = asdict(self)
        row.pop("signature_ssh")
        return row

    def signed_material(self) -> bytes:
        return json.dumps(
            self.unsigned_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()


@dataclass(frozen=True)
class VerifiedHyperVWorkerAcceptance:
    receipt: HyperVWorkerAcceptance
    drill: HyperVRecoveryDrill
    receipt_bytes: bytes
    drill_bytes: bytes
    allowed_signers: Path
    require_trusted_policy: bool = False

    @property
    def nonce(self) -> str:
        return self.receipt.nonce

    def validate_binding(
        self,
        manifest: HyperVProverManifest,
        manifest_sha256: str,
        scope: WindowsScope,
        scope_manifest_sha256: str,
        grant: HyperVExecutionGrant,
        execution_grant_sha256: str,
        *,
        key: bytes | str | None = None,
    ) -> None:
        del key  # retained temporarily for call-site compatibility during migration
        receipt_raw = json.loads(self.receipt_bytes)
        drill_raw = json.loads(self.drill_bytes)
        if (
            not isinstance(receipt_raw, dict)
            or self.receipt != HyperVWorkerAcceptance.from_mapping(receipt_raw)
        ):
            raise ValueError("live worker acceptance differs from retained receipt bytes")
        if (
            not isinstance(drill_raw, dict)
            or self.drill != HyperVRecoveryDrill.from_mapping(drill_raw)
        ):
            raise ValueError("live recovery drill differs from retained drill bytes")
        if hashlib.sha256(self.drill_bytes).hexdigest() != self.receipt.recovery_drill_sha256:
            raise ValueError("retained recovery drill differs from signed receipt SHA-256")
        self.receipt.validate()
        self.drill.validate()
        _verify_ssh_signature(
            self.receipt,
            self.allowed_signers,
            require_trusted_policy=self.require_trusted_policy,
        )
        scope.require_source_binding(scope_manifest_sha256)
        grant.require_signed_authorization()
        grant.validate_binding(manifest, manifest_sha256, scope_manifest_sha256)
        expected: dict[str, str] = {
            "campaign_sha256": manifest_sha256,
            "scope_manifest_sha256": scope_manifest_sha256,
            "campaign_id": manifest.campaign_id,
            "worker": manifest.worker,
            "guest_worker": manifest.guest_worker,
            "vm_name": manifest.vm_name,
            "checkpoint_name": manifest.checkpoint_name,
            "dump_path": manifest.dump_path,
            "build_lab_ex": scope.preflight_build_lab_ex,
            "trigger_executable_sha256": grant.trigger_executable_sha256,
            "control_executable_sha256": grant.control_executable_sha256,
        }
        mismatches = [
            name for name, value in expected.items()
            if getattr(self.receipt, name) != value or getattr(self.drill, name) != value
        ]
        if self.receipt.execution_grant_sha256 != execution_grant_sha256:
            mismatches.append("execution_grant_sha256")
        if self.receipt.execution_grant_nonce != grant.nonce:
            mismatches.append("execution_grant_nonce")
        if _timestamp(self.receipt.issued_at, "issued_at") < _timestamp(
            self.drill.completed_at, "completed_at"
        ):
            mismatches.append("issued_at")
        if _timestamp(self.receipt.expires_at, "expires_at") > _timestamp(
            grant.expires_at, "grant expires_at"
        ):
            mismatches.append("expires_at")
        if _timestamp(self.receipt.expires_at, "expires_at") > _timestamp(
            scope.expires_at, "scope expires_at"
        ):
            mismatches.append("scope_expires_at")
        for name in ("checkpoint_identity_sha256", "debugger_executable_sha256"):
            if getattr(self.receipt, name) != getattr(self.drill, name):
                mismatches.append(name)
        if mismatches:
            raise ValueError(
                "worker acceptance binding mismatch: "
                + ", ".join(sorted(set(mismatches)))
            )

    def validate_live_host(
        self,
        state: Mapping[str, str],
        *,
        expected_host_boot_id: str | None = None,
    ) -> None:
        expected = {
            "build_lab_ex": self.receipt.build_lab_ex,
            "checkpoint_identity_sha256": self.receipt.checkpoint_identity_sha256,
            "debugger_executable_sha256": self.receipt.debugger_executable_sha256,
            "worker_machine_id": self.drill.worker_machine_id,
            "host_boot_id": expected_host_boot_id or self.drill.post_host_boot_id,
        }
        mismatches = [name for name, value in expected.items() if state.get(name) != value]
        if mismatches:
            raise ValueError("live Hyper-V host acceptance drift: " + ", ".join(mismatches))

    def validate_live_guest(self, state: Mapping[str, str]) -> None:
        expected = {
            "guest_machine_id": self.drill.guest_machine_id,
            "trigger_executable_sha256": self.receipt.trigger_executable_sha256,
            "control_executable_sha256": self.receipt.control_executable_sha256,
        }
        mismatches = [name for name, value in expected.items() if state.get(name) != value]
        if mismatches:
            raise ValueError("live Hyper-V guest acceptance drift: " + ", ".join(mismatches))


def _verify_ssh_signature(
    receipt: HyperVWorkerAcceptance,
    allowed_signers: Path,
    *,
    require_trusted_policy: bool = False,
) -> None:
    if not allowed_signers.is_file() or allowed_signers.is_symlink():
        raise ValueError("worker acceptance allowed-signers file is missing or unsafe")
    if require_trusted_policy:
        metadata = allowed_signers.stat()
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(
                "worker acceptance allowed-signers policy must be root-owned "
                "and not group/world writable"
            )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as signature:
        signature.write(receipt.signature_ssh)
        signature.flush()
        result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I",
             receipt.accepted_by, "-n", SIGNATURE_NAMESPACE, "-s", signature.name],
            input=receipt.signed_material(), capture_output=True, timeout=10, check=False,
        )
    if result.returncode != 0:
        raise ValueError("worker acceptance SSH signature is invalid")


def load_worker_acceptance(
    path: str | Path, *, allowed_signers: str | Path | None = None, key: bytes | str | None = None
) -> tuple[VerifiedHyperVWorkerAcceptance, str]:
    del key
    receipt_path = Path(path).resolve()
    data = receipt_path.read_bytes()
    raw = json.loads(data)
    if not isinstance(raw, dict):
        raise ValueError("Hyper-V worker acceptance must be a JSON object")
    receipt = HyperVWorkerAcceptance.from_mapping(raw)
    drill_path = receipt_path.parent / receipt.recovery_drill_path
    if (
        not drill_path.is_file()
        or drill_path.is_symlink()
        or drill_path.parent != receipt_path.parent
    ):
        raise ValueError("worker acceptance recovery drill sidecar is missing or unsafe")
    drill_bytes = drill_path.read_bytes()
    if hashlib.sha256(drill_bytes).hexdigest() != receipt.recovery_drill_sha256:
        raise ValueError("worker acceptance recovery drill SHA-256 mismatch")
    drill_raw = json.loads(drill_bytes)
    if not isinstance(drill_raw, dict):
        raise ValueError("Hyper-V recovery drill must be a JSON object")
    drill = HyperVRecoveryDrill.from_mapping(drill_raw)
    _verify_recovery_artifacts(receipt_path.parent, drill)
    configured_signers = Path(allowed_signers) if allowed_signers else DEFAULT_ALLOWED_SIGNERS
    if configured_signers.is_symlink():
        raise ValueError("worker acceptance allowed-signers file is missing or unsafe")
    signer_path = configured_signers.expanduser().resolve()
    require_trusted_policy = allowed_signers is None
    verified = VerifiedHyperVWorkerAcceptance(
        receipt,
        drill,
        data,
        drill_bytes,
        signer_path,
        require_trusted_policy,
    )
    _verify_ssh_signature(
        receipt,
        signer_path,
        require_trusted_policy=require_trusted_policy,
    )
    return verified, hashlib.sha256(data).hexdigest()


def issue_worker_acceptance(
    manifest: HyperVProverManifest,
    manifest_sha256: str,
    scope: WindowsScope,
    scope_manifest_sha256: str,
    grant: HyperVExecutionGrant,
    execution_grant_sha256: str,
    recovery_drill_path: str | Path,
    output_dir: str | Path,
    accepted_by: str,
    control: HyperVControlPlane,
    *,
    ttl: timedelta = timedelta(hours=4),
    signing_key: str | Path | None = None,
    allowed_signers: str | Path | None = None,
) -> tuple[Path, str]:
    """Issue a short-lived receipt from an independent acceptance controller."""
    manifest.validate()
    scope.require_signed_authorization()
    grant.require_signed_authorization()
    grant.validate_binding(manifest, manifest_sha256, scope_manifest_sha256)
    if not accepted_by.strip() or "\x00" in accepted_by:
        raise ValueError("worker acceptance accepted_by is empty or contains NUL")
    if ttl <= timedelta(0) or ttl > timedelta(hours=24):
        raise ValueError("worker acceptance TTL must be between zero and 24 hours")

    drill_source = Path(recovery_drill_path)
    if drill_source.is_symlink() or not drill_source.is_file():
        raise ValueError("Hyper-V recovery drill is missing or unsafe")
    drill_bytes = drill_source.read_bytes()
    drill_raw = json.loads(drill_bytes)
    if not isinstance(drill_raw, dict):
        raise ValueError("Hyper-V recovery drill must be a JSON object")
    drill = HyperVRecoveryDrill.from_mapping(drill_raw)
    _verify_recovery_artifacts(drill_source.parent.resolve(), drill)

    expected = {
        "campaign_sha256": manifest_sha256,
        "scope_manifest_sha256": scope_manifest_sha256,
        "campaign_id": manifest.campaign_id,
        "worker": manifest.worker,
        "guest_worker": manifest.guest_worker,
        "vm_name": manifest.vm_name,
        "checkpoint_name": manifest.checkpoint_name,
        "dump_path": manifest.dump_path,
        "build_lab_ex": scope.preflight_build_lab_ex,
        "trigger_executable_sha256": grant.trigger_executable_sha256,
        "control_executable_sha256": grant.control_executable_sha256,
    }
    mismatches = [name for name, value in expected.items() if getattr(drill, name) != value]
    if mismatches:
        raise ValueError(
            "worker acceptance recovery drill binding mismatch: "
            + ", ".join(sorted(mismatches))
        )

    destination = Path(output_dir)
    if destination.exists() or not destination.parent.is_dir():
        raise ValueError("worker acceptance output directory must be a new path")
    key_value = signing_key or os.environ.get(SIGNING_KEY_ENV, "")
    key_path = Path(key_value).expanduser() if key_value else Path()
    if not key_value or key_path.is_symlink() or not key_path.is_file():
        raise ValueError(f"{SIGNING_KEY_ENV} must name a safe private key file")
    key_metadata = key_path.stat()
    if key_metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("worker acceptance signing key permissions are too broad")

    live_host = control.host_acceptance_state(manifest).to_dict()
    expected_host = {
        "build_lab_ex": drill.build_lab_ex,
        "checkpoint_identity_sha256": drill.checkpoint_identity_sha256,
        "debugger_executable_sha256": drill.debugger_executable_sha256,
        "worker_machine_id": drill.worker_machine_id,
        "host_boot_id": drill.post_host_boot_id,
    }
    host_drift = [name for name, value in expected_host.items() if live_host.get(name) != value]
    if host_drift:
        raise ValueError("live Hyper-V host acceptance drift: " + ", ".join(host_drift))
    control.restore_checkpoint(manifest)
    control.wait_guest(manifest)
    live_guest = control.guest_acceptance_state(manifest).to_dict()
    expected_guest = {
        "guest_machine_id": drill.guest_machine_id,
        "trigger_executable_sha256": drill.trigger_executable_sha256,
        "control_executable_sha256": drill.control_executable_sha256,
    }
    guest_drift = [name for name, value in expected_guest.items() if live_guest.get(name) != value]
    if guest_drift:
        raise ValueError("live Hyper-V guest acceptance drift: " + ", ".join(guest_drift))

    issued = datetime.now(UTC)
    drill_completed = _timestamp(drill.completed_at, "completed_at")
    if issued < drill_completed:
        raise ValueError("worker acceptance cannot be issued before drill completion")
    grant_expires = _timestamp(grant.expires_at, "grant expires_at")
    scope_expires = _timestamp(scope.expires_at, "scope expires_at")
    expires = min(issued + ttl, grant_expires, scope_expires)
    if expires <= issued:
        raise ValueError("execution grant expires before worker acceptance can be issued")

    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    drill_destination = destination / "recovery-drill.json"
    with drill_destination.open("xb") as output:
        output.write(drill_bytes)
    for filename in RECOVERY_ARTIFACTS.values():
        source_path = drill_source.parent / filename
        destination_path = destination / filename
        with source_path.open("rb") as source, destination_path.open("xb") as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)

    unsigned = HyperVWorkerAcceptance(
        campaign_sha256=manifest_sha256,
        scope_manifest_sha256=scope_manifest_sha256,
        campaign_id=manifest.campaign_id,
        worker=manifest.worker,
        guest_worker=manifest.guest_worker,
        vm_name=manifest.vm_name,
        checkpoint_name=manifest.checkpoint_name,
        dump_path=manifest.dump_path,
        build_lab_ex=drill.build_lab_ex,
        checkpoint_identity_sha256=drill.checkpoint_identity_sha256,
        debugger_executable_sha256=drill.debugger_executable_sha256,
        trigger_executable_sha256=grant.trigger_executable_sha256,
        control_executable_sha256=grant.control_executable_sha256,
        recovery_drill_path=drill_destination.name,
        recovery_drill_sha256=hashlib.sha256(drill_bytes).hexdigest(),
        execution_grant_sha256=execution_grant_sha256,
        execution_grant_nonce=grant.nonce,
        issued_at=issued.isoformat(),
        expires_at=expires.isoformat(),
        nonce=secrets.token_urlsafe(32),
        accepted_by=accepted_by,
        signature_ssh="pending",
    )
    unsigned.validate()
    with tempfile.NamedTemporaryFile("wb", delete=False) as material:
        material.write(unsigned.signed_material())
        material_path = Path(material.name)
    signature_path = Path(f"{material_path}.sig")
    try:
        result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
            ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key_path), "-n",
             SIGNATURE_NAMESPACE, str(material_path)],
            capture_output=True, timeout=10, check=False,
        )
        if result.returncode != 0 or not signature_path.is_file():
            raise ValueError("worker acceptance signing failed")
        receipt_raw = unsigned.unsigned_dict()
        receipt_raw["signature_ssh"] = signature_path.read_text()
        receipt = HyperVWorkerAcceptance.from_mapping(receipt_raw)
    finally:
        material_path.unlink(missing_ok=True)
        signature_path.unlink(missing_ok=True)
    receipt.validate()
    policy = Path(allowed_signers) if allowed_signers else DEFAULT_ALLOWED_SIGNERS
    _verify_ssh_signature(
        receipt,
        policy,
        require_trusted_policy=allowed_signers is None,
    )
    receipt_path = destination / "worker-acceptance.json"
    receipt_bytes = json.dumps(
        asdict(receipt), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    with receipt_path.open("xb") as output:
        output.write(receipt_bytes)
    receipt_path.chmod(0o600)
    return receipt_path, hashlib.sha256(receipt_bytes).hexdigest()
