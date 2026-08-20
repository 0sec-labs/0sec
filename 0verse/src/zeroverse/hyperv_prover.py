"""Fail-closed adjudication for authorized Hyper-V guest-to-host reproductions.

The transport is deliberately a protocol: an operator-controlled worker owns
checkpoint restore, guest invocation, host recovery, and dump collection.  This
module owns the part that must remain deterministic and testable: scope binding,
trial ordering, evidence provenance, and promotion from candidate to reproduced.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Protocol

from .windows_scope import (
    DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS,
    WindowsScope,
    verify_evidence_builds,
)

if TYPE_CHECKING:
    from .hyperv_acceptance import VerifiedHyperVWorkerAcceptance

SCHEMA_VERSION = "0verse.hyperv-prover/v1"
GRANT_SCHEMA_VERSION = "0verse.hyperv-execution-grant/v1"
SIGNED_GRANT_SCHEMA_VERSION = "0verse.hyperv-execution-grant/v2"
GRANT_AUTHORIZATION_NAMESPACE = "0verse-hyperv-execution-grant"
EVIDENCE_SCHEMA_VERSION = "0verse.hyperv-evidence/v1"
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_DENIED_REMOTE_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "mac",
        "mac-mini",
        "peakbook",
        "peakbuntu",
        "fabian-mac",
        "feza-macbook-air",
        "vega",
        "vega-root",
        "fuzzer",
        "bench",
    }
)


def _string_sequence(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a non-empty string array")
    result = tuple(value)
    if any(not item or "\x00" in item for item in result):
        raise ValueError(f"{name} entries must be non-empty and NUL-free")
    return result


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return value


@dataclass(frozen=True)
class HyperVProverManifest:
    campaign_id: str
    worker: str
    guest_worker: str
    vm_name: str
    checkpoint_name: str
    trigger_argv: tuple[str, ...]
    control_argv: tuple[str, ...]
    trials: int = 3
    minimum_confirmations: int = 3
    dump_path: str = "C:\\dumps\\MEMORY.DMP"
    connect_timeout_seconds: int = 8
    guest_ready_timeout_seconds: int = 180
    guest_timeout_seconds: int = 30
    settle_seconds: int = 10
    recovery_timeout_seconds: int = 600
    dump_timeout_seconds: int = 600
    poll_interval_seconds: int = 10
    schema_version: str = SCHEMA_VERSION
    _source_material: bytes = dataclass_field(default=b"", repr=False, compare=False)
    _source_sha256: str = dataclass_field(default="", repr=False, compare=False)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> HyperVProverManifest:
        required = {
            "campaign_id",
            "worker",
            "guest_worker",
            "vm_name",
            "checkpoint_name",
            "trigger_argv",
            "control_argv",
        }
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing Hyper-V prover fields: {', '.join(missing)}")
        manifest = cls(
            campaign_id=str(raw["campaign_id"]),
            worker=str(raw["worker"]),
            guest_worker=str(raw["guest_worker"]),
            vm_name=str(raw["vm_name"]),
            checkpoint_name=str(raw["checkpoint_name"]),
            trigger_argv=_string_sequence(raw["trigger_argv"], "trigger_argv"),
            control_argv=_string_sequence(raw["control_argv"], "control_argv"),
            trials=_integer(raw.get("trials", 3), "trials"),
            minimum_confirmations=_integer(
                raw.get("minimum_confirmations", raw.get("trials", 3)),
                "minimum_confirmations",
            ),
            dump_path=str(raw.get("dump_path", "C:\\dumps\\MEMORY.DMP")),
            connect_timeout_seconds=_integer(
                raw.get("connect_timeout_seconds", 8), "connect_timeout_seconds"
            ),
            guest_ready_timeout_seconds=_integer(
                raw.get("guest_ready_timeout_seconds", 180), "guest_ready_timeout_seconds"
            ),
            guest_timeout_seconds=_integer(
                raw.get("guest_timeout_seconds", 30), "guest_timeout_seconds"
            ),
            settle_seconds=_integer(raw.get("settle_seconds", 10), "settle_seconds"),
            recovery_timeout_seconds=_integer(
                raw.get("recovery_timeout_seconds", 600), "recovery_timeout_seconds"
            ),
            dump_timeout_seconds=_integer(
                raw.get("dump_timeout_seconds", 600), "dump_timeout_seconds"
            ),
            poll_interval_seconds=_integer(
                raw.get("poll_interval_seconds", 10), "poll_interval_seconds"
            ),
            schema_version=str(raw.get("schema_version", SCHEMA_VERSION)),
        )
        manifest.validate()
        return manifest

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported Hyper-V prover schema: {self.schema_version}")
        if not self.campaign_id.strip():
            raise ValueError("Hyper-V campaign_id is empty")
        for name in ("worker", "guest_worker"):
            value = getattr(self, name)
            if not _HOST_RE.fullmatch(value):
                raise ValueError(f"{name} must be a plain SSH host token")
            if value.lower() in _DENIED_REMOTE_HOSTS:
                raise ValueError(f"{name} is denied for disruptive Hyper-V work")
        if self.worker == self.guest_worker:
            raise ValueError("worker and guest_worker must be different hosts")
        for name in ("vm_name", "checkpoint_name"):
            if not _NAME_RE.fullmatch(getattr(self, name)):
                raise ValueError(f"invalid Hyper-V {name}")
        if self.trials < 2 or self.trials > 20:
            raise ValueError("trials must be between 2 and 20")
        if not 2 <= self.minimum_confirmations <= self.trials:
            raise ValueError("minimum_confirmations must be between 2 and trials")
        self._validate_dump_path()
        bounded = {
            "connect_timeout_seconds": (1, 60),
            "guest_ready_timeout_seconds": (10, 1800),
            "guest_timeout_seconds": (1, 1800),
            "settle_seconds": (1, 300),
            "recovery_timeout_seconds": (30, 3600),
            "dump_timeout_seconds": (30, 3600),
            "poll_interval_seconds": (1, 60),
        }
        for name, (minimum, maximum) in bounded.items():
            value = getattr(self, name)
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
        self._validate_guest_command(self.trigger_argv, "trigger_argv")
        self._validate_guest_command(self.control_argv, "control_argv")
        if self.trigger_argv == self.control_argv:
            raise ValueError("trigger and control commands must differ")

    @staticmethod
    def _validate_guest_command(argv: Sequence[str], name: str) -> None:
        if len(argv) > 64 or sum(len(item) for item in argv) > 16_384:
            raise ValueError(f"{name} exceeds the argv size limit")
        if any(len(item) > 4096 or any(ord(char) < 32 for char in item) for item in argv):
            raise ValueError(f"{name} contains an oversized or control-character argument")
        executable = PurePosixPath(argv[0])
        if (
            not executable.is_absolute()
            or executable == PurePosixPath("/root/harness")
            or not executable.is_relative_to("/root/harness")
            or any(part in {".", ".."} for part in executable.parts)
        ):
            raise ValueError(f"{name} executable must be under /root/harness")

    def _validate_dump_path(self) -> None:
        if any(ord(char) < 32 for char in self.dump_path):
            raise ValueError("dump_path contains control characters")
        path = PureWindowsPath(self.dump_path)
        if (
            not path.is_absolute()
            or path.suffix.lower() != ".dmp"
            or any(part in {".", ".."} for part in path.parts)
            or ":" in self.dump_path[2:]
        ):
            raise ValueError("dump_path must be a traversal-free absolute .dmp path")

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload.pop("_source_material")
        payload.pop("_source_sha256")
        return payload

    def require_source_binding(self, source_sha256: str) -> None:
        """Reject live campaign objects that diverge from their loaded source file."""
        self.validate()
        if not self._source_material or not self._source_sha256:
            raise ValueError("Hyper-V campaign is not bound to a loaded source file")
        if hashlib.sha256(self._source_material).hexdigest() != self._source_sha256:
            raise ValueError("Hyper-V campaign source bytes fail their retained SHA-256")
        raw = json.loads(self._source_material, object_pairs_hook=_unique_json_object)
        if not isinstance(raw, dict) or self != HyperVProverManifest.from_mapping(raw):
            raise ValueError("live Hyper-V campaign fields differ from source material")
        if source_sha256 != self._source_sha256:
            raise ValueError("Hyper-V campaign SHA-256 differs from loaded source file")


@dataclass(frozen=True)
class HyperVExecutionGrant:
    """Short-lived operator grant bound to exact campaign, scope, and placement."""

    campaign_sha256: str
    scope_manifest_sha256: str
    campaign_id: str
    worker: str
    guest_worker: str
    vm_name: str
    checkpoint_name: str
    dump_path: str
    trigger_executable_sha256: str
    control_executable_sha256: str
    issued_at: str
    expires_at: str
    nonce: str
    authorized_by: str
    signature_ssh: str = ""
    schema_version: str = GRANT_SCHEMA_VERSION
    _signed_material: bytes = dataclass_field(default=b"", repr=False, compare=False)
    _allowed_signers: Path | None = dataclass_field(default=None, repr=False, compare=False)
    _require_trusted_policy: bool = dataclass_field(default=True, repr=False, compare=False)
    _authorization_verified: bool = dataclass_field(default=False, repr=False, compare=False)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> HyperVExecutionGrant:
        schema = str(raw.get("schema_version", GRANT_SCHEMA_VERSION))
        required = {
            "campaign_sha256",
            "scope_manifest_sha256",
            "campaign_id",
            "worker",
            "guest_worker",
            "vm_name",
            "checkpoint_name",
            "dump_path",
            "trigger_executable_sha256",
            "control_executable_sha256",
            "issued_at",
            "expires_at",
            "nonce",
            "authorized_by",
        }
        if schema == SIGNED_GRANT_SCHEMA_VERSION:
            required |= {"schema_version", "signature_ssh"}
            unknown = sorted(raw.keys() - required)
            if unknown:
                raise ValueError(
                    "unknown Hyper-V execution grant fields: " + ", ".join(unknown)
                )
            for field_name in required:
                if not isinstance(raw.get(field_name), str):
                    raise ValueError(
                        f"signed Hyper-V execution grant {field_name} must be a string"
                    )
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing Hyper-V execution grant fields: {', '.join(missing)}")
        grant = cls(
            campaign_sha256=str(raw["campaign_sha256"]),
            scope_manifest_sha256=str(raw["scope_manifest_sha256"]),
            campaign_id=str(raw["campaign_id"]),
            worker=str(raw["worker"]),
            guest_worker=str(raw["guest_worker"]),
            vm_name=str(raw["vm_name"]),
            checkpoint_name=str(raw["checkpoint_name"]),
            dump_path=str(raw["dump_path"]),
            trigger_executable_sha256=str(raw["trigger_executable_sha256"]),
            control_executable_sha256=str(raw["control_executable_sha256"]),
            issued_at=str(raw["issued_at"]),
            expires_at=str(raw["expires_at"]),
            nonce=str(raw["nonce"]),
            authorized_by=str(raw["authorized_by"]),
            signature_ssh=str(raw.get("signature_ssh", "")),
            schema_version=schema,
        )
        grant.validate()
        return grant

    def validate(self) -> None:
        if self.schema_version not in {GRANT_SCHEMA_VERSION, SIGNED_GRANT_SCHEMA_VERSION}:
            raise ValueError(f"unsupported Hyper-V execution grant schema: {self.schema_version}")
        for name in (
            "campaign_sha256",
            "scope_manifest_sha256",
            "trigger_executable_sha256",
            "control_executable_sha256",
        ):
            if not _SHA256_RE.fullmatch(getattr(self, name)):
                raise ValueError(f"execution grant {name} must be a lowercase SHA-256")
        if not _NONCE_RE.fullmatch(self.nonce):
            raise ValueError("execution grant nonce must be 32-128 URL-safe characters")
        if not self.authorized_by.strip():
            raise ValueError("execution grant authorized_by is empty")
        try:
            issued = datetime.fromisoformat(self.issued_at.replace("Z", "+00:00"))
            expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("execution grant timestamps must be ISO-8601") from exc
        if issued.tzinfo is None or expires.tzinfo is None:
            raise ValueError("execution grant timestamps must include a timezone")
        now = datetime.now(UTC)
        issued_utc = issued.astimezone(UTC)
        expires_utc = expires.astimezone(UTC)
        if issued_utc > now + timedelta(minutes=5):
            raise ValueError("execution grant was issued in the future")
        if now - issued_utc > timedelta(hours=24):
            raise ValueError("execution grant is older than 24 hours")
        if expires_utc <= now:
            raise ValueError("execution grant has expired")
        if expires_utc - issued_utc > timedelta(hours=24):
            raise ValueError("execution grant lifetime exceeds 24 hours")
        if self.schema_version == SIGNED_GRANT_SCHEMA_VERSION and not self.signature_ssh:
            raise ValueError("signed execution grant is missing signature_ssh")

    def require_signed_authorization(self) -> None:
        """Reverify operator authorization before a disruptive action."""
        self.validate()
        if (
            self.schema_version != SIGNED_GRANT_SCHEMA_VERSION
            or not self._authorization_verified
            or not self._signed_material
            or self._allowed_signers is None
        ):
            raise ValueError("Hyper-V execution requires a verified signed grant v2")
        signed_raw = json.loads(
            self._signed_material, object_pairs_hook=_unique_json_object
        )
        if not isinstance(signed_raw, dict):
            raise ValueError("signed Hyper-V execution grant material is malformed")
        signed_raw["signature_ssh"] = self.signature_ssh
        if self != HyperVExecutionGrant.from_mapping(signed_raw):
            raise ValueError("live Hyper-V execution grant fields differ from signed material")
        from .ssh_authorization import verify_ssh_signature

        verify_ssh_signature(
            self._signed_material,
            self.signature_ssh,
            identity=self.authorized_by,
            namespace=GRANT_AUTHORIZATION_NAMESPACE,
            allowed_signers=self._allowed_signers,
            label="Hyper-V execution grant authorization",
            require_trusted_policy=self._require_trusted_policy,
        )

    def validate_binding(
        self,
        manifest: HyperVProverManifest,
        manifest_sha256: str,
        scope_manifest_sha256: str,
    ) -> None:
        manifest.require_source_binding(manifest_sha256)
        if self.schema_version == SIGNED_GRANT_SCHEMA_VERSION:
            self.require_signed_authorization()
        self.validate()
        expected: dict[str, str] = {
            "campaign_sha256": manifest_sha256,
            "scope_manifest_sha256": scope_manifest_sha256,
            "campaign_id": manifest.campaign_id,
            "worker": manifest.worker,
            "guest_worker": manifest.guest_worker,
            "vm_name": manifest.vm_name,
            "checkpoint_name": manifest.checkpoint_name,
            "dump_path": manifest.dump_path,
        }
        mismatches = [name for name, value in expected.items() if getattr(self, name) != value]
        if (
            manifest.trigger_argv[0] == manifest.control_argv[0]
            and self.trigger_executable_sha256 != self.control_executable_sha256
        ):
            mismatches.append("executable_sha256")
        if mismatches:
            raise ValueError(
                "execution grant binding mismatch: " + ", ".join(sorted(mismatches))
            )

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        for field_name in (
            "_signed_material",
            "_allowed_signers",
            "_require_trusted_policy",
            "_authorization_verified",
        ):
            payload.pop(field_name)
        if self.schema_version == GRANT_SCHEMA_VERSION:
            payload.pop("signature_ssh")
        return payload


@dataclass(frozen=True)
class HyperVObservation:
    case: str
    trial: int
    build_lab_ex: str
    status: str
    crash_signature: str = ""
    dump_sha256: str = ""
    dump_identity: str = ""
    dump_artifact_path: str = ""
    guest_transcript_sha256: str = ""
    guest_transcript_path: str = ""
    dump_analysis_path: str = ""
    dump_analysis_sha256: str = ""
    run_nonce: str = ""
    argv_sha256: str = ""
    error: str = ""

    def validate(self, expected_case: str, expected_trial: int) -> None:
        if self.case != expected_case or self.trial != expected_trial:
            raise ValueError("worker returned evidence for the wrong Hyper-V case/trial")
        if self.status not in {"CLEAN", "CRASH", "ERROR"}:
            raise ValueError(f"unknown Hyper-V observation status: {self.status}")
        if not _NONCE_RE.fullmatch(self.run_nonce):
            raise ValueError("Hyper-V observation has no valid run nonce")
        if not _SHA256_RE.fullmatch(self.argv_sha256):
            raise ValueError("Hyper-V observation has no valid argv hash")
        for name in ("dump_sha256", "guest_transcript_sha256", "dump_analysis_sha256"):
            value = getattr(self, name)
            if value and not _SHA256_RE.fullmatch(value):
                raise ValueError(f"{name} must be a lowercase SHA-256")
        if self.status in {"CLEAN", "CRASH"} and not self.build_lab_ex:
            raise ValueError("successful Hyper-V observation has no BuildLabEx")
        if self.status == "CRASH":
            if not all(
                (
                    self.crash_signature,
                    self.dump_sha256,
                    self.dump_identity,
                    self.dump_artifact_path,
                    self.guest_transcript_sha256,
                )
            ):
                raise ValueError("crash evidence is missing provenance")
            if self.error:
                raise ValueError("crash evidence cannot contain an error")
        elif self.status == "CLEAN":
            if not self.guest_transcript_sha256:
                raise ValueError("clean evidence requires a transcript hash")
            if any(
                (
                    self.crash_signature,
                    self.dump_sha256,
                    self.dump_identity,
                    self.dump_artifact_path,
                    self.error,
                )
            ):
                raise ValueError("clean evidence contains crash or error provenance")
        elif not self.error:
            raise ValueError("error evidence requires an error message")
        elif any(
            (self.crash_signature, self.dump_sha256, self.dump_identity, self.dump_artifact_path)
        ):
            raise ValueError("error evidence cannot contain crash provenance")
        for name in ("guest_transcript_path", "dump_analysis_path"):
            if "\x00" in getattr(self, name):
                raise ValueError(f"{name} must be NUL-free")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class HyperVProverEvidence:
    manifest_sha256: str
    scope_manifest_sha256: str
    campaign_id: str
    scope_program: str
    worker: str
    status: str
    crash_signature: str
    confirmations: int
    required_confirmations: int
    observations: tuple[HyperVObservation, ...]
    error: str = ""
    schema_version: str = EVIDENCE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["observations"] = [observation.to_dict() for observation in self.observations]
        return row


def write_evidence_bundle(
    evidence: HyperVProverEvidence,
    artifact_dir: str | Path,
    receipt_path: str | Path | None = None,
    *,
    extra: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], Path]:
    """Write a portable receipt whose sidecar paths are bundle-relative.

    The transport records absolute paths while it is collecting evidence so
    callers can inspect artifacts immediately.  Absolute producer paths are not
    portable across the pwnkit/0cloud handoff, though, so the canonical receipt
    is always written next to its sidecars and refers to them by relative path.
    """
    root = Path(artifact_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = Path(receipt_path).resolve() if receipt_path else root / "evidence.json"
    if destination.parent != root:
        raise ValueError("Hyper-V evidence receipt must be directly inside --artifact-dir")

    payload = evidence.to_dict()
    if extra:
        payload.update(extra)
    observations = payload.get("observations")
    if not isinstance(observations, list):
        raise ValueError("Hyper-V evidence observations are malformed")
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("Hyper-V evidence observation is malformed")
        for field in ("guest_transcript_path", "dump_analysis_path", "dump_artifact_path"):
            raw = observation.get(field)
            if not raw:
                continue
            sidecar = Path(str(raw)).resolve()
            if not sidecar.is_relative_to(root) or not sidecar.is_file():
                raise ValueError(f"{field} is outside the retained Hyper-V evidence bundle")
            observation[field] = sidecar.relative_to(root).as_posix()

    with destination.open("x", encoding="utf-8") as output:
        output.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload, destination


class HyperVWorker(Protocol):
    def run_case(
        self,
        manifest: HyperVProverManifest,
        *,
        case: str,
        trial: int,
        argv: Sequence[str],
    ) -> HyperVObservation: ...


def load_manifest(path: str | Path) -> tuple[HyperVProverManifest, str]:
    data = Path(path).read_bytes()
    raw = json.loads(data)
    if not isinstance(raw, dict):
        raise ValueError("Hyper-V prover manifest must be a JSON object")
    digest = hashlib.sha256(data).hexdigest()
    manifest = replace(
        HyperVProverManifest.from_mapping(raw),
        _source_material=data,
        _source_sha256=digest,
    )
    return manifest, digest


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_execution_grant(
    path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
    require_authorized: bool = False,
) -> tuple[HyperVExecutionGrant, str]:
    grant_path = Path(path)
    if grant_path.is_symlink() or not grant_path.is_file():
        raise ValueError("Hyper-V execution grant must be a regular non-symlink file")
    data = grant_path.read_bytes()
    raw = json.loads(data, object_pairs_hook=_unique_json_object)
    if not isinstance(raw, dict):
        raise ValueError("Hyper-V execution grant must be a JSON object")
    grant = HyperVExecutionGrant.from_mapping(raw)
    if grant.schema_version == SIGNED_GRANT_SCHEMA_VERSION:
        from .ssh_authorization import canonical_signed_material, verify_ssh_signature

        configured = (
            Path(allowed_signers)
            if allowed_signers is not None
            else DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS
        )
        require_trusted = allowed_signers is None
        material = canonical_signed_material(raw)
        verify_ssh_signature(
            material,
            grant.signature_ssh,
            identity=grant.authorized_by,
            namespace=GRANT_AUTHORIZATION_NAMESPACE,
            allowed_signers=configured,
            label="Hyper-V execution grant authorization",
            require_trusted_policy=require_trusted,
        )
        grant = replace(
            grant,
            _signed_material=material,
            _allowed_signers=configured.expanduser().resolve(),
            _require_trusted_policy=require_trusted,
            _authorization_verified=True,
        )
    if require_authorized:
        grant.require_signed_authorization()
    return grant, hashlib.sha256(data).hexdigest()


def prove_hyperv(
    manifest: HyperVProverManifest,
    manifest_sha256: str,
    scope: WindowsScope,
    scope_manifest_sha256: str,
    *,
    worker: HyperVWorker,
    execution_grant: HyperVExecutionGrant,
    worker_acceptance: VerifiedHyperVWorkerAcceptance,
    execution_grant_sha256: str,
    acceptance_seal_key: bytes | str | None = None,
) -> HyperVProverEvidence:
    """Run paired controls/targets and promote only repeatable target-only crashes."""
    scope.require_source_binding(scope_manifest_sha256)
    execution_grant.require_signed_authorization()
    validate_campaign_scope(manifest, scope)
    if not _SHA256_RE.fullmatch(manifest_sha256):
        raise ValueError("manifest_sha256 must be a lowercase SHA-256")
    if not _SHA256_RE.fullmatch(scope_manifest_sha256):
        raise ValueError("scope_manifest_sha256 must be a lowercase SHA-256")
    execution_grant.validate_binding(manifest, manifest_sha256, scope_manifest_sha256)
    worker_acceptance.validate_binding(
        manifest,
        manifest_sha256,
        scope,
        scope_manifest_sha256,
        execution_grant,
        execution_grant_sha256,
        key=acceptance_seal_key,
    )

    observations: list[HyperVObservation] = []
    target_dump_hashes: set[str] = set()
    target_signatures: set[str] = set()
    try:
        for trial in range(1, manifest.trials + 1):
            # Every authorization layer is rechecked before every remote case.
            scope.require_source_binding(scope_manifest_sha256)
            execution_grant.validate_binding(manifest, manifest_sha256, scope_manifest_sha256)
            worker_acceptance.validate_binding(
                manifest,
                manifest_sha256,
                scope,
                scope_manifest_sha256,
                execution_grant,
                execution_grant_sha256,
                key=acceptance_seal_key,
            )
            control = worker.run_case(
                manifest, case="control", trial=trial, argv=manifest.control_argv
            )
            control.validate("control", trial)
            observations.append(control)
            if control.build_lab_ex:
                verify_evidence_builds(scope, [control.build_lab_ex])
            if control.status != "CLEAN":
                return _evidence(
                    manifest,
                    manifest_sha256,
                    scope,
                    scope_manifest_sha256,
                    observations,
                    status="INCONCLUSIVE",
                    error=f"control was not clean: {control.error or control.status}",
                )

            scope.require_source_binding(scope_manifest_sha256)
            execution_grant.validate_binding(manifest, manifest_sha256, scope_manifest_sha256)
            worker_acceptance.validate_binding(
                manifest,
                manifest_sha256,
                scope,
                scope_manifest_sha256,
                execution_grant,
                execution_grant_sha256,
                key=acceptance_seal_key,
            )
            target = worker.run_case(
                manifest, case="target", trial=trial, argv=manifest.trigger_argv
            )
            target.validate("target", trial)
            observations.append(target)
            if target.build_lab_ex:
                verify_evidence_builds(scope, [target.build_lab_ex])
            if target.status == "ERROR":
                return _evidence(
                    manifest,
                    manifest_sha256,
                    scope,
                    scope_manifest_sha256,
                    observations,
                    status="INCONCLUSIVE",
                    error=f"target trial failed: {target.error}",
                )
            if target.status == "CRASH":
                if target.dump_sha256 in target_dump_hashes:
                    return _evidence(
                        manifest,
                        manifest_sha256,
                        scope,
                        scope_manifest_sha256,
                        observations,
                        status="INCONCLUSIVE",
                        error="target confirmations reused a dump artifact",
                    )
                target_dump_hashes.add(target.dump_sha256)
                target_signatures.add(target.crash_signature)
                if len(target_signatures) > 1:
                    return _evidence(
                        manifest,
                        manifest_sha256,
                        scope,
                        scope_manifest_sha256,
                        observations,
                        status="INCONCLUSIVE",
                        error="target crash signatures were not identical",
                    )
    except (OSError, RuntimeError, ValueError) as exc:
        return _evidence(
            manifest,
            manifest_sha256,
            scope,
            scope_manifest_sha256,
            observations,
            status="INCONCLUSIVE",
            error=str(exc),
        )

    targets = [row for row in observations if row.case == "target"]
    signatures = [row.crash_signature for row in targets if row.status == "CRASH"]
    unique = set(signatures)
    confirmations = len(signatures)
    if unique and confirmations >= manifest.minimum_confirmations:
        try:
            scope.require_source_binding(scope_manifest_sha256)
            execution_grant.validate_binding(
                manifest, manifest_sha256, scope_manifest_sha256
            )
            worker_acceptance.validate_binding(
                manifest,
                manifest_sha256,
                scope,
                scope_manifest_sha256,
                execution_grant,
                execution_grant_sha256,
                key=acceptance_seal_key,
            )
        except ValueError as exc:
            return _evidence(
                manifest,
                manifest_sha256,
                scope,
                scope_manifest_sha256,
                observations,
                status="INCONCLUSIVE",
                error=f"authorization expired before promotion: {exc}",
            )
        return _evidence(
            manifest,
            manifest_sha256,
            scope,
            scope_manifest_sha256,
            observations,
            status="REPRODUCED",
        )
    status, error = "NOT_REPRODUCED", "confirmation threshold was not met"
    return _evidence(
        manifest,
        manifest_sha256,
        scope,
        scope_manifest_sha256,
        observations,
        status=status,
        error=error,
    )


def validate_campaign_scope(
    manifest: HyperVProverManifest,
    scope: WindowsScope,
) -> None:
    """Validate the no-execution binding between a campaign and bounty scope."""
    manifest.validate()
    scope.validate()
    if scope.program not in {"hyperv-insider", "hyperv-server"}:
        raise ValueError("Hyper-V prover requires a Hyper-V bounty scope")
    if manifest.worker != scope.worker:
        raise ValueError("Hyper-V manifest worker does not match scope worker")
    if manifest.campaign_id != scope.campaign_id:
        raise ValueError("Hyper-V manifest campaign_id does not match scope campaign_id")


def _evidence(
    manifest: HyperVProverManifest,
    manifest_sha256: str,
    scope: WindowsScope,
    scope_manifest_sha256: str,
    observations: Sequence[HyperVObservation],
    *,
    status: str,
    error: str = "",
) -> HyperVProverEvidence:
    target_signatures = [
        row.crash_signature
        for row in observations
        if row.case == "target" and row.status == "CRASH"
    ]
    signature = target_signatures[0] if len(set(target_signatures)) == 1 else ""
    return HyperVProverEvidence(
        manifest_sha256=manifest_sha256,
        scope_manifest_sha256=scope_manifest_sha256,
        campaign_id=manifest.campaign_id,
        scope_program=scope.program,
        worker=manifest.worker,
        status=status,
        crash_signature=signature,
        confirmations=len(target_signatures),
        required_confirmations=manifest.minimum_confirmations,
        observations=tuple(observations),
        error=error,
    )
