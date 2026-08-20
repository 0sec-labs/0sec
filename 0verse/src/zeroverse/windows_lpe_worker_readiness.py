"""Non-executing readiness gate for an isolated Windows LPE worker.

The gate consumes already-signed Windows token authority plus independently
signed drill assertions and hash-bound opaque artifacts.  It emits only a
deterministic future run plan.  It has no transport, command runner, device
handle, native artifact-semantic verifier, or adapter dispatch.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_scope import DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS, WindowsScope, load_scope
from .windows_token_runner import (
    DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS,
    DEFAULT_GRANT_ALLOWED_SIGNERS,
    WindowsTokenCampaign,
    WindowsTokenExecutionGrant,
    WindowsTokenWorkerAcceptance,
    load_windows_token_campaign,
    load_windows_token_execution_grant,
    load_windows_token_worker_acceptance,
)

READINESS_SCHEMA_VERSION = "0verse.windows-lpe-worker-readiness/v1"
PLAN_SCHEMA_VERSION = "0verse.windows-lpe-worker-plan/v1"
SIGNATURE_NAMESPACE = "0verse-windows-lpe-worker-readiness"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-lpe-readiness.allowed_signers")
_MAX_RECEIPT_BYTES = 4 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$")
_ARTIFACTS = {
    "checkpoint_before_sha256": "checkpoint-before.bin",
    "checkpoint_dirty_sha256": "checkpoint-dirty.bin",
    "checkpoint_after_sha256": "checkpoint-after.bin",
    "benign_dump_sha256": "benign.dmp",
    "benign_dump_analysis_sha256": "benign-cdb.txt",
}


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Windows LPE readiness {label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"Windows LPE readiness {label} must include a timezone")
    return parsed.astimezone(UTC)


def _read_regular(path: Path, maximum: int) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise ValueError("Windows LPE readiness file is missing or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size == 0
            or before.st_size > maximum
        ):
            raise ValueError("Windows LPE readiness file must be bounded and regular")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ValueError("Windows LPE readiness file exceeds its byte limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or total != before.st_size
    ):
        raise ValueError("Windows LPE readiness file changed while it was read")
    return b"".join(chunks)


def _sha256_regular(path: Path) -> tuple[str, int]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size == 0
            or before.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise ValueError("Windows LPE readiness artifact must be bounded and regular")
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or total != before.st_size
    ):
        raise ValueError("Windows LPE readiness artifact changed while it was read")
    return digest.hexdigest(), total


@dataclass(frozen=True)
class WindowsLpeWorkerReadiness:
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    worker_acceptance_sha256: str
    campaign_id: str
    worker: str
    build_lab_ex: str
    worker_machine_id: str
    runner_executable_sha256: str
    target_vm_name: str
    checkpoint_name: str
    checkpoint_identity_sha256: str
    debugger_executable_sha256: str
    dump_configuration_sha256: str
    checkpoint_before_sha256: str
    checkpoint_dirty_sha256: str
    checkpoint_after_sha256: str
    benign_dump_sha256: str
    benign_dump_analysis_sha256: str
    drill_started_at: str
    drill_completed_at: str
    issued_at: str
    expires_at: str
    nonce: str
    accepted_by: str
    checkpoint_restore_confirmed: bool
    debugger_smoke_confirmed: bool
    complete_dump_confirmed: bool
    network_isolated: bool
    compile_time_adapter_registry_only: bool
    arbitrary_command_allowed: bool
    device_io_control_allowed: bool
    candidate_execution_authorized: bool
    human_start_gate: bool
    signature_ssh: str
    schema_version: str = READINESS_SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _allowed_signers: Path | None = field(default=None, repr=False, compare=False)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> WindowsLpeWorkerReadiness:
        expected = {
            item.name
            for item in cls.__dataclass_fields__.values()
            if not item.name.startswith("_")
        }
        missing = sorted(expected - raw.keys())
        unknown = sorted(raw.keys() - expected)
        if missing or unknown:
            raise ValueError(
                "Windows LPE readiness fields invalid: "
                + "; ".join(
                    part
                    for part in (
                        f"missing {', '.join(missing)}" if missing else "",
                        f"unknown {', '.join(unknown)}" if unknown else "",
                    )
                    if part
                )
            )
        bool_fields = {
            "checkpoint_restore_confirmed",
            "debugger_smoke_confirmed",
            "complete_dump_confirmed",
            "network_isolated",
            "compile_time_adapter_registry_only",
            "arbitrary_command_allowed",
            "device_io_control_allowed",
            "candidate_execution_authorized",
            "human_start_gate",
        }
        if any(not isinstance(raw[name], bool) for name in bool_fields):
            raise ValueError("Windows LPE readiness safety fields must be booleans")
        if any(not isinstance(raw[name], str) for name in expected - bool_fields):
            raise ValueError("Windows LPE readiness non-safety fields must be strings")
        readiness = cls(**dict(raw))  # type: ignore[arg-type]
        readiness.validate()
        return readiness

    def validate(self) -> None:
        if self.schema_version != READINESS_SCHEMA_VERSION:
            raise ValueError("unsupported Windows LPE readiness schema")
        digest_fields = {
            name for name in self.__dataclass_fields__ if name.endswith("_sha256")
        }
        if any(not _SHA256.fullmatch(getattr(self, name)) for name in digest_fields):
            raise ValueError("Windows LPE readiness contains an invalid SHA-256")
        if not _NONCE.fullmatch(self.nonce):
            raise ValueError("Windows LPE readiness nonce is invalid")
        for name in ("campaign_id", "worker", "target_vm_name", "checkpoint_name"):
            if not _NAME.fullmatch(getattr(self, name)):
                raise ValueError(f"Windows LPE readiness {name} is invalid")
        for name in ("build_lab_ex", "worker_machine_id", "accepted_by", "signature_ssh"):
            value = getattr(self, name)
            if not value.strip() or "\x00" in value or len(value) > 16_384:
                raise ValueError(f"Windows LPE readiness {name} is invalid")
        required_true = (
            self.checkpoint_restore_confirmed,
            self.debugger_smoke_confirmed,
            self.complete_dump_confirmed,
            self.network_isolated,
            self.compile_time_adapter_registry_only,
            self.human_start_gate,
        )
        required_false = (
            self.arbitrary_command_allowed,
            self.device_io_control_allowed,
            self.candidate_execution_authorized,
        )
        if not all(required_true) or any(required_false):
            raise ValueError("Windows LPE readiness safety posture is not fail-closed")
        if self.checkpoint_before_sha256 != self.checkpoint_after_sha256:
            raise ValueError("Windows LPE checkpoint did not return to its baseline probe")
        if self.checkpoint_dirty_sha256 == self.checkpoint_before_sha256:
            raise ValueError("Windows LPE checkpoint drill did not observe dirty state")
        started = _timestamp(self.drill_started_at, "drill_started_at")
        completed = _timestamp(self.drill_completed_at, "drill_completed_at")
        issued = _timestamp(self.issued_at, "issued_at")
        expires = _timestamp(self.expires_at, "expires_at")
        now = datetime.now(UTC)
        if not started < completed <= issued <= now + timedelta(minutes=5):
            raise ValueError("Windows LPE readiness timeline is invalid")
        if now - completed > timedelta(hours=24) or completed - started > timedelta(hours=4):
            raise ValueError("Windows LPE readiness drill is stale or too long")
        if expires <= now or expires <= issued or expires - issued > timedelta(hours=24):
            raise ValueError("Windows LPE readiness expiry is invalid")


@dataclass(frozen=True)
class WindowsLpeWorkerPlan:
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    worker_acceptance_sha256: str
    readiness_sha256: str
    campaign_id: str
    worker: str
    build_lab_ex: str
    worker_machine_id: str
    runner_executable_sha256: str
    target_vm_name: str
    checkpoint_name: str
    checkpoint_identity_sha256: str
    debugger_executable_sha256: str
    dump_configuration_sha256: str
    authority_key_commitments: dict[str, str]
    opaque_artifacts: tuple[dict[str, object], ...]
    trials: int
    steps: tuple[dict[str, object], ...]
    schema_version: str = PLAN_SCHEMA_VERSION
    status: str = "UNTRUSTED_POLICY_REVIEW_ONLY"
    trusted_policy: bool = False
    production_ready: bool = False
    artifact_semantics_verified: bool = False
    checkpoint_restore_semantics_verified: bool = False
    debugger_smoke_semantics_verified: bool = False
    complete_dump_semantics_verified: bool = False
    opaque_artifact_receipt_only: bool = True
    execution_authorized: bool = False
    device_io_control_authorized: bool = False
    arbitrary_command_authorized: bool = False
    network_access_authorized: bool = False
    human_start_gate: bool = True

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["opaque_artifacts"] = list(self.opaque_artifacts)
        payload["steps"] = list(self.steps)
        return payload


def verify_windows_lpe_worker_readiness(
    *,
    campaign_path: str | Path,
    scope_path: str | Path,
    execution_grant_path: str | Path,
    worker_acceptance_path: str | Path,
    readiness_path: str | Path,
    scope_allowed_signers: str | Path | None = None,
    grant_allowed_signers: str | Path | None = None,
    acceptance_allowed_signers: str | Path | None = None,
    readiness_allowed_signers: str | Path | None = None,
) -> WindowsLpeWorkerPlan:
    campaign, campaign_sha256 = load_windows_token_campaign(campaign_path)
    trusted_policy = all(
        value is None
        for value in (
            scope_allowed_signers,
            grant_allowed_signers,
            acceptance_allowed_signers,
            readiness_allowed_signers,
        )
    )
    scope_policy = Path(scope_allowed_signers or DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS)
    grant_policy = Path(grant_allowed_signers or DEFAULT_GRANT_ALLOWED_SIGNERS)
    acceptance_policy = Path(acceptance_allowed_signers or DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS)
    readiness_policy = Path(readiness_allowed_signers or DEFAULT_ALLOWED_SIGNERS)
    scope, scope_sha256 = load_scope(
        scope_path, allowed_signers=scope_allowed_signers, require_authorized=True
    )
    grant, grant_sha256 = load_windows_token_execution_grant(
        execution_grant_path,
        allowed_signers=grant_allowed_signers,
        require_authorized=True,
    )
    acceptance, acceptance_sha256 = load_windows_token_worker_acceptance(
        worker_acceptance_path,
        allowed_signers=acceptance_allowed_signers,
        require_authorized=True,
    )
    acceptance.require_binding(
        campaign,
        campaign_sha256,
        scope,
        scope_sha256,
        grant,
        grant_sha256,
        acceptance_sha256,
    )
    readiness_path = Path(os.path.abspath(readiness_path))  # noqa: PTH100 - do not follow links
    data = _read_regular(readiness_path, _MAX_RECEIPT_BYTES)
    raw = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("Windows LPE readiness must be a JSON object")
    readiness = WindowsLpeWorkerReadiness.from_mapping(raw)
    material = canonical_signed_material(raw)
    verify_ssh_signature(
        material,
        readiness.signature_ssh,
        identity=readiness.accepted_by,
        namespace=SIGNATURE_NAMESPACE,
        allowed_signers=readiness_policy,
        label="Windows LPE worker readiness",
        require_trusted_policy=readiness_allowed_signers is None,
    )
    readiness = WindowsLpeWorkerReadiness(
        **{name: getattr(readiness, name) for name in raw},
        _signed_material=material,
        _allowed_signers=readiness_policy.expanduser().resolve(),
    )
    readiness_sha256 = hashlib.sha256(data).hexdigest()
    _require_bindings(
        readiness,
        campaign,
        campaign_sha256,
        scope,
        scope_sha256,
        grant,
        grant_sha256,
        acceptance,
        acceptance_sha256,
    )
    opaque_artifacts = _verify_artifacts(readiness_path.parent, readiness)
    authority_key_commitments = {
        role: ssh_authority_key_commitment(policy)
        for role, policy in (
            ("scope", scope_policy),
            ("execution_grant", grant_policy),
            ("worker_acceptance", acceptance_policy),
            ("readiness", readiness_policy),
        )
    }
    if len(set(authority_key_commitments.values())) != 4:
        raise ValueError("Windows LPE readiness requires four independent SSH authorities")
    identities = {
        scope.authorized_by,
        grant.authorized_by,
        acceptance.accepted_by,
        acceptance.capture_signer,
        readiness.accepted_by,
    }
    if len(identities) != 5:
        raise ValueError("Windows LPE readiness role identities must be distinct")
    return WindowsLpeWorkerPlan(
        campaign_sha256=campaign_sha256,
        scope_manifest_sha256=scope_sha256,
        execution_grant_sha256=grant_sha256,
        worker_acceptance_sha256=acceptance_sha256,
        readiness_sha256=readiness_sha256,
        campaign_id=campaign.campaign_id,
        worker=campaign.worker,
        build_lab_ex=acceptance.build_lab_ex,
        worker_machine_id=readiness.worker_machine_id,
        runner_executable_sha256=readiness.runner_executable_sha256,
        target_vm_name=readiness.target_vm_name,
        checkpoint_name=readiness.checkpoint_name,
        checkpoint_identity_sha256=readiness.checkpoint_identity_sha256,
        debugger_executable_sha256=readiness.debugger_executable_sha256,
        dump_configuration_sha256=readiness.dump_configuration_sha256,
        authority_key_commitments=authority_key_commitments,
        opaque_artifacts=opaque_artifacts,
        trials=campaign.trials,
        steps=_plan_steps(campaign),
        status=(
            "READY_FOR_OPERATOR_REVIEW"
            if trusted_policy
            else "UNTRUSTED_POLICY_REVIEW_ONLY"
        ),
        trusted_policy=trusted_policy,
        production_ready=trusted_policy,
    )


def _require_bindings(
    readiness: WindowsLpeWorkerReadiness,
    campaign: WindowsTokenCampaign,
    campaign_sha256: str,
    scope: WindowsScope,
    scope_sha256: str,
    grant: WindowsTokenExecutionGrant,
    grant_sha256: str,
    acceptance: WindowsTokenWorkerAcceptance,
    acceptance_sha256: str,
) -> None:
    expected: dict[str, str] = {
        "campaign_sha256": campaign_sha256,
        "scope_manifest_sha256": scope_sha256,
        "execution_grant_sha256": grant_sha256,
        "worker_acceptance_sha256": acceptance_sha256,
        "campaign_id": campaign.campaign_id,
        "worker": campaign.worker,
        "build_lab_ex": acceptance.build_lab_ex,
        "worker_machine_id": acceptance.worker_machine_id,
        "runner_executable_sha256": acceptance.runner_executable_sha256,
    }
    mismatches = [name for name, value in expected.items() if getattr(readiness, name) != value]
    if mismatches:
        raise ValueError(
            "Windows LPE readiness authority binding mismatch: "
            + ", ".join(mismatches)
        )
    if _timestamp(readiness.issued_at, "issued_at") < _timestamp(
        acceptance.issued_at, "acceptance issued_at"
    ):
        raise ValueError("Windows LPE readiness predates worker acceptance")
    drill_started = _timestamp(readiness.drill_started_at, "drill_started_at")
    authority_issued = max(
        _timestamp(scope.issued_at, "scope issued_at"),
        _timestamp(grant.issued_at, "grant issued_at"),
        _timestamp(acceptance.issued_at, "acceptance issued_at"),
    )
    if drill_started < authority_issued:
        raise ValueError("Windows LPE readiness drill predates its authority")
    if _timestamp(readiness.expires_at, "expires_at") > min(
        _timestamp(scope.expires_at, "scope expires_at"),
        _timestamp(grant.expires_at, "grant expires_at"),
        _timestamp(acceptance.expires_at, "acceptance expires_at"),
    ):
        raise ValueError("Windows LPE readiness outlives its authority")


def _verify_artifacts(
    base: Path, readiness: WindowsLpeWorkerReadiness
) -> tuple[dict[str, object], ...]:
    artifacts: list[dict[str, object]] = []
    for field_name, filename in _ARTIFACTS.items():
        path = base / filename
        if path.parent != base:
            raise ValueError(f"Windows LPE readiness artifact is unsafe: {filename}")
        try:
            digest, size = _sha256_regular(path)
        except (FileNotFoundError, OSError) as exc:
            raise ValueError(
                f"Windows LPE readiness artifact is missing or unsafe: {filename}"
            ) from exc
        if digest != getattr(readiness, field_name):
            raise ValueError(f"Windows LPE readiness artifact SHA-256 mismatch: {filename}")
        artifacts.append(
            {
                "path": filename,
                "sha256": digest,
                "size_bytes": size,
                "semantics_verified": False,
            }
        )
    return tuple(artifacts)


def _plan_steps(campaign: WindowsTokenCampaign) -> tuple[dict[str, object], ...]:
    steps: list[dict[str, object]] = []
    for trial in range(1, campaign.trials + 1):
        for case, operation_sha256 in (("control", campaign.control_operation_sha256),):
            steps.extend(
                (
                    {"action": "restore-checkpoint", "case": case, "trial": trial},
                    {"action": "verify-baseline-probe", "case": case, "trial": trial},
                    {
                        "action": "operator-gated-adapter",
                        "case": case,
                        "trial": trial,
                        "operation_sha256": operation_sha256,
                        "execution_authorized": False,
                    },
                    {"action": "collect-token-and-dump-evidence", "case": case, "trial": trial},
                )
            )
        steps.append(
            {
                "action": "require-clean-control",
                "trial": trial,
                "on_failure": "abort-and-quarantine",
            }
        )
        for case, operation_sha256 in (("target", campaign.target_operation_sha256),):
            steps.extend(
                (
                    {"action": "restore-checkpoint", "case": case, "trial": trial},
                    {"action": "verify-baseline-probe", "case": case, "trial": trial},
                    {
                        "action": "operator-gated-adapter",
                        "case": case,
                        "trial": trial,
                        "operation_sha256": operation_sha256,
                        "execution_authorized": False,
                    },
                    {"action": "collect-token-and-dump-evidence", "case": case, "trial": trial},
                )
            )
    steps.extend(
        (
            {"action": "restore-checkpoint", "case": "final", "trial": campaign.trials},
            {"action": "verify-baseline-probe", "case": "final", "trial": campaign.trials},
        )
    )
    return tuple(steps)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result
