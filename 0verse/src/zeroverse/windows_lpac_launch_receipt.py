"""Verifier-only contract for one service-held Windows LPAC launch.

The receipt authenticates OS facts sampled from a held ``PROCESS_INFORMATION``
capability.  It cannot launch, locate, select, or command a process.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_app_container import valid_package_app_container_sid
from .windows_token_runner import ELIGIBLE_WINDOWS_SANDBOXES

SCHEMA_VERSION = "0verse.windows-lpac-launch-receipt/v2"
SIGNATURE_NAMESPACE = "0verse-windows-lpac-launch-receipt-v2"
LAUNCH_METHOD = "service-held-process-information"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-lpac-launch.allowed_signers")

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_PACKAGE = re.compile(r"^[A-Za-z0-9._~-]{1,256}$")
_PROCESS_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_FIELDS = frozenset(
    {
        "schema_version",
        "launch_method",
        "launch_profile_id",
        "launch_profile_sha256",
        "eligible_sandbox",
        "launch_app_container_executable_sha256",
        "sandbox_process_executable_sha256",
        "package_full_name",
        "package_family_name",
        "app_container_sid",
        "less_privileged_app_container",
        "created_suspended",
        "process_id",
        "thread_id",
        "process_creation_filetime",
        "process_instance_id",
        "process_locator_identity_sha256",
        "launch_started_at",
        "launch_completed_at",
        "process_alive_at_handoff",
        "process_handle_held",
        "thread_handle_held",
        "launch_transcript_sha256",
        "receipt_nonce",
        "fixed_adapter_operation_sha256",
        "campaign_sha256",
        "scope_manifest_sha256",
        "execution_grant_sha256",
        "worker_acceptance_sha256",
        "campaign_id",
        "case",
        "trial",
        "run_nonce",
        "worker",
        "worker_machine_id",
        "build_lab_ex",
        "signed_by",
        "signature_ssh",
    }
)
_INTEGER_FIELDS = frozenset({"process_id", "thread_id", "process_creation_filetime", "trial"})
_BOOLEAN_FIELDS = frozenset(
    {
        "less_privileged_app_container",
        "created_suspended",
        "process_alive_at_handoff",
        "process_handle_held",
        "thread_handle_held",
    }
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Windows LPAC launch receipt {name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"Windows LPAC launch receipt {name} must include a timezone")
    return parsed.astimezone(UTC)


def _read_regular_nofollow(path: Path, maximum: int = 1024 * 1024) -> bytes:
    if path.is_symlink():
        raise ValueError("Windows LPAC launch receipt cannot be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Windows LPAC launch receipt must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Windows LPAC launch receipt exceeds the size limit")
        return data
    finally:
        os.close(descriptor)


def derive_process_locator_identity(
    *, worker_machine_id: str, process_id: int, process_creation_filetime: int
) -> str:
    if (
        _SHA256.fullmatch(worker_machine_id) is None
        or isinstance(process_id, bool)
        or not 0 < process_id < 2**32
        or isinstance(process_creation_filetime, bool)
        or not 0 < process_creation_filetime < 2**64
    ):
        raise ValueError("Windows LPAC launch process locator facts are invalid")
    return hashlib.sha256(
        b"0verse-windows-lpac-launch-process-locator-v2\0"
        + worker_machine_id.encode("ascii")
        + b"\0"
        + process_id.to_bytes(4, "little")
        + process_creation_filetime.to_bytes(8, "little")
    ).hexdigest()


def derive_process_instance_id(
    *, worker_machine_id: str, process_id: int, process_creation_filetime: int
) -> str:
    if (
        _SHA256.fullmatch(worker_machine_id) is None
        or isinstance(process_id, bool)
        or not 0 < process_id < 2**32
        or isinstance(process_creation_filetime, bool)
        or not 0 < process_creation_filetime < 2**64
    ):
        raise ValueError("Windows LPAC launch process instance facts are invalid")
    digest = hashlib.sha256(
        b"0verse-windows-lpac-launch-process-instance-v2\0"
        + worker_machine_id.encode("ascii")
        + b"\0"
        + process_id.to_bytes(4, "little")
        + process_creation_filetime.to_bytes(8, "little")
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class WindowsLpacLaunchReceipt:
    launch_method: str
    launch_profile_id: str
    launch_profile_sha256: str
    eligible_sandbox: str
    launch_app_container_executable_sha256: str
    sandbox_process_executable_sha256: str
    package_full_name: str
    package_family_name: str
    app_container_sid: str
    less_privileged_app_container: bool
    created_suspended: bool
    process_id: int
    thread_id: int
    process_creation_filetime: int
    process_instance_id: str
    process_locator_identity_sha256: str
    launch_started_at: str
    launch_completed_at: str
    process_alive_at_handoff: bool
    process_handle_held: bool
    thread_handle_held: bool
    launch_transcript_sha256: str
    receipt_nonce: str
    fixed_adapter_operation_sha256: str
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    worker_acceptance_sha256: str
    campaign_id: str
    case: str
    trial: int
    run_nonce: str
    worker: str
    worker_machine_id: str
    build_lab_ex: str
    signed_by: str
    signature_ssh: str
    schema_version: str = SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _signature_verified: bool = field(default=False, repr=False, compare=False)
    _source_material: bytes = field(default=b"", repr=False, compare=False)
    _source_sha256: str = field(default="", repr=False, compare=False)

    @classmethod
    def from_mapping(cls, raw: object) -> WindowsLpacLaunchReceipt:
        if not isinstance(raw, dict) or set(raw) != _FIELDS:
            raise ValueError("Windows LPAC launch receipt must contain the exact fields")
        if any(not isinstance(raw[name], bool) for name in _BOOLEAN_FIELDS):
            raise ValueError("Windows LPAC launch receipt safety facts must be boolean")
        for name in _INTEGER_FIELDS:
            if isinstance(raw[name], bool) or not isinstance(raw[name], int):
                raise ValueError(f"Windows LPAC launch receipt {name} must be an integer")
        for name in _FIELDS - _INTEGER_FIELDS - _BOOLEAN_FIELDS:
            if not isinstance(raw[name], str):
                raise ValueError(f"Windows LPAC launch receipt {name} must be a string")
        receipt = cls(**raw)
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION or self.launch_method != LAUNCH_METHOD:
            raise ValueError("unsupported Windows LPAC launch receipt schema or method")
        if self.eligible_sandbox not in ELIGIBLE_WINDOWS_SANDBOXES:
            raise ValueError("Windows LPAC launch receipt sandbox is not officially eligible")
        for name in (
            "launch_profile_sha256",
            "launch_app_container_executable_sha256",
            "sandbox_process_executable_sha256",
            "process_locator_identity_sha256",
            "launch_transcript_sha256",
            "fixed_adapter_operation_sha256",
            "campaign_sha256",
            "scope_manifest_sha256",
            "execution_grant_sha256",
            "worker_acceptance_sha256",
            "worker_machine_id",
        ):
            if _SHA256.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"Windows LPAC launch receipt {name} must be a SHA-256")
        if not 0 < self.process_id < 2**32 or not 0 < self.thread_id < 2**32:
            raise ValueError("Windows LPAC launch receipt process/thread identity is invalid")
        if not 0 < self.process_creation_filetime < 2**64:
            raise ValueError("Windows LPAC launch receipt creation FILETIME is invalid")
        if not all(
            (
                self.less_privileged_app_container,
                self.created_suspended,
                self.process_alive_at_handoff,
                self.process_handle_held,
                self.thread_handle_held,
            )
        ):
            raise ValueError(
                "Windows LPAC launch receipt requires held suspended LPAC process facts"
            )
        if not valid_package_app_container_sid(self.app_container_sid):
            raise ValueError("Windows LPAC launch receipt AppContainer SID is invalid")
        if (
            _PACKAGE.fullmatch(self.package_full_name) is None
            or _PACKAGE.fullmatch(self.package_family_name) is None
        ):
            raise ValueError("Windows LPAC launch receipt package identity is invalid")
        if _NONCE.fullmatch(self.receipt_nonce) is None or _NONCE.fullmatch(self.run_nonce) is None:
            raise ValueError("Windows LPAC launch receipt nonce is invalid")
        if self.receipt_nonce == self.run_nonce:
            raise ValueError("Windows LPAC launch receipt nonce domains collide")
        if self.case not in {"target", "control"} or not 1 <= self.trial <= 32:
            raise ValueError("Windows LPAC launch receipt case or trial is invalid")
        if _PROCESS_ID.fullmatch(self.process_instance_id) is None:
            raise ValueError("Windows LPAC launch receipt process instance is invalid")
        for name in ("launch_profile_id", "campaign_id", "worker", "build_lab_ex", "signed_by"):
            value = getattr(self, name)
            if (
                not value
                or value != value.strip()
                or len(value) > 256
                or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
            ):
                raise ValueError(f"Windows LPAC launch receipt {name} is invalid")
        started = _timestamp(self.launch_started_at, "launch_started_at")
        completed = _timestamp(self.launch_completed_at, "launch_completed_at")
        now = datetime.now(UTC)
        if completed < started or completed - started > timedelta(hours=1):
            raise ValueError("Windows LPAC launch receipt timestamps are out of order or too long")
        if completed > now + timedelta(minutes=5) or now - completed > timedelta(hours=24):
            raise ValueError("Windows LPAC launch receipt is outside the 24-hour evidence window")
        expected_locator = derive_process_locator_identity(
            worker_machine_id=self.worker_machine_id,
            process_id=self.process_id,
            process_creation_filetime=self.process_creation_filetime,
        )
        expected_instance = derive_process_instance_id(
            worker_machine_id=self.worker_machine_id,
            process_id=self.process_id,
            process_creation_filetime=self.process_creation_filetime,
        )
        if self.process_locator_identity_sha256 != expected_locator:
            raise ValueError("Windows LPAC launch receipt locator is not OS-fact-derived")
        if self.process_instance_id != expected_instance:
            raise ValueError("Windows LPAC launch receipt process instance is not OS-fact-derived")
        if not self.signature_ssh:
            raise ValueError("Windows LPAC launch receipt signature is required")

    def require_signature(self) -> None:
        self.validate()
        if not self._signature_verified or not self._signed_material:
            raise ValueError("Windows LPAC launch receipt requires a verified signature")
        raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("signed Windows LPAC launch receipt is malformed")
        raw["signature_ssh"] = self.signature_ssh
        if self != WindowsLpacLaunchReceipt.from_mapping(raw):
            raise ValueError("Windows LPAC launch receipt differs from signed material")

    @property
    def source_sha256(self) -> str:
        if (
            not self._source_sha256
            or not self._source_material
            or hashlib.sha256(self._source_material).hexdigest() != self._source_sha256
        ):
            raise ValueError("Windows LPAC launch receipt is not source-bound")
        raw = json.loads(self._source_material, object_pairs_hook=_unique_object)
        canonical_source = (
            json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            + b"\n"
        )
        if self._source_material != canonical_source or self != self.from_mapping(raw):
            raise ValueError("Windows LPAC launch receipt differs from its exact source bytes")
        return self._source_sha256


def load_windows_lpac_launch_receipt(
    path: str | Path, *, allowed_signers: str | Path | None = None
) -> tuple[WindowsLpacLaunchReceipt, str]:
    data = _read_regular_nofollow(Path(path))
    raw = json.loads(data, object_pairs_hook=_unique_object)
    canonical_source = (
        json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    if data != canonical_source:
        raise ValueError("Windows LPAC launch receipt source bytes are not canonical")
    receipt = WindowsLpacLaunchReceipt.from_mapping(raw)
    policy = Path(allowed_signers) if allowed_signers is not None else DEFAULT_ALLOWED_SIGNERS
    material = canonical_signed_material(raw)
    verify_ssh_signature(
        material,
        receipt.signature_ssh,
        identity=receipt.signed_by,
        namespace=SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows LPAC launch receipt",
        require_trusted_policy=allowed_signers is None,
    )
    digest = hashlib.sha256(data).hexdigest()
    receipt = replace(
        receipt,
        _signed_material=material,
        _signature_verified=True,
        _source_material=data,
        _source_sha256=digest,
    )
    receipt.require_signature()
    return receipt, digest


def derive_burn_only_replay_identities(
    receipt: WindowsLpacLaunchReceipt,
) -> tuple[str, str, str]:
    receipt.require_signature()
    return (
        hashlib.sha256(
            b"0verse-windows-lpac-launch-receipt-once-v2\0"
            + receipt.worker_machine_id.encode("ascii")
            + b"\0"
            + receipt.receipt_nonce.encode("ascii")
        ).hexdigest(),
        hashlib.sha256(
            b"0verse-windows-lpac-launch-process-once-v2\0"
            + receipt.process_locator_identity_sha256.encode("ascii")
        ).hexdigest(),
        hashlib.sha256(
            b"0verse-windows-lpac-launch-transcript-once-v2\0"
            + receipt.launch_transcript_sha256.encode("ascii")
        ).hexdigest(),
    )


def require_launch_receipt_binding(
    receipt: WindowsLpacLaunchReceipt,
    *,
    receipt_sha256: str,
    capture: object,
    broker: object,
    campaign: object,
    scope: object,
    grant: object,
    acceptance: object,
    campaign_sha256: str,
    scope_sha256: str,
    grant_sha256: str,
    acceptance_sha256: str,
) -> None:
    """Cross-bind one verified launch to the v5 capture and broker measurement."""
    receipt.require_signature()
    if receipt.source_sha256 != receipt_sha256:
        raise ValueError("Windows LPAC launch receipt differs from its exact source bytes")
    capture.require_signature()  # type: ignore[attr-defined]
    broker.require_signature()  # type: ignore[attr-defined]
    expected_operation = (
        campaign.target_operation_sha256  # type: ignore[attr-defined]
        if capture.case == "target"  # type: ignore[attr-defined]
        else campaign.control_operation_sha256  # type: ignore[attr-defined]
    )
    launch_completed = _timestamp(receipt.launch_completed_at, "launch_completed_at")
    launch_started = _timestamp(receipt.launch_started_at, "launch_started_at")
    measured_started = _timestamp(broker.measured_started_at, "measured_started_at")  # type: ignore[attr-defined]
    authority_issued = max(
        _timestamp(scope.issued_at, "scope issued_at"),  # type: ignore[attr-defined]
        _timestamp(grant.issued_at, "grant issued_at"),  # type: ignore[attr-defined]
        _timestamp(acceptance.issued_at, "acceptance issued_at"),  # type: ignore[attr-defined]
    )
    authority_expires = min(
        _timestamp(scope.expires_at, "scope expires_at"),  # type: ignore[attr-defined]
        _timestamp(grant.expires_at, "grant expires_at"),  # type: ignore[attr-defined]
        _timestamp(acceptance.expires_at, "acceptance expires_at"),  # type: ignore[attr-defined]
    )
    handoff = measured_started - launch_completed
    if (
        capture.lpac_launch_receipt_sha256 != receipt_sha256  # type: ignore[attr-defined]
        or broker.launch_receipt_sha256 != receipt_sha256  # type: ignore[attr-defined]
        or receipt.process_id != broker.measured_pid  # type: ignore[attr-defined]
        or receipt.process_creation_filetime != broker.measured_creation_filetime  # type: ignore[attr-defined]
        or receipt.process_instance_id != capture.process_instance_id  # type: ignore[attr-defined]
        or receipt.process_instance_id != broker.process_instance_id  # type: ignore[attr-defined]
        or receipt.sandbox_process_executable_sha256 != broker.image_sha256  # type: ignore[attr-defined]
        or receipt.package_full_name != broker.package_full_name  # type: ignore[attr-defined]
        or receipt.package_family_name != broker.package_family_name  # type: ignore[attr-defined]
        or receipt.app_container_sid != broker.app_container_sid  # type: ignore[attr-defined]
        or receipt.less_privileged_app_container != broker.less_privileged_app_container  # type: ignore[attr-defined]
        or receipt.eligible_sandbox != campaign.eligible_sandbox  # type: ignore[attr-defined]
        or receipt.launch_app_container_executable_sha256
        != campaign.launch_app_container_executable_sha256  # type: ignore[attr-defined]
        or receipt.sandbox_process_executable_sha256 != campaign.sandbox_process_executable_sha256  # type: ignore[attr-defined]
        or receipt.app_container_sid != campaign.app_container_sid  # type: ignore[attr-defined]
        or receipt.fixed_adapter_operation_sha256 != expected_operation
        or receipt.campaign_sha256 != campaign_sha256
        or receipt.scope_manifest_sha256 != scope_sha256
        or receipt.execution_grant_sha256 != grant_sha256
        or receipt.worker_acceptance_sha256 != acceptance_sha256
        or receipt.campaign_id != capture.campaign_id  # type: ignore[attr-defined]
        or receipt.case != capture.case  # type: ignore[attr-defined]
        or receipt.trial != capture.trial  # type: ignore[attr-defined]
        or receipt.run_nonce != capture.run_nonce  # type: ignore[attr-defined]
        or receipt.worker != capture.worker  # type: ignore[attr-defined]
        or receipt.worker_machine_id != capture.worker_machine_id  # type: ignore[attr-defined]
        or receipt.build_lab_ex != capture.build_lab_ex  # type: ignore[attr-defined]
        or launch_started < authority_issued
        or launch_completed >= authority_expires
        or handoff < timedelta(0)
        or handoff > timedelta(minutes=5)
    ):
        raise ValueError("Windows LPAC launch receipt is not authority/capture/broker-bound")
