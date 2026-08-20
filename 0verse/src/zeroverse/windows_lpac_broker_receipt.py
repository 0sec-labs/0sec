"""Verifier-only contract for externally measured Windows LPAC processes.

This module accepts evidence; it cannot locate, launch, select, or command a
process.  The caller-provided PID/creation FILETIME pair remains an untrusted
locator until the separately authorized broker signs matching OS measurements.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_app_container import valid_package_app_container_sid
from .windows_token_runner import ELIGIBLE_WINDOWS_SANDBOXES

SCHEMA_VERSION = "0verse.windows-lpac-process-broker-receipt/v1"
SIGNATURE_NAMESPACE = "0verse-windows-lpac-process-broker-receipt-v1"
OBSERVATION_LOCUS = "process-primary"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-lpac-broker.allowed_signers")

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{16}$")
_HEX128 = re.compile(r"^[0-9a-f]{32}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_PROCESS_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_TOKEN_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_PACKAGE = re.compile(r"^[A-Za-z0-9._~-]{1,256}$")
_SID = re.compile(r"^S-1-(?:\d+-){1,14}\d+$")
_AUTHENTICATION_ID = re.compile(r"^[0-9a-f]{16}$")
_FIELDS = frozenset(
    {
        "schema_version",
        "observation_locus",
        "locator_pid",
        "locator_creation_filetime",
        "measured_pid",
        "measured_creation_filetime",
        "measured_started_at",
        "measured_completed_at",
        "process_alive_before",
        "process_alive_after",
        "image_file_handle_held_before_after",
        "image_volume_serial_number",
        "image_file_id",
        "image_sha256",
        "package_full_name",
        "package_family_name",
        "eligible_sandbox",
        "app_container_sid",
        "less_privileged_app_container",
        "start_token_id",
        "finish_token_id",
        "start_user_sid",
        "finish_user_sid",
        "start_session_id",
        "finish_session_id",
        "start_authentication_id",
        "finish_authentication_id",
        "start_token_profile_sha256",
        "finish_token_profile_sha256",
        "start_statistics_token_id",
        "finish_statistics_token_id",
        "start_modified_id",
        "finish_modified_id",
        "process_identity_sha256",
        "measurement_transcript_sha256",
        "receipt_nonce",
        "fixed_adapter_operation_sha256",
        "launch_receipt_sha256",
        "campaign_sha256",
        "scope_manifest_sha256",
        "execution_grant_sha256",
        "worker_acceptance_sha256",
        "case",
        "trial",
        "run_nonce",
        "process_instance_id",
        "worker",
        "worker_machine_id",
        "build_lab_ex",
        "signed_by",
        "signature_ssh",
    }
)
_TOKEN_PROFILE_FIELDS = frozenset(
    {
        "token_id",
        "user_sid",
        "integrity_rid",
        "elevation_type",
        "elevated",
        "admin_group",
        "app_container",
        "app_container_sid",
        "restricted_sid_count",
        "enabled_privileges",
        "token_source",
        "statistics_token_id_before",
        "statistics_token_id_after",
        "modified_id_before",
        "modified_id_after",
        "lpac_supported",
        "less_privileged_app_container",
        "session_id",
        "authentication_id",
    }
)
_INTEGER_FIELDS = frozenset(
    {
        "locator_pid",
        "locator_creation_filetime",
        "measured_pid",
        "measured_creation_filetime",
        "start_statistics_token_id",
        "finish_statistics_token_id",
        "start_modified_id",
        "finish_modified_id",
        "start_session_id",
        "finish_session_id",
        "trial",
    }
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _measurement_timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Windows LPAC broker receipt {name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"Windows LPAC broker receipt {name} must include a timezone")
    return parsed.astimezone(UTC)


def _read_regular_nofollow(path: Path, maximum: int = 1024 * 1024) -> bytes:
    if path.is_symlink():
        raise ValueError("Windows LPAC broker receipt cannot be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Windows LPAC broker receipt must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Windows LPAC broker receipt exceeds the size limit")
        return data
    finally:
        os.close(descriptor)


def derive_process_identity(
    *,
    worker_machine_id: str,
    measured_pid: int,
    measured_creation_filetime: int,
    image_volume_serial_number: str,
    image_file_id: str,
    image_sha256: str,
    package_full_name: str,
    package_family_name: str,
    app_container_sid: str,
) -> str:
    """Derive the stable identity of one OS process object.

    Mutable token observations, receipt/transcript nonces, and signatures are
    deliberately excluded so remeasurement cannot evade process-once replay.
    """
    fields = (
        worker_machine_id,
        str(measured_pid),
        str(measured_creation_filetime),
        image_volume_serial_number,
        image_file_id,
        image_sha256,
        package_full_name,
        package_family_name,
        app_container_sid,
    )
    return hashlib.sha256(
        b"0verse-windows-lpac-process-identity-v1\0"
        + b"\0".join(value.encode("utf-8") for value in fields)
    ).hexdigest()


def derive_token_profile_sha256(snapshot: object) -> str:
    """Commit to every serialized v5 production-token fact."""
    value = snapshot.to_dict() if hasattr(snapshot, "to_dict") else snapshot
    if not isinstance(value, Mapping) or set(value) != _TOKEN_PROFILE_FIELDS:
        raise ValueError("Windows LPAC token profile must contain every exact v5 token field")
    canonical = json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(b"0verse-windows-lpac-token-profile-v1\0" + canonical).hexdigest()


@dataclass(frozen=True)
class WindowsLpacBrokerReceipt:
    observation_locus: str
    locator_pid: int
    locator_creation_filetime: int
    measured_pid: int
    measured_creation_filetime: int
    measured_started_at: str
    measured_completed_at: str
    process_alive_before: bool
    process_alive_after: bool
    image_file_handle_held_before_after: bool
    image_volume_serial_number: str
    image_file_id: str
    image_sha256: str
    package_full_name: str
    package_family_name: str
    eligible_sandbox: str
    app_container_sid: str
    less_privileged_app_container: bool
    start_token_id: str
    finish_token_id: str
    start_user_sid: str
    finish_user_sid: str
    start_session_id: int
    finish_session_id: int
    start_authentication_id: str
    finish_authentication_id: str
    start_token_profile_sha256: str
    finish_token_profile_sha256: str
    start_statistics_token_id: int
    finish_statistics_token_id: int
    start_modified_id: int
    finish_modified_id: int
    process_identity_sha256: str
    measurement_transcript_sha256: str
    receipt_nonce: str
    fixed_adapter_operation_sha256: str
    launch_receipt_sha256: str
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    worker_acceptance_sha256: str
    case: str
    trial: int
    run_nonce: str
    process_instance_id: str
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
    def from_mapping(cls, raw: object) -> WindowsLpacBrokerReceipt:
        if not isinstance(raw, dict) or set(raw) != _FIELDS:
            raise ValueError("Windows LPAC broker receipt must contain the exact fields")
        boolean_fields = {
            "less_privileged_app_container",
            "process_alive_before",
            "process_alive_after",
            "image_file_handle_held_before_after",
        }
        if any(not isinstance(raw[name], bool) for name in boolean_fields):
            raise ValueError("Windows LPAC broker receipt liveness/LPAC facts must be boolean")
        for name in _INTEGER_FIELDS:
            if isinstance(raw[name], bool) or not isinstance(raw[name], int):
                raise ValueError(f"Windows LPAC broker receipt {name} must be an integer")
        for name in _FIELDS - _INTEGER_FIELDS - boolean_fields:
            if not isinstance(raw[name], str):
                raise ValueError(f"Windows LPAC broker receipt {name} must be a string")
        receipt = cls(**raw)
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported Windows LPAC broker receipt schema")
        if self.observation_locus != OBSERVATION_LOCUS:
            raise ValueError("Windows LPAC broker observation locus must be process-primary")
        for name in ("locator_pid", "measured_pid"):
            if not 0 < getattr(self, name) < 2**32:
                raise ValueError(f"Windows LPAC broker receipt {name} is invalid")
        for name in (
            "locator_creation_filetime",
            "measured_creation_filetime",
            "start_statistics_token_id",
            "finish_statistics_token_id",
            "start_modified_id",
            "finish_modified_id",
        ):
            if not 0 < getattr(self, name) < 2**64:
                raise ValueError(f"Windows LPAC broker receipt {name} is invalid")
        if (
            self.locator_pid != self.measured_pid
            or self.locator_creation_filetime != self.measured_creation_filetime
        ):
            raise ValueError("untrusted process locator does not match broker measurement")
        measured_started = _measurement_timestamp(
            self.measured_started_at, "measured_started_at"
        )
        measured_completed = _measurement_timestamp(
            self.measured_completed_at, "measured_completed_at"
        )
        now = datetime.now(UTC)
        if (
            measured_completed < measured_started
            or measured_completed - measured_started > timedelta(hours=1)
        ):
            raise ValueError(
                "Windows LPAC broker measurement timestamps are out of order or too long"
            )
        if (
            measured_completed > now + timedelta(minutes=5)
            or now - measured_completed > timedelta(hours=24)
        ):
            raise ValueError(
                "Windows LPAC broker measurement is outside the 24-hour evidence window"
            )
        if (
            not self.process_alive_before
            or not self.process_alive_after
            or not self.image_file_handle_held_before_after
        ):
            raise ValueError(
                "Windows LPAC broker receipt requires a live pinned process before/after"
            )
        if _HEX64.fullmatch(self.image_volume_serial_number) is None:
            raise ValueError("Windows LPAC broker image volume identity is invalid")
        if _HEX128.fullmatch(self.image_file_id) is None:
            raise ValueError("Windows LPAC broker image file identity is invalid")
        for name in (
            "image_sha256",
            "measurement_transcript_sha256",
            "start_token_profile_sha256",
            "finish_token_profile_sha256",
            "fixed_adapter_operation_sha256",
            "launch_receipt_sha256",
            "campaign_sha256",
            "scope_manifest_sha256",
            "execution_grant_sha256",
            "worker_acceptance_sha256",
            "worker_machine_id",
        ):
            if _SHA256.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"Windows LPAC broker receipt {name} must be a SHA-256")
        if self.eligible_sandbox not in ELIGIBLE_WINDOWS_SANDBOXES:
            raise ValueError("Windows LPAC broker receipt sandbox is not officially eligible")
        if not self.less_privileged_app_container:
            raise ValueError("Windows LPAC broker receipt must record LPAC")
        if not valid_package_app_container_sid(self.app_container_sid):
            raise ValueError("Windows LPAC broker AppContainer SID is invalid")
        if (
            _PACKAGE.fullmatch(self.package_full_name) is None
            or _PACKAGE.fullmatch(self.package_family_name) is None
        ):
            raise ValueError("Windows LPAC broker package identity is invalid")
        if (
            _TOKEN_ID.fullmatch(self.start_token_id) is None
            or _TOKEN_ID.fullmatch(self.finish_token_id) is None
            or self.start_token_id == self.finish_token_id
        ):
            raise ValueError("Windows LPAC broker token identities are invalid")
        if (
            _SID.fullmatch(self.start_user_sid) is None
            or _SID.fullmatch(self.finish_user_sid) is None
            or _AUTHENTICATION_ID.fullmatch(self.start_authentication_id) is None
            or _AUTHENTICATION_ID.fullmatch(self.finish_authentication_id) is None
            or not 0 <= self.start_session_id < 2**32
            or not 0 <= self.finish_session_id < 2**32
        ):
            raise ValueError("Windows LPAC broker measured process identities are invalid")
        if self.case not in {"target", "control"} or not 1 <= self.trial <= 32:
            raise ValueError("Windows LPAC broker case or trial is invalid")
        if (
            _NONCE.fullmatch(self.run_nonce) is None
            or _NONCE.fullmatch(self.receipt_nonce) is None
            or self.run_nonce == self.receipt_nonce
        ):
            raise ValueError("Windows LPAC broker nonce domains are invalid")
        if _PROCESS_ID.fullmatch(self.process_instance_id) is None:
            raise ValueError("Windows LPAC broker process instance is invalid")
        for name in ("worker", "build_lab_ex", "signed_by"):
            value = getattr(self, name)
            if (
                not value
                or value != value.strip()
                or len(value) > 256
                or any(ord(character) < 0x20 for character in value)
            ):
                raise ValueError(f"Windows LPAC broker receipt {name} is invalid")
        expected_identity = derive_process_identity(
            worker_machine_id=self.worker_machine_id,
            measured_pid=self.measured_pid,
            measured_creation_filetime=self.measured_creation_filetime,
            image_volume_serial_number=self.image_volume_serial_number,
            image_file_id=self.image_file_id,
            image_sha256=self.image_sha256,
            package_full_name=self.package_full_name,
            package_family_name=self.package_family_name,
            app_container_sid=self.app_container_sid,
        )
        if self.process_identity_sha256 != expected_identity:
            raise ValueError("Windows LPAC broker process identity is not OS-fact-derived")
        if not self.signature_ssh:
            raise ValueError("Windows LPAC broker receipt signature is required")

    def require_signature(self) -> None:
        self.validate()
        if not self._signature_verified or not self._signed_material:
            raise ValueError("Windows LPAC broker receipt requires a verified signature")
        raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("signed Windows LPAC broker receipt is malformed")
        raw["signature_ssh"] = self.signature_ssh
        if self != WindowsLpacBrokerReceipt.from_mapping(raw):
            raise ValueError("Windows LPAC broker receipt differs from signed material")

    @property
    def source_sha256(self) -> str:
        if not self._source_sha256:
            raise ValueError("Windows LPAC broker receipt is not source-bound")
        return self._source_sha256


def load_windows_lpac_broker_receipt(
    path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
) -> tuple[WindowsLpacBrokerReceipt, str]:
    source = Path(path)
    data = _read_regular_nofollow(source)
    raw = json.loads(data, object_pairs_hook=_unique_object)
    receipt = WindowsLpacBrokerReceipt.from_mapping(raw)
    policy = Path(allowed_signers) if allowed_signers is not None else DEFAULT_ALLOWED_SIGNERS
    material = canonical_signed_material(raw)
    verify_ssh_signature(
        material,
        receipt.signature_ssh,
        identity=receipt.signed_by,
        namespace=SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows LPAC process broker receipt",
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
    receipt: WindowsLpacBrokerReceipt,
) -> tuple[str, str, str]:
    """Return receipt/process/transcript identities without consuming state."""
    receipt.require_signature()
    return (
        hashlib.sha256(
            b"0verse-windows-lpac-broker-receipt-once-v1\0"
            + receipt.worker_machine_id.encode("utf-8")
            + b"\0"
            + receipt.receipt_nonce.encode("ascii")
        ).hexdigest(),
        hashlib.sha256(
            b"0verse-windows-lpac-broker-process-once-v1\0"
            + receipt.process_identity_sha256.encode("ascii")
        ).hexdigest(),
        hashlib.sha256(
            b"0verse-windows-lpac-broker-transcript-once-v1\0"
            + receipt.measurement_transcript_sha256.encode("ascii")
        ).hexdigest(),
    )


def require_broker_receipt_binding(
    receipt: WindowsLpacBrokerReceipt,
    *,
    receipt_sha256: str,
    capture: object,
    campaign: object,
    campaign_sha256: str,
    scope_sha256: str,
    grant_sha256: str,
    acceptance_sha256: str,
) -> None:
    """Cross-bind a verified receipt to authority and one capture without execution."""
    # Attribute access is deliberate: keeping this verifier module independent
    # avoids a capture/receipt import cycle while the strict comparisons below
    # reject objects that do not expose the complete contract.
    receipt.require_signature()
    start = capture.start_token  # type: ignore[attr-defined]
    finish = capture.finish_token  # type: ignore[attr-defined]
    expected_operation = (
        campaign.target_operation_sha256  # type: ignore[attr-defined]
        if capture.case == "target"  # type: ignore[attr-defined]
        else campaign.control_operation_sha256  # type: ignore[attr-defined]
    )
    if (
        capture.lpac_broker_receipt_sha256 != receipt_sha256  # type: ignore[attr-defined]
        or receipt.eligible_sandbox != campaign.eligible_sandbox  # type: ignore[attr-defined]
        or receipt.image_sha256 != campaign.sandbox_process_executable_sha256  # type: ignore[attr-defined]
        or receipt.app_container_sid != campaign.app_container_sid  # type: ignore[attr-defined]
        or receipt.fixed_adapter_operation_sha256 != expected_operation
        or receipt.campaign_sha256 != campaign_sha256
        or receipt.scope_manifest_sha256 != scope_sha256
        or receipt.execution_grant_sha256 != grant_sha256
        or receipt.worker_acceptance_sha256 != acceptance_sha256
        or receipt.case != capture.case  # type: ignore[attr-defined]
        or receipt.trial != capture.trial  # type: ignore[attr-defined]
        or receipt.run_nonce != capture.run_nonce  # type: ignore[attr-defined]
        or receipt.process_instance_id != capture.process_instance_id  # type: ignore[attr-defined]
        or receipt.worker != capture.worker  # type: ignore[attr-defined]
        or receipt.worker_machine_id != capture.worker_machine_id  # type: ignore[attr-defined]
        or receipt.build_lab_ex != capture.build_lab_ex  # type: ignore[attr-defined]
        or receipt.measured_started_at != capture.started_at  # type: ignore[attr-defined]
        or receipt.measured_completed_at != capture.completed_at  # type: ignore[attr-defined]
        or receipt.start_token_id != start.token_id
        or receipt.finish_token_id != finish.token_id
        or receipt.start_user_sid != start.user_sid
        or receipt.finish_user_sid != finish.user_sid
        or receipt.start_session_id != start.session_id
        or receipt.finish_session_id != finish.session_id
        or receipt.start_authentication_id != start.authentication_id
        or receipt.finish_authentication_id != finish.authentication_id
        or receipt.start_token_profile_sha256 != derive_token_profile_sha256(start)
        or receipt.finish_token_profile_sha256 != derive_token_profile_sha256(finish)
        or receipt.start_statistics_token_id != start.statistics_token_id_before
        or receipt.finish_statistics_token_id != finish.statistics_token_id_before
        or receipt.start_modified_id != start.modified_id_before
        or receipt.finish_modified_id != finish.modified_id_before
        or not start.less_privileged_app_container
        or start.token_source != OBSERVATION_LOCUS
        or finish.token_source != OBSERVATION_LOCUS
        or start.app_container_sid != receipt.app_container_sid
        or receipt.launch_receipt_sha256
        != capture.lpac_launch_receipt_sha256  # type: ignore[attr-defined]
    ):
        raise ValueError("Windows LPAC broker receipt is not authority/capture-bound")
