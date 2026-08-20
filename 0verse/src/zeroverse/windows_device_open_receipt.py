"""Verify signed, capability-only Windows device-open boundary observations.

The contract deliberately describes one query-only ``CreateFileW`` observation.
It cannot enumerate devices, open handles, load drivers, or issue IOCTLs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Set
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .ssh_authorization import canonical_signed_material, verify_ssh_signature

SCHEMA_VERSION = "0verse.windows-device-open-boundary-receipt/v2"
SIGNATURE_NAMESPACE = "0verse-windows-device-open-boundary-receipt-v2"
OBSERVATION_KIND = "natural-standard-user-device-open"
EVIDENCE_CLASS = "candidate-capability-only"
PRODUCER_AUTHORITY = "system-held-device-open-broker"
ENUMERATION_API = (
    "SetupDiGetClassDevsW+SetupDiEnumDeviceInterfaces+"
    "SetupDiGetDeviceInterfaceDetailW"
)
CREATE_FILE_API = "CreateFileW"
QUERY_ONLY_DESIRED_ACCESS = 0
FILE_SHARE_READ_WRITE = 0x00000003
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
DEFAULT_ALLOWED_SIGNERS = Path(
    "/etc/0verse/windows-device-open-boundary.allowed_signers"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_GUID = re.compile(
    r"^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$"
)
_ACCOUNT_SID = re.compile(r"^S-1-5-21-(\d+)-(\d+)-(\d+)-(\d+)$")
_AUTHENTICATION_ID = re.compile(r"^[0-9a-f]{16}$")
_ALLOWED_STANDARD_USER_PRIVILEGES = frozenset(
    {
        "SeChangeNotifyPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeShutdownPrivilege",
        "SeTimeZonePrivilege",
        "SeUndockPrivilege",
    }
)
_FIELDS = frozenset(
    {
        "schema_version",
        "observation_kind",
        "evidence_class",
        "producer_authority",
        "broker_duplicate_handle_held_during_signing",
        "broker_revalidated_primary_token",
        "broker_reenumerated_interface",
        "worker",
        "worker_machine_id",
        "worker_acceptance_sha256",
        "windows_build_lab_ex",
        "windows_ubr",
        "boot_id",
        "boundary_manifest_sha256",
        "collector_id",
        "collector_sha256",
        "collector_registry_sha256",
        "driver_id",
        "driver_service_name",
        "driver_image_sha256",
        "interface_class_guid",
        "interface_instance_id",
        "interface_path_sha256",
        "enumeration_api",
        "enumeration_flags",
        "interface_count",
        "selected_interface_index",
        "create_file_api",
        "desired_access",
        "share_mode",
        "security_attributes_null",
        "creation_disposition",
        "flags_and_attributes",
        "template_file_null",
        "process_id",
        "process_creation_filetime",
        "primary_token_id",
        "primary_token_modified_id",
        "token_type",
        "thread_token_present",
        "impersonation_active",
        "elevation_type",
        "elevated",
        "integrity_rid",
        "admin_group_present",
        "linked_token_present",
        "token_restricted",
        "restricted_sid_count",
        "enabled_privileges",
        "app_container",
        "debug_privilege_present",
        "user_sid",
        "authentication_id",
        "session_id",
        "observation_started_at",
        "observation_completed_at",
        "create_file_succeeded",
        "handle_held_during_observation",
        "handle_closed_cleanly",
        "device_io_control_call_count",
        "driver_load_call_count",
        "device_handle_read_call_count",
        "device_handle_write_call_count",
        "observation_transcript_sha256",
        "receipt_nonce",
        "signed_by",
        "signature_ssh",
    }
)
_BOOLEAN_FIELDS = frozenset(
    {
        "security_attributes_null",
        "broker_duplicate_handle_held_during_signing",
        "broker_revalidated_primary_token",
        "broker_reenumerated_interface",
        "template_file_null",
        "thread_token_present",
        "impersonation_active",
        "elevated",
        "admin_group_present",
        "linked_token_present",
        "token_restricted",
        "app_container",
        "debug_privilege_present",
        "create_file_succeeded",
        "handle_held_during_observation",
        "handle_closed_cleanly",
    }
)
_INTEGER_FIELDS = frozenset(
    {
        "windows_ubr",
        "enumeration_flags",
        "interface_count",
        "selected_interface_index",
        "desired_access",
        "share_mode",
        "creation_disposition",
        "flags_and_attributes",
        "process_id",
        "process_creation_filetime",
        "primary_token_id",
        "primary_token_modified_id",
        "integrity_rid",
        "restricted_sid_count",
        "session_id",
        "device_io_control_call_count",
        "driver_load_call_count",
        "device_handle_read_call_count",
        "device_handle_write_call_count",
    }
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular_nofollow(path: Path, maximum: int = 1024 * 1024) -> bytes:
    if path.is_symlink():
        raise ValueError("Windows device-open receipt cannot be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Windows device-open receipt must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Windows device-open receipt exceeds the size limit")
        return data
    finally:
        os.close(descriptor)


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Windows device-open receipt {name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"Windows device-open receipt {name} must include a timezone")
    return parsed.astimezone(UTC)


def _safe_text(value: str, name: str, maximum: int = 512) -> None:
    if (
        not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise ValueError(f"Windows device-open receipt {name} is invalid")


@dataclass(frozen=True)
class WindowsDeviceOpenReceipt:
    observation_kind: str
    evidence_class: str
    producer_authority: str
    broker_duplicate_handle_held_during_signing: bool
    broker_revalidated_primary_token: bool
    broker_reenumerated_interface: bool
    worker: str
    worker_machine_id: str
    worker_acceptance_sha256: str
    windows_build_lab_ex: str
    windows_ubr: int
    boot_id: str
    boundary_manifest_sha256: str
    collector_id: str
    collector_sha256: str
    collector_registry_sha256: str
    driver_id: str
    driver_service_name: str
    driver_image_sha256: str
    interface_class_guid: str
    interface_instance_id: str
    interface_path_sha256: str
    enumeration_api: str
    enumeration_flags: int
    interface_count: int
    selected_interface_index: int
    create_file_api: str
    desired_access: int
    share_mode: int
    security_attributes_null: bool
    creation_disposition: int
    flags_and_attributes: int
    template_file_null: bool
    process_id: int
    process_creation_filetime: int
    primary_token_id: int
    primary_token_modified_id: int
    token_type: str
    thread_token_present: bool
    impersonation_active: bool
    elevation_type: str
    elevated: bool
    integrity_rid: int
    admin_group_present: bool
    linked_token_present: bool
    token_restricted: bool
    restricted_sid_count: int
    enabled_privileges: tuple[str, ...]
    app_container: bool
    debug_privilege_present: bool
    user_sid: str
    authentication_id: str
    session_id: int
    observation_started_at: str
    observation_completed_at: str
    create_file_succeeded: bool
    handle_held_during_observation: bool
    handle_closed_cleanly: bool
    device_io_control_call_count: int
    driver_load_call_count: int
    device_handle_read_call_count: int
    device_handle_write_call_count: int
    observation_transcript_sha256: str
    receipt_nonce: str
    signed_by: str
    signature_ssh: str
    schema_version: str = SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _signature_verified: bool = field(default=False, repr=False, compare=False)
    _source_material: bytes = field(default=b"", repr=False, compare=False)
    _source_sha256: str = field(default="", repr=False, compare=False)

    @classmethod
    def from_mapping(cls, raw: object) -> WindowsDeviceOpenReceipt:
        if not isinstance(raw, dict) or set(raw) != _FIELDS:
            raise ValueError("Windows device-open receipt must contain the exact fields")
        if any(not isinstance(raw[name], bool) for name in _BOOLEAN_FIELDS):
            raise ValueError("Windows device-open receipt safety facts must be boolean")
        for name in _INTEGER_FIELDS:
            if isinstance(raw[name], bool) or not isinstance(raw[name], int):
                raise ValueError(f"Windows device-open receipt {name} must be an integer")
        if (
            not isinstance(raw["enabled_privileges"], list)
            or any(not isinstance(item, str) for item in raw["enabled_privileges"])
        ):
            raise ValueError(
                "Windows device-open receipt enabled_privileges must be a string list"
            )
        for name in _FIELDS - _BOOLEAN_FIELDS - _INTEGER_FIELDS - {"enabled_privileges"}:
            if not isinstance(raw[name], str):
                raise ValueError(f"Windows device-open receipt {name} must be a string")
        normalized = dict(raw)
        normalized["enabled_privileges"] = tuple(raw["enabled_privileges"])
        receipt = cls(**normalized)
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if (
            self.schema_version != SCHEMA_VERSION
            or self.observation_kind != OBSERVATION_KIND
            or self.evidence_class != EVIDENCE_CLASS
            or self.producer_authority != PRODUCER_AUTHORITY
        ):
            raise ValueError("unsupported Windows device-open receipt contract")
        if not all(
            (
                self.broker_duplicate_handle_held_during_signing,
                self.broker_revalidated_primary_token,
                self.broker_reenumerated_interface,
            )
        ):
            raise ValueError("Windows device-open receipt lacks broker-held authority facts")
        for name in (
            "worker_machine_id",
            "worker_acceptance_sha256",
            "boundary_manifest_sha256",
            "collector_sha256",
            "collector_registry_sha256",
            "driver_image_sha256",
            "interface_path_sha256",
            "observation_transcript_sha256",
        ):
            if _SHA256.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"Windows device-open receipt {name} must be a SHA-256")
        for name in (
            "worker",
            "windows_build_lab_ex",
            "collector_id",
            "driver_id",
            "driver_service_name",
            "interface_instance_id",
            "signed_by",
        ):
            _safe_text(getattr(self, name), name)
        try:
            if str(uuid.UUID(self.boot_id)) != self.boot_id:
                raise ValueError
        except ValueError as exc:
            raise ValueError("Windows device-open receipt boot_id is not a canonical UUID") from exc
        if _GUID.fullmatch(self.interface_class_guid) is None:
            raise ValueError("Windows device-open receipt interface class GUID is not canonical")
        sid_match = _ACCOUNT_SID.fullmatch(self.user_sid)
        if sid_match is None or any(
            str(int(part)) != part or int(part) >= 2**32 for part in sid_match.groups()
        ) or int(sid_match.group(4)) < 1000:
            raise ValueError("Windows device-open receipt user is not a canonical account SID")
        if (
            _AUTHENTICATION_ID.fullmatch(self.authentication_id) is None
            or not 0x3E7 < int(self.authentication_id, 16) < 2**64
        ):
            raise ValueError("Windows device-open receipt token identity is invalid")
        if (
            not self.enabled_privileges
            or tuple(sorted(self.enabled_privileges)) != self.enabled_privileges
            or len(set(self.enabled_privileges)) != len(self.enabled_privileges)
            or not set(self.enabled_privileges) <= _ALLOWED_STANDARD_USER_PRIVILEGES
        ):
            raise ValueError(
                "Windows device-open receipt enabled privileges are incomplete or unsafe"
            )
        if _NONCE.fullmatch(self.receipt_nonce) is None:
            raise ValueError("Windows device-open receipt nonce is invalid")
        if not 0 <= self.windows_ubr < 2**32:
            raise ValueError("Windows device-open receipt UBR is invalid")
        if (
            not 0 < self.process_id < 2**32
            or not 0 < self.process_creation_filetime < 2**64
            or not 0 < self.primary_token_id < 2**64
            or not 0 < self.primary_token_modified_id < 2**64
        ):
            raise ValueError("Windows device-open receipt process identity is invalid")
        if not 0 <= self.session_id < 2**32:
            raise ValueError("Windows device-open receipt session is invalid")
        if self.enumeration_api != ENUMERATION_API or self.create_file_api != CREATE_FILE_API:
            raise ValueError("Windows device-open receipt APIs are not fixed")
        if self.enumeration_flags != 0x12:  # DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
            raise ValueError("Windows device-open receipt enumeration flags are not fixed")
        if not 1 <= self.interface_count <= 256 or not (
            0 <= self.selected_interface_index < self.interface_count
        ):
            raise ValueError("Windows device-open receipt interface selection is invalid")
        if (
            self.desired_access != QUERY_ONLY_DESIRED_ACCESS
            or self.share_mode != FILE_SHARE_READ_WRITE
            or not self.security_attributes_null
            or self.creation_disposition != OPEN_EXISTING
            or self.flags_and_attributes != FILE_ATTRIBUTE_NORMAL
            or not self.template_file_null
        ):
            raise ValueError("Windows device-open receipt CreateFileW arguments are not query-only")
        if (
            self.token_type != "TokenPrimary"
            or self.thread_token_present
            or self.impersonation_active
            or self.elevation_type != "TokenElevationTypeDefault"
            or self.elevated
            or self.integrity_rid != 8192
            or self.admin_group_present
            or self.linked_token_present
            or self.token_restricted
            or self.restricted_sid_count != 0
            or self.app_container
            or self.debug_privilege_present
        ):
            raise ValueError("Windows device-open receipt is not a natural standard-user context")
        if not all(
            (
                self.create_file_succeeded,
                self.handle_held_during_observation,
                self.handle_closed_cleanly,
            )
        ):
            raise ValueError("Windows device-open receipt lacks a held-handle observation")
        if any(
            count != 0
            for count in (
                self.device_io_control_call_count,
                self.driver_load_call_count,
                self.device_handle_read_call_count,
                self.device_handle_write_call_count,
            )
        ):
            raise ValueError("Windows device-open receipt crossed the capability-only boundary")
        started = _timestamp(self.observation_started_at, "observation_started_at")
        completed = _timestamp(self.observation_completed_at, "observation_completed_at")
        now = datetime.now(UTC)
        if completed < started or completed - started > timedelta(minutes=5):
            raise ValueError("Windows device-open receipt timestamps are out of order or too long")
        if completed > now + timedelta(minutes=5) or now - completed > timedelta(hours=24):
            raise ValueError("Windows device-open receipt is outside the 24-hour evidence window")
        if not self.signature_ssh:
            raise ValueError("Windows device-open receipt signature is required")

    def require_signature(self) -> None:
        self.validate()
        if not self._signature_verified or not self._signed_material:
            raise ValueError("Windows device-open receipt requires a verified signature")
        raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("signed Windows device-open receipt is malformed")
        raw["signature_ssh"] = self.signature_ssh
        if self != WindowsDeviceOpenReceipt.from_mapping(raw):
            raise ValueError("Windows device-open receipt differs from signed material")

    @property
    def source_sha256(self) -> str:
        if (
            not self._source_material
            or not self._source_sha256
            or hashlib.sha256(self._source_material).hexdigest() != self._source_sha256
        ):
            raise ValueError("Windows device-open receipt is not source-bound")
        return self._source_sha256


def derive_burn_only_replay_identities(
    receipt: WindowsDeviceOpenReceipt,
) -> tuple[str, str, str]:
    """Derive receipt, boot/interface, and transcript identities for an external ledger."""
    receipt.require_signature()
    return (
        hashlib.sha256(
            b"0verse-windows-device-open-receipt-once-v1\0"
            + receipt.worker_machine_id.encode("ascii")
            + b"\0"
            + receipt.receipt_nonce.encode("ascii")
        ).hexdigest(),
        hashlib.sha256(
            b"0verse-windows-device-open-boundary-once-v1\0"
            + receipt.worker_machine_id.encode("ascii")
            + b"\0"
            + receipt.boot_id.encode("ascii")
            + b"\0"
            + receipt.interface_path_sha256.encode("ascii")
        ).hexdigest(),
        hashlib.sha256(
            b"0verse-windows-device-open-transcript-once-v1\0"
            + receipt.observation_transcript_sha256.encode("ascii")
        ).hexdigest(),
    )


def require_device_open_receipt_binding(
    receipt: WindowsDeviceOpenReceipt,
    *,
    receipt_sha256: str,
    boundary_manifest_sha256: str,
    worker_acceptance_sha256: str,
    worker: str,
    worker_machine_id: str,
    windows_build_lab_ex: str,
    windows_ubr: int,
    boot_id: str,
    collector_id: str,
    collector_sha256: str,
    collector_registry_sha256: str,
    driver_id: str,
    driver_service_name: str,
    driver_image_sha256: str,
    interface_class_guid: str,
    interface_instance_id: str,
    observation_transcript: bytes,
    burned_replay_identities: Set[str] = frozenset(),
) -> tuple[str, str, str]:
    """Require exact external bindings without promoting the observation to a finding."""
    receipt.require_signature()
    if receipt.source_sha256 != receipt_sha256:
        raise ValueError("Windows device-open receipt differs from its exact source bytes")
    expected = {
        "boundary_manifest_sha256": boundary_manifest_sha256,
        "worker_acceptance_sha256": worker_acceptance_sha256,
        "worker": worker,
        "worker_machine_id": worker_machine_id,
        "windows_build_lab_ex": windows_build_lab_ex,
        "windows_ubr": windows_ubr,
        "boot_id": boot_id,
        "collector_id": collector_id,
        "collector_sha256": collector_sha256,
        "collector_registry_sha256": collector_registry_sha256,
        "driver_id": driver_id,
        "driver_service_name": driver_service_name,
        "driver_image_sha256": driver_image_sha256,
        "interface_class_guid": interface_class_guid,
        "interface_instance_id": interface_instance_id,
    }
    for name, value in expected.items():
        if getattr(receipt, name) != value:
            raise ValueError(f"Windows device-open receipt {name} binding does not match")
    if hashlib.sha256(observation_transcript).hexdigest() != receipt.observation_transcript_sha256:
        raise ValueError("Windows device-open receipt retained transcript hash does not match")
    identities = derive_burn_only_replay_identities(receipt)
    if any(identity in burned_replay_identities for identity in identities):
        raise ValueError("Windows device-open receipt replay identity was already burned")
    return identities


def load_windows_device_open_receipt(
    path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
) -> tuple[WindowsDeviceOpenReceipt, str]:
    data = _read_regular_nofollow(Path(path))
    raw = json.loads(data, object_pairs_hook=_unique_object)
    canonical_source = (
        json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    if data != canonical_source:
        raise ValueError("Windows device-open receipt source bytes are not canonical")
    receipt = WindowsDeviceOpenReceipt.from_mapping(raw)
    material = canonical_signed_material(raw)
    policy = Path(allowed_signers) if allowed_signers is not None else DEFAULT_ALLOWED_SIGNERS
    verify_ssh_signature(
        material,
        receipt.signature_ssh,
        identity=receipt.signed_by,
        namespace=SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows device-open boundary receipt",
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
