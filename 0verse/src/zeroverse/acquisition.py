"""Versioned, hardware-free contract for firmware acquisition evidence.

The manifest records what an acquisition produced; it never opens a transport,
authorizes a diagnostic request, or treats a device claim as trusted merely
because it appears in JSON.  Live adapters belong on the producer side of this
boundary.  Offline analysis consumes only the validated projections below.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal, cast

ACQUISITION_MANIFEST_VERSION = "0verse.acquisition-manifest/v1"

TransportKind = Literal["file", "can", "serial", "network", "debug-port", "storage", "unknown"]
TransportMode = Literal["offline", "passive", "active-read", "active-write"]
ObservationBasis = Literal["configured", "declared", "observed", "inferred", "unknown"]
RegionRole = Literal[
    "firmware",
    "bootloader",
    "code",
    "calibration",
    "data",
    "filesystem",
    "configuration",
    "unknown",
]
ArtifactKind = Literal[
    "firmware-image",
    "memory-region",
    "traffic-capture",
    "transaction-log",
    "tool-log",
    "metadata",
    "other",
]
Availability = Literal["present", "missing"]
Integrity = Literal["recorded", "verified", "modified", "unavailable"]
ContentState = Literal["plaintext", "encoded", "encrypted", "unknown"]
Coverage = Literal[
    "full", "partial", "virtual-read", "calibration-only", "not-applicable", "unknown"
]
AuthorizationBasis = Literal[
    "owner-operated", "written-authorization", "published-scope", "synthetic-fixture", "unknown"
]
Sensitivity = Literal["technical", "personal", "secret"]
RedactionStatus = Literal["not-required", "unredacted", "partial", "complete"]
RedactionClassification = Literal[
    "personal", "secret", "operator", "location", "network", "other"
]
RedactionAction = Literal["removed", "replaced", "generalized", "hashed"]

TRANSPORT_KINDS = frozenset(
    {"file", "can", "serial", "network", "debug-port", "storage", "unknown"}
)
TRANSPORT_MODES = frozenset({"offline", "passive", "active-read", "active-write"})
OBSERVATION_BASES = frozenset({"configured", "declared", "observed", "inferred", "unknown"})
REGION_ROLES = frozenset(
    {
        "firmware",
        "bootloader",
        "code",
        "calibration",
        "data",
        "filesystem",
        "configuration",
        "unknown",
    }
)
ARTIFACT_KINDS = frozenset(
    {
        "firmware-image",
        "memory-region",
        "traffic-capture",
        "transaction-log",
        "tool-log",
        "metadata",
        "other",
    }
)
AVAILABILITY_STATES = frozenset({"present", "missing"})
INTEGRITY_STATES = frozenset({"recorded", "verified", "modified", "unavailable"})
CONTENT_STATES = frozenset({"plaintext", "encoded", "encrypted", "unknown"})
COVERAGE_STATES = frozenset(
    {"full", "partial", "virtual-read", "calibration-only", "not-applicable", "unknown"}
)
AUTHORIZATION_BASES = frozenset(
    {"owner-operated", "written-authorization", "published-scope", "synthetic-fixture", "unknown"}
)
SENSITIVITIES = frozenset({"technical", "personal", "secret"})
REDACTION_STATUSES = frozenset({"not-required", "unredacted", "partial", "complete"})
REDACTION_CLASSIFICATIONS = frozenset(
    {"personal", "secret", "operator", "location", "network", "other"}
)
REDACTION_ACTIONS = frozenset({"removed", "replaced", "generalized", "hashed"})
REGION_PERMISSIONS = frozenset({"read", "write", "execute"})

_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*")
_RFC3339 = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_MAX_MANIFEST_BYTES = 1024 * 1024


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_manifest_file(path: Path) -> bytes:
    try:
        path_before = os.lstat(path)
    except OSError as exc:
        raise ValueError("acquisition manifest must be a readable file") from exc
    if not stat.S_ISREG(path_before.st_mode):
        raise ValueError("acquisition manifest must be a regular non-symlink file")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("acquisition manifest must be a readable file") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (path_before.st_dev, path_before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ValueError("acquisition manifest path changed while it was opened")
        if opened.st_size < 2 or opened.st_size > _MAX_MANIFEST_BYTES:
            raise ValueError("acquisition manifest must be a bounded JSON document")

        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise ValueError("acquisition manifest changed while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("acquisition manifest changed while it was read")

        after = os.fstat(descriptor)
        try:
            path_after = os.lstat(path)
        except OSError as exc:
            raise ValueError("acquisition manifest path changed while it was read") from exc
        if (
            _stat_identity(after) != _stat_identity(opened)
            or not stat.S_ISREG(path_after.st_mode)
            or (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise ValueError("acquisition manifest changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object with string keys")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> tuple[object, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{label} must be an array")
    return tuple(value)


def _exact_fields(raw: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    unexpected = sorted(raw.keys() - expected)
    if missing or unexpected:
        raise ValueError(f"{label} fields differ: missing={missing}, unexpected={unexpected}")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{label} must be non-empty text without NUL")
    return value


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _identifier(value: object, label: str) -> str:
    result = _text(value, label)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ValueError(f"{label} must be a stable identifier")
    return result


def _choice(value: object, choices: frozenset[str], label: str) -> str:
    result = _text(value, label)
    if result not in choices:
        raise ValueError(f"unsupported {label}: {result}")
    return result


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def _non_negative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _optional_non_negative_int(value: object, label: str) -> int | None:
    return None if value is None else _non_negative_int(value, label)


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if _DIGEST.fullmatch(result) is None or result == "0" * 64:
        raise ValueError(f"{label} must be a nonzero lowercase SHA-256")
    return result


def _optional_digest(value: object, label: str) -> str | None:
    return None if value is None else _digest(value, label)


def _relative_path(value: object, label: str) -> str:
    result = _text(value, label)
    path = PurePosixPath(result)
    if (
        path.is_absolute()
        or result in {".", ".."}
        or ".." in path.parts
        or "\\" in result
        or path.as_posix() != result
    ):
        raise ValueError(f"{label} must be a canonical bundle-relative POSIX path")
    return result


def _timestamp(value: object, label: str) -> datetime:
    result = _text(value, label)
    if _RFC3339.fullmatch(result) is None:
        raise ValueError(f"{label} must be a canonical RFC3339 date-time")
    return datetime.fromisoformat(result.replace("Z", "+00:00")).astimezone(UTC)


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    result = tuple(_text(item, f"{label}[]") for item in _sequence(value, label))
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must not contain duplicates")
    return result


@dataclass(frozen=True)
class DeviceIdentifier:
    kind: str
    value: str | None
    alias: str | None
    sensitivity: Sensitivity

    _FIELDS = frozenset({"kind", "value", "alias", "sensitivity"})

    def __post_init__(self) -> None:
        _identifier(self.kind, "device identifier kind")
        if self.value is None and self.alias is None:
            raise ValueError("device identifier requires a value or redacted alias")
        if self.value is not None:
            _text(self.value, "device identifier value")
        if self.alias is not None:
            _identifier(self.alias, "device identifier alias")
        _choice(self.sensitivity, SENSITIVITIES, "device identifier sensitivity")

    @classmethod
    def from_mapping(cls, value: object) -> DeviceIdentifier:
        raw = _mapping(value, "device identifier")
        _exact_fields(raw, cls._FIELDS, "device identifier")
        return cls(
            kind=_identifier(raw["kind"], "device identifier kind"),
            value=_optional_text(raw["value"], "device identifier value"),
            alias=(
                None
                if raw["alias"] is None
                else _identifier(raw["alias"], "device identifier alias")
            ),
            sensitivity=cast(
                Sensitivity,
                _choice(raw["sensitivity"], SENSITIVITIES, "device identifier sensitivity"),
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "value": self.value,
            "alias": self.alias,
            "sensitivity": self.sensitivity,
        }


@dataclass(frozen=True)
class DeviceIdentity:
    category: str
    manufacturer: str | None
    model: str | None
    hardware_revision: str | None
    identifiers: tuple[DeviceIdentifier, ...]

    _FIELDS = frozenset(
        {"category", "manufacturer", "model", "hardware_revision", "identifiers"}
    )

    def __post_init__(self) -> None:
        _identifier(self.category, "device category")
        for label, value in (
            ("device manufacturer", self.manufacturer),
            ("device model", self.model),
            ("device hardware revision", self.hardware_revision),
        ):
            if value is not None:
                _text(value, label)
        identities = [(item.kind, item.value, item.alias) for item in self.identifiers]
        if len(identities) != len(set(identities)):
            raise ValueError("device identifiers must be unique")

    @classmethod
    def from_mapping(cls, value: object) -> DeviceIdentity:
        raw = _mapping(value, "device identity")
        _exact_fields(raw, cls._FIELDS, "device identity")
        return cls(
            category=_identifier(raw["category"], "device category"),
            manufacturer=_optional_text(raw["manufacturer"], "device manufacturer"),
            model=_optional_text(raw["model"], "device model"),
            hardware_revision=_optional_text(
                raw["hardware_revision"], "device hardware revision"
            ),
            identifiers=tuple(
                DeviceIdentifier.from_mapping(item)
                for item in _sequence(raw["identifiers"], "device identifiers")
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "hardware_revision": self.hardware_revision,
            "identifiers": [item.to_dict() for item in self.identifiers],
        }


@dataclass(frozen=True)
class TransportParameter:
    name: str
    value: str
    basis: ObservationBasis

    _FIELDS = frozenset({"name", "value", "basis"})

    def __post_init__(self) -> None:
        _identifier(self.name, "transport parameter name")
        _text(self.value, "transport parameter value")
        _choice(self.basis, OBSERVATION_BASES, "transport parameter basis")

    @classmethod
    def from_mapping(cls, value: object) -> TransportParameter:
        raw = _mapping(value, "transport parameter")
        _exact_fields(raw, cls._FIELDS, "transport parameter")
        return cls(
            name=_identifier(raw["name"], "transport parameter name"),
            value=_text(raw["value"], "transport parameter value"),
            basis=cast(
                ObservationBasis,
                _choice(raw["basis"], OBSERVATION_BASES, "transport parameter basis"),
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "value": self.value, "basis": self.basis}


@dataclass(frozen=True)
class TransportObservation:
    kind: TransportKind
    protocol: str | None
    interface: str | None
    mode: TransportMode
    transmitted: bool
    parameters: tuple[TransportParameter, ...]
    capture_artifact_ids: tuple[str, ...]

    _FIELDS = frozenset(
        {
            "kind",
            "protocol",
            "interface",
            "mode",
            "transmitted",
            "parameters",
            "capture_artifact_ids",
        }
    )

    def __post_init__(self) -> None:
        _choice(self.kind, TRANSPORT_KINDS, "transport kind")
        if self.protocol is not None:
            _text(self.protocol, "transport protocol")
        if self.interface is not None:
            _text(self.interface, "transport interface")
        _choice(self.mode, TRANSPORT_MODES, "transport mode")
        _boolean(self.transmitted, "transport transmitted")
        if self.mode in {"offline", "passive"} and self.transmitted:
            raise ValueError(f"{self.mode} transport cannot claim transmitted frames")
        names = [item.name for item in self.parameters]
        if len(names) != len(set(names)):
            raise ValueError("transport parameter names must be unique")
        if len(self.capture_artifact_ids) != len(set(self.capture_artifact_ids)):
            raise ValueError("transport capture artifact references must be unique")
        for artifact_id in self.capture_artifact_ids:
            _identifier(artifact_id, "transport capture artifact id")

    @classmethod
    def from_mapping(cls, value: object) -> TransportObservation:
        raw = _mapping(value, "transport observation")
        _exact_fields(raw, cls._FIELDS, "transport observation")
        return cls(
            kind=cast(TransportKind, _choice(raw["kind"], TRANSPORT_KINDS, "transport kind")),
            protocol=_optional_text(raw["protocol"], "transport protocol"),
            interface=_optional_text(raw["interface"], "transport interface"),
            mode=cast(TransportMode, _choice(raw["mode"], TRANSPORT_MODES, "transport mode")),
            transmitted=_boolean(raw["transmitted"], "transport transmitted"),
            parameters=tuple(
                TransportParameter.from_mapping(item)
                for item in _sequence(raw["parameters"], "transport parameters")
            ),
            capture_artifact_ids=tuple(
                _identifier(item, "transport capture artifact id")
                for item in _sequence(raw["capture_artifact_ids"], "transport capture artifacts")
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "protocol": self.protocol,
            "interface": self.interface,
            "mode": self.mode,
            "transmitted": self.transmitted,
            "parameters": [item.to_dict() for item in self.parameters],
            "capture_artifact_ids": list(self.capture_artifact_ids),
        }


@dataclass(frozen=True)
class MemoryRegion:
    region_id: str
    address_space: str
    start: int | None
    length: int
    role: RegionRole
    basis: ObservationBasis
    permissions: tuple[str, ...]
    artifact_id: str | None
    artifact_offset: int | None

    _FIELDS = frozenset(
        {
            "region_id",
            "address_space",
            "start",
            "length",
            "role",
            "basis",
            "permissions",
            "artifact_id",
            "artifact_offset",
        }
    )

    def __post_init__(self) -> None:
        _identifier(self.region_id, "memory region id")
        _text(self.address_space, "memory region address space")
        if self.start is not None:
            _non_negative_int(self.start, "memory region start")
        if _non_negative_int(self.length, "memory region length") == 0:
            raise ValueError("memory region length must be positive")
        _choice(self.role, REGION_ROLES, "memory region role")
        _choice(self.basis, OBSERVATION_BASES, "memory region basis")
        if len(self.permissions) != len(set(self.permissions)) or any(
            item not in REGION_PERMISSIONS for item in self.permissions
        ):
            raise ValueError("memory region permissions must be unique read/write/execute values")
        if (self.artifact_id is None) != (self.artifact_offset is None):
            raise ValueError("memory region artifact id and offset must be supplied together")
        if self.artifact_id is not None:
            _identifier(self.artifact_id, "memory region artifact id")
        if self.artifact_offset is not None:
            _non_negative_int(self.artifact_offset, "memory region artifact offset")

    @classmethod
    def from_mapping(cls, value: object) -> MemoryRegion:
        raw = _mapping(value, "memory region")
        _exact_fields(raw, cls._FIELDS, "memory region")
        return cls(
            region_id=_identifier(raw["region_id"], "memory region id"),
            address_space=_text(raw["address_space"], "memory region address space"),
            start=_optional_non_negative_int(raw["start"], "memory region start"),
            length=_non_negative_int(raw["length"], "memory region length"),
            role=cast(RegionRole, _choice(raw["role"], REGION_ROLES, "memory region role")),
            basis=cast(
                ObservationBasis,
                _choice(raw["basis"], OBSERVATION_BASES, "memory region basis"),
            ),
            permissions=_string_tuple(raw["permissions"], "memory region permissions"),
            artifact_id=(
                None
                if raw["artifact_id"] is None
                else _identifier(raw["artifact_id"], "memory region artifact id")
            ),
            artifact_offset=_optional_non_negative_int(
                raw["artifact_offset"], "memory region artifact offset"
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "region_id": self.region_id,
            "address_space": self.address_space,
            "start": self.start,
            "length": self.length,
            "role": self.role,
            "basis": self.basis,
            "permissions": list(self.permissions),
            "artifact_id": self.artifact_id,
            "artifact_offset": self.artifact_offset,
        }


@dataclass(frozen=True)
class AcquisitionArtifact:
    artifact_id: str
    kind: ArtifactKind
    path: str
    media_type: str
    size: int | None
    sha256: str | None
    observed_size: int | None
    observed_sha256: str | None
    availability: Availability
    integrity: Integrity
    content: ContentState
    coverage: Coverage
    region_ids: tuple[str, ...]

    _FIELDS = frozenset(
        {
            "artifact_id",
            "kind",
            "path",
            "media_type",
            "size",
            "sha256",
            "observed_size",
            "observed_sha256",
            "availability",
            "integrity",
            "content",
            "coverage",
            "region_ids",
        }
    )

    def __post_init__(self) -> None:
        _identifier(self.artifact_id, "artifact id")
        _choice(self.kind, ARTIFACT_KINDS, "artifact kind")
        _relative_path(self.path, "artifact path")
        if _MEDIA_TYPE.fullmatch(self.media_type) is None:
            raise ValueError("artifact media type must be a lowercase type/subtype")
        for label, value in (
            ("artifact size", self.size),
            ("artifact observed size", self.observed_size),
        ):
            if value is not None:
                _non_negative_int(value, label)
        for label, digest_value in (
            ("artifact SHA-256", self.sha256),
            ("artifact observed SHA-256", self.observed_sha256),
        ):
            if digest_value is not None:
                _digest(digest_value, label)
        _choice(self.availability, AVAILABILITY_STATES, "artifact availability")
        _choice(self.integrity, INTEGRITY_STATES, "artifact integrity")
        _choice(self.content, CONTENT_STATES, "artifact content")
        _choice(self.coverage, COVERAGE_STATES, "artifact coverage")
        if len(self.region_ids) != len(set(self.region_ids)):
            raise ValueError("artifact memory region references must be unique")
        for region_id in self.region_ids:
            _identifier(region_id, "artifact memory region id")

        if self.availability == "missing":
            if self.integrity != "unavailable":
                raise ValueError("missing artifact integrity must be unavailable")
            if self.observed_size is not None or self.observed_sha256 is not None:
                raise ValueError("missing artifact cannot have observed identity")
            return
        if self.size is None or self.sha256 is None:
            raise ValueError("present artifact requires declared size and SHA-256")
        if self.integrity == "unavailable":
            raise ValueError("present artifact integrity cannot be unavailable")
        if self.integrity == "recorded":
            if self.observed_size is not None or self.observed_sha256 is not None:
                raise ValueError("recorded artifact cannot claim independent verification")
        elif self.integrity == "verified":
            if self.observed_size != self.size or self.observed_sha256 != self.sha256:
                raise ValueError("verified artifact observed identity must match its declaration")
        elif self.integrity == "modified":
            if self.observed_size is None or self.observed_sha256 is None:
                raise ValueError("modified artifact requires an observed size and SHA-256")
            if self.observed_size == self.size and self.observed_sha256 == self.sha256:
                raise ValueError("modified artifact must differ from its declared identity")

    @classmethod
    def from_mapping(cls, value: object) -> AcquisitionArtifact:
        raw = _mapping(value, "acquisition artifact")
        _exact_fields(raw, cls._FIELDS, "acquisition artifact")
        return cls(
            artifact_id=_identifier(raw["artifact_id"], "artifact id"),
            kind=cast(ArtifactKind, _choice(raw["kind"], ARTIFACT_KINDS, "artifact kind")),
            path=_relative_path(raw["path"], "artifact path"),
            media_type=_text(raw["media_type"], "artifact media type"),
            size=_optional_non_negative_int(raw["size"], "artifact size"),
            sha256=_optional_digest(raw["sha256"], "artifact SHA-256"),
            observed_size=_optional_non_negative_int(
                raw["observed_size"], "artifact observed size"
            ),
            observed_sha256=_optional_digest(
                raw["observed_sha256"], "artifact observed SHA-256"
            ),
            availability=cast(
                Availability,
                _choice(raw["availability"], AVAILABILITY_STATES, "artifact availability"),
            ),
            integrity=cast(
                Integrity, _choice(raw["integrity"], INTEGRITY_STATES, "artifact integrity")
            ),
            content=cast(
                ContentState, _choice(raw["content"], CONTENT_STATES, "artifact content")
            ),
            coverage=cast(
                Coverage, _choice(raw["coverage"], COVERAGE_STATES, "artifact coverage")
            ),
            region_ids=tuple(
                _identifier(item, "artifact memory region id")
                for item in _sequence(raw["region_ids"], "artifact memory regions")
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "path": self.path,
            "media_type": self.media_type,
            "size": self.size,
            "sha256": self.sha256,
            "observed_size": self.observed_size,
            "observed_sha256": self.observed_sha256,
            "availability": self.availability,
            "integrity": self.integrity,
            "content": self.content,
            "coverage": self.coverage,
            "region_ids": list(self.region_ids),
        }


@dataclass(frozen=True)
class AcquisitionProvenance:
    source: str
    method: str
    collector: str
    authorization_basis: AuthorizationBasis
    started_at: str
    completed_at: str
    tool_name: str
    tool_version: str
    evidence_artifact_ids: tuple[str, ...]
    notes: str | None

    _FIELDS = frozenset(
        {
            "source",
            "method",
            "collector",
            "authorization_basis",
            "started_at",
            "completed_at",
            "tool_name",
            "tool_version",
            "evidence_artifact_ids",
            "notes",
        }
    )

    def __post_init__(self) -> None:
        _text(self.source, "provenance source")
        _text(self.method, "provenance method")
        _text(self.collector, "provenance collector")
        _choice(self.authorization_basis, AUTHORIZATION_BASES, "provenance authorization basis")
        if _timestamp(self.completed_at, "provenance completed_at") < _timestamp(
            self.started_at, "provenance started_at"
        ):
            raise ValueError("provenance completion must not precede its start")
        _text(self.tool_name, "provenance tool name")
        _text(self.tool_version, "provenance tool version")
        if len(self.evidence_artifact_ids) != len(set(self.evidence_artifact_ids)):
            raise ValueError("provenance evidence artifact references must be unique")
        for artifact_id in self.evidence_artifact_ids:
            _identifier(artifact_id, "provenance evidence artifact id")
        if self.notes is not None:
            _text(self.notes, "provenance notes")

    @classmethod
    def from_mapping(cls, value: object) -> AcquisitionProvenance:
        raw = _mapping(value, "acquisition provenance")
        _exact_fields(raw, cls._FIELDS, "acquisition provenance")
        return cls(
            source=_text(raw["source"], "provenance source"),
            method=_text(raw["method"], "provenance method"),
            collector=_text(raw["collector"], "provenance collector"),
            authorization_basis=cast(
                AuthorizationBasis,
                _choice(
                    raw["authorization_basis"],
                    AUTHORIZATION_BASES,
                    "provenance authorization basis",
                ),
            ),
            started_at=_text(raw["started_at"], "provenance started_at"),
            completed_at=_text(raw["completed_at"], "provenance completed_at"),
            tool_name=_text(raw["tool_name"], "provenance tool name"),
            tool_version=_text(raw["tool_version"], "provenance tool version"),
            evidence_artifact_ids=tuple(
                _identifier(item, "provenance evidence artifact id")
                for item in _sequence(
                    raw["evidence_artifact_ids"], "provenance evidence artifacts"
                )
            ),
            notes=_optional_text(raw["notes"], "provenance notes"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "method": self.method,
            "collector": self.collector,
            "authorization_basis": self.authorization_basis,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "evidence_artifact_ids": list(self.evidence_artifact_ids),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class RedactionEntry:
    path: str
    classification: RedactionClassification
    action: RedactionAction

    _FIELDS = frozenset({"path", "classification", "action"})

    def __post_init__(self) -> None:
        if (
            not self.path.startswith("/")
            or "\x00" in self.path
            or re.search(r"~(?![01])", self.path) is not None
        ):
            raise ValueError("redaction path must be an escaped JSON Pointer")
        _choice(self.classification, REDACTION_CLASSIFICATIONS, "redaction classification")
        _choice(self.action, REDACTION_ACTIONS, "redaction action")

    @classmethod
    def from_mapping(cls, value: object) -> RedactionEntry:
        raw = _mapping(value, "redaction entry")
        _exact_fields(raw, cls._FIELDS, "redaction entry")
        return cls(
            path=_text(raw["path"], "redaction path"),
            classification=cast(
                RedactionClassification,
                _choice(
                    raw["classification"],
                    REDACTION_CLASSIFICATIONS,
                    "redaction classification",
                ),
            ),
            action=cast(
                RedactionAction,
                _choice(raw["action"], REDACTION_ACTIONS, "redaction action"),
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "classification": self.classification,
            "action": self.action,
        }


@dataclass(frozen=True)
class RedactionRecord:
    status: RedactionStatus
    policy: str
    contains_sensitive_values: bool
    entries: tuple[RedactionEntry, ...]

    _FIELDS = frozenset({"status", "policy", "contains_sensitive_values", "entries"})

    def __post_init__(self) -> None:
        _choice(self.status, REDACTION_STATUSES, "redaction status")
        _text(self.policy, "redaction policy")
        _boolean(self.contains_sensitive_values, "redaction contains_sensitive_values")
        paths = [entry.path for entry in self.entries]
        if len(paths) != len(set(paths)):
            raise ValueError("redaction paths must be unique")
        if self.status in {"not-required", "unredacted"} and self.entries:
            raise ValueError(f"{self.status} redaction cannot contain transformation entries")
        if self.status in {"partial", "complete"} and not self.entries:
            raise ValueError(f"{self.status} redaction requires transformation entries")
        expected_sensitive = self.status in {"unredacted", "partial"}
        if self.contains_sensitive_values != expected_sensitive:
            raise ValueError("redaction status and sensitive-value declaration disagree")

    @classmethod
    def from_mapping(cls, value: object) -> RedactionRecord:
        raw = _mapping(value, "redaction record")
        _exact_fields(raw, cls._FIELDS, "redaction record")
        return cls(
            status=cast(
                RedactionStatus,
                _choice(raw["status"], REDACTION_STATUSES, "redaction status"),
            ),
            policy=_text(raw["policy"], "redaction policy"),
            contains_sensitive_values=_boolean(
                raw["contains_sensitive_values"], "redaction contains_sensitive_values"
            ),
            entries=tuple(
                RedactionEntry.from_mapping(item)
                for item in _sequence(raw["entries"], "redaction entries")
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "policy": self.policy,
            "contains_sensitive_values": self.contains_sensitive_values,
            "entries": [entry.to_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class FirmwareAnalysisInput:
    """A verified bundle-relative binary that offline analysis may inspect."""

    artifact_id: str
    path: str
    size: int
    sha256: str
    content: ContentState
    coverage: Coverage
    regions: tuple[MemoryRegion, ...]


@dataclass(frozen=True)
class AcquisitionManifest:
    acquisition_id: str
    created_at: str
    device: DeviceIdentity
    transport: TransportObservation
    regions: tuple[MemoryRegion, ...]
    artifacts: tuple[AcquisitionArtifact, ...]
    provenance: AcquisitionProvenance
    redaction: RedactionRecord
    schema_version: str = ACQUISITION_MANIFEST_VERSION

    _FIELDS = frozenset(
        {
            "schema_version",
            "acquisition_id",
            "created_at",
            "device",
            "transport",
            "regions",
            "artifacts",
            "provenance",
            "redaction",
        }
    )

    def __post_init__(self) -> None:
        if self.schema_version != ACQUISITION_MANIFEST_VERSION:
            raise ValueError(f"unsupported acquisition manifest schema: {self.schema_version}")
        _identifier(self.acquisition_id, "acquisition id")
        if _timestamp(self.created_at, "manifest created_at") < _timestamp(
            self.provenance.completed_at, "provenance completed_at"
        ):
            raise ValueError("manifest creation must not precede acquisition completion")
        if not self.artifacts:
            raise ValueError("acquisition manifest requires at least one artifact")

        regions = {region.region_id: region for region in self.regions}
        if len(regions) != len(self.regions):
            raise ValueError("memory region ids must be unique")
        artifacts = {artifact.artifact_id: artifact for artifact in self.artifacts}
        if len(artifacts) != len(self.artifacts):
            raise ValueError("artifact ids must be unique")
        paths = [artifact.path for artifact in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError("artifact paths must be unique")

        for region in self.regions:
            if region.artifact_id is None:
                continue
            artifact = artifacts.get(region.artifact_id)
            if artifact is None:
                raise ValueError(f"memory region references unknown artifact: {region.artifact_id}")
            if region.region_id not in artifact.region_ids:
                raise ValueError("memory region and artifact references must be reciprocal")
            if (
                artifact.size is not None
                and region.artifact_offset is not None
                and region.artifact_offset + region.length > artifact.size
            ):
                raise ValueError("memory region exceeds its declared artifact size")
        for artifact in self.artifacts:
            for region_id in artifact.region_ids:
                linked_region = regions.get(region_id)
                if linked_region is None:
                    raise ValueError(f"artifact references unknown memory region: {region_id}")
                if linked_region.artifact_id != artifact.artifact_id:
                    raise ValueError("artifact and memory region references must be reciprocal")

        for artifact_id in self.transport.capture_artifact_ids:
            artifact = artifacts.get(artifact_id)
            if artifact is None or artifact.kind != "traffic-capture":
                raise ValueError("transport capture must reference a traffic-capture artifact")
        for artifact_id in self.provenance.evidence_artifact_ids:
            if artifact_id not in artifacts:
                raise ValueError(f"provenance references unknown artifact: {artifact_id}")

        has_raw_sensitive_identifier = any(
            item.sensitivity in {"personal", "secret"} and item.value is not None
            for item in self.device.identifiers
        )
        if has_raw_sensitive_identifier and not self.redaction.contains_sensitive_values:
            raise ValueError("redaction record denies a raw sensitive device identifier")

    @classmethod
    def from_mapping(cls, value: object) -> AcquisitionManifest:
        raw = _mapping(value, "acquisition manifest")
        _exact_fields(raw, cls._FIELDS, "acquisition manifest")
        return cls(
            schema_version=_text(raw["schema_version"], "schema_version"),
            acquisition_id=_identifier(raw["acquisition_id"], "acquisition id"),
            created_at=_text(raw["created_at"], "manifest created_at"),
            device=DeviceIdentity.from_mapping(raw["device"]),
            transport=TransportObservation.from_mapping(raw["transport"]),
            regions=tuple(
                MemoryRegion.from_mapping(item)
                for item in _sequence(raw["regions"], "memory regions")
            ),
            artifacts=tuple(
                AcquisitionArtifact.from_mapping(item)
                for item in _sequence(raw["artifacts"], "acquisition artifacts")
            ),
            provenance=AcquisitionProvenance.from_mapping(raw["provenance"]),
            redaction=RedactionRecord.from_mapping(raw["redaction"]),
        )

    def analysis_inputs(self) -> tuple[FirmwareAnalysisInput, ...]:
        """Project verified firmware artifacts into the offline analysis boundary.

        Missing, modified, unverified, and encrypted artifacts remain represented
        in the manifest but cannot silently enter a decompiler or emulator lane.
        """

        regions = {region.region_id: region for region in self.regions}
        result: list[FirmwareAnalysisInput] = []
        for artifact in self.artifacts:
            if (
                artifact.kind not in {"firmware-image", "memory-region"}
                or artifact.availability != "present"
                or artifact.integrity != "verified"
                or artifact.content == "encrypted"
            ):
                continue
            if artifact.size is None or artifact.sha256 is None:  # guarded by artifact validation
                raise AssertionError("verified artifact lacks a declared identity")
            result.append(
                FirmwareAnalysisInput(
                    artifact_id=artifact.artifact_id,
                    path=artifact.path,
                    size=artifact.size,
                    sha256=artifact.sha256,
                    content=artifact.content,
                    coverage=artifact.coverage,
                    regions=tuple(regions[region_id] for region_id in artifact.region_ids),
                )
            )
        return tuple(result)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "acquisition_id": self.acquisition_id,
            "created_at": self.created_at,
            "device": self.device.to_dict(),
            "transport": self.transport.to_dict(),
            "regions": [region.to_dict() for region in self.regions],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "provenance": self.provenance.to_dict(),
            "redaction": self.redaction.to_dict(),
        }


def load_acquisition_manifest(path: str | Path) -> AcquisitionManifest:
    """Load one bounded manifest without touching any referenced artifact."""

    manifest_path = Path(path)
    data = _read_manifest_file(manifest_path)
    try:
        raw = json.loads(data, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("acquisition manifest is not valid JSON") from exc
    return AcquisitionManifest.from_mapping(raw)
