"""Passive Firmware Scout evidence recording, replay, and virtual CAN fixtures.

This module is deliberately transport-free.  It records observations supplied by
an adapter, seals them into ``AcquisitionManifest`` v1, and replays retained
evidence into a consumer.  It never opens a CAN interface and exposes no transmit
operation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Literal, Protocol, Self, cast

from .acquisition import (
    AcquisitionArtifact,
    AcquisitionManifest,
    AcquisitionProvenance,
    AuthorizationBasis,
    DeviceIdentity,
    RedactionRecord,
    TransportObservation,
    TransportParameter,
)
from .acquisition_bundle import (
    AcquisitionBundle,
    ValidatedAcquisitionArtifact,
    load_acquisition_bundle,
)

SCOUT_EVENT_VERSION = "0verse.scout-event/v1"
SCOUT_CAPTURE_VERSION = "0verse.scout-capture/v1"
SCOUT_SESSION_LOG_VERSION = "0verse.scout-session-log/v1"

SCOUT_CAPTURE_MEDIA_TYPE = "application/vnd.0verse.scout-capture"
SCOUT_TRANSACTION_MEDIA_TYPE = "application/x-ndjson"
SCOUT_SESSION_LOG_MEDIA_TYPE = "application/json"

SCOUT_CAPTURE_ARTIFACT_ID = "scout-capture"
SCOUT_TRANSACTION_ARTIFACT_ID = "scout-transactions"
SCOUT_SESSION_LOG_ARTIFACT_ID = "scout-session"

SCOUT_CAPTURE_PATH = "captures/passive-can.scoutcap"
SCOUT_TRANSACTION_PATH = "logs/transactions.jsonl"
SCOUT_SESSION_LOG_PATH = "logs/session.json"

_CAPTURE_MAGIC = b"0VERSE-SCOUT-CAPTURE\x00v1\n"
_CAPTURE_RECORD = struct.Struct(">BQQQIBHH")
_CAPTURE_FRAME = 1
_CAPTURE_MALFORMED = 2
_CAPTURE_ID_PRESENT = 0x80
_CAPTURE_EXTENDED = 0x01
_CAPTURE_REMOTE = 0x02
_CAPTURE_ERROR = 0x04
_NO_ARBITRATION_ID = 0xFFFFFFFF
_NO_DECLARED_LENGTH = 0xFFFF

_MAX_CAN_DATA_BYTES = 64
_MAX_MALFORMED_BYTES = 4096
_MAX_DETAIL_LENGTH = 4096
_MAX_EVENT_LINE_BYTES = 64 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")

ScoutEventKind = Literal["frame", "timeout", "malformed-frame", "reset", "capture-error"]
SCOUT_EVENT_KINDS = frozenset(
    {"frame", "timeout", "malformed-frame", "reset", "capture-error"}
)


def _non_negative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _optional_non_negative_int(value: object, label: str) -> int | None:
    return None if value is None else _non_negative_int(value, label)


def _optional_bool(value: object, label: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean or null")
    return value


def _text(value: object, label: str, *, maximum: int = _MAX_DETAIL_LENGTH) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or len(value) > maximum
    ):
        raise ValueError(f"{label} must be bounded non-empty text without NUL")
    return value


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object with string keys")
    return cast(Mapping[str, object], value)


def _exact_fields(raw: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    unexpected = sorted(raw.keys() - expected)
    if missing or unexpected:
        raise ValueError(f"{label} fields differ: missing={missing}, unexpected={unexpected}")


def _event_data(value: object) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) % 2 or re.fullmatch(r"[0-9a-f]*", value) is None:
        raise ValueError("event data_hex must be lowercase even-length hexadecimal or null")
    return bytes.fromhex(value)


def _validate_arbitration_id(arbitration_id: int, extended_id: bool) -> None:
    if arbitration_id > 0x1FFFFFFF:
        raise ValueError("CAN arbitration id exceeds 29 bits")
    if not extended_id and arbitration_id > 0x7FF:
        raise ValueError("standard CAN arbitration id exceeds 11 bits")


@dataclass(frozen=True)
class ScoutEvent:
    """One closed, canonical passive observation in a Scout transaction log."""

    sequence: int
    timestamp_ns: int
    kind: ScoutEventKind
    capture_index: int | None
    arbitration_id: int | None
    extended_id: bool | None
    remote_frame: bool | None
    error_frame: bool | None
    declared_length: int | None
    data: bytes | None
    detail: str | None
    schema_version: str = SCOUT_EVENT_VERSION

    _FIELDS = frozenset(
        {
            "schema_version",
            "sequence",
            "timestamp_ns",
            "kind",
            "capture_index",
            "arbitration_id",
            "extended_id",
            "remote_frame",
            "error_frame",
            "declared_length",
            "data_hex",
            "detail",
        }
    )

    def __post_init__(self) -> None:
        if self.schema_version != SCOUT_EVENT_VERSION:
            raise ValueError(f"unsupported Scout event schema: {self.schema_version}")
        _non_negative_int(self.sequence, "event sequence")
        _non_negative_int(self.timestamp_ns, "event timestamp_ns")
        if self.kind not in SCOUT_EVENT_KINDS:
            raise ValueError(f"unsupported Scout event kind: {self.kind}")
        if self.detail is not None:
            _text(self.detail, "event detail")

        if self.kind == "frame":
            self._validate_frame()
        elif self.kind == "malformed-frame":
            self._validate_malformed_frame()
        elif any(
            value is not None
            for value in (
                self.capture_index,
                self.arbitration_id,
                self.extended_id,
                self.remote_frame,
                self.error_frame,
                self.declared_length,
                self.data,
            )
        ):
            raise ValueError(f"{self.kind} event cannot carry frame fields")
        elif self.detail is None:
            raise ValueError(f"{self.kind} event requires detail")

    def _validate_frame(self) -> None:
        if self.capture_index is None:
            raise ValueError("frame event requires capture_index")
        _non_negative_int(self.capture_index, "frame capture_index")
        if self.arbitration_id is None:
            raise ValueError("frame event requires arbitration_id")
        if self.extended_id is None or self.remote_frame is None or self.error_frame is None:
            raise ValueError("frame event requires explicit CAN flags")
        _validate_arbitration_id(self.arbitration_id, self.extended_id)
        if self.data is None or not isinstance(self.data, bytes):
            raise ValueError("frame event requires byte data")
        if len(self.data) > _MAX_CAN_DATA_BYTES:
            raise ValueError("CAN frame data exceeds 64 bytes")
        if self.declared_length is None:
            raise ValueError("frame event requires declared_length")
        declared = _non_negative_int(self.declared_length, "frame declared_length")
        if self.remote_frame:
            if self.data:
                raise ValueError("remote CAN frame cannot carry captured data")
            if declared > 8:
                raise ValueError("classical remote CAN frame length exceeds 8 bytes")
        elif declared != len(self.data):
            raise ValueError("frame declared_length must match captured data")
        if self.detail is not None:
            raise ValueError("normal frame event cannot carry error detail")

    def _validate_malformed_frame(self) -> None:
        if self.capture_index is None:
            raise ValueError("malformed frame requires capture_index")
        _non_negative_int(self.capture_index, "malformed frame capture_index")
        if self.data is None or not isinstance(self.data, bytes) or not self.data:
            raise ValueError("malformed frame requires retained raw bytes")
        if len(self.data) > _MAX_MALFORMED_BYTES:
            raise ValueError("malformed frame bytes exceed the retention limit")
        if self.declared_length is not None:
            declared = _non_negative_int(self.declared_length, "malformed declared_length")
            if declared >= _NO_DECLARED_LENGTH:
                raise ValueError("malformed declared_length exceeds the capture format")
        if self.arbitration_id is None:
            if any(
                value is not None
                for value in (self.extended_id, self.remote_frame, self.error_frame)
            ):
                raise ValueError("unparsed malformed frame cannot claim CAN flags")
        else:
            if self.extended_id is None or self.remote_frame is None or self.error_frame is None:
                raise ValueError("parsed malformed frame requires explicit CAN flags")
            _validate_arbitration_id(self.arbitration_id, self.extended_id)
        if self.detail is None:
            raise ValueError("malformed frame requires detail")

    @property
    def has_capture_record(self) -> bool:
        return self.kind in {"frame", "malformed-frame"}

    @classmethod
    def from_mapping(cls, value: object) -> ScoutEvent:
        raw = _mapping(value, "Scout event")
        _exact_fields(raw, cls._FIELDS, "Scout event")
        kind = raw["kind"]
        if not isinstance(kind, str) or kind not in SCOUT_EVENT_KINDS:
            raise ValueError(f"unsupported Scout event kind: {kind}")
        return cls(
            schema_version=_text(raw["schema_version"], "event schema_version", maximum=128),
            sequence=_non_negative_int(raw["sequence"], "event sequence"),
            timestamp_ns=_non_negative_int(raw["timestamp_ns"], "event timestamp_ns"),
            kind=cast(ScoutEventKind, kind),
            capture_index=_optional_non_negative_int(raw["capture_index"], "capture_index"),
            arbitration_id=_optional_non_negative_int(raw["arbitration_id"], "arbitration_id"),
            extended_id=_optional_bool(raw["extended_id"], "extended_id"),
            remote_frame=_optional_bool(raw["remote_frame"], "remote_frame"),
            error_frame=_optional_bool(raw["error_frame"], "error_frame"),
            declared_length=_optional_non_negative_int(
                raw["declared_length"], "declared_length"
            ),
            data=_event_data(raw["data_hex"]),
            detail=_optional_text(raw["detail"], "event detail"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "timestamp_ns": self.timestamp_ns,
            "kind": self.kind,
            "capture_index": self.capture_index,
            "arbitration_id": self.arbitration_id,
            "extended_id": self.extended_id,
            "remote_frame": self.remote_frame,
            "error_frame": self.error_frame,
            "declared_length": self.declared_length,
            "data_hex": None if self.data is None else self.data.hex(),
            "detail": self.detail,
        }

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")


class ScoutObservationConsumer(Protocol):
    """Pure observation seam shared by live capture and offline replay."""

    def observe(self, event: ScoutEvent) -> None: ...


@dataclass(frozen=True)
class ScoutSessionMetadata:
    """Metadata fixed before an append-only passive session starts."""

    acquisition_id: str
    device: DeviceIdentity
    redaction: RedactionRecord
    interface: str
    source: str
    collector: str
    authorization_basis: AuthorizationBasis
    started_at: str
    tool_name: str
    tool_version: str
    protocol: str = "raw-can"
    method: str = "passive CAN observation"
    parameters: tuple[TransportParameter, ...] = ()
    notes: str | None = None

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.acquisition_id) is None:
            raise ValueError("Scout acquisition_id must be a stable identifier")
        for label, value, maximum in (
            ("Scout interface", self.interface, 1024),
            ("Scout protocol", self.protocol, 1024),
            ("Scout source", self.source, 4096),
            ("Scout method", self.method, 4096),
            ("Scout collector", self.collector, 4096),
            ("Scout tool_name", self.tool_name, 4096),
            ("Scout tool_version", self.tool_version, 4096),
        ):
            _text(value, label, maximum=maximum)
        if self.notes is not None:
            _text(self.notes, "Scout notes")
        transport = TransportObservation(
            kind="can",
            protocol=self.protocol,
            interface=self.interface,
            mode="passive",
            transmitted=False,
            parameters=self.parameters,
            capture_artifact_ids=(SCOUT_CAPTURE_ARTIFACT_ID,),
        )
        if transport.transmitted:
            raise AssertionError("passive Scout metadata unexpectedly permits transmission")
        AcquisitionProvenance(
            source=self.source,
            method=self.method,
            collector=self.collector,
            authorization_basis=self.authorization_basis,
            started_at=self.started_at,
            completed_at=self.started_at,
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            evidence_artifact_ids=(
                SCOUT_CAPTURE_ARTIFACT_ID,
                SCOUT_TRANSACTION_ARTIFACT_ID,
                SCOUT_SESSION_LOG_ARTIFACT_ID,
            ),
            notes=self.notes,
        )
        has_raw_sensitive_identifier = any(
            item.sensitivity in {"personal", "secret"} and item.value is not None
            for item in self.device.identifiers
        )
        if has_raw_sensitive_identifier and not self.redaction.contains_sensitive_values:
            raise ValueError("Scout redaction record denies a raw sensitive device identifier")


@dataclass(frozen=True)
class _FileIdentity:
    size: int
    sha256: str


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("append-only Scout write made no progress")
        offset += written


def _open_append_only(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_APPEND
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _write_exclusive(path: Path, data: bytes) -> None:
    descriptor = _open_append_only(path)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _hash_regular_file(path: Path) -> _FileIdentity:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"Scout artifact is not a regular file: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ValueError(f"Scout artifact identity changed while opening: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if (
            size != opened.st_size
            or _stat_identity(after) != _stat_identity(opened)
            or not stat.S_ISREG(path_after.st_mode)
            or (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise ValueError(f"Scout artifact changed while hashing: {path}")
    finally:
        os.close(descriptor)
    return _FileIdentity(size=size, sha256=digest.hexdigest())


def _fsync_directory(path: Path) -> None:
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if directory_flag is None:
        return
    flags = os.O_RDONLY | directory_flag | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _capture_record(event: ScoutEvent) -> bytes:
    if not event.has_capture_record or event.capture_index is None or event.data is None:
        raise ValueError("event does not have a raw capture record")
    if event.arbitration_id is None:
        arbitration_id = _NO_ARBITRATION_ID
        flags = 0
    else:
        if event.extended_id is None or event.remote_frame is None or event.error_frame is None:
            raise AssertionError("validated event lacks CAN flags")
        arbitration_id = event.arbitration_id
        flags = _CAPTURE_ID_PRESENT
        if event.extended_id:
            flags |= _CAPTURE_EXTENDED
        if event.remote_frame:
            flags |= _CAPTURE_REMOTE
        if event.error_frame:
            flags |= _CAPTURE_ERROR
    declared_length = (
        _NO_DECLARED_LENGTH if event.declared_length is None else event.declared_length
    )
    kind = _CAPTURE_FRAME if event.kind == "frame" else _CAPTURE_MALFORMED
    return _CAPTURE_RECORD.pack(
        kind,
        event.capture_index,
        event.sequence,
        event.timestamp_ns,
        arbitration_id,
        flags,
        declared_length,
        len(event.data),
    ) + event.data


def _session_log_mapping(
    *,
    acquisition_id: str,
    started_at: str,
    completed_at: str,
    tool_name: str,
    tool_version: str,
    protocol: str | None,
    interface: str | None,
    counts: Mapping[str, int],
) -> dict[str, object]:
    return {
        "schema_version": SCOUT_SESSION_LOG_VERSION,
        "acquisition_id": acquisition_id,
        "formats": {
            "capture": SCOUT_CAPTURE_VERSION,
            "event": SCOUT_EVENT_VERSION,
        },
        "started_at": started_at,
        "completed_at": completed_at,
        "tool": {"name": tool_name, "version": tool_version},
        "transport": {
            "interface": interface,
            "mode": "passive",
            "protocol": protocol,
            "transmitted": False,
        },
        "event_counts": dict(counts),
    }


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


class ScoutEvidenceSession:
    """Exclusive-create, append-only producer for one passive Scout session."""

    def __init__(self, root: str | Path, metadata: ScoutSessionMetadata) -> None:
        candidate = Path(root)
        if candidate.name in {"", ".", ".."}:
            raise ValueError("Scout session root must name a new directory")
        parent = candidate.parent.resolve(strict=True)
        if not parent.is_dir():
            raise ValueError("Scout session parent must be a directory")

        self.root = parent / candidate.name
        self.metadata = metadata
        self._capture_descriptor: int | None = None
        self._transaction_descriptor: int | None = None
        self._state = "opening"
        self._event_count = 0
        self._capture_count = 0
        self._last_timestamp_ns: int | None = None
        self._counts: dict[ScoutEventKind, int] = {
            "frame": 0,
            "timeout": 0,
            "malformed-frame": 0,
            "reset": 0,
            "capture-error": 0,
        }

        self.root.mkdir(mode=0o700)
        try:
            captures = self.root / "captures"
            logs = self.root / "logs"
            captures.mkdir(mode=0o700)
            logs.mkdir(mode=0o700)
            self._capture_descriptor = _open_append_only(self.root / SCOUT_CAPTURE_PATH)
            self._transaction_descriptor = _open_append_only(
                self.root / SCOUT_TRANSACTION_PATH
            )
            _write_all(self._capture_descriptor, _CAPTURE_MAGIC)
            os.fsync(self._capture_descriptor)
        except Exception:
            self._close_outputs()
            self._state = "failed"
            raise
        self._state = "open"

    @property
    def state(self) -> str:
        return self._state

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def last_timestamp_ns(self) -> int | None:
        return self._last_timestamp_ns

    def __enter__(self) -> Self:
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        if self._state == "open":
            self.abort()

    def _ensure_open(self) -> None:
        if self._state != "open":
            raise RuntimeError(f"Scout evidence session is {self._state}, not open")

    def _close_outputs(self) -> None:
        descriptors = (self._capture_descriptor, self._transaction_descriptor)
        self._capture_descriptor = None
        self._transaction_descriptor = None
        first_error: OSError | None = None
        for descriptor in descriptors:
            if descriptor is None:
                continue
            try:
                os.fsync(descriptor)
            except OSError as exc:
                first_error = first_error or exc
            try:
                os.close(descriptor)
            except OSError as exc:
                first_error = first_error or exc
        if first_error is not None:
            raise first_error

    def _append(self, event: ScoutEvent) -> ScoutEvent:
        self._ensure_open()
        if event.sequence != self._event_count:
            raise AssertionError("Scout event sequence does not match append position")
        if event.has_capture_record and event.capture_index != self._capture_count:
            raise AssertionError("Scout capture index does not match append position")
        if self._last_timestamp_ns is not None and event.timestamp_ns < self._last_timestamp_ns:
            raise ValueError("Scout timestamps must be monotonic")
        if self._transaction_descriptor is None or self._capture_descriptor is None:
            raise AssertionError("open Scout session lacks output descriptors")

        try:
            if event.has_capture_record:
                _write_all(self._capture_descriptor, _capture_record(event))
                os.fsync(self._capture_descriptor)
            _write_all(self._transaction_descriptor, event.canonical_bytes())
            os.fsync(self._transaction_descriptor)
        except Exception:
            self._state = "failed"
            self._close_outputs()
            raise

        self._event_count += 1
        if event.has_capture_record:
            self._capture_count += 1
        self._last_timestamp_ns = event.timestamp_ns
        self._counts[event.kind] += 1
        return event

    def record_frame(
        self,
        *,
        timestamp_ns: int,
        arbitration_id: int,
        data: bytes,
        extended_id: bool = False,
        remote_frame: bool = False,
        error_frame: bool = False,
        declared_length: int | None = None,
    ) -> ScoutEvent:
        payload = bytes(data)
        return self._append(
            ScoutEvent(
                sequence=self._event_count,
                timestamp_ns=timestamp_ns,
                kind="frame",
                capture_index=self._capture_count,
                arbitration_id=arbitration_id,
                extended_id=extended_id,
                remote_frame=remote_frame,
                error_frame=error_frame,
                declared_length=len(payload) if declared_length is None else declared_length,
                data=payload,
                detail=None,
            )
        )

    def record_malformed_frame(
        self,
        *,
        timestamp_ns: int,
        data: bytes,
        detail: str,
        declared_length: int | None = None,
        arbitration_id: int | None = None,
        extended_id: bool | None = None,
        remote_frame: bool | None = None,
        error_frame: bool | None = None,
    ) -> ScoutEvent:
        return self._append(
            ScoutEvent(
                sequence=self._event_count,
                timestamp_ns=timestamp_ns,
                kind="malformed-frame",
                capture_index=self._capture_count,
                arbitration_id=arbitration_id,
                extended_id=extended_id,
                remote_frame=remote_frame,
                error_frame=error_frame,
                declared_length=declared_length,
                data=bytes(data),
                detail=detail,
            )
        )

    def record_timeout(self, *, timestamp_ns: int, detail: str) -> ScoutEvent:
        return self._append(self._signal_event("timeout", timestamp_ns, detail))

    def record_reset(self, *, timestamp_ns: int, detail: str) -> ScoutEvent:
        return self._append(self._signal_event("reset", timestamp_ns, detail))

    def record_capture_error(self, *, timestamp_ns: int, detail: str) -> ScoutEvent:
        return self._append(self._signal_event("capture-error", timestamp_ns, detail))

    def _signal_event(
        self, kind: Literal["timeout", "reset", "capture-error"], timestamp_ns: int, detail: str
    ) -> ScoutEvent:
        return ScoutEvent(
            sequence=self._event_count,
            timestamp_ns=timestamp_ns,
            kind=kind,
            capture_index=None,
            arbitration_id=None,
            extended_id=None,
            remote_frame=None,
            error_frame=None,
            declared_length=None,
            data=None,
            detail=detail,
        )

    def abort(self) -> None:
        self._ensure_open()
        try:
            self._close_outputs()
        finally:
            self._state = "aborted"

    def seal(self, *, completed_at: str) -> AcquisitionBundle:
        """Close the append streams, hash every artifact, and publish the manifest last."""

        self._ensure_open()
        try:
            self._close_outputs()
            counts: dict[str, int] = {}
            for kind in sorted(self._counts):
                counts[kind] = self._counts[kind]
            counts["total"] = self._event_count
            session_log = _session_log_mapping(
                acquisition_id=self.metadata.acquisition_id,
                started_at=self.metadata.started_at,
                completed_at=completed_at,
                tool_name=self.metadata.tool_name,
                tool_version=self.metadata.tool_version,
                protocol=self.metadata.protocol,
                interface=self.metadata.interface,
                counts=counts,
            )
            _write_exclusive(self.root / SCOUT_SESSION_LOG_PATH, _canonical_json(session_log))

            artifacts = (
                self._artifact(
                    SCOUT_CAPTURE_ARTIFACT_ID,
                    "traffic-capture",
                    SCOUT_CAPTURE_PATH,
                    SCOUT_CAPTURE_MEDIA_TYPE,
                ),
                self._artifact(
                    SCOUT_TRANSACTION_ARTIFACT_ID,
                    "transaction-log",
                    SCOUT_TRANSACTION_PATH,
                    SCOUT_TRANSACTION_MEDIA_TYPE,
                ),
                self._artifact(
                    SCOUT_SESSION_LOG_ARTIFACT_ID,
                    "tool-log",
                    SCOUT_SESSION_LOG_PATH,
                    SCOUT_SESSION_LOG_MEDIA_TYPE,
                ),
            )
            manifest = AcquisitionManifest(
                acquisition_id=self.metadata.acquisition_id,
                created_at=completed_at,
                device=self.metadata.device,
                transport=TransportObservation(
                    kind="can",
                    protocol=self.metadata.protocol,
                    interface=self.metadata.interface,
                    mode="passive",
                    transmitted=False,
                    parameters=self.metadata.parameters,
                    capture_artifact_ids=(SCOUT_CAPTURE_ARTIFACT_ID,),
                ),
                regions=(),
                artifacts=artifacts,
                provenance=AcquisitionProvenance(
                    source=self.metadata.source,
                    method=self.metadata.method,
                    collector=self.metadata.collector,
                    authorization_basis=self.metadata.authorization_basis,
                    started_at=self.metadata.started_at,
                    completed_at=completed_at,
                    tool_name=self.metadata.tool_name,
                    tool_version=self.metadata.tool_version,
                    evidence_artifact_ids=tuple(item.artifact_id for item in artifacts),
                    notes=self.metadata.notes,
                ),
                redaction=self.metadata.redaction,
            )
            manifest_bytes = (
                json.dumps(manifest.to_dict(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
            ).encode("ascii")
            manifest_path = self.root / "acquisition.json"
            _write_exclusive(manifest_path, manifest_bytes)

            retained_paths = [self.root / artifact.path for artifact in artifacts]
            retained_paths.append(manifest_path)
            for path in retained_paths:
                path.chmod(0o444)
            _fsync_directory(self.root / "captures")
            _fsync_directory(self.root / "logs")
            _fsync_directory(self.root)

            bundle = load_acquisition_bundle(self.root)
        except Exception:
            self._state = "failed"
            raise
        self._state = "sealed"
        return bundle

    def _artifact(
        self,
        artifact_id: str,
        kind: Literal["traffic-capture", "transaction-log", "tool-log"],
        path: str,
        media_type: str,
    ) -> AcquisitionArtifact:
        identity = _hash_regular_file(self.root / path)
        return AcquisitionArtifact(
            artifact_id=artifact_id,
            kind=kind,
            path=path,
            media_type=media_type,
            size=identity.size,
            sha256=identity.sha256,
            observed_size=identity.size,
            observed_sha256=identity.sha256,
            availability="present",
            integrity="verified",
            content="plaintext",
            coverage="not-applicable",
            region_ids=(),
        )


class ScoutReplayError(ValueError):
    """Stable fail-closed replay error."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"[{code}] {detail}")


@dataclass(frozen=True)
class ScoutReplayLimits:
    max_events: int = 500_000
    max_transaction_bytes: int = 64 * 1024 * 1024
    max_capture_bytes: int = 128 * 1024 * 1024
    max_session_log_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        for label, value in (
            ("max_events", self.max_events),
            ("max_transaction_bytes", self.max_transaction_bytes),
            ("max_capture_bytes", self.max_capture_bytes),
            ("max_session_log_bytes", self.max_session_log_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"Scout replay {label} must be a positive integer")


@dataclass(frozen=True)
class ScoutReplayResult:
    acquisition_id: str
    event_count: int
    frame_count: int
    timeout_count: int
    malformed_frame_count: int
    reset_count: int
    capture_error_count: int
    capture_sha256: str
    transaction_sha256: str
    tool_name: str
    tool_version: str

    @property
    def transmitted_frames(self) -> Literal[0]:
        return 0

    def to_dict(self) -> dict[str, object]:
        return {
            "acquisition_id": self.acquisition_id,
            "event_count": self.event_count,
            "frame_count": self.frame_count,
            "timeout_count": self.timeout_count,
            "malformed_frame_count": self.malformed_frame_count,
            "reset_count": self.reset_count,
            "capture_error_count": self.capture_error_count,
            "capture_sha256": self.capture_sha256,
            "transaction_sha256": self.transaction_sha256,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "transmitted_frames": self.transmitted_frames,
        }


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ScoutReplayError("duplicate-json-key", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_replay_artifact(
    artifact: ValidatedAcquisitionArtifact, *, maximum: int
) -> bytes:
    declaration = artifact.artifact
    if declaration.availability != "present" or declaration.integrity != "verified":
        raise ScoutReplayError(
            "unverified-artifact",
            f"{declaration.artifact_id} must be a present verified artifact",
        )
    if declaration.size is None or declaration.sha256 is None:
        raise AssertionError("verified Scout artifact lacks identity")
    if declaration.size > maximum:
        raise ScoutReplayError(
            "artifact-limit",
            f"{declaration.artifact_id} exceeds the configured replay byte limit",
        )
    try:
        before = os.lstat(artifact.path)
        descriptor = os.open(
            artifact.path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise ScoutReplayError(
            "artifact-read", f"could not open {declaration.artifact_id}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size != declaration.size
        ):
            raise ScoutReplayError(
                "artifact-changed", f"{declaration.artifact_id} changed before replay"
            )
        chunks: list[bytes] = []
        remaining = declaration.size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ScoutReplayError(
                    "artifact-changed", f"{declaration.artifact_id} was truncated during replay"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ScoutReplayError(
                "artifact-changed", f"{declaration.artifact_id} grew during replay"
            )
        after = os.fstat(descriptor)
        path_after = os.lstat(artifact.path)
        if (
            _stat_identity(after) != _stat_identity(opened)
            or not stat.S_ISREG(path_after.st_mode)
            or (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise ScoutReplayError(
                "artifact-changed", f"{declaration.artifact_id} changed during replay"
            )
    except OSError as exc:
        raise ScoutReplayError(
            "artifact-read", f"could not read {declaration.artifact_id}"
        ) from exc
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if hashlib.sha256(data).hexdigest() != declaration.sha256:
        raise ScoutReplayError(
            "artifact-hash", f"{declaration.artifact_id} failed replay-time SHA-256"
        )
    return data


def _one_artifact(
    bundle: AcquisitionBundle,
    *,
    kind: Literal["traffic-capture", "transaction-log", "tool-log"],
    media_type: str,
    evidence_only: bool,
) -> ValidatedAcquisitionArtifact:
    evidence_ids = set(bundle.manifest.provenance.evidence_artifact_ids)
    matches = [
        item
        for item in bundle.artifacts
        if item.artifact.kind == kind
        and item.artifact.media_type == media_type
        and (not evidence_only or item.artifact.artifact_id in evidence_ids)
    ]
    if len(matches) != 1:
        raise ScoutReplayError(
            "artifact-contract",
            f"Scout replay requires exactly one {kind} artifact with media type {media_type}",
        )
    return matches[0]


def _parse_events(raw: bytes, *, maximum: int) -> tuple[ScoutEvent, ...]:
    lines = raw.splitlines(keepends=True)
    if len(lines) > maximum:
        raise ScoutReplayError("event-limit", "transaction log exceeds the event limit")
    events: list[ScoutEvent] = []
    next_capture_index = 0
    last_timestamp: int | None = None
    for index, line in enumerate(lines):
        if not line or len(line) > _MAX_EVENT_LINE_BYTES:
            raise ScoutReplayError("event-line", f"event line {index} is empty or oversized")
        try:
            value = json.loads(line, object_pairs_hook=_unique_json_object)
            event = ScoutEvent.from_mapping(value)
        except ScoutReplayError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ScoutReplayError(
                "invalid-event", f"event line {index} is invalid: {exc}"
            ) from exc
        if event.canonical_bytes() != line:
            raise ScoutReplayError("noncanonical-event", f"event line {index} is not canonical")
        if event.sequence != index:
            raise ScoutReplayError("event-sequence", f"event line {index} has a sequence gap")
        if last_timestamp is not None and event.timestamp_ns < last_timestamp:
            raise ScoutReplayError("event-time", f"event line {index} moves backwards in time")
        if event.has_capture_record:
            if event.capture_index != next_capture_index:
                raise ScoutReplayError(
                    "capture-sequence", f"event line {index} has a capture index gap"
                )
            next_capture_index += 1
        events.append(event)
        last_timestamp = event.timestamp_ns
    return tuple(events)


def _parse_canonical_object(raw: bytes, label: str) -> Mapping[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json_object)
        result = _mapping(value, label)
    except ScoutReplayError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ScoutReplayError("invalid-session-log", f"{label} is invalid: {exc}") from exc
    if _canonical_json(result) != raw:
        raise ScoutReplayError("noncanonical-session-log", f"{label} is not canonical")
    return result


def replay_scout_bundle(
    source: str | Path | AcquisitionBundle,
    consumer: ScoutObservationConsumer,
    *,
    limits: ScoutReplayLimits | None = None,
) -> ScoutReplayResult:
    """Verify a complete passive bundle, then replay every event without transmission."""

    if limits is None:
        limits = ScoutReplayLimits()
    bundle_source = source.root if isinstance(source, AcquisitionBundle) else source
    bundle = load_acquisition_bundle(bundle_source)
    manifest = bundle.manifest
    if (
        manifest.transport.kind != "can"
        or manifest.transport.mode not in {"offline", "passive"}
        or manifest.transport.transmitted
    ):
        raise ScoutReplayError(
            "transport-safety", "Scout replay accepts only non-transmitting CAN evidence"
        )

    capture = _one_artifact(
        bundle,
        kind="traffic-capture",
        media_type=SCOUT_CAPTURE_MEDIA_TYPE,
        evidence_only=False,
    )
    if manifest.transport.capture_artifact_ids != (capture.artifact.artifact_id,):
        raise ScoutReplayError(
            "capture-reference", "transport must reference exactly the replayed capture"
        )
    transactions = _one_artifact(
        bundle,
        kind="transaction-log",
        media_type=SCOUT_TRANSACTION_MEDIA_TYPE,
        evidence_only=True,
    )
    session_log = _one_artifact(
        bundle,
        kind="tool-log",
        media_type=SCOUT_SESSION_LOG_MEDIA_TYPE,
        evidence_only=True,
    )

    capture_bytes = _read_replay_artifact(capture, maximum=limits.max_capture_bytes)
    transaction_bytes = _read_replay_artifact(
        transactions, maximum=limits.max_transaction_bytes
    )
    session_log_bytes = _read_replay_artifact(
        session_log, maximum=limits.max_session_log_bytes
    )
    events = _parse_events(transaction_bytes, maximum=limits.max_events)

    expected_capture = bytearray(_CAPTURE_MAGIC)
    for event in events:
        if event.has_capture_record:
            expected_capture.extend(_capture_record(event))
    if capture_bytes != bytes(expected_capture):
        raise ScoutReplayError(
            "capture-mismatch", "raw capture does not exactly match structured frame events"
        )

    counts: dict[str, int] = dict.fromkeys(sorted(SCOUT_EVENT_KINDS), 0)
    for event in events:
        counts[event.kind] += 1
    counts["total"] = len(events)
    expected_session_log = _session_log_mapping(
        acquisition_id=manifest.acquisition_id,
        started_at=manifest.provenance.started_at,
        completed_at=manifest.provenance.completed_at,
        tool_name=manifest.provenance.tool_name,
        tool_version=manifest.provenance.tool_version,
        protocol=manifest.transport.protocol,
        interface=manifest.transport.interface,
        counts=counts,
    )
    if _parse_canonical_object(session_log_bytes, "Scout session log") != expected_session_log:
        raise ScoutReplayError(
            "session-log-mismatch", "session log does not match manifest and event evidence"
        )

    # Delivery happens only after every retained artifact and cross-reference passed.
    for event in events:
        consumer.observe(event)

    return ScoutReplayResult(
        acquisition_id=manifest.acquisition_id,
        event_count=len(events),
        frame_count=counts["frame"],
        timeout_count=counts["timeout"],
        malformed_frame_count=counts["malformed-frame"],
        reset_count=counts["reset"],
        capture_error_count=counts["capture-error"],
        capture_sha256=cast(str, capture.artifact.sha256),
        transaction_sha256=cast(str, transactions.artifact.sha256),
        tool_name=manifest.provenance.tool_name,
        tool_version=manifest.provenance.tool_version,
    )


@dataclass(frozen=True)
class VirtualCanObservation:
    """One deterministic bus observation emitted by an in-memory ECU fixture."""

    timestamp_ns: int
    kind: ScoutEventKind
    arbitration_id: int | None
    extended_id: bool | None
    remote_frame: bool | None
    error_frame: bool | None
    declared_length: int | None
    data: bytes | None
    detail: str | None

    def __post_init__(self) -> None:
        ScoutEvent(
            sequence=0,
            timestamp_ns=self.timestamp_ns,
            kind=self.kind,
            capture_index=0 if self.kind in {"frame", "malformed-frame"} else None,
            arbitration_id=self.arbitration_id,
            extended_id=self.extended_id,
            remote_frame=self.remote_frame,
            error_frame=self.error_frame,
            declared_length=self.declared_length,
            data=self.data,
            detail=self.detail,
        )

    @classmethod
    def frame(
        cls,
        *,
        timestamp_ns: int,
        arbitration_id: int,
        data: bytes,
        extended_id: bool = False,
    ) -> Self:
        payload = bytes(data)
        return cls(
            timestamp_ns=timestamp_ns,
            kind="frame",
            arbitration_id=arbitration_id,
            extended_id=extended_id,
            remote_frame=False,
            error_frame=False,
            declared_length=len(payload),
            data=payload,
            detail=None,
        )

    @classmethod
    def malformed_frame(
        cls,
        *,
        timestamp_ns: int,
        data: bytes,
        detail: str,
        declared_length: int | None,
        arbitration_id: int | None = None,
        extended_id: bool | None = None,
    ) -> Self:
        parsed = arbitration_id is not None
        return cls(
            timestamp_ns=timestamp_ns,
            kind="malformed-frame",
            arbitration_id=arbitration_id,
            extended_id=extended_id if parsed else None,
            remote_frame=False if parsed else None,
            error_frame=False if parsed else None,
            declared_length=declared_length,
            data=bytes(data),
            detail=detail,
        )

    @classmethod
    def signal(
        cls,
        *,
        timestamp_ns: int,
        kind: Literal["timeout", "reset", "capture-error"],
        detail: str,
    ) -> Self:
        return cls(
            timestamp_ns=timestamp_ns,
            kind=kind,
            arbitration_id=None,
            extended_id=None,
            remote_frame=None,
            error_frame=None,
            declared_length=None,
            data=None,
            detail=detail,
        )

    def emit(self, session: ScoutEvidenceSession) -> ScoutEvent:
        if self.kind == "frame":
            if self.arbitration_id is None or self.data is None:
                raise AssertionError("validated virtual frame lacks data")
            return session.record_frame(
                timestamp_ns=self.timestamp_ns,
                arbitration_id=self.arbitration_id,
                data=self.data,
                extended_id=bool(self.extended_id),
            )
        if self.kind == "malformed-frame":
            if self.data is None:
                raise AssertionError("validated malformed fixture lacks data")
            return session.record_malformed_frame(
                timestamp_ns=self.timestamp_ns,
                data=self.data,
                detail=cast(str, self.detail),
                declared_length=self.declared_length,
                arbitration_id=self.arbitration_id,
                extended_id=self.extended_id,
                remote_frame=self.remote_frame,
                error_frame=self.error_frame,
            )
        if self.kind == "timeout":
            return session.record_timeout(
                timestamp_ns=self.timestamp_ns, detail=cast(str, self.detail)
            )
        if self.kind == "reset":
            return session.record_reset(
                timestamp_ns=self.timestamp_ns, detail=cast(str, self.detail)
            )
        return session.record_capture_error(
            timestamp_ns=self.timestamp_ns, detail=cast(str, self.detail)
        )


@dataclass(frozen=True)
class VirtualCanEcu:
    """Deterministic in-memory ECU trace used by no-hardware CI."""

    name: str
    observations: tuple[VirtualCanObservation, ...]

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.name) is None:
            raise ValueError("virtual ECU name must be a stable identifier")
        previous: int | None = None
        for observation in self.observations:
            if previous is not None and observation.timestamp_ns < previous:
                raise ValueError("virtual ECU observations must be monotonic")
            previous = observation.timestamp_ns

    @property
    def transmitted_frames(self) -> int:
        return 0

    @classmethod
    def standard_fixture(cls) -> Self:
        return cls(
            name="fixture-ecu-v1",
            observations=(
                VirtualCanObservation.frame(
                    timestamp_ns=1_000_000,
                    arbitration_id=0x7E8,
                    data=b"\x04\x62\xf1\x90\x01\x00\x00\x00",
                ),
                VirtualCanObservation.signal(
                    timestamp_ns=2_000_000,
                    kind="timeout",
                    detail="fixture bus silence interval elapsed",
                ),
                VirtualCanObservation.malformed_frame(
                    timestamp_ns=3_000_000,
                    arbitration_id=0x7E8,
                    extended_id=False,
                    declared_length=20,
                    data=b"\x10\x14\x62\xf1",
                    detail="declared payload length exceeds retained bytes",
                ),
                VirtualCanObservation.signal(
                    timestamp_ns=4_000_000,
                    kind="reset",
                    detail="fixture ECU reset observed",
                ),
                VirtualCanObservation.frame(
                    timestamp_ns=5_000_000,
                    arbitration_id=0x700,
                    data=b"\x02\x50\x01\x00\x00\x00\x00\x00",
                ),
            ),
        )

    def capture(self, session: ScoutEvidenceSession) -> tuple[ScoutEvent, ...]:
        """Append the fixture's bus trace; no request or transmit path exists."""

        return tuple(observation.emit(session) for observation in self.observations)
