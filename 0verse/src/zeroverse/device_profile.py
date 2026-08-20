"""Closed, inert device-profile metadata for Firmware Scout.

A profile records target knowledge and its provenance. It never opens a transport,
constructs a request, or grants permission to communicate with a device.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Generic, Literal, TypeVar, cast

DEVICE_PROFILE_VERSION = "0verse.device-profile/v1"
NO_SUBFUNCTION = "none"

KnowledgeState = Literal["unknown", "declared", "observed", "inferred"]
Confidence = Literal["unassessed", "low", "medium", "high"]
TransportKind = Literal["file", "can", "serial", "network", "debug-port", "storage"]
Subfunction = int | Literal["none"]
MemoryRole = Literal[
    "firmware",
    "bootloader",
    "code",
    "calibration",
    "data",
    "filesystem",
    "configuration",
]

KNOWLEDGE_STATES = frozenset({"unknown", "declared", "observed", "inferred"})
CONFIDENCES = frozenset({"unassessed", "low", "medium", "high"})
TRANSPORT_KINDS = frozenset({"file", "can", "serial", "network", "debug-port", "storage"})
MEMORY_ROLES = frozenset(
    {"firmware", "bootloader", "code", "calibration", "data", "filesystem", "configuration"}
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_RFC3339 = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_MAX_CAN_ID = 0x1FFFFFFF

T = TypeVar("T")


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


def _exact_fields(raw: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    unexpected = sorted(raw.keys() - expected)
    if missing or unexpected:
        raise ValueError(f"{label} fields differ: missing={missing}, unexpected={unexpected}")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{label} must be non-empty text without NUL")
    return value


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


def _timestamp(value: object, label: str) -> str:
    result = _text(value, label)
    if _RFC3339.fullmatch(result) is None:
        raise ValueError(f"{label} must be a canonical RFC3339 date-time")
    try:
        datetime.fromisoformat(result.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as exc:
        raise ValueError(f"{label} must be a canonical RFC3339 date-time") from exc
    return result


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def _unsigned_int(value: object, label: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be at most {maximum}")
    return value


def _positive_int(value: object, label: str) -> int:
    result = _unsigned_int(value, label)
    if result == 0:
        raise ValueError(f"{label} must be a positive integer")
    return result


def _json_unsigned_int(value: object, label: str, *, maximum: int | None = None) -> int:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return _unsigned_int(value, label, maximum=maximum)


def _json_positive_int(value: object, label: str) -> int:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return _positive_int(value, label)


def _subfunction(value: object, label: str) -> Subfunction:
    if value == NO_SUBFUNCTION:
        return cast(Subfunction, NO_SUBFUNCTION)
    return cast(Subfunction, _unsigned_int(value, label, maximum=0x7F))


def _json_subfunction(value: object, label: str) -> Subfunction:
    if value == NO_SUBFUNCTION:
        return cast(Subfunction, NO_SUBFUNCTION)
    return cast(Subfunction, _json_unsigned_int(value, label, maximum=0x7F))


def _schema_version(value: object) -> str:
    if value != DEVICE_PROFILE_VERSION:
        raise ValueError(f"unsupported device profile schema: {value}")
    return DEVICE_PROFILE_VERSION


def _validate_fact(
    fact: Knowledge[T], label: str, validator: Callable[[object, str], object]
) -> None:
    if not isinstance(fact, Knowledge):
        raise ValueError(f"{label} must be a knowledge fact")
    if fact.state != "unknown":
        validator(fact.value, f"{label} value")


def _fact_value(fact: Knowledge[T]) -> T | None:
    return None if fact.state == "unknown" else cast(T, fact.value)


@dataclass(frozen=True)
class Knowledge(Generic[T]):
    """One sourced fact, or an explicit unknown with no invented defaults.

    ``observed_at`` is when the source recorded this fact. For a ``declared``
    fact, that timestamp records the declaration rather than a physical target
    observation; its state remains ``declared``.
    """

    state: KnowledgeState
    value: T | None
    source: str | None
    confidence: Confidence | None
    observed_at: str | None

    _FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"state", "value", "source", "confidence", "observed_at"}
    )

    def __post_init__(self) -> None:
        state = _choice(self.state, KNOWLEDGE_STATES, "knowledge state")
        if state == "unknown":
            if any(
                item is not None
                for item in (self.value, self.source, self.confidence, self.observed_at)
            ):
                raise ValueError("unknown knowledge must have null value and provenance")
            return
        if self.value is None:
            raise ValueError("known knowledge requires a value")
        _text(self.source, "knowledge source")
        _choice(self.confidence, CONFIDENCES, "knowledge confidence")
        _timestamp(self.observed_at, "knowledge observed_at")

    @classmethod
    def from_mapping(
        cls,
        value: object,
        label: str,
        decoder: Callable[[object, str], T],
    ) -> Knowledge[T]:
        raw = _mapping(value, label)
        _exact_fields(raw, cls._FIELDS, label)
        state = cast(KnowledgeState, _choice(raw["state"], KNOWLEDGE_STATES, f"{label} state"))
        if state == "unknown":
            return cls(
                state=state,
                value=cast(T | None, raw["value"]),
                source=cast(str | None, raw["source"]),
                confidence=cast(Confidence | None, raw["confidence"]),
                observed_at=cast(str | None, raw["observed_at"]),
            )
        return cls(
            state=state,
            value=decoder(raw["value"], f"{label} value"),
            source=_text(raw["source"], f"{label} source"),
            confidence=cast(
                Confidence,
                _choice(raw["confidence"], CONFIDENCES, f"{label} confidence"),
            ),
            observed_at=_timestamp(raw["observed_at"], f"{label} observed_at"),
        )

    def to_dict(self, encoder: Callable[[T], object]) -> dict[str, object]:
        return {
            "state": self.state,
            "value": None if self.state == "unknown" else encoder(cast(T, self.value)),
            "source": self.source,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True)
class DeviceIdentity:
    category: Knowledge[str]
    manufacturer: Knowledge[str]
    model: Knowledge[str]
    part_number: Knowledge[str]

    _FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"category", "manufacturer", "model", "part_number"}
    )

    def __post_init__(self) -> None:
        for label, fact in (
            ("identity category", self.category),
            ("identity manufacturer", self.manufacturer),
            ("identity model", self.model),
            ("identity part number", self.part_number),
        ):
            _validate_fact(fact, label, _text)

    @classmethod
    def from_mapping(cls, value: object) -> DeviceIdentity:
        raw = _mapping(value, "device identity")
        _exact_fields(raw, cls._FIELDS, "device identity")
        return cls(
            category=Knowledge.from_mapping(raw["category"], "identity category", _text),
            manufacturer=Knowledge.from_mapping(
                raw["manufacturer"], "identity manufacturer", _text
            ),
            model=Knowledge.from_mapping(raw["model"], "identity model", _text),
            part_number=Knowledge.from_mapping(raw["part_number"], "identity part number", _text),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category.to_dict(lambda item: item),
            "manufacturer": self.manufacturer.to_dict(lambda item: item),
            "model": self.model.to_dict(lambda item: item),
            "part_number": self.part_number.to_dict(lambda item: item),
        }


@dataclass(frozen=True)
class TransportParameter:
    parameter_id: str
    value: Knowledge[str]

    _FIELDS: ClassVar[frozenset[str]] = frozenset({"value"})

    def __post_init__(self) -> None:
        _identifier(self.parameter_id, "transport parameter_id")
        _validate_fact(self.value, "transport parameter", _text)

    @classmethod
    def from_mapping(cls, parameter_id: object, value: object) -> TransportParameter:
        raw = _mapping(value, "transport parameter")
        _exact_fields(raw, cls._FIELDS, "transport parameter")
        return cls(
            parameter_id=_identifier(parameter_id, "transport parameter_id"),
            value=Knowledge.from_mapping(raw["value"], "transport parameter", _text),
        )

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value.to_dict(lambda item: item)}


def _transport_parameters(value: object, label: str) -> tuple[TransportParameter, ...]:
    raw = _mapping(value, label)
    result = tuple(
        TransportParameter.from_mapping(identifier, item) for identifier, item in raw.items()
    )
    _validate_transport_parameters(result, label)
    return result


def _validate_transport_parameters(value: object, label: str) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, TransportParameter) for item in value
    ):
        raise ValueError(f"{label} value must be transport parameters")
    identifiers = [item.parameter_id for item in value]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{label} parameter ids must be unique")


@dataclass(frozen=True)
class ExpectedTransport:
    transport_id: str
    kind: Knowledge[TransportKind]
    protocol: Knowledge[str]
    parameters: Knowledge[tuple[TransportParameter, ...]]

    _FIELDS: ClassVar[frozenset[str]] = frozenset({"kind", "protocol", "parameters"})

    def __post_init__(self) -> None:
        _identifier(self.transport_id, "transport_id")
        _validate_fact(
            self.kind,
            "transport kind",
            lambda value, label: _choice(value, TRANSPORT_KINDS, label),
        )
        _validate_fact(self.protocol, "transport protocol", _text)
        _validate_fact(self.parameters, "transport parameters", _validate_transport_parameters)

    @classmethod
    def from_mapping(cls, transport_id: object, value: object) -> ExpectedTransport:
        raw = _mapping(value, "transport")
        _exact_fields(raw, cls._FIELDS, "transport")
        return cls(
            transport_id=_identifier(transport_id, "transport_id"),
            kind=Knowledge.from_mapping(
                raw["kind"],
                "transport kind",
                lambda item, label: cast(TransportKind, _choice(item, TRANSPORT_KINDS, label)),
            ),
            protocol=Knowledge.from_mapping(raw["protocol"], "transport protocol", _text),
            parameters=Knowledge.from_mapping(
                raw["parameters"], "transport parameters", _transport_parameters
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.to_dict(lambda item: item),
            "protocol": self.protocol.to_dict(lambda item: item),
            "parameters": self.parameters.to_dict(
                lambda items: {item.parameter_id: item.to_dict() for item in items}
            ),
        }


def _transports(value: object, label: str) -> tuple[ExpectedTransport, ...]:
    raw = _mapping(value, label)
    result = tuple(
        ExpectedTransport.from_mapping(identifier, item) for identifier, item in raw.items()
    )
    _validate_transports(result, label)
    return result


def _validate_transports(value: object, label: str) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, ExpectedTransport) for item in value
    ):
        raise ValueError(f"{label} value must be transports")
    identifiers = [item.transport_id for item in value]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{label} ids must be unique")


@dataclass(frozen=True)
class EndpointDescription:
    endpoint_id: str
    transport_id: Knowledge[str]
    request_can_id: Knowledge[int]
    response_can_id: Knowledge[int]
    extended_id: Knowledge[bool]

    _FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"transport_id", "request_can_id", "response_can_id", "extended_id"}
    )

    def __post_init__(self) -> None:
        _identifier(self.endpoint_id, "endpoint_id")
        _validate_fact(self.transport_id, "endpoint transport_id", _identifier)
        _validate_fact(
            self.request_can_id,
            "endpoint request_can_id",
            lambda value, label: _unsigned_int(value, label, maximum=_MAX_CAN_ID),
        )
        _validate_fact(
            self.response_can_id,
            "endpoint response_can_id",
            lambda value, label: _unsigned_int(value, label, maximum=_MAX_CAN_ID),
        )
        _validate_fact(self.extended_id, "endpoint extended_id", _boolean)

        can_ids = (
            _fact_value(self.request_can_id),
            _fact_value(self.response_can_id),
        )
        if (
            any(can_id is not None and can_id > 0x7FF for can_id in can_ids)
            and _fact_value(self.extended_id) is not True
        ):
            raise ValueError("extended endpoint CAN ids require a known true extended_id")

    @classmethod
    def from_mapping(cls, endpoint_id: object, value: object) -> EndpointDescription:
        raw = _mapping(value, "endpoint")
        _exact_fields(raw, cls._FIELDS, "endpoint")
        return cls(
            endpoint_id=_identifier(endpoint_id, "endpoint_id"),
            transport_id=Knowledge.from_mapping(
                raw["transport_id"], "endpoint transport_id", _identifier
            ),
            request_can_id=Knowledge.from_mapping(
                raw["request_can_id"],
                "endpoint request_can_id",
                lambda item, label: _json_unsigned_int(item, label, maximum=_MAX_CAN_ID),
            ),
            response_can_id=Knowledge.from_mapping(
                raw["response_can_id"],
                "endpoint response_can_id",
                lambda item, label: _json_unsigned_int(item, label, maximum=_MAX_CAN_ID),
            ),
            extended_id=Knowledge.from_mapping(
                raw["extended_id"], "endpoint extended_id", _boolean
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "transport_id": self.transport_id.to_dict(lambda item: item),
            "request_can_id": self.request_can_id.to_dict(lambda item: item),
            "response_can_id": self.response_can_id.to_dict(lambda item: item),
            "extended_id": self.extended_id.to_dict(lambda item: item),
        }


def _endpoints(value: object, label: str) -> tuple[EndpointDescription, ...]:
    raw = _mapping(value, label)
    result = tuple(
        EndpointDescription.from_mapping(identifier, item) for identifier, item in raw.items()
    )
    _validate_endpoints(result, label)
    return result


def _validate_endpoints(value: object, label: str) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, EndpointDescription) for item in value
    ):
        raise ValueError(f"{label} value must be endpoints")
    identifiers = [item.endpoint_id for item in value]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{label} ids must be unique")


@dataclass(frozen=True)
class ServiceSessionClaim:
    claim_id: str
    service: Knowledge[int]
    subfunction: Knowledge[Subfunction]
    session: Knowledge[int]
    safety_evidence: Knowledge[str]
    authorization_effect: Literal["none"] = "none"

    _FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"service", "subfunction", "session", "safety_evidence", "authorization_effect"}
    )

    def __post_init__(self) -> None:
        _identifier(self.claim_id, "service/session claim_id")
        _validate_fact(
            self.service,
            "service/session service",
            lambda value, label: _unsigned_int(value, label, maximum=0xFF),
        )
        _validate_fact(self.subfunction, "service/session subfunction", _subfunction)
        _validate_fact(
            self.session,
            "service/session session",
            lambda value, label: _unsigned_int(value, label, maximum=0x7F),
        )
        _validate_fact(self.safety_evidence, "service/session safety_evidence", _text)
        if self.authorization_effect != "none":
            raise ValueError("service/session authorization_effect must be none")

    @classmethod
    def from_mapping(cls, claim_id: object, value: object) -> ServiceSessionClaim:
        raw = _mapping(value, "service/session claim")
        _exact_fields(raw, cls._FIELDS, "service/session claim")
        return cls(
            claim_id=_identifier(claim_id, "service/session claim_id"),
            service=Knowledge.from_mapping(
                raw["service"],
                "service/session service",
                lambda item, label: _json_unsigned_int(item, label, maximum=0xFF),
            ),
            subfunction=Knowledge.from_mapping(
                raw["subfunction"], "service/session subfunction", _json_subfunction
            ),
            session=Knowledge.from_mapping(
                raw["session"],
                "service/session session",
                lambda item, label: _json_unsigned_int(item, label, maximum=0x7F),
            ),
            safety_evidence=Knowledge.from_mapping(
                raw["safety_evidence"], "service/session safety_evidence", _text
            ),
            authorization_effect=cast(Literal["none"], raw["authorization_effect"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "service": self.service.to_dict(lambda item: item),
            "subfunction": self.subfunction.to_dict(lambda item: item),
            "session": self.session.to_dict(lambda item: item),
            "safety_evidence": self.safety_evidence.to_dict(lambda item: item),
            "authorization_effect": self.authorization_effect,
        }


def _service_session_claims(value: object, label: str) -> tuple[ServiceSessionClaim, ...]:
    raw = _mapping(value, label)
    result = tuple(
        ServiceSessionClaim.from_mapping(identifier, item) for identifier, item in raw.items()
    )
    _validate_service_session_claims(result, label)
    return result


def _validate_service_session_claims(value: object, label: str) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, ServiceSessionClaim) for item in value
    ):
        raise ValueError(f"{label} value must be service/session claims")
    identifiers = [item.claim_id for item in value]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{label} ids must be unique")


@dataclass(frozen=True)
class MemoryMetadata:
    metadata_id: str
    address_space: Knowledge[str]
    start: Knowledge[int]
    length: Knowledge[int]
    role: Knowledge[MemoryRole]

    _FIELDS: ClassVar[frozenset[str]] = frozenset({"address_space", "start", "length", "role"})

    def __post_init__(self) -> None:
        _identifier(self.metadata_id, "memory metadata_id")
        _validate_fact(self.address_space, "memory address_space", _text)
        _validate_fact(self.start, "memory start", _unsigned_int)
        _validate_fact(self.length, "memory length", _positive_int)
        _validate_fact(
            self.role,
            "memory role",
            lambda value, label: _choice(value, MEMORY_ROLES, label),
        )

    @classmethod
    def from_mapping(cls, metadata_id: object, value: object) -> MemoryMetadata:
        raw = _mapping(value, "memory metadata")
        _exact_fields(raw, cls._FIELDS, "memory metadata")
        return cls(
            metadata_id=_identifier(metadata_id, "memory metadata_id"),
            address_space=Knowledge.from_mapping(
                raw["address_space"], "memory address_space", _text
            ),
            start=Knowledge.from_mapping(raw["start"], "memory start", _json_unsigned_int),
            length=Knowledge.from_mapping(raw["length"], "memory length", _json_positive_int),
            role=Knowledge.from_mapping(
                raw["role"],
                "memory role",
                lambda item, label: cast(MemoryRole, _choice(item, MEMORY_ROLES, label)),
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "address_space": self.address_space.to_dict(lambda item: item),
            "start": self.start.to_dict(lambda item: item),
            "length": self.length.to_dict(lambda item: item),
            "role": self.role.to_dict(lambda item: item),
        }


def _memory_metadata(value: object, label: str) -> tuple[MemoryMetadata, ...]:
    raw = _mapping(value, label)
    result = tuple(
        MemoryMetadata.from_mapping(identifier, item) for identifier, item in raw.items()
    )
    _validate_memory_metadata(result, label)
    return result


def _validate_memory_metadata(value: object, label: str) -> None:
    if not isinstance(value, tuple) or any(not isinstance(item, MemoryMetadata) for item in value):
        raise ValueError(f"{label} value must be memory metadata")
    identifiers = [item.metadata_id for item in value]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{label} ids must be unique")


@dataclass(frozen=True)
class DeviceProfile:
    """One closed declarative profile; no field is an authorization decision."""

    profile_id: str
    identity: DeviceIdentity
    transports: Knowledge[tuple[ExpectedTransport, ...]]
    endpoints: Knowledge[tuple[EndpointDescription, ...]]
    service_session_claims: Knowledge[tuple[ServiceSessionClaim, ...]]
    memory_metadata: Knowledge[tuple[MemoryMetadata, ...]]
    schema_version: str = DEVICE_PROFILE_VERSION

    _FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "schema_version",
            "profile_id",
            "identity",
            "transports",
            "endpoints",
            "service_session_claims",
            "memory_metadata",
        }
    )

    def __post_init__(self) -> None:
        _schema_version(self.schema_version)
        _identifier(self.profile_id, "profile_id")
        if not isinstance(self.identity, DeviceIdentity):
            raise ValueError("profile identity must be a device identity")
        _validate_fact(self.transports, "profile transports", _validate_transports)
        _validate_fact(self.endpoints, "profile endpoints", _validate_endpoints)
        _validate_fact(
            self.service_session_claims,
            "profile service/session claims",
            _validate_service_session_claims,
        )
        _validate_fact(self.memory_metadata, "profile memory metadata", _validate_memory_metadata)

    @classmethod
    def from_mapping(cls, value: object) -> DeviceProfile:
        raw = _mapping(value, "device profile")
        _exact_fields(raw, cls._FIELDS, "device profile")
        return cls(
            schema_version=_schema_version(raw["schema_version"]),
            profile_id=_identifier(raw["profile_id"], "profile_id"),
            identity=DeviceIdentity.from_mapping(raw["identity"]),
            transports=Knowledge.from_mapping(raw["transports"], "profile transports", _transports),
            endpoints=Knowledge.from_mapping(raw["endpoints"], "profile endpoints", _endpoints),
            service_session_claims=Knowledge.from_mapping(
                raw["service_session_claims"],
                "profile service/session claims",
                _service_session_claims,
            ),
            memory_metadata=Knowledge.from_mapping(
                raw["memory_metadata"], "profile memory metadata", _memory_metadata
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "identity": self.identity.to_dict(),
            "transports": self.transports.to_dict(
                lambda items: {item.transport_id: item.to_dict() for item in items}
            ),
            "endpoints": self.endpoints.to_dict(
                lambda items: {item.endpoint_id: item.to_dict() for item in items}
            ),
            "service_session_claims": self.service_session_claims.to_dict(
                lambda items: {item.claim_id: item.to_dict() for item in items}
            ),
            "memory_metadata": self.memory_metadata.to_dict(
                lambda items: {item.metadata_id: item.to_dict() for item in items}
            ),
        }


def load_device_profile(path: str | Path) -> DeviceProfile:
    """Load one local profile without opening or configuring any interface."""

    try:
        data = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("device profile must be a readable UTF-8 file") from exc
    try:
        raw = json.loads(data, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError("device profile is not valid JSON") from exc
    return DeviceProfile.from_mapping(raw)


__all__ = [
    "DEVICE_PROFILE_VERSION",
    "NO_SUBFUNCTION",
    "Confidence",
    "DeviceIdentity",
    "DeviceProfile",
    "EndpointDescription",
    "ExpectedTransport",
    "Knowledge",
    "KnowledgeState",
    "MemoryMetadata",
    "MemoryRole",
    "ServiceSessionClaim",
    "Subfunction",
    "TransportKind",
    "TransportParameter",
    "load_device_profile",
]
