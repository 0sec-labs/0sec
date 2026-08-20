from __future__ import annotations

import builtins
import importlib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

import zeroverse.device_profile as device_profile
from zeroverse.device_profile import DEVICE_PROFILE_VERSION, DeviceProfile, load_device_profile

ROOT = Path(__file__).resolve().parents[1]
SKELETON = ROOT / "profiles" / "delphi-mt05.3-42012692-v1.json"
SOURCE = "synthetic profile evidence"
OBSERVED_AT = "2026-07-20T12:00:00Z"
ISSUE_69_CREATED_AT = "2026-07-13T18:20:27Z"


def _unknown() -> dict[str, None | str]:
    return {
        "state": "unknown",
        "value": None,
        "source": None,
        "confidence": None,
        "observed_at": None,
    }


def _fact(
    value: object, *, state: str = "declared", observed_at: str = OBSERVED_AT
) -> dict[str, object]:
    return {
        "state": state,
        "value": value,
        "source": SOURCE,
        "confidence": "high",
        "observed_at": observed_at,
    }


def _collection(value: dict[str, object]) -> dict[str, object]:
    return _fact(value)


def _profile() -> dict[str, object]:
    return {
        "schema_version": DEVICE_PROFILE_VERSION,
        "profile_id": "synthetic-profile",
        "identity": {
            "category": _fact("ecu"),
            "manufacturer": _fact("Example Controls"),
            "model": _fact("ECU-1"),
            "part_number": _fact("EXAMPLE-0001"),
        },
        "transports": _collection(
            {
                "engine-can": {
                    "kind": _fact("can"),
                    "protocol": _fact("raw-can"),
                    "parameters": _collection({"bitrate": {"value": _fact("500000")}}),
                }
            }
        ),
        "endpoints": _collection(
            {
                "engine": {
                    "transport_id": _fact("engine-can"),
                    "request_can_id": _fact(0x7E0),
                    "response_can_id": _fact(0x7E8),
                    "extended_id": _fact(False),
                }
            }
        ),
        "service_session_claims": _collection(
            {
                "identity-read-evidence": {
                    "service": _fact(0x22),
                    "subfunction": _fact("none"),
                    "session": _fact(1),
                    "safety_evidence": _fact("synthetic read-only safety evidence"),
                    "authorization_effect": "none",
                }
            }
        ),
        "memory_metadata": _collection(
            {
                "flash": {
                    "address_space": _fact("physical"),
                    "start": _fact(0),
                    "length": _fact(1024),
                    "role": _fact("firmware"),
                }
            }
        ),
    }


def _schema() -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads((ROOT / "schemas" / "device-profile-v1.schema.json").read_text()),
    )


def _validate_schema(raw: object) -> None:
    Draft202012Validator(_schema()).validate(raw)


def _assert_schema_and_runtime_reject(raw: object) -> None:
    with pytest.raises(ValidationError):
        _validate_schema(raw)
    with pytest.raises(ValueError):
        DeviceProfile.from_mapping(raw)


def test_delphi_skeleton_round_trips_and_loads(tmp_path: Path) -> None:
    raw = json.loads(SKELETON.read_text())
    _validate_schema(raw)

    profile = DeviceProfile.from_mapping(raw)
    assert profile.to_dict() == raw
    assert load_device_profile(SKELETON) == profile

    path = tmp_path / "profile.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert load_device_profile(path) == profile
    assert profile.profile_id == "delphi.mt05.3.42012692"


def test_published_schema_matches_runtime_contract() -> None:
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    properties = cast(dict[str, object], schema["properties"])
    schema_version = cast(dict[str, object], properties["schema_version"])
    assert schema_version["const"] == DEVICE_PROFILE_VERSION

    raw = _profile()
    _validate_schema(raw)
    profile = DeviceProfile.from_mapping(raw)
    assert profile.to_dict() == raw
    assert DeviceProfile.from_mapping(profile.to_dict()) == profile


def test_unknown_and_known_fact_provenance_are_distinct() -> None:
    raw: Any = _profile()
    raw["identity"]["category"] = _unknown()
    raw["transports"] = _unknown()
    raw["endpoints"] = _unknown()
    raw["service_session_claims"] = _unknown()
    raw["memory_metadata"] = _unknown()
    _validate_schema(raw)
    profile = DeviceProfile.from_mapping(raw)
    assert profile.identity.category.state == "unknown"
    assert profile.identity.category.value is None
    assert profile.transports.value is None

    known_empty: Any = _profile()
    known_empty["transports"] = _collection({})
    known_empty["endpoints"] = _collection({})
    known_empty["service_session_claims"] = _collection({})
    known_empty["memory_metadata"] = _collection({})
    _validate_schema(known_empty)
    parsed = DeviceProfile.from_mapping(known_empty)
    assert parsed.transports.state == "declared"
    assert parsed.transports.value == ()

    missing_provenance: Any = _profile()
    missing_provenance["identity"]["manufacturer"]["source"] = None
    _assert_schema_and_runtime_reject(missing_provenance)

    missing_time: Any = _profile()
    missing_time["identity"]["manufacturer"]["observed_at"] = None
    _assert_schema_and_runtime_reject(missing_time)

    unknown_with_value: Any = _profile()
    unknown_with_value["identity"]["model"] = _unknown()
    unknown_with_value["identity"]["model"]["value"] = "invented default"
    _assert_schema_and_runtime_reject(unknown_with_value)

    member_without_provenance: Any = _profile()
    member_without_provenance["transports"]["value"]["engine-can"]["parameters"]["value"][
        "bitrate"
    ]["value"]["confidence"] = None
    _assert_schema_and_runtime_reject(member_without_provenance)


def test_delphi_skeleton_records_declaration_time_without_physical_observation() -> None:
    raw: Any = json.loads(SKELETON.read_text())
    identity = raw["identity"]
    assert identity["category"] == _unknown()
    for name, expected in (
        ("manufacturer", "Delphi"),
        ("model", "MT05.3"),
        ("part_number", "42012692"),
    ):
        assert identity[name] == {
            "state": "declared",
            "value": expected,
            "source": "https://github.com/0sec-labs/0verse/issues/69",
            "confidence": "unassessed",
            "observed_at": ISSUE_69_CREATED_AT,
        }
    for name in ("transports", "endpoints", "service_session_claims", "memory_metadata"):
        assert raw[name] == _unknown()

    profile = DeviceProfile.from_mapping(raw)
    assert profile.identity.model.state == "declared"
    assert profile.identity.model.observed_at == ISSUE_69_CREATED_AT


@pytest.mark.parametrize(
    "case",
    [
        "root-extra",
        "fact-extra",
        "unknown-state",
        "unknown-confidence",
        "identifier-newline",
        "identifier-whitespace",
        "missing-fact-field",
        "bad-timestamp",
        "timestamp-newline",
        "non-null-unknown-source",
    ],
)
def test_schema_and_runtime_reject_closed_or_malformed_data(case: str) -> None:
    raw: Any = _profile()
    if case == "root-extra":
        raw["unexpected"] = True
    elif case == "fact-extra":
        raw["identity"]["model"]["unexpected"] = True
    elif case == "unknown-state":
        raw["identity"]["model"]["state"] = "probably"
    elif case == "unknown-confidence":
        raw["identity"]["model"]["confidence"] = "certain"
    elif case == "identifier-newline":
        raw["profile_id"] = "synthetic-profile\n"
    elif case == "identifier-whitespace":
        raw["profile_id"] = "synthetic profile"
    elif case == "missing-fact-field":
        del raw["identity"]["model"]["observed_at"]
    elif case == "bad-timestamp":
        raw["identity"]["model"]["observed_at"] = "2026-07-20 12:00:00Z"
    elif case == "timestamp-newline":
        raw["identity"]["model"]["observed_at"] = f"{OBSERVED_AT}\n"
    else:
        raw["identity"]["model"] = _unknown()
        raw["identity"]["model"]["source"] = SOURCE
    _assert_schema_and_runtime_reject(raw)


def test_plain_schema_validator_and_runtime_share_calendar_edges() -> None:
    for timestamp in ("2026-02-31T12:00:00Z", "0000-02-29T12:00:00Z"):
        invalid: Any = _profile()
        invalid["identity"]["model"]["observed_at"] = timestamp
        assert list(Draft202012Validator(_schema()).iter_errors(invalid))
        with pytest.raises(ValueError, match="RFC3339"):
            DeviceProfile.from_mapping(invalid)

    for timestamp in (
        "2024-02-29T23:59:59.123+05:30",
        "0004-02-29T12:00:00Z",
        "0001-01-01T00:00:00Z",
        "0999-12-31T23:59:59-00:30",
    ):
        valid: Any = _profile()
        valid["identity"]["model"]["observed_at"] = timestamp
        _validate_schema(valid)
        assert DeviceProfile.from_mapping(valid).identity.model.observed_at == timestamp


def test_identifier_keyed_collections_allow_independent_endpoint_knowledge() -> None:
    raw: Any = _profile()
    assert set(raw["transports"]["value"]) == {"engine-can"}
    assert "transport_id" not in raw["transports"]["value"]["engine-can"]
    assert "endpoint_id" not in raw["endpoints"]["value"]["engine"]
    assert "claim_id" not in raw["service_session_claims"]["value"]["identity-read-evidence"]
    assert "metadata_id" not in raw["memory_metadata"]["value"]["flash"]
    _validate_schema(raw)
    assert DeviceProfile.from_mapping(raw).to_dict() == raw

    invalid_key: Any = _profile()
    invalid_key["transports"]["value"] = {
        "engine can": invalid_key["transports"]["value"]["engine-can"]
    }
    _assert_schema_and_runtime_reject(invalid_key)

    unknown_transports: Any = _profile()
    unknown_transports["transports"] = _unknown()
    _validate_schema(unknown_transports)
    assert DeviceProfile.from_mapping(unknown_transports).to_dict() == unknown_transports

    unlisted_transport: Any = _profile()
    unlisted_transport["transports"] = _collection({})
    _validate_schema(unlisted_transport)
    assert DeviceProfile.from_mapping(unlisted_transport).to_dict() == unlisted_transport


def test_endpoint_transport_identifier_fact_and_extended_addressing_requirements() -> None:
    invalid_transport_fact: Any = _profile()
    invalid_transport_fact["endpoints"]["value"]["engine"]["transport_id"]["value"] = "engine can"
    _assert_schema_and_runtime_reject(invalid_transport_fact)

    extended_unknown: Any = _profile()
    extended_unknown["endpoints"]["value"]["engine"]["request_can_id"]["value"] = 0x800
    extended_unknown["endpoints"]["value"]["engine"]["extended_id"] = _unknown()
    _assert_schema_and_runtime_reject(extended_unknown)

    extended_false: Any = _profile()
    extended_false["endpoints"]["value"]["engine"]["request_can_id"]["value"] = 0x800
    _assert_schema_and_runtime_reject(extended_false)

    extended_true: Any = _profile()
    extended_true["endpoints"]["value"]["engine"]["request_can_id"]["value"] = 0x800
    extended_true["endpoints"]["value"]["engine"]["extended_id"] = _fact(True)
    _validate_schema(extended_true)
    assert DeviceProfile.from_mapping(extended_true).endpoints.value is not None


def test_subfunction_no_subfunction_discriminator_and_numeric_bounds() -> None:
    raw: Any = _profile()
    assert (
        raw["service_session_claims"]["value"]["identity-read-evidence"]["subfunction"]["value"]
        == "none"
    )
    _validate_schema(raw)
    assert DeviceProfile.from_mapping(raw).service_session_claims.value is not None

    numeric: Any = _profile()
    numeric["service_session_claims"]["value"]["identity-read-evidence"]["subfunction"]["value"] = (
        0.0
    )
    _validate_schema(numeric)
    parsed = DeviceProfile.from_mapping(numeric)
    assert parsed.service_session_claims.value is not None
    assert parsed.service_session_claims.value[0].subfunction.value == 0

    for field, value in (
        ("subfunction", 128),
        ("subfunction", "absent"),
        ("service", 256),
        ("session", 128),
    ):
        bounded: Any = _profile()
        bounded["service_session_claims"]["value"]["identity-read-evidence"][field]["value"] = value
        _assert_schema_and_runtime_reject(bounded)


def test_numeric_bounds_and_integral_json_float_parity() -> None:
    raw: Any = _profile()
    raw["endpoints"]["value"]["engine"]["request_can_id"]["value"] = float(0x7E0)
    raw["memory_metadata"]["value"]["flash"]["length"]["value"] = 1024.0
    _validate_schema(raw)
    parsed = DeviceProfile.from_mapping(raw)
    assert parsed.endpoints.value is not None
    assert isinstance(parsed.endpoints.value[0].request_can_id.value, int)
    assert parsed.endpoints.value[0].request_can_id.value == 0x7E0
    assert parsed.to_dict()["endpoints"] == raw["endpoints"]

    for collection, member, field, value in (
        ("endpoints", "engine", "request_can_id", 0x20000000),
        ("memory_metadata", "flash", "length", 0),
    ):
        bounded: Any = _profile()
        bounded[collection]["value"][member][field]["value"] = value
        _assert_schema_and_runtime_reject(bounded)


def test_service_claims_are_non_authorizing_and_authorization_shape_is_closed() -> None:
    invalid_effect: Any = _profile()
    invalid_effect["service_session_claims"]["value"]["identity-read-evidence"][
        "authorization_effect"
    ] = "allow"
    _assert_schema_and_runtime_reject(invalid_effect)

    for field in (
        "authorization",
        "allow",
        "deny",
        "rules",
        "mode",
        "budgets",
        "retries",
        "timeout",
        "security_algorithm",
        "request_bytes",
        "operation",
    ):
        raw: Any = _profile()
        raw[field] = {"synthetic": True}
        _assert_schema_and_runtime_reject(raw)


def test_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"0verse.device-profile/v1","profile_id":"first","profile_id":"second"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key: profile_id"):
        load_device_profile(duplicate)


def test_public_api_reimports_without_optional_or_hardware_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden = {"can", "canlib", "isotp", "jtag", "qiling", "serial", "socketcan", "swd", "uds"}
    original_import = builtins.__import__

    def guarded_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name.split(".", 1)[0] in forbidden:
            raise AssertionError(f"profile contract imported forbidden dependency: {name}")
        return original_import(name, globals, locals, fromlist, level)

    with monkeypatch.context() as context:
        context.setattr(builtins, "__import__", guarded_import)
        reloaded = importlib.reload(device_profile)

    assert reloaded.load_device_profile(SKELETON).to_dict() == json.loads(SKELETON.read_text())
    for name in ("authorize", "request", "send", "open_transport", "configure_interface"):
        assert not hasattr(reloaded.DeviceProfile, name)
