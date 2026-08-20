from __future__ import annotations

import builtins
import importlib
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from typing import Literal, cast

import pytest

import zeroverse.device_profile as device_profile
import zeroverse.uds_safety as uds_safety
from zeroverse.acquisition import TransportMode
from zeroverse.device_profile import NO_SUBFUNCTION, Subfunction
from zeroverse.uds_safety import (
    UdsDenialReason,
    UdsRequest,
    UdsSafetyDecision,
    authorize_uds_request,
)

MODE_REASONS: tuple[tuple[TransportMode, UdsDenialReason], ...] = (
    ("offline", "offline-mode"),
    ("passive", "passive-mode"),
    ("active-read", "unreviewed-active-read-policy"),
    ("active-write", "active-write-unsupported"),
)
DEFAULT_SUBFUNCTION: Subfunction = cast(Subfunction, NO_SUBFUNCTION)


def _request(
    *,
    profile_id: str = "synthetic-profile",
    mode: TransportMode = "active-read",
    service: int = 0x22,
    subfunction: Subfunction = DEFAULT_SUBFUNCTION,
    session: int = 1,
) -> UdsRequest:
    return UdsRequest(profile_id, mode, service, subfunction, session)


def _request_with(field: str, value: object) -> UdsRequest:
    return UdsRequest(
        profile_id=cast(str, value if field == "profile_id" else "synthetic-profile"),
        mode=cast(TransportMode, value if field == "mode" else "active-read"),
        service=cast(int, value if field == "service" else 0x22),
        subfunction=cast(Subfunction, value if field == "subfunction" else NO_SUBFUNCTION),
        session=cast(int, value if field == "session" else 1),
    )


@pytest.mark.parametrize(("mode", "reason"), MODE_REASONS)
def test_each_transport_mode_is_denied_with_its_closed_reason(
    mode: TransportMode, reason: UdsDenialReason
) -> None:
    decision = authorize_uds_request(_request(mode=mode))

    assert decision.permitted is False
    assert decision.reason == reason


@pytest.mark.parametrize("mode", tuple(mode for mode, _reason in MODE_REASONS))
@pytest.mark.parametrize("subfunction", (NO_SUBFUNCTION, 0, 127))
@pytest.mark.parametrize("session", (0, 127))
def test_every_constructed_request_is_denied(
    mode: TransportMode, subfunction: Subfunction, session: int
) -> None:
    decision = authorize_uds_request(
        _request(mode=mode, service=0, subfunction=subfunction, session=session)
    )

    assert decision.permitted is False


def test_every_service_byte_is_denied_in_active_read_mode() -> None:
    for service in range(256):
        decision = authorize_uds_request(_request(service=service))

        assert decision.permitted is False
        assert decision.reason == "unreviewed-active-read-policy"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("profile_id", ""),
        ("profile_id", "profile id"),
        ("profile_id", "profile\x00id"),
        ("profile_id", 7),
        ("mode", "active"),
        ("mode", True),
        ("service", True),
        ("service", -1),
        ("service", 256),
        ("service", 1.0),
        ("service", "1"),
        ("subfunction", "absent"),
        ("subfunction", None),
        ("subfunction", True),
        ("subfunction", -1),
        ("subfunction", 128),
        ("subfunction", 1.0),
        ("session", True),
        ("session", -1),
        ("session", 128),
        ("session", 1.0),
    ),
)
def test_request_construction_rejects_malformed_values(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        _request_with(field, value)


def test_request_does_not_coerce_or_default_inputs() -> None:
    constructor = cast(Callable[[], object], UdsRequest)
    with pytest.raises(TypeError):
        constructor()

    for candidate in (
        None,
        {},
        {
            "profile_id": "synthetic-profile",
            "mode": "active-read",
            "service": 0x22,
            "subfunction": NO_SUBFUNCTION,
            "session": 1,
        },
    ):
        decision = authorize_uds_request(candidate)
        assert decision.permitted is False
        assert decision.reason == "invalid-request"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("profile_id", "not an identifier"),
        ("mode", "active"),
        ("service", True),
        ("service", 256),
        ("subfunction", "absent"),
        ("subfunction", 128),
        ("session", True),
        ("session", 128),
    ),
)
def test_authorizer_revalidates_forcibly_corrupted_requests(field: str, value: object) -> None:
    candidate = _request()
    object.__setattr__(candidate, field, value)

    decision = authorize_uds_request(candidate)

    assert decision.permitted is False
    assert decision.reason == "invalid-request"


def test_authorizer_fails_closed_when_a_frozen_field_is_removed() -> None:
    candidate = _request()
    object.__delattr__(candidate, "service")

    decision = authorize_uds_request(candidate)

    assert decision.permitted is False
    assert decision.reason == "invalid-request"


def test_request_is_frozen() -> None:
    request = _request()

    with pytest.raises(FrozenInstanceError):
        request.__setattr__("service", 0x10)


def test_decision_is_immutable_and_rejects_invalid_construction() -> None:
    decision = authorize_uds_request(_request())

    with pytest.raises(AttributeError):
        object.__setattr__(decision, "permitted", True)
    with pytest.raises(AttributeError):
        object.__setattr__(decision, "reason", "unsupported-reason")

    assert decision.permitted is False
    assert decision.reason == "unreviewed-active-read-policy"

    with pytest.raises(ValueError):
        UdsSafetyDecision(cast(Literal[False], True), "offline-mode")
    with pytest.raises(ValueError):
        UdsSafetyDecision(False, cast(UdsDenialReason, "unsupported-reason"))


def test_profile_identifier_remains_opaque_without_device_profile_loading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_profile_load(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("UDS authorization must not load a DeviceProfile")

    monkeypatch.setattr(device_profile.DeviceProfile, "from_mapping", fail_profile_load)

    decision = authorize_uds_request(_request(profile_id="opaque-profile:1"))

    assert decision.permitted is False
    assert decision.reason == "unreviewed-active-read-policy"


def test_public_api_reimports_without_hardware_or_optional_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden = {
        "can",
        "canlib",
        "isotp",
        "jtag",
        "qiling",
        "serial",
        "socket",
        "socketcan",
        "swd",
        "uds",
    }
    original_import = builtins.__import__

    def guarded_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name.split(".", 1)[0] in forbidden:
            raise AssertionError(f"UDS safety policy imported forbidden dependency: {name}")
        return original_import(name, globals, locals, fromlist, level)

    with monkeypatch.context() as context:
        context.setattr(builtins, "__import__", guarded_import)
        reloaded = importlib.reload(uds_safety)

    assert set(reloaded.__all__) == {
        "UdsRequest",
        "UdsDenialReason",
        "UdsSafetyDecision",
        "authorize_uds_request",
    }
    assert "DeviceProfile" not in vars(reloaded)
    for name in (
        "allow",
        "send",
        "transmit",
        "write",
        "open_transport",
        "configure_interface",
        "dispatch",
        "plugin",
        "encode",
        "socket",
    ):
        assert not hasattr(reloaded, name)
