"""Inert, default-deny UDS authorization policy-core groundwork.

This is not #77 completion: guarded transport enforcement, plugin integration,
budgets, and disarm state do not exist yet.  The module never loads a device
profile, opens a transport, or sends a request.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, TypeAlias, TypeGuard

from zeroverse.acquisition import TRANSPORT_MODES, TransportMode
from zeroverse.device_profile import NO_SUBFUNCTION, Subfunction

__all__ = ["UdsDenialReason", "UdsRequest", "UdsSafetyDecision", "authorize_uds_request"]

UdsDenialReason: TypeAlias = Literal[
    "invalid-request",
    "offline-mode",
    "passive-mode",
    "active-write-unsupported",
    "unreviewed-active-read-policy",
]

_DENIAL_REASONS = frozenset(
    {
        "invalid-request",
        "offline-mode",
        "passive-mode",
        "active-write-unsupported",
        "unreviewed-active-read-policy",
    }
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


@dataclass(frozen=True)
class UdsRequest:
    """One declarative UDS request; constructing it has no operational effect."""

    profile_id: str
    mode: TransportMode
    service: int
    subfunction: Subfunction
    session: int

    def __post_init__(self) -> None:
        _validate_request_fields(
            self.profile_id,
            self.mode,
            self.service,
            self.subfunction,
            self.session,
        )


class UdsSafetyDecision(tuple[Literal[False], UdsDenialReason]):
    """A closed, tuple-backed denial result with immutable public fields."""

    __slots__ = ()

    def __new__(cls, permitted: Literal[False], reason: UdsDenialReason) -> UdsSafetyDecision:
        if permitted is not False:
            raise ValueError("UDS safety decisions must deny")
        if type(reason) is not str or reason not in _DENIAL_REASONS:
            raise ValueError("unsupported UDS denial reason")
        return tuple.__new__(cls, (False, reason))

    @property
    def permitted(self) -> Literal[False]:
        return self[0]

    @property
    def reason(self) -> UdsDenialReason:
        return self[1]


def _validate_request_fields(
    profile_id: object,
    mode: object,
    service: object,
    subfunction: object,
    session: object,
) -> None:
    if type(profile_id) is not str or _IDENTIFIER.fullmatch(profile_id) is None:
        raise ValueError("profile_id must be a stable identifier")
    if type(mode) is not str or mode not in TRANSPORT_MODES:
        raise ValueError("mode must be a supported transport mode")
    if type(service) is not int or not 0 <= service <= 0xFF:
        raise ValueError("service must be an 8-bit integer")
    if type(subfunction) is str:
        if subfunction != NO_SUBFUNCTION:
            raise ValueError("subfunction must be none or a 7-bit integer")
    elif type(subfunction) is not int or not 0 <= subfunction <= 0x7F:
        raise ValueError("subfunction must be none or a 7-bit integer")
    if type(session) is not int or not 0 <= session <= 0x7F:
        raise ValueError("session must be a 7-bit integer")


def _is_valid_request(candidate: object) -> TypeGuard[UdsRequest]:
    if type(candidate) is not UdsRequest:
        return False
    try:
        _validate_request_fields(
            candidate.profile_id,
            candidate.mode,
            candidate.service,
            candidate.subfunction,
            candidate.session,
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def authorize_uds_request(candidate: object) -> UdsSafetyDecision:
    """Deny ``candidate`` without transmitting, loading, or inspecting anything."""

    if not _is_valid_request(candidate):
        return UdsSafetyDecision(False, "invalid-request")
    if candidate.mode == "offline":
        return UdsSafetyDecision(False, "offline-mode")
    if candidate.mode == "passive":
        return UdsSafetyDecision(False, "passive-mode")
    if candidate.mode == "active-write":
        return UdsSafetyDecision(False, "active-write-unsupported")
    return UdsSafetyDecision(False, "unreviewed-active-read-policy")
