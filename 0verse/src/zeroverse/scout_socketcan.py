"""Optional, receive-only SocketCAN capture for Firmware Scout evidence."""

from __future__ import annotations

import importlib
import math
import time
from decimal import Decimal, InvalidOperation
from typing import Protocol, cast

from .scout_evidence import ScoutEvent, ScoutEvidenceSession

_MAX_DETAIL_LENGTH = 4096
_MAX_CLASSICAL_CAN_DATA_BYTES = 8
_MAX_MALFORMED_BYTES = 4096


class _CanMessage(Protocol):
    timestamp: float | None
    arbitration_id: int
    data: bytes | bytearray
    dlc: int
    is_extended_id: bool
    is_remote_frame: bool
    is_error_frame: bool
    is_fd: bool


class _RawCanMessage(Protocol):
    data: object


def _byte_length(data: bytes | bytearray | memoryview) -> int:
    return data.nbytes if isinstance(data, memoryview) else len(data)


class _CanReceiver(Protocol):
    def recv(self, timeout: float | None = None) -> _CanMessage | None: ...

    def shutdown(self) -> None: ...


class _CanModule(Protocol):
    CanError: type[Exception]

    def Bus(
        self,
        *,
        interface: str,
        channel: str,
        receive_own_messages: bool,
    ) -> _CanReceiver: ...


class _SocketCanOpenError(Exception):
    """Expected failure while opening the optional SocketCAN backend."""


def _load_can() -> _CanModule:
    try:
        return cast(_CanModule, importlib.import_module("can"))
    except ModuleNotFoundError as exc:
        if exc.name == "can":
            raise RuntimeError(
                "SocketCAN capture requires the optional Scout dependency; install 0verse[scout]"
            ) from exc
        raise


def _open_socketcan(interface: str) -> tuple[_CanReceiver, type[Exception]]:
    can = _load_can()
    try:
        receiver = can.Bus(
            interface="socketcan",
            channel=interface,
            receive_own_messages=False,
        )
    except (OSError, can.CanError) as exc:
        raise _SocketCanOpenError from exc
    return receiver, can.CanError


def _timestamp_ns(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("SocketCAN frame timestamp is missing or not numeric")
    if not math.isfinite(value) or value < 0:
        raise ValueError("SocketCAN frame timestamp must be finite and non-negative")
    try:
        nanoseconds = Decimal(str(value)) * Decimal(1_000_000_000)
    except InvalidOperation as exc:
        raise ValueError("SocketCAN frame timestamp is not representable in nanoseconds") from exc
    if nanoseconds != nanoseconds.to_integral_value():
        raise ValueError("SocketCAN frame timestamp is not an exact nanosecond value")
    return int(nanoseconds)


def _detail(context: str, exc: BaseException | None = None) -> str:
    if exc is None:
        suffix = ""
    else:
        exception_text = str(exc)[:_MAX_DETAIL_LENGTH].replace("\x00", r"\0")
        suffix = f": {type(exc).__name__}: {exception_text}"
    return f"SocketCAN {context}{suffix}"[:_MAX_DETAIL_LENGTH]


def _timestamp_floor(session: ScoutEvidenceSession) -> int:
    return 0 if session.last_timestamp_ns is None else session.last_timestamp_ns


def _record_error(
    session: ScoutEvidenceSession,
    *,
    detail: str,
    timestamp_ns: int | None = None,
) -> ScoutEvent:
    timestamp = time.time_ns() if timestamp_ns is None else timestamp_ns
    return session.record_capture_error(
        timestamp_ns=max(timestamp, _timestamp_floor(session)),
        detail=detail,
    )


def _record_rejected_frame(
    session: ScoutEvidenceSession,
    message: object,
    *,
    timestamp_ns: int,
    detail: str,
) -> ScoutEvent:
    try:
        raw_data = cast(_RawCanMessage, message).data
        if not isinstance(raw_data, (bytes, bytearray, memoryview)):
            raise ValueError
        raw_length = _byte_length(raw_data)
        if not raw_length or raw_length > _MAX_MALFORMED_BYTES:
            raise ValueError
        raw = bytes(raw_data)
    except (AttributeError, TypeError, ValueError):
        return _record_error(session, timestamp_ns=timestamp_ns, detail=detail)
    return session.record_malformed_frame(
        timestamp_ns=timestamp_ns,
        data=raw,
        detail=detail,
    )


def _classical_frame_fields(message: _CanMessage) -> tuple[bytes, bool, bool, bool, int]:
    flags = (message.is_extended_id, message.is_remote_frame, message.is_error_frame)
    if any(type(flag) is not bool for flag in flags):
        raise ValueError("SocketCAN classical CAN flags must be bool")
    declared_length = message.dlc
    if isinstance(declared_length, bool) or not isinstance(declared_length, int):
        raise ValueError("SocketCAN classical CAN DLC must be an integer")
    if not 0 <= declared_length <= _MAX_CLASSICAL_CAN_DATA_BYTES:
        raise ValueError("SocketCAN classical CAN DLC must be between 0 and 8")
    if not isinstance(message.data, (bytes, bytearray, memoryview)):
        raise ValueError("SocketCAN classical CAN payload must be byte-like")
    if _byte_length(message.data) > _MAX_CLASSICAL_CAN_DATA_BYTES:
        raise ValueError("SocketCAN classical CAN payload exceeds 8 bytes")
    payload = bytes(message.data)
    extended_id, remote_frame, error_frame = flags
    if remote_frame and payload:
        raise ValueError("SocketCAN remote CAN frame cannot carry captured data")
    return payload, extended_id, remote_frame, error_frame, declared_length


def _capture_from_receiver(
    session: ScoutEvidenceSession,
    receiver: _CanReceiver,
    *,
    can_error: type[Exception],
    max_events: int,
    receive_timeout_s: float,
) -> tuple[ScoutEvent, ...]:
    events: list[ScoutEvent] = []
    while len(events) < max_events:
        try:
            message = receiver.recv(receive_timeout_s)
        except (OSError, can_error) as exc:
            events.append(_record_error(session, detail=_detail("receive failed", exc)))
            break
        if message is None:
            events.append(
                session.record_timeout(
                    timestamp_ns=max(time.time_ns(), _timestamp_floor(session)),
                    detail=_detail("receive timeout"),
                )
            )
            break

        timestamp_ns: int | None = None
        try:
            timestamp_ns = _timestamp_ns(message.timestamp)
            if timestamp_ns < _timestamp_floor(session):
                raise ValueError("timestamp precedes session evidence")
        except (AttributeError, TypeError, ValueError) as exc:
            events.append(
                _record_error(
                    session,
                    timestamp_ns=timestamp_ns,
                    detail=_detail("frame rejected", exc),
                )
            )
            break
        assert timestamp_ns is not None

        try:
            if type(message.is_fd) is not bool:
                raise ValueError("CAN-FD flag must be bool")
            if message.is_fd:
                raise ValueError("CAN-FD frame rejected by Scout v1 evidence format")
            payload, extended_id, remote_frame, error_frame, declared_length = (
                _classical_frame_fields(message)
            )
            events.append(
                session.record_frame(
                    timestamp_ns=timestamp_ns,
                    arbitration_id=message.arbitration_id,
                    data=payload,
                    extended_id=extended_id,
                    remote_frame=remote_frame,
                    error_frame=error_frame,
                    declared_length=declared_length,
                )
            )
        except (AttributeError, TypeError, ValueError) as exc:
            events.append(
                _record_rejected_frame(
                    session,
                    message,
                    timestamp_ns=timestamp_ns,
                    detail=_detail("frame rejected", exc),
                )
            )
            break
    return tuple(events)


def _preflight(
    session: ScoutEvidenceSession,
    *,
    interface: object,
    max_events: object,
    receive_timeout_s: object,
) -> tuple[str, int, float]:
    if not isinstance(interface, str):
        raise ValueError("SocketCAN interface must be a string")
    if not interface:
        raise ValueError("SocketCAN interface must not be empty")
    if "\x00" in interface:
        raise ValueError("SocketCAN interface must not contain NUL")
    if any(character.isspace() for character in interface):
        raise ValueError("SocketCAN interface must not contain whitespace")
    if interface != session.metadata.interface:
        raise ValueError("SocketCAN interface must match Scout session metadata")
    if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events <= 0:
        raise ValueError("SocketCAN max_events must be a positive integer")
    if (
        isinstance(receive_timeout_s, bool)
        or not isinstance(receive_timeout_s, (int, float))
        or not math.isfinite(receive_timeout_s)
        or receive_timeout_s < 0
    ):
        raise ValueError("SocketCAN receive_timeout_s must be a finite non-negative number")
    return interface, max_events, float(receive_timeout_s)


def capture_socketcan(
    session: ScoutEvidenceSession,
    *,
    interface: str,
    max_events: int,
    receive_timeout_s: float,
) -> tuple[ScoutEvent, ...]:
    """Capture bounded, receive-only classical CAN evidence into ``session``.

    The receive loop records at most ``max_events`` observations. A handled
    shutdown failure may append one final ``capture-error`` reserve event.
    """
    checked_interface, checked_max_events, checked_timeout_s = _preflight(
        session,
        interface=interface,
        max_events=max_events,
        receive_timeout_s=receive_timeout_s,
    )
    try:
        receiver, can_error = _open_socketcan(checked_interface)
    except _SocketCanOpenError as exc:
        return (_record_error(session, detail=_detail("open failed", exc.__cause__)),)

    events: tuple[ScoutEvent, ...] = ()
    try:
        events = _capture_from_receiver(
            session,
            receiver,
            can_error=can_error,
            max_events=checked_max_events,
            receive_timeout_s=checked_timeout_s,
        )
    finally:
        try:
            receiver.shutdown()
        except (OSError, can_error) as exc:
            events = (*events, _record_error(session, detail=_detail("close failed", exc)))
    return events
