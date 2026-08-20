from __future__ import annotations

import inspect
import os
import sys
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import assert_never

import pytest

import zeroverse.scout_socketcan as socketcan
from zeroverse.acquisition import DeviceIdentity, RedactionRecord
from zeroverse.scout_evidence import (
    ScoutEvent,
    ScoutEvidenceSession,
    ScoutSessionMetadata,
    replay_scout_bundle,
)
from zeroverse.scout_socketcan import capture_socketcan

_SOCKETCAN_INTERFACE = os.environ.get("ZEROVERSE_SOCKETCAN_INTERFACE", "")
_SOCKETCAN_HARDWARE_TEST_ENABLED = (
    sys.platform == "linux"
    and bool(_SOCKETCAN_INTERFACE)
    and "\x00" not in _SOCKETCAN_INTERFACE
    and not any(character.isspace() for character in _SOCKETCAN_INTERFACE)
    and os.environ.get("ZEROVERSE_SOCKETCAN_HARDWARE_TEST") == "YES"
)


class _FakeCanError(Exception):
    pass


@dataclass(frozen=True)
class _FakeMessage:
    timestamp: float | None
    arbitration_id: int = 0x123
    data: object = b"\x01\x02"
    dlc: object = 2
    is_extended_id: object = False
    is_remote_frame: object = False
    is_error_frame: object = False
    is_fd: object = False


class _FakeBus:
    def __init__(
        self,
        observations: list[_FakeMessage | Exception | None],
        *,
        shutdown_error: Exception | None = None,
    ) -> None:
        self._observations = iter(observations)
        self._shutdown_error = shutdown_error
        self.recv_timeouts: list[float | None] = []
        self.send_calls = 0
        self.shutdown_calls = 0

    def recv(self, timeout: float | None = None) -> _FakeMessage | None:
        self.recv_timeouts.append(timeout)
        observation = next(self._observations)
        if isinstance(observation, Exception):
            raise observation
        return observation

    def send(self, message: object) -> None:
        del message
        self.send_calls += 1
        raise AssertionError("receive-only capture attempted to send")

    def shutdown(self) -> None:
        self.shutdown_calls += 1
        if self._shutdown_error is not None:
            raise self._shutdown_error


class _FakeCan:
    CanError = _FakeCanError

    def __init__(self, bus: _FakeBus | None = None, *, open_error: Exception | None = None) -> None:
        self.bus = bus
        self.open_error = open_error
        self.open_calls: list[dict[str, object]] = []

    def Bus(self, **kwargs: object) -> _FakeBus:
        self.open_calls.append(kwargs)
        if self.open_error is not None:
            raise self.open_error
        assert self.bus is not None
        return self.bus


class _Collector:
    def __init__(self) -> None:
        self.events: list[ScoutEvent] = []

    def observe(self, event: ScoutEvent) -> None:
        self.events.append(event)


def _metadata(interface: str = "can0") -> ScoutSessionMetadata:
    return ScoutSessionMetadata(
        acquisition_id="socketcan-001",
        device=DeviceIdentity(
            category="ecu",
            manufacturer=None,
            model=None,
            hardware_revision=None,
            identifiers=(),
        ),
        redaction=RedactionRecord(
            status="not-required",
            policy="0verse.default-export/v1",
            contains_sensitive_values=False,
            entries=(),
        ),
        interface=interface,
        source="fake SocketCAN receiver",
        collector="0verse-tests",
        authorization_basis="synthetic-fixture",
        started_at="2026-07-31T10:00:00Z",
        tool_name="0verse-firmware-scout",
        tool_version="0.0.1+test",
    )


def _session(tmp_path: Path, name: str, *, interface: str = "can0") -> ScoutEvidenceSession:
    return ScoutEvidenceSession(tmp_path / name, _metadata(interface))


def _install_fake_can(monkeypatch: pytest.MonkeyPatch, fake_can: _FakeCan) -> None:
    monkeypatch.setattr(socketcan.importlib, "import_module", lambda name: fake_can)


def test_capture_is_lazy_receive_only_and_preserves_classical_frames(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus = _FakeBus(
        [
            _FakeMessage(timestamp=1.25, arbitration_id=0x123, data=b"\x01\x02", dlc=2),
            _FakeMessage(
                timestamp=2.5,
                arbitration_id=0x1ABCDE,
                data=b"",
                dlc=4,
                is_extended_id=True,
                is_remote_frame=True,
            ),
            _FakeMessage(
                timestamp=3.75,
                arbitration_id=0x456,
                data=b"\x99",
                dlc=1,
                is_error_frame=True,
            ),
        ]
    )
    fake_can = _FakeCan(bus)
    _install_fake_can(monkeypatch, fake_can)
    session = _session(tmp_path, "capture")

    events = capture_socketcan(
        session,
        interface="can0",
        max_events=3,
        receive_timeout_s=0.25,
    )

    assert fake_can.open_calls == [
        {"interface": "socketcan", "channel": "can0", "receive_own_messages": False}
    ]
    assert bus.recv_timeouts == [0.25, 0.25, 0.25]
    assert bus.send_calls == 0
    assert bus.shutdown_calls == 1
    assert [event.timestamp_ns for event in events] == [1_250_000_000, 2_500_000_000, 3_750_000_000]
    assert [(event.arbitration_id, event.extended_id) for event in events] == [
        (0x123, False),
        (0x1ABCDE, True),
        (0x456, False),
    ]
    assert [
        (event.remote_frame, event.error_frame, event.declared_length, event.data)
        for event in events
    ] == [
        (False, False, 2, b"\x01\x02"),
        (True, False, 4, b""),
        (False, True, 1, b"\x99"),
    ]
    assert all(isinstance(event, ScoutEvent) for event in events)
    assert not hasattr(capture_socketcan, "send")
    assert "send" not in inspect.getsource(socketcan._CanReceiver)
    assert set(inspect.signature(capture_socketcan).parameters) == {
        "session",
        "interface",
        "max_events",
        "receive_timeout_s",
    }

    root = session.root
    bundle = session.seal(completed_at="2026-07-31T10:01:00Z")
    assert bundle.manifest.transport.interface == "can0"
    assert bundle.manifest.transport.mode == "passive"
    assert bundle.manifest.transport.transmitted is False
    collector = _Collector()
    replay_scout_bundle(root, collector)
    assert collector.events == list(events)


def test_capture_imports_optional_dependency_only_at_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    imports: list[str] = []

    def missing_can(name: str) -> object:
        imports.append(name)
        raise ModuleNotFoundError("No module named 'can'", name=name)

    monkeypatch.setattr(socketcan.importlib, "import_module", missing_can)
    session = _session(tmp_path, "missing")

    with pytest.raises(RuntimeError, match=r"install 0verse\[scout\]"):
        capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)
    assert imports == ["can"]
    assert session.event_count == 0


@pytest.mark.parametrize(
    ("interface", "max_events", "receive_timeout_s"),
    [
        (None, 1, 0),
        ("", 1, 0),
        ("can 0", 1, 0),
        ("can\x000", 1, 0),
        ("can1", 1, 0),
        ("can0", True, 0),
        ("can0", 0, 0),
        ("can0", 1, True),
        ("can0", 1, float("nan")),
        ("can0", 1, -0.1),
    ],
)
def test_capture_preflight_rejects_before_optional_import_or_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interface: object,
    max_events: object,
    receive_timeout_s: object,
) -> None:
    imports: list[str] = []

    def unexpected_import(name: str) -> object:
        imports.append(name)
        raise AssertionError("preflight imported optional dependency")

    monkeypatch.setattr(socketcan.importlib, "import_module", unexpected_import)
    session = _session(tmp_path, f"invalid-{len(str(interface))}-{max_events}")

    with pytest.raises(ValueError):
        capture_socketcan(
            session,
            interface=interface,  # type: ignore[arg-type]
            max_events=max_events,  # type: ignore[arg-type]
            receive_timeout_s=receive_timeout_s,  # type: ignore[arg-type]
        )
    assert imports == []
    assert session.event_count == 0


@pytest.mark.parametrize(
    ("name", "observation", "expected"),
    [
        ("timeout", None, "timeout"),
        ("receive-error", _FakeCanError("receiver offline"), "capture-error"),
        ("invalid-timestamp", _FakeMessage(timestamp=None), "capture-error"),
        ("nonexact-timestamp", _FakeMessage(timestamp=1.0000000001), "capture-error"),
        ("can-fd", _FakeMessage(timestamp=1.0, is_fd=True), "malformed-frame"),
    ],
)
def test_capture_retains_bounded_terminal_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    observation: _FakeMessage | Exception | None,
    expected: str,
) -> None:
    bus = _FakeBus([observation])
    _install_fake_can(monkeypatch, _FakeCan(bus))
    session = _session(tmp_path, name)

    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert [event.kind for event in events] == [expected]
    assert bus.send_calls == 0
    assert bus.shutdown_calls == 1
    if name == "can-fd":
        assert events[0].detail is not None and "CAN-FD" in events[0].detail
        assert events[0].data == b"\x01\x02"
        assert events[0].capture_index == 0
        assert events[0].has_capture_record
    if name == "receive-error":
        assert events[0].detail is not None and "receiver offline" in events[0].detail
    if name in {"invalid-timestamp", "nonexact-timestamp"}:
        assert events[0].capture_index is None
        assert events[0].data is None
    if name == "nonexact-timestamp":
        assert events[0].detail is not None and "exact nanosecond" in events[0].detail


def test_capture_sanitizes_nul_in_handled_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus = _FakeBus([_FakeCanError("receiver\x00" + "x" * 5000)])
    _install_fake_can(monkeypatch, _FakeCan(bus))
    session = _session(tmp_path, "nul-error")

    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert [event.kind for event in events] == ["capture-error"]
    assert events[0].detail is not None
    assert "\x00" not in events[0].detail
    assert r"\0" in events[0].detail
    assert len(events[0].detail) <= 4096
    assert session.event_count == 1


@pytest.mark.parametrize(
    ("name", "message", "detail"),
    [
        (
            "oversized-payload",
            _FakeMessage(timestamp=1.0, data=b"\x00" * 9, dlc=8),
            "payload exceeds 8 bytes",
        ),
        ("oversized-dlc", _FakeMessage(timestamp=1.0, data=b"\x00", dlc=9), "DLC must be between"),
        ("non-bool-flag", _FakeMessage(timestamp=1.0, is_error_frame=1), "flags must be bool"),
        ("non-bool-fd-flag", _FakeMessage(timestamp=1.0, is_fd=0), "CAN-FD flag must be bool"),
        ("remote-data", _FakeMessage(timestamp=1.0, is_remote_frame=True), "cannot carry"),
    ],
)
def test_capture_preserves_rejected_classical_raw_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    message: _FakeMessage,
    detail: str,
) -> None:
    bus = _FakeBus([message])
    _install_fake_can(monkeypatch, _FakeCan(bus))
    session = _session(tmp_path, name)

    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert [event.kind for event in events] == ["malformed-frame"]
    assert events[0].has_capture_record
    assert events[0].capture_index == 0
    assert events[0].data == bytes(message.data)
    assert events[0].arbitration_id is None
    assert events[0].extended_id is None
    assert events[0].remote_frame is None
    assert events[0].error_frame is None
    assert events[0].declared_length is None
    assert events[0].detail is not None and detail in events[0].detail
    assert session.event_count == 1
    assert bus.send_calls == 0


@pytest.mark.parametrize(
    "raw_data",
    [bytearray(b"\x00" * 4097), memoryview(bytearray(b"\x00" * 4097))],
    ids=["bytearray", "memoryview"],
)
def test_capture_rejects_oversized_mutable_raw_data_without_capture_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw_data: object
) -> None:
    bus = _FakeBus([_FakeMessage(timestamp=1.0, data=raw_data, is_fd=True)])
    _install_fake_can(monkeypatch, _FakeCan(bus))
    session = _session(tmp_path, "oversized-raw")

    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert [event.kind for event in events] == ["capture-error"]
    assert len(events) == session.event_count == 1
    assert events[0].capture_index is None
    assert events[0].data is None
    assert not events[0].has_capture_record


def test_capture_seals_and_replays_retained_raw_fd_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus = _FakeBus([_FakeMessage(timestamp=1.0, data=b"\xde\xad", is_fd=True)])
    _install_fake_can(monkeypatch, _FakeCan(bus))
    session = _session(tmp_path, "replay-fd")

    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert events[0].kind == "malformed-frame"
    assert events[0].data == b"\xde\xad"
    assert events[0].has_capture_record
    root = session.root
    session.seal(completed_at="2026-07-31T10:01:00Z")
    collector = _Collector()
    replay_scout_bundle(root, collector)
    assert collector.events == list(events)


@pytest.mark.parametrize(
    ("terminal_observation", "expected_kind"),
    [(None, "timeout"), (_FakeCanError("receiver offline"), "capture-error")],
)
def test_capture_uses_session_wide_timestamp_floor_for_terminal_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_observation: Exception | None,
    expected_kind: str,
) -> None:
    session = _session(tmp_path, f"floor-{expected_kind}")
    _install_fake_can(monkeypatch, _FakeCan(_FakeBus([_FakeMessage(timestamp=10.0)])))
    capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)
    assert session.last_timestamp_ns == 10_000_000_000

    monkeypatch.setattr(time, "time_ns", lambda: 1)
    _install_fake_can(monkeypatch, _FakeCan(_FakeBus([terminal_observation])))
    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert [event.kind for event in events] == [expected_kind]
    assert events[0].timestamp_ns == 10_000_000_000
    assert session.last_timestamp_ns == 10_000_000_000


def test_capture_rejects_frame_older_than_session_timestamp_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path, "floor-frame")
    _install_fake_can(monkeypatch, _FakeCan(_FakeBus([_FakeMessage(timestamp=10.0)])))
    capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    stale_bus = _FakeBus([_FakeMessage(timestamp=1.0)])
    _install_fake_can(monkeypatch, _FakeCan(stale_bus))
    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert [event.kind for event in events] == ["capture-error"]
    assert events[0].timestamp_ns == 10_000_000_000
    assert events[0].detail is not None and "precedes session evidence" in events[0].detail
    assert session.event_count == 2


def test_capture_retains_open_error_as_singleton_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opening = _FakeCan(open_error=_FakeCanError("permission denied"))
    _install_fake_can(monkeypatch, opening)
    session = _session(tmp_path, "open-error")

    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert [event.kind for event in events] == ["capture-error"]
    assert events[0].detail is not None and "permission denied" in events[0].detail
    assert session.event_count == 1
    assert opening.open_calls == [
        {"interface": "socketcan", "channel": "can0", "receive_own_messages": False}
    ]


def test_capture_reserves_only_final_shutdown_error_beyond_receive_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus = _FakeBus(
        [_FakeMessage(timestamp=1.0), _FakeMessage(timestamp=2.0)],
        shutdown_error=_FakeCanError("shutdown failed"),
    )
    _install_fake_can(monkeypatch, _FakeCan(bus))
    session = _session(tmp_path, "shutdown-reserve")

    events = capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)

    assert [event.kind for event in events] == ["frame", "capture-error"]
    assert len(events) == session.event_count == 2
    assert [event.sequence for event in events] == [0, 1]
    assert [event.timestamp_ns for event in events] == sorted(
        event.timestamp_ns for event in events
    )
    assert len(bus.recv_timeouts) == 1
    assert bus.shutdown_calls == 1
    assert bus.send_calls == 0


def test_capture_propagates_unexpected_receiver_exception_after_shutdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bus = _FakeBus([RuntimeError("unexpected backend failure")])
    _install_fake_can(monkeypatch, _FakeCan(bus))
    session = _session(tmp_path, "unexpected")

    with pytest.raises(RuntimeError, match="unexpected backend failure"):
        capture_socketcan(session, interface="can0", max_events=1, receive_timeout_s=0)
    assert bus.shutdown_calls == 1
    assert session.event_count == 0


@pytest.mark.skipif(
    not _SOCKETCAN_HARDWARE_TEST_ENABLED,
    reason=(
        "requires Linux plus an authorized nonempty, whitespace-free "
        "ZEROVERSE_SOCKETCAN_INTERFACE and ZEROVERSE_SOCKETCAN_HARDWARE_TEST=YES"
    ),
)
def test_capture_real_authorized_socketcan(tmp_path: Path) -> None:
    pytest.importorskip("can", reason="requires optional 0verse[scout] dependency")
    interface = _SOCKETCAN_INTERFACE
    session = ScoutEvidenceSession(
        tmp_path / "hardware-capture",
        replace(
            _metadata(interface),
            acquisition_id="socketcan-hardware-acceptance",
            source="authorized receive-only SocketCAN acceptance test",
            collector="0verse-socketcan-hardware-test",
            authorization_basis="written-authorization",
        ),
    )

    events = capture_socketcan(
        session,
        interface=interface,
        max_events=1,
        receive_timeout_s=0.25,
    )

    root = session.root
    bundle = session.seal(completed_at=datetime.now(UTC).isoformat())
    collector = _Collector()
    replay_scout_bundle(root, collector)

    assert bundle.manifest.transport.interface == interface
    assert bundle.manifest.transport.mode == "passive"
    assert bundle.manifest.transport.transmitted is False
    assert len(events) == 1
    event = events[0]
    if event.kind not in {"frame", "timeout"}:
        assert_never(event.kind)
    assert collector.events == list(events)
