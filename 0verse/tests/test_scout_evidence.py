from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from zeroverse.acquisition import (
    DeviceIdentifier,
    DeviceIdentity,
    RedactionRecord,
    TransportParameter,
)
from zeroverse.acquisition_bundle import AcquisitionBundleValidationError
from zeroverse.scout_evidence import (
    SCOUT_CAPTURE_ARTIFACT_ID,
    SCOUT_CAPTURE_MEDIA_TYPE,
    SCOUT_CAPTURE_PATH,
    SCOUT_EVENT_VERSION,
    SCOUT_SESSION_LOG_ARTIFACT_ID,
    SCOUT_SESSION_LOG_PATH,
    SCOUT_TRANSACTION_ARTIFACT_ID,
    SCOUT_TRANSACTION_PATH,
    ScoutEvent,
    ScoutEvidenceSession,
    ScoutReplayError,
    ScoutReplayLimits,
    ScoutSessionMetadata,
    VirtualCanEcu,
    VirtualCanObservation,
    replay_scout_bundle,
)

ROOT = Path(__file__).resolve().parents[1]


class _Collector:
    def __init__(self) -> None:
        self.events: list[ScoutEvent] = []

    def observe(self, event: ScoutEvent) -> None:
        self.events.append(event)


class _DiscoveryProbe:
    """Small stand-in for the issue #75 consumer behind the observation seam."""

    def __init__(self) -> None:
        self.responders: set[tuple[int, bool]] = set()
        self.positive_services: list[tuple[int, int]] = []
        self.interruptions: list[str] = []

    def observe(self, event: ScoutEvent) -> None:
        if event.kind != "frame":
            self.interruptions.append(event.kind)
            return
        assert event.arbitration_id is not None
        assert event.extended_id is not None
        assert event.data is not None
        self.responders.add((event.arbitration_id, event.extended_id))
        if len(event.data) >= 2 and event.data[0] >> 4 == 0 and event.data[1] >= 0x40:
            self.positive_services.append((event.arbitration_id, event.data[1]))


def _metadata(*, acquisition_id: str = "virtual-scout-001") -> ScoutSessionMetadata:
    return ScoutSessionMetadata(
        acquisition_id=acquisition_id,
        device=DeviceIdentity(
            category="ecu",
            manufacturer="Synthetic Controls",
            model="Virtual ECU",
            hardware_revision="v1",
            identifiers=(
                DeviceIdentifier(
                    kind="fixture-id",
                    value="SYNTHETIC-001",
                    alias=None,
                    sensitivity="technical",
                ),
            ),
        ),
        redaction=RedactionRecord(
            status="not-required",
            policy="0verse.default-export/v1",
            contains_sensitive_values=False,
            entries=(),
        ),
        interface="virtual-can0",
        source="deterministic in-memory virtual ECU",
        collector="0verse-tests",
        authorization_basis="synthetic-fixture",
        started_at="2026-07-18T10:00:00Z",
        tool_name="0verse-firmware-scout",
        tool_version="0.0.1+test",
        parameters=(TransportParameter(name="bitrate", value="500000", basis="configured"),),
        notes="No hardware or live transport was used.",
    )


def _sealed_fixture(
    tmp_path: Path, *, name: str = "session"
) -> tuple[Path, tuple[ScoutEvent, ...], VirtualCanEcu]:
    root = tmp_path / name
    fixture = VirtualCanEcu.standard_fixture()
    session = ScoutEvidenceSession(root, _metadata(acquisition_id=f"{name}-001"))
    live_events = fixture.capture(session)
    session.seal(completed_at="2026-07-18T10:01:00Z")
    return root, live_events, fixture


def _rewrite_artifact(
    root: Path, artifact_id: str, transform: object
) -> None:
    manifest_path = root / "acquisition.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    artifact = next(item for item in manifest["artifacts"] if item["artifact_id"] == artifact_id)
    artifact_path = root / artifact["path"]
    before = artifact_path.read_bytes()
    if not callable(transform):
        raise TypeError("artifact transform must be callable")
    after = transform(before)
    if not isinstance(after, bytes):
        raise TypeError("artifact transform must return bytes")
    artifact_path.chmod(0o600)
    artifact_path.write_bytes(after)
    artifact_path.chmod(0o444)

    digest = hashlib.sha256(after).hexdigest()
    artifact["size"] = len(after)
    artifact["sha256"] = digest
    artifact["observed_size"] = len(after)
    artifact["observed_sha256"] = digest
    manifest_path.chmod(0o600)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    manifest_path.chmod(0o444)


def test_virtual_ecu_runs_complete_passive_capture_and_replay_workflow(
    tmp_path: Path,
) -> None:
    root, live_events, fixture = _sealed_fixture(tmp_path)

    manifest = json.loads((root / "acquisition.json").read_text(encoding="ascii"))
    manifest_schema = json.loads(
        (ROOT / "schemas" / "acquisition-manifest-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(
        manifest_schema, format_checker=FormatChecker()
    ).validate(manifest)
    assert manifest["transport"] == {
        "capture_artifact_ids": [SCOUT_CAPTURE_ARTIFACT_ID],
        "interface": "virtual-can0",
        "kind": "can",
        "mode": "passive",
        "parameters": [{"basis": "configured", "name": "bitrate", "value": "500000"}],
        "protocol": "raw-can",
        "transmitted": False,
    }
    assert [item["artifact_id"] for item in manifest["artifacts"]] == [
        SCOUT_CAPTURE_ARTIFACT_ID,
        SCOUT_TRANSACTION_ARTIFACT_ID,
        SCOUT_SESSION_LOG_ARTIFACT_ID,
    ]
    assert all(item["integrity"] == "verified" for item in manifest["artifacts"])
    assert manifest["provenance"]["tool_version"] == "0.0.1+test"

    capture = (root / SCOUT_CAPTURE_PATH).read_bytes()
    assert capture.startswith(b"0VERSE-SCOUT-CAPTURE\x00v1\n")
    assert manifest["artifacts"][0]["media_type"] == SCOUT_CAPTURE_MEDIA_TYPE
    assert hashlib.sha256(capture).hexdigest() == manifest["artifacts"][0]["sha256"]

    event_schema = json.loads(
        (ROOT / "schemas" / "scout-event-v1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(event_schema)
    transaction_lines = (root / SCOUT_TRANSACTION_PATH).read_bytes().splitlines(keepends=True)
    assert transaction_lines == [event.canonical_bytes() for event in live_events]
    for event in live_events:
        validator.validate(event.to_dict())

    live_probe = _DiscoveryProbe()
    for event in live_events:
        live_probe.observe(event)
    replay_probe = _DiscoveryProbe()
    result = replay_scout_bundle(root, replay_probe)

    assert replay_probe.responders == live_probe.responders == {
        (0x700, False),
        (0x7E8, False),
    }
    assert replay_probe.positive_services == live_probe.positive_services == [
        (0x7E8, 0x62),
        (0x700, 0x50),
    ]
    assert replay_probe.interruptions == ["timeout", "malformed-frame", "reset"]
    assert result.event_count == 5
    assert result.frame_count == 2
    assert result.timeout_count == 1
    assert result.malformed_frame_count == 1
    assert result.reset_count == 1
    assert result.capture_error_count == 0
    assert result.transmitted_frames == fixture.transmitted_frames == 0


def test_session_log_binds_tool_formats_counts_and_transport(tmp_path: Path) -> None:
    root, _, _ = _sealed_fixture(tmp_path)
    session_log_path = root / SCOUT_SESSION_LOG_PATH
    raw = session_log_path.read_bytes()
    session_log = json.loads(raw)

    assert raw == (
        json.dumps(session_log, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    assert session_log["schema_version"] == "0verse.scout-session-log/v1"
    assert session_log["formats"] == {
        "capture": "0verse.scout-capture/v1",
        "event": SCOUT_EVENT_VERSION,
    }
    assert session_log["tool"] == {
        "name": "0verse-firmware-scout",
        "version": "0.0.1+test",
    }
    assert session_log["event_counts"] == {
        "capture-error": 0,
        "frame": 2,
        "malformed-frame": 1,
        "reset": 1,
        "timeout": 1,
        "total": 5,
    }
    assert session_log["transport"]["transmitted"] is False


def test_event_contract_is_closed_and_runtime_matches_published_schema() -> None:
    event = VirtualCanEcu.standard_fixture().observations[0]
    session_event = ScoutEvent(
        sequence=0,
        timestamp_ns=event.timestamp_ns,
        kind=event.kind,
        capture_index=0,
        arbitration_id=event.arbitration_id,
        extended_id=event.extended_id,
        remote_frame=event.remote_frame,
        error_frame=event.error_frame,
        declared_length=event.declared_length,
        data=event.data,
        detail=event.detail,
    )
    raw = session_event.to_dict()
    schema = json.loads(
        (ROOT / "schemas" / "scout-event-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(raw)
    assert ScoutEvent.from_mapping(raw) == session_event

    raw["unexpected"] = True
    with pytest.raises(ValueError, match="unexpected"):
        ScoutEvent.from_mapping(raw)
    assert list(Draft202012Validator(schema).iter_errors(raw))


def test_session_is_exclusive_append_only_and_sealed_files_are_read_only(
    tmp_path: Path,
) -> None:
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    sentinel = occupied / "sentinel"
    sentinel.write_text("keep", encoding="ascii")
    with pytest.raises(FileExistsError):
        ScoutEvidenceSession(occupied, _metadata())
    assert sentinel.read_text(encoding="ascii") == "keep"

    root = tmp_path / "sealed"
    session = ScoutEvidenceSession(root, _metadata(acquisition_id="sealed-001"))
    session.record_timeout(timestamp_ns=1, detail="bounded passive poll elapsed")
    bundle = session.seal(completed_at="2026-07-18T10:01:00Z")

    assert session.state == "sealed"
    assert bundle.manifest.transport.transmitted is False
    with pytest.raises(RuntimeError, match="sealed"):
        session.record_reset(timestamp_ns=2, detail="late event")
    with pytest.raises(RuntimeError, match="sealed"):
        session.seal(completed_at="2026-07-18T10:02:00Z")
    for relative in (
        "acquisition.json",
        SCOUT_CAPTURE_PATH,
        SCOUT_TRANSACTION_PATH,
        SCOUT_SESSION_LOG_PATH,
    ):
        assert stat.S_IMODE((root / relative).stat().st_mode) & stat.S_IWUSR == 0


def test_context_exit_aborts_without_publishing_a_manifest(tmp_path: Path) -> None:
    root = tmp_path / "aborted"
    with ScoutEvidenceSession(root, _metadata(acquisition_id="aborted-001")) as session:
        session.record_frame(timestamp_ns=1, arbitration_id=0x123, data=b"\x01")

    assert session.state == "aborted"
    assert not (root / "acquisition.json").exists()
    assert (root / SCOUT_CAPTURE_PATH).exists()
    with pytest.raises(AcquisitionBundleValidationError):
        replay_scout_bundle(root, _Collector())


def test_session_rejects_invalid_frames_and_backwards_time_before_append(
    tmp_path: Path,
) -> None:
    session = ScoutEvidenceSession(tmp_path / "invalid", _metadata())
    session.record_frame(timestamp_ns=10, arbitration_id=0x123, data=b"\x01")

    with pytest.raises(ValueError, match="monotonic"):
        session.record_timeout(timestamp_ns=9, detail="backwards")
    with pytest.raises(ValueError, match="11 bits"):
        session.record_frame(timestamp_ns=11, arbitration_id=0x1234, data=b"\x01")
    with pytest.raises(ValueError, match="64 bytes"):
        session.record_frame(timestamp_ns=11, arbitration_id=0x123, data=b"A" * 65)
    with pytest.raises(ValueError, match="remote CAN frame length"):
        session.record_frame(
            timestamp_ns=11,
            arbitration_id=0x123,
            data=b"",
            remote_frame=True,
            declared_length=9,
        )
    assert session.event_count == 1
    session.abort()


def test_extended_frames_and_capture_errors_round_trip(tmp_path: Path) -> None:
    root = tmp_path / "extended"
    session = ScoutEvidenceSession(root, _metadata(acquisition_id="extended-001"))
    first = session.record_frame(
        timestamp_ns=1,
        arbitration_id=0x18DAF110,
        data=b"\x03\x7f\x22\x31",
        extended_id=True,
    )
    remote = session.record_frame(
        timestamp_ns=2,
        arbitration_id=0x321,
        data=b"",
        remote_frame=True,
        declared_length=8,
    )
    second = session.record_capture_error(timestamp_ns=3, detail="synthetic receive overflow")
    session.seal(completed_at="2026-07-18T10:01:00Z")

    collector = _Collector()
    result = replay_scout_bundle(root, collector)
    assert collector.events == [first, remote, second]
    assert remote.declared_length == 8
    assert result.frame_count == 2
    assert result.capture_error_count == 1
    assert result.transmitted_frames == 0


def test_maximum_escaped_event_detail_remains_replayable(tmp_path: Path) -> None:
    root = tmp_path / "escaped-detail"
    detail = "\U0001f4a5" * 4096
    session = ScoutEvidenceSession(root, _metadata(acquisition_id="escaped-detail-001"))
    event = session.record_capture_error(timestamp_ns=1, detail=detail)
    session.seal(completed_at="2026-07-18T10:01:00Z")

    collector = _Collector()
    replay_scout_bundle(root, collector)
    assert collector.events == [event]


def test_unrecorded_tampering_fails_bundle_validation_before_delivery(tmp_path: Path) -> None:
    root, _, _ = _sealed_fixture(tmp_path)
    capture_path = root / SCOUT_CAPTURE_PATH
    capture_path.chmod(0o600)
    capture_path.write_bytes(capture_path.read_bytes() + b"tamper")
    capture_path.chmod(0o444)
    collector = _Collector()

    with pytest.raises(AcquisitionBundleValidationError):
        replay_scout_bundle(root, collector)
    assert collector.events == []


def test_coherently_rehashed_capture_still_must_match_transaction_events(
    tmp_path: Path,
) -> None:
    root, _, _ = _sealed_fixture(tmp_path)

    def mutate_last_byte(data: bytes) -> bytes:
        return data[:-1] + bytes([data[-1] ^ 1])

    _rewrite_artifact(root, SCOUT_CAPTURE_ARTIFACT_ID, mutate_last_byte)
    collector = _Collector()
    with pytest.raises(ScoutReplayError) as caught:
        replay_scout_bundle(root, collector)
    assert caught.value.code == "capture-mismatch"
    assert collector.events == []


def test_replay_rejects_noncanonical_transactions_before_delivery(tmp_path: Path) -> None:
    root, _, _ = _sealed_fixture(tmp_path)

    def add_json_whitespace(data: bytes) -> bytes:
        lines = data.splitlines()
        first = json.loads(lines[0])
        lines[0] = json.dumps(first, sort_keys=True).encode("ascii")
        return b"\n".join(lines) + b"\n"

    _rewrite_artifact(root, SCOUT_TRANSACTION_ARTIFACT_ID, add_json_whitespace)
    collector = _Collector()
    with pytest.raises(ScoutReplayError) as caught:
        replay_scout_bundle(root, collector)
    assert caught.value.code == "noncanonical-event"
    assert collector.events == []


def test_replay_rejects_session_log_drift_before_delivery(tmp_path: Path) -> None:
    root, _, _ = _sealed_fixture(tmp_path)

    def change_tool_version(data: bytes) -> bytes:
        value = json.loads(data)
        value["tool"]["version"] = "rewritten"
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        )

    _rewrite_artifact(root, SCOUT_SESSION_LOG_ARTIFACT_ID, change_tool_version)
    collector = _Collector()
    with pytest.raises(ScoutReplayError) as caught:
        replay_scout_bundle(root, collector)
    assert caught.value.code == "session-log-mismatch"
    assert collector.events == []


def test_replay_limits_fail_closed_before_consumer_delivery(tmp_path: Path) -> None:
    root, _, _ = _sealed_fixture(tmp_path)
    collector = _Collector()
    with pytest.raises(ScoutReplayError) as caught:
        replay_scout_bundle(root, collector, limits=ScoutReplayLimits(max_events=4))
    assert caught.value.code == "event-limit"
    assert collector.events == []


def test_virtual_fixture_validates_all_scenarios_and_monotonic_order() -> None:
    fixture = VirtualCanEcu.standard_fixture()
    assert [item.kind for item in fixture.observations] == [
        "frame",
        "timeout",
        "malformed-frame",
        "reset",
        "frame",
    ]
    malformed = fixture.observations[2]
    assert malformed.declared_length == 20
    assert malformed.data == b"\x10\x14\x62\xf1"

    with pytest.raises(ValueError, match="monotonic"):
        VirtualCanEcu(
            name="backwards",
            observations=(
                VirtualCanObservation.signal(timestamp_ns=2, kind="reset", detail="first"),
                VirtualCanObservation.signal(timestamp_ns=1, kind="timeout", detail="second"),
            ),
        )


def test_scout_module_imports_without_hardware_dependencies_or_send_api() -> None:
    code = """
import builtins

forbidden = {"can", "isotp", "serial", "socketcan"}
original_import = builtins.__import__

def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.split(".", 1)[0] in forbidden:
        raise RuntimeError(f"hardware transport imported: {name}")
    return original_import(name, globals, locals, fromlist, level)

builtins.__import__ = guarded_import
from zeroverse.scout_evidence import ScoutEvidenceSession, VirtualCanEcu, replay_scout_bundle
assert ScoutEvidenceSession
assert VirtualCanEcu
assert replay_scout_bundle
assert not hasattr(ScoutEvidenceSession, "send")
assert not hasattr(VirtualCanEcu, "send")
"""
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


def test_sensitive_identifiers_require_an_honest_redaction_record() -> None:
    with pytest.raises(ValueError, match="denies a raw sensitive"):
        ScoutSessionMetadata(
            acquisition_id="private-001",
            device=DeviceIdentity(
                category="ecu",
                manufacturer=None,
                model=None,
                hardware_revision=None,
                identifiers=(
                    DeviceIdentifier(
                        kind="vin",
                        value="SYNTHETIC-VIN",
                        alias=None,
                        sensitivity="personal",
                    ),
                ),
            ),
            redaction=RedactionRecord(
                status="not-required",
                policy="0verse.default-export/v1",
                contains_sensitive_values=False,
                entries=(),
            ),
            interface="virtual-can0",
            source="fixture",
            collector="tests",
            authorization_basis="synthetic-fixture",
            started_at="2026-07-18T10:00:00Z",
            tool_name="test",
            tool_version="1",
        )
