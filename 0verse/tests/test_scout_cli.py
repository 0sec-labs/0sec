from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from zeroverse.acquisition import DeviceIdentifier, DeviceIdentity, RedactionRecord
from zeroverse.acquisition_bundle import load_acquisition_bundle
from zeroverse.cli import main
from zeroverse.scout_evidence import (
    SCOUT_SESSION_LOG_ARTIFACT_ID,
    SCOUT_TRANSACTION_PATH,
    ScoutEvidenceSession,
    ScoutSessionMetadata,
    VirtualCanEcu,
)

RAW_VIN = "1HGBH41JXMN109186"


def _bundle_with_raw_vin(root: Path) -> Path:
    metadata = ScoutSessionMetadata(
        acquisition_id="raw-vin-fixture",
        device=DeviceIdentity(
            category="ecu",
            manufacturer="Synthetic Controls",
            model="Virtual ECU",
            hardware_revision="v1",
            identifiers=(
                DeviceIdentifier(
                    kind="vin",
                    value=RAW_VIN,
                    alias=None,
                    sensitivity="personal",
                ),
            ),
        ),
        redaction=RedactionRecord(
            status="unredacted",
            policy="test-unredacted-source/v1",
            contains_sensitive_values=True,
            entries=(),
        ),
        interface="virtual-can0",
        source="deterministic in-memory virtual ECU",
        collector="0verse-tests",
        authorization_basis="synthetic-fixture",
        started_at="2026-07-18T10:00:00Z",
        tool_name="0verse-tests",
        tool_version="0.0.1",
        notes="Source bundle intentionally contains a raw VIN for export-redaction testing.",
    )
    session = ScoutEvidenceSession(root, metadata)
    VirtualCanEcu.standard_fixture().capture(session)
    session.seal(completed_at="2026-07-18T10:01:00Z")
    return root


def _rewrite_artifact(root: Path, artifact_id: str, transform: object) -> None:
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


def test_capture_standard_fixture_creates_loadable_manifest_v1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "capture"

    assert main(["scout", "capture", "--fixture", "standard", "--output", str(output)]) == 0

    capture = json.loads(capsys.readouterr().out)
    bundle = load_acquisition_bundle(output)
    assert bundle.manifest.schema_version == "0verse.acquisition-manifest/v1"
    assert bundle.manifest.transport.mode == "passive"
    assert bundle.manifest.transport.transmitted is False
    assert capture["observed"]["transport"]["transmitted"] is False

    assert main(["scout", "inspect", str(output)]) == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["observed"]["replay"]["event_count"] == 5
    assert rendered["observed"]["replay"]["frame_count"] == 2
    assert rendered["observed"]["replay"]["transmitted_frames"] == 0


def test_inspect_emits_taxonomy_without_transmission(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle_with_raw_vin(tmp_path / "capture")

    assert main(["scout", "inspect", str(bundle)]) == 0

    rendered = json.loads(capsys.readouterr().out)
    assert set(rendered) == {"observed", "inferences", "unknowns"}
    assert rendered["observed"]["acquisition"]["transport"]["transmitted"] is False
    assert isinstance(rendered["inferences"]["inspections"], list)
    assert isinstance(rendered["unknowns"]["inspections"], list)


def test_reports_redact_raw_identifier_values_in_json_and_markdown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle_with_raw_vin(tmp_path / "raw-vin")

    raw_manifest = (bundle / "acquisition.json").read_text(encoding="ascii")
    raw_transaction = (bundle / SCOUT_TRANSACTION_PATH).read_text(encoding="ascii")
    raw_payload = json.loads(raw_transaction.splitlines()[0])["data_hex"]
    assert isinstance(raw_payload, str)

    for output_format in ("json", "md"):
        assert main(["scout", "report", str(bundle), "--format", output_format]) == 0
        rendered = capsys.readouterr().out
        assert RAW_VIN not in rendered
        assert raw_manifest not in rendered
        assert raw_transaction not in rendered
        assert raw_payload not in rendered
        if output_format == "json":
            assert set(json.loads(rendered)) == {"observed", "inferences", "unknowns"}
        else:
            assert "## Observed" in rendered
            assert "## Inferences" in rendered
            assert "## Unknowns" in rendered


def test_inspect_and_report_fail_closed_for_corrupt_replay_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle_with_raw_vin(tmp_path / "corrupt-replay")

    def corrupt_session_log(data: bytes) -> bytes:
        session_log = json.loads(data)
        session_log["tool"]["version"] = "rewritten"
        return (json.dumps(session_log, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        )

    _rewrite_artifact(bundle, SCOUT_SESSION_LOG_ARTIFACT_ID, corrupt_session_log)
    commands = (
        ["scout", "inspect", str(bundle)],
        ["scout", "report", str(bundle), "--format", "json"],
    )
    for command in commands:
        assert main(command) == 2
        assert "session-log-mismatch" in capsys.readouterr().err


def test_scout_help_states_hardware_and_transmission_boundaries(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for command in ("capture", "inspect", "report"):
        with pytest.raises(SystemExit) as caught:
            main(["scout", command, "--help"])

        assert caught.value.code == 0
        help_text = capsys.readouterr().out.lower()
        assert "hardware" in help_text
        assert "live transport" in help_text
        assert "transmitted" in help_text


def test_inspect_and_report_fail_closed_for_missing_bundle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    commands = (
        ["scout", "inspect", str(tmp_path / "missing")],
        ["scout", "report", str(tmp_path / "missing")],
    )
    for command in commands:
        assert main(command) == 2
        assert "error:" in capsys.readouterr().err
