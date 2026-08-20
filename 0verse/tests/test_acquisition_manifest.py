from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from zeroverse import firmware
from zeroverse.acquisition import (
    ACQUISITION_MANIFEST_VERSION,
    AcquisitionArtifact,
    AcquisitionManifest,
    load_acquisition_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_SHA = "1" * 64
CAPTURE_SHA = "2" * 64


def _manifest() -> dict[str, object]:
    return {
        "schema_version": ACQUISITION_MANIFEST_VERSION,
        "acquisition_id": "acq-fixture-001",
        "created_at": "2026-07-17T12:02:00Z",
        "device": {
            "category": "ecu",
            "manufacturer": "Example Controls",
            "model": "ECU-1",
            "hardware_revision": "A",
            "identifiers": [
                {
                    "kind": "part-number",
                    "value": "EXAMPLE-0001",
                    "alias": None,
                    "sensitivity": "technical",
                }
            ],
        },
        "transport": {
            "kind": "can",
            "protocol": "raw-can",
            "interface": "fixture-can0",
            "mode": "passive",
            "transmitted": False,
            "parameters": [
                {"name": "bitrate", "value": "500000", "basis": "observed"}
            ],
            "capture_artifact_ids": ["capture"],
        },
        "regions": [
            {
                "region_id": "flash",
                "address_space": "physical",
                "start": 0,
                "length": 16,
                "role": "firmware",
                "basis": "declared",
                "permissions": ["read", "execute"],
                "artifact_id": "firmware",
                "artifact_offset": 0,
            }
        ],
        "artifacts": [
            {
                "artifact_id": "firmware",
                "kind": "firmware-image",
                "path": "artifacts/firmware.bin",
                "media_type": "application/octet-stream",
                "size": 16,
                "sha256": FIRMWARE_SHA,
                "observed_size": 16,
                "observed_sha256": FIRMWARE_SHA,
                "availability": "present",
                "integrity": "verified",
                "content": "plaintext",
                "coverage": "full",
                "region_ids": ["flash"],
            },
            {
                "artifact_id": "capture",
                "kind": "traffic-capture",
                "path": "captures/passive-can.log",
                "media_type": "application/x-can-log",
                "size": 32,
                "sha256": CAPTURE_SHA,
                "observed_size": 32,
                "observed_sha256": CAPTURE_SHA,
                "availability": "present",
                "integrity": "verified",
                "content": "plaintext",
                "coverage": "not-applicable",
                "region_ids": [],
            },
        ],
        "provenance": {
            "source": "synthetic ECU fixture",
            "method": "offline fixture assembly",
            "collector": "fixture-collector",
            "authorization_basis": "synthetic-fixture",
            "started_at": "2026-07-17T12:00:00Z",
            "completed_at": "2026-07-17T12:01:00Z",
            "tool_name": "0verse-test",
            "tool_version": "1.0",
            "evidence_artifact_ids": ["capture"],
            "notes": None,
        },
        "redaction": {
            "status": "not-required",
            "policy": "0verse.default-export/v1",
            "contains_sensitive_values": False,
            "entries": [],
        },
    }


def _schema() -> dict[str, object]:
    return json.loads((ROOT / "schemas" / "acquisition-manifest-v1.schema.json").read_text())


def test_manifest_round_trips_through_mapping_and_json(tmp_path: Path) -> None:
    raw = _manifest()
    manifest = AcquisitionManifest.from_mapping(raw)
    assert manifest.to_dict() == raw
    assert AcquisitionManifest.from_mapping(manifest.to_dict()) == manifest

    path = tmp_path / "acquisition.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert load_acquisition_manifest(path) == manifest


def test_published_schema_matches_runtime_contract() -> None:
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == ACQUISITION_MANIFEST_VERSION
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(_manifest())


@pytest.mark.parametrize(
    "case",
    [
        "extra-field",
        "unknown-enum",
        "passive-transmit",
        "traversal",
        "missing-recorded",
        "empty-identity",
    ],
)
def test_schema_and_runtime_reject_invalid_local_states(case: str) -> None:
    raw: Any = _manifest()
    if case == "extra-field":
        raw["unexpected"] = True
    elif case == "unknown-enum":
        raw["artifacts"][0]["coverage"] = "future-guess"
    elif case == "passive-transmit":
        raw["transport"]["transmitted"] = True
    elif case == "traversal":
        raw["artifacts"][0]["path"] = "../firmware.bin"
    elif case == "missing-recorded":
        raw["artifacts"][0]["availability"] = "missing"
    else:
        raw["device"]["identifiers"][0]["value"] = None

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(), format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError):
        AcquisitionManifest.from_mapping(raw)


def test_runtime_rejects_unknown_versions_and_broken_cross_references() -> None:
    versioned: Any = _manifest()
    versioned["schema_version"] = "0verse.acquisition-manifest/v2"
    with pytest.raises(ValueError, match="unsupported acquisition manifest schema"):
        AcquisitionManifest.from_mapping(versioned)

    unknown: Any = _manifest()
    unknown["regions"][0]["artifact_id"] = "not-present"
    with pytest.raises(ValueError, match="unknown artifact"):
        AcquisitionManifest.from_mapping(unknown)

    one_way: Any = _manifest()
    one_way["artifacts"][0]["region_ids"] = []
    with pytest.raises(ValueError, match="reciprocal"):
        AcquisitionManifest.from_mapping(one_way)

    oversized: Any = _manifest()
    oversized["regions"][0]["length"] = 17
    with pytest.raises(ValueError, match="exceeds"):
        AcquisitionManifest.from_mapping(oversized)


def test_artifact_dimensions_represent_intake_outcomes() -> None:
    template: Any = deepcopy(_manifest()["artifacts"][0])
    template["region_ids"] = []

    missing = deepcopy(template)
    missing.update(
        artifact_id="missing",
        path="artifacts/missing.bin",
        size=None,
        sha256=None,
        observed_size=None,
        observed_sha256=None,
        availability="missing",
        integrity="unavailable",
        content="unknown",
        coverage="unknown",
    )
    modified = deepcopy(template)
    modified.update(
        artifact_id="modified",
        path="artifacts/modified.bin",
        observed_size=15,
        observed_sha256="3" * 64,
        integrity="modified",
        coverage="partial",
    )
    encrypted = deepcopy(template)
    encrypted.update(
        artifact_id="encrypted",
        path="artifacts/encrypted.bin",
        content="encrypted",
    )
    virtual = deepcopy(template)
    virtual.update(
        artifact_id="virtual",
        path="artifacts/virtual.bin",
        coverage="virtual-read",
    )
    calibration = deepcopy(template)
    calibration.update(
        artifact_id="calibration",
        path="artifacts/calibration.bin",
        coverage="calibration-only",
    )

    artifacts = [
        AcquisitionArtifact.from_mapping(item)
        for item in (missing, modified, encrypted, virtual, calibration)
    ]
    assert [item.availability for item in artifacts] == [
        "missing",
        "present",
        "present",
        "present",
        "present",
    ]
    assert [item.coverage for item in artifacts[-2:]] == ["virtual-read", "calibration-only"]


def test_analysis_projection_is_verified_and_offline_only() -> None:
    raw: Any = _manifest()
    opaque = deepcopy(raw["artifacts"][0])
    opaque.update(
        artifact_id="encrypted",
        path="artifacts/encrypted.bin",
        region_ids=[],
        content="encrypted",
    )
    changed = deepcopy(raw["artifacts"][0])
    changed.update(
        artifact_id="changed",
        path="artifacts/changed.bin",
        region_ids=[],
        integrity="modified",
        observed_size=15,
        observed_sha256="3" * 64,
    )
    raw["artifacts"].extend([opaque, changed])

    inputs = firmware.acquisition_analysis_inputs(AcquisitionManifest.from_mapping(raw))
    assert [item.artifact_id for item in inputs] == ["firmware"]
    assert inputs[0].regions[0].region_id == "flash"


def test_redaction_tracks_private_and_exported_device_identity() -> None:
    private: Any = _manifest()
    identifier = private["device"]["identifiers"][0]
    identifier.update(kind="vin", value="EXAMPLEVIN00000001", sensitivity="personal")
    private["redaction"].update(
        status="unredacted", contains_sensitive_values=True, entries=[]
    )
    AcquisitionManifest.from_mapping(private)

    exported = deepcopy(private)
    exported_identifier = exported["device"]["identifiers"][0]
    exported_identifier.update(value=None, alias="vehicle-001")
    exported["redaction"].update(
        status="complete",
        contains_sensitive_values=False,
        entries=[
            {
                "path": "/device/identifiers/0/value",
                "classification": "personal",
                "action": "replaced",
            }
        ],
    )
    AcquisitionManifest.from_mapping(exported)

    exported_identifier["value"] = "EXAMPLEVIN00000001"
    with pytest.raises(ValueError, match="raw sensitive device identifier"):
        AcquisitionManifest.from_mapping(exported)


def test_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_acquisition_manifest(path)


def test_contract_and_analysis_import_without_hardware_transports() -> None:
    code = """
import builtins

forbidden = {"can", "isotp", "serial", "socketcan"}
original_import = builtins.__import__

def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.split(".", 1)[0] in forbidden:
        raise RuntimeError(f"hardware transport imported: {name}")
    return original_import(name, globals, locals, fromlist, level)

builtins.__import__ = guarded_import
from zeroverse.acquisition import AcquisitionManifest
from zeroverse.acquisition_bundle import load_acquisition_bundle
from zeroverse.firmware import acquisition_analysis_inputs
from zeroverse.firmware_inspection import inspect_bundle
assert AcquisitionManifest
assert load_acquisition_bundle
assert acquisition_analysis_inputs
assert inspect_bundle
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


def test_safety_decision_records_passive_and_versioning_boundaries() -> None:
    decision = (ROOT / "docs" / "FIRMWARE-SCOUT-SAFETY.md").read_text(encoding="utf-8")
    for required in (
        "passive means zero",
        "An acquisition manifest is evidence, not authority",
        "ReadMemoryByAddress",
        "SecurityAccess",
        "issue `#77`",
        "unknown fields are rejected",
        "requires a new manifest version",
    ):
        assert required in decision
