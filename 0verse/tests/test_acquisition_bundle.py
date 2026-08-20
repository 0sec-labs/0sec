from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from zeroverse.acquisition import load_acquisition_manifest
from zeroverse.acquisition_bundle import (
    ACQUISITION_BUNDLE_MANIFEST,
    AcquisitionBundleValidationError,
    load_acquisition_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "acquisition-bundles" / "v1"
VALID = FIXTURES / "valid"


@pytest.mark.parametrize(
    "bundle_root",
    [
        VALID,
        FIXTURES / "negative" / "size-mismatch",
        FIXTURES / "negative" / "hash-mismatch",
        FIXTURES / "negative" / "unexpected-missing",
        FIXTURES / "negative" / "missing-present",
    ],
)
def test_committed_bundle_manifests_conform_to_v1_schema(bundle_root: Path) -> None:
    schema = json.loads(
        (ROOT / "schemas" / "acquisition-manifest-v1.schema.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (bundle_root / ACQUISITION_BUNDLE_MANIFEST).read_text(encoding="utf-8")
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)


def test_loads_complete_synthetic_bundle_and_preserves_evidence_states() -> None:
    bundle = load_acquisition_bundle(VALID)

    assert bundle.root == VALID.resolve()
    assert bundle.manifest_path == VALID.resolve() / ACQUISITION_BUNDLE_MANIFEST
    assert [item.artifact.artifact_id for item in bundle.artifacts] == [
        "firmware",
        "capture",
        "transactions",
        "collector-log",
        "missing",
        "modified",
        "encrypted",
        "virtual-read",
        "calibration",
    ]

    firmware = bundle.artifact("firmware")
    assert firmware.path == VALID.resolve() / "artifacts" / "firmware.bin"
    assert firmware.observed_size == 26
    assert firmware.observed_sha256 == firmware.artifact.sha256

    missing = bundle.artifact("missing")
    assert missing.artifact.availability == "missing"
    assert missing.path == VALID.resolve() / "artifacts" / "missing.bin"
    assert not missing.is_present

    modified = bundle.artifact("modified")
    assert modified.artifact.integrity == "modified"
    assert modified.observed_size == modified.artifact.observed_size == 32
    assert modified.observed_sha256 == modified.artifact.observed_sha256

    encrypted = bundle.artifact("encrypted")
    virtual = bundle.artifact("virtual-read")
    calibration = bundle.artifact("calibration")
    assert encrypted.artifact.content == "encrypted"
    assert virtual.artifact.coverage == "virtual-read"
    assert calibration.artifact.coverage == "calibration-only"

    assert [item.artifact.artifact_id for item in bundle.analysis_artifacts()] == [
        "firmware",
        "virtual-read",
        "calibration",
    ]


@pytest.mark.parametrize(
    ("fixture", "expected_codes"),
    [
        ("size-mismatch", ["artifact-size-mismatch"]),
        ("hash-mismatch", ["artifact-sha256-mismatch"]),
        ("unexpected-missing", ["artifact-unexpected"]),
        ("missing-present", ["artifact-missing"]),
    ],
)
def test_committed_negative_bundles_report_stable_issue_codes(
    fixture: str, expected_codes: list[str]
) -> None:
    with pytest.raises(AcquisitionBundleValidationError) as caught:
        load_acquisition_bundle(FIXTURES / "negative" / fixture)

    assert [issue.code for issue in caught.value.issues] == expected_codes
    assert all(issue.artifact_id == "firmware" for issue in caught.value.issues)
    assert "acquisition bundle validation failed" in str(caught.value)


def test_reports_all_artifact_failures_in_canonical_path_order(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    shutil.copytree(VALID, bundle_root)
    (bundle_root / "artifacts" / "firmware.bin").unlink()
    (bundle_root / "captures" / "passive-can.log").unlink()

    with pytest.raises(AcquisitionBundleValidationError) as caught:
        load_acquisition_bundle(bundle_root)

    assert [(issue.path, issue.code) for issue in caught.value.issues] == [
        ("artifacts/firmware.bin", "artifact-missing"),
        ("captures/passive-can.log", "artifact-missing"),
    ]


def test_recorded_artifact_bytes_are_checked_without_promoting_the_claim(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    shutil.copytree(VALID, bundle_root)
    collector = bundle_root / "logs" / "collector.log"
    collector.write_text("changed\n", encoding="utf-8")

    with pytest.raises(AcquisitionBundleValidationError) as caught:
        load_acquisition_bundle(bundle_root)

    assert [issue.code for issue in caught.value.issues] == [
        "artifact-sha256-mismatch",
        "artifact-size-mismatch",
    ]
    assert all(issue.artifact_id == "collector-log" for issue in caught.value.issues)


def test_rejects_artifact_symlinks_even_when_target_bytes_match(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    shutil.copytree(VALID, bundle_root)
    firmware = bundle_root / "artifacts" / "firmware.bin"
    target = tmp_path / "outside.bin"
    target.write_bytes(firmware.read_bytes())
    firmware.unlink()
    try:
        firmware.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(AcquisitionBundleValidationError) as caught:
        load_acquisition_bundle(bundle_root)

    assert [issue.code for issue in caught.value.issues] == ["artifact-path-symlink"]
    assert caught.value.issues[0].artifact_id == "firmware"


def test_rejects_symlinked_artifact_parent_directory(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    shutil.copytree(VALID, bundle_root)
    artifact_dir = bundle_root / "artifacts"
    outside = tmp_path / "outside-artifacts"
    artifact_dir.rename(outside)
    try:
        artifact_dir.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(AcquisitionBundleValidationError) as caught:
        load_acquisition_bundle(bundle_root)

    assert {issue.code for issue in caught.value.issues} == {"artifact-path-symlink"}
    assert {issue.artifact_id for issue in caught.value.issues} == {
        "firmware",
        "missing",
        "modified",
        "encrypted",
        "virtual-read",
        "calibration",
    }


def test_rejects_hard_link_aliases_between_declared_artifacts(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    shutil.copytree(VALID, bundle_root)
    manifest_path = bundle_root / ACQUISITION_BUNDLE_MANIFEST
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    firmware = raw["artifacts"][0]
    calibration = next(
        item for item in raw["artifacts"] if item["artifact_id"] == "calibration"
    )
    calibration.update(
        size=firmware["size"],
        sha256=firmware["sha256"],
        observed_size=firmware["observed_size"],
        observed_sha256=firmware["observed_sha256"],
    )
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    calibration_path = bundle_root / calibration["path"]
    calibration_path.unlink()
    try:
        os.link(bundle_root / firmware["path"], calibration_path)
    except OSError as exc:
        pytest.skip(f"hard-link creation unavailable: {exc}")

    with pytest.raises(AcquisitionBundleValidationError) as caught:
        load_acquisition_bundle(bundle_root)

    aliases = [issue for issue in caught.value.issues if issue.code == "artifact-path-alias"]
    assert len(aliases) == 1
    assert aliases[0].artifact_id == "firmware"
    assert "artifacts/calibration.bin" in aliases[0].detail


def test_rejects_bundle_root_and_manifest_symlinks(tmp_path: Path) -> None:
    root_link = tmp_path / "bundle-link"
    manifest_link = tmp_path / "manifest-link.json"
    try:
        root_link.symlink_to(VALID, target_is_directory=True)
        manifest_link.symlink_to(VALID / ACQUISITION_BUNDLE_MANIFEST)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(AcquisitionBundleValidationError) as root_error:
        load_acquisition_bundle(root_link)
    assert [issue.code for issue in root_error.value.issues] == ["bundle-invalid"]

    with pytest.raises(ValueError, match="regular non-symlink"):
        load_acquisition_manifest(manifest_link)


def test_rejects_manifest_as_an_artifact_path_before_hashing(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    shutil.copytree(VALID, bundle_root)
    manifest_path = bundle_root / ACQUISITION_BUNDLE_MANIFEST
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["regions"] = []
    firmware = raw["artifacts"][0]
    firmware["path"] = ACQUISITION_BUNDLE_MANIFEST
    firmware["region_ids"] = []
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(AcquisitionBundleValidationError) as caught:
        load_acquisition_bundle(bundle_root)

    assert "artifact-reserved-path" in [issue.code for issue in caught.value.issues]
