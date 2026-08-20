from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from zeroverse.acquisition import AcquisitionManifest
from zeroverse.acquisition_bundle import load_acquisition_bundle
from zeroverse.firmware_inspection import (
    FIRMWARE_INSPECTION_VERSION,
    inspect_bundle,
    inspect_bundle_artifact,
    inspect_firmware,
    inspect_firmware_bytes,
    with_inspection_regions,
)

ROOT = Path(__file__).resolve().parents[1]
BUNDLES = ROOT / "tests" / "fixtures" / "acquisition-bundles" / "v1"
MIPS_ELF = ROOT / "tests" / "fixtures" / "mips_parse_o32.elf"


def _pattern(length: int, seed: int) -> bytes:
    return bytes(((index * 73 + seed) & 0xFF) for index in range(length))


def _put_cortex_m_vectors(image: bytearray, offset: int, reset: int) -> None:
    image[offset : offset + 32] = struct.pack(
        "<8I",
        0x20002000,
        reset,
        reset + 4,
        reset + 8,
        0,
        reset + 12,
        reset + 16,
        reset + 20,
    )


def _synthetic_image() -> bytes:
    image = bytearray(_pattern(0x1000, 19))
    for start, end in ((0x200, 0x400), (0x800, 0xA00), (0xC00, 0xE00)):
        image[start:end] = b"\xff" * (end - start)

    _put_cortex_m_vectors(image, 0x000, 0x08000081)
    _put_cortex_m_vectors(image, 0x400, 0x08000481)
    image[0x040:0x04A] = b"BOOTLOADER"
    image[0x440:0x44B] = b"APP_CODE_OK"
    calibration = b"CALIBRATION FUEL-MAP IGNITION-MAP TORQUE-MAP"
    image[0xA00 : 0xA00 + len(calibration)] = calibration
    repeated = bytes(range(64))
    image[0xE00:0xE40] = repeated
    image[0xE40:0xE80] = repeated
    return bytes(image)


def _manifest_for(image: bytes) -> AcquisitionManifest:
    raw: Any = json.loads((BUNDLES / "valid" / "acquisition.json").read_text())
    digest = hashlib.sha256(image).hexdigest()
    raw["regions"] = []
    firmware = raw["artifacts"][0]
    firmware.update(
        size=len(image),
        sha256=digest,
        observed_size=len(image),
        observed_sha256=digest,
        region_ids=[],
    )
    return AcquisitionManifest.from_mapping(raw)


def test_reports_statistics_strings_padding_repeats_and_candidate_regions() -> None:
    report = inspect_firmware_bytes(_synthetic_image(), artifact_id="firmware")

    assert report.schema_version == FIRMWARE_INSPECTION_VERSION
    assert report.size == 0x1000
    assert 0.0 < report.overall_entropy < 8.0
    assert report.entropy_window_size == 256
    assert len(report.entropy_windows) == 16
    assert any("BOOTLOADER" in item.value for item in report.strings)
    assert any("CALIBRATION" in item.value for item in report.strings)
    assert [(item.offset, item.length, item.byte_value) for item in report.padding_runs] == [
        (0x200, 0x200, 0xFF),
        (0x800, 0x200, 0xFF),
        (0xC00, 0x200, 0xFF),
    ]
    assert report.repeated_region_count > 0
    assert any({0xE00, 0xE40}.issubset(item.offsets) for item in report.repeated_regions)
    assert [item.role for item in report.regions] == [
        "bootloader",
        "code",
        "calibration",
        "data",
    ]
    assert [item.artifact_offset for item in report.regions] == [0, 0x400, 0xA00, 0xE00]
    assert all(item.evidence for item in report.regions)


def test_vector_and_architecture_candidates_carry_confidence_and_evidence() -> None:
    report = inspect_firmware_bytes(_synthetic_image())

    assert report.load_address == 0x08000000
    assert report.load_address_basis == "inferred"
    assert report.load_address_evidence == (
        "cortex-m-reset@0x0:0x8000080",
        "cortex-m-reset@0x400:0x8000480",
    )
    assert [item.offset for item in report.vector_tables] == [0, 0x400]
    assert all(item.architecture == "arm-cortex-m" for item in report.vector_tables)
    assert all(item.confidence >= 80 for item in report.vector_tables)
    assert all(item.evidence for item in report.vector_tables)
    vector_arches = [item for item in report.architectures if item.source == "vector-table"]
    assert [item.offset for item in vector_arches] == [0, 0x400]
    assert all(item.confidence >= 80 and item.evidence for item in vector_arches)


def test_user_load_address_overrides_inference_without_mutating_input(tmp_path: Path) -> None:
    source = tmp_path / "firmware.bin"
    source.write_bytes(_synthetic_image())
    before_bytes = source.read_bytes()
    before = os.lstat(source)

    report = inspect_firmware(source, load_address=0x10000000)

    after = os.lstat(source)
    assert report.load_address == 0x10000000
    assert report.load_address_basis == "user-supplied"
    assert report.load_address_evidence == ("caller-supplied:0x10000000",)
    assert [item.start for item in report.regions] == [
        0x10000000,
        0x10000400,
        0x10000A00,
        0x10000E00,
    ]
    assert source.read_bytes() == before_bytes
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )


def test_repeated_runs_are_byte_stable_and_canonical() -> None:
    first = inspect_firmware_bytes(_synthetic_image())
    second = inspect_firmware_bytes(_synthetic_image())

    assert first == second
    assert first.canonical_bytes() == second.canonical_bytes()
    raw = json.loads(first.canonical_bytes())
    assert raw == first.to_dict()
    assert first.canonical_bytes().endswith(b"\n")


def test_container_headers_produce_structural_and_architecture_evidence() -> None:
    report = inspect_firmware(MIPS_ELF, artifact_id="mips-fixture")

    elf = next(item for item in report.containers if item.kind == "elf")
    architecture = next(item for item in report.architectures if item.source == "elf-header")
    assert elf.offset == 0 and elf.confidence == 98
    assert "elf-header-valid" in elf.evidence
    assert architecture.architecture == "mips"
    assert architecture.bits == 32
    assert architecture.confidence == 98
    assert not report.vector_tables
    assert "vector-table-not-established" in report.unknowns


def test_uimage_and_embedded_filesystem_lengths_are_bounded() -> None:
    image = bytearray(_pattern(160, 7))
    struct.pack_into(">I", image, 0, 0x27051956)
    struct.pack_into(">I", image, 12, 32)
    image[64:68] = b"hsqs"

    report = inspect_firmware_bytes(bytes(image))

    uimage = next(item for item in report.containers if item.kind == "uimage")
    squashfs = next(item for item in report.containers if item.kind == "squashfs")
    assert uimage.length == 96
    assert uimage.confidence == 95
    assert "declared-length-bounded" in uimage.evidence
    assert squashfs.offset == 64
    assert report.container_candidate_count == len(report.containers) == 2
    assert not report.containers_truncated


def test_embedded_executable_base_does_not_rebase_its_enclosing_image() -> None:
    report = inspect_firmware_bytes(_pattern(128, 3) + MIPS_ELF.read_bytes())

    elf = next(item for item in report.containers if item.kind == "elf")
    assert elf.offset == 128
    assert report.load_address is None
    assert report.load_address_basis == "unknown"


def test_container_truncation_and_address_overflow_are_explicit() -> None:
    report = inspect_firmware_bytes(b"\x85\x19" * 1025)
    assert report.container_candidate_count == 1025
    assert len(report.containers) == 1024
    assert report.containers_truncated
    assert "container-observations-truncated" in report.unknowns

    with pytest.raises(ValueError, match="exceeds the 64-bit address space"):
        inspect_firmware_bytes(b"firmware", load_address=(1 << 64) - 4)


def test_unsupported_bytes_remain_explicitly_unknown() -> None:
    report = inspect_firmware_bytes(bytes(range(256)) * 2)

    assert not report.architectures
    assert not report.vector_tables
    assert report.load_address is None
    assert report.load_address_basis == "unknown"
    assert {
        "container-structure-not-recognized",
        "architecture-not-established",
        "vector-table-not-established",
        "load-address-not-established",
    }.issubset(report.unknowns)


def test_bundle_inspection_admits_only_verified_analysis_artifacts() -> None:
    bundle = load_acquisition_bundle(BUNDLES / "valid")

    reports = inspect_bundle(bundle, load_addresses={"firmware": 0x08000000})
    assert [item.artifact_id for item in reports] == [
        "firmware",
        "virtual-read",
        "calibration",
    ]
    assert reports[0].load_address_basis == "user-supplied"
    assert reports[0].sha256 == bundle.artifact("firmware").observed_sha256

    with pytest.raises(ValueError, match="not a verified offline firmware"):
        inspect_bundle_artifact(bundle, "encrypted")
    with pytest.raises(ValueError, match="ineligible artifacts"):
        inspect_bundle(bundle, load_addresses={"encrypted": 0})


def test_manifest_projection_is_copy_on_write_reciprocal_and_schema_valid() -> None:
    image = _synthetic_image()
    report = inspect_firmware_bytes(image, artifact_id="firmware")
    original = _manifest_for(image)
    original_dict = original.to_dict()

    projected = with_inspection_regions(original, report)

    assert original.to_dict() == original_dict
    assert not original.regions
    projected_firmware = next(
        item for item in projected.artifacts if item.artifact_id == "firmware"
    )
    assert projected_firmware.region_ids == tuple(item.region_id for item in report.regions)
    assert [item.role for item in projected.regions] == [
        "bootloader",
        "code",
        "calibration",
        "data",
    ]
    assert all(item.basis == "inferred" for item in projected.regions)
    assert all(item.artifact_id == "firmware" for item in projected.regions)
    assert with_inspection_regions(projected, report) == projected

    schema = json.loads(
        (ROOT / "schemas" / "acquisition-manifest-v1.schema.json").read_text()
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(projected.to_dict())


def test_projection_can_select_candidates_and_rejects_identity_drift() -> None:
    image = _synthetic_image()
    report = inspect_firmware_bytes(image, artifact_id="firmware")
    original = _manifest_for(image)
    selected = [report.regions[1].region_id, report.regions[2].region_id]

    projected = with_inspection_regions(original, report, candidate_ids=selected)
    assert [item.region_id for item in projected.regions] == selected

    wrong = inspect_firmware_bytes(image + b"x", artifact_id="firmware")
    with pytest.raises(ValueError, match="identity does not match"):
        with_inspection_regions(original, wrong)
    with pytest.raises(ValueError, match="unknown candidate"):
        with_inspection_regions(original, report, candidate_ids=["not-a-candidate"])


def test_file_inspection_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(_synthetic_image())
    link = tmp_path / "firmware.bin"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="regular non-symlink"):
        inspect_firmware(link)
