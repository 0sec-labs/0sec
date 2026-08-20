from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from zeroverse.windows_ioctl_ghidra_export import (
    VID_CODEVIEW,
    VID_DRIVER_SHA256,
    VID_EXTRACTOR_CONFIG_SHA256,
    VID_EXTRACTOR_PROFILE,
    VID_IOCTL,
    VID_PDB_SHA256,
    canonical_export_bytes,
)
from zeroverse.windows_variant import (
    ANALYSIS_RECEIPT_VERSION_V2,
    _ioctl_analysis_cache_key,
    _load_artifact,
    produce_windows_ioctl_analysis_bundle,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("ZEROVERSE_VID_GHIDRA_INTEGRATION") != "1",
    reason="requires the exact private Vid.sys/PDB pair and Ghidra 11.3.2",
)


def test_exact_vid_bundle_typed_high_pcode_acquisition(tmp_path: Path) -> None:
    descriptor = produce_windows_ioctl_analysis_bundle(
        Path(os.environ["ZEROVERSE_VID_SYS"]),
        Path(os.environ["ZEROVERSE_VID_PDB"]),
        tmp_path / "bundle",
        ghidra_home=Path(os.environ["GHIDRA_HOME"]),
    )
    export = json.loads((tmp_path / descriptor["ghidra_export_path"]).read_bytes())
    assert export["extractor_profile"] == VID_EXTRACTOR_PROFILE
    assert export["extractor_config_sha256"] == VID_EXTRACTOR_CONFIG_SHA256
    assert export["driver_sha256"] == descriptor["binary_sha256"] == VID_DRIVER_SHA256
    assert export["pdb_sha256"] == VID_PDB_SHA256
    assert export["pdb_codeview_identity"] == VID_CODEVIEW
    coverage = export["facts"]["coverage"]
    assert coverage["scope"] == {
        "kind": "ioctl-allowlist",
        "ioctl_codes": [VID_IOCTL],
        "exhaustive": True,
    }
    dispatch = export["facts"]["dispatches"][0]
    assert dispatch["ioctl_code"] == VID_IOCTL
    registration = dispatch["registration_evidence"]
    assert registration["preprocess_rva"] == "0x2e600"
    assert registration["driver_api_table_offset"] == 0x3A0
    assert registration["registration_api_table_offset"] == 0x248
    assert registration["driver_config_argument_index"] == 4
    assert registration["callback_argument_index"] == 2
    assert registration["major_function_argument_index"] == 3
    field = dispatch["fields"][0]
    assert (field["offset"], field["width"]) == (4, 4)
    assert field["sink_function"] == "VidInformationIoctlGetSystemInformation"
    assert field["sink_address"] == "0xc5c78"
    assert field["sink_argument_index"] == 2
    assert dispatch["fields"][0]["guards"] == [
        "field-within-input",
        "input-buffer-length",
    ]
    export_bytes = canonical_export_bytes(export)
    assert export_bytes == (tmp_path / descriptor["ghidra_export_path"]).read_bytes()
    receipt = json.loads((tmp_path / descriptor["analysis_receipt_path"]).read_bytes())
    assert receipt["schema_version"] == ANALYSIS_RECEIPT_VERSION_V2
    assert receipt["tool_version"] == "11.3.2"
    assert receipt["binary_sha256"] == VID_DRIVER_SHA256
    assert receipt["ghidra_export_sha256"] == descriptor["ghidra_export_sha256"]
    assert receipt["pdb"] == {
        "path": "target.pdb",
        "sha256": VID_PDB_SHA256,
        "codeview_identity": VID_CODEVIEW,
    }
    assert receipt["extractor_profile"] == VID_EXTRACTOR_PROFILE
    assert receipt["extractor_config_sha256"] == VID_EXTRACTOR_CONFIG_SHA256
    assert receipt["cache_key"] == _ioctl_analysis_cache_key(
        VID_DRIVER_SHA256,
        VID_PDB_SHA256,
        "11.3.2",
        VID_EXTRACTOR_PROFILE,
        VID_EXTRACTOR_CONFIG_SHA256,
    )
    loaded = _load_artifact(descriptor, tmp_path, "exact-vid")
    assert loaded.binary_sha256 == VID_DRIVER_SHA256
    assert loaded.pdb_sha256 == VID_PDB_SHA256
    assert loaded.export["extractor_profile"] == VID_EXTRACTOR_PROFILE
