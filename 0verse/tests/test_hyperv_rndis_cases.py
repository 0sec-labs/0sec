import importlib.util
import json
import struct
import sys
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts/hyperv/rndis_short_checksum_cases.py"
SPEC = importlib.util.spec_from_file_location("rndis_cases", SCRIPT)
assert SPEC and SPEC.loader
cases = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cases
SPEC.loader.exec_module(cases)


def parse(blob: bytes) -> dict[str, int]:
    values = struct.unpack_from("<IIIIIIIIIII", blob)
    keys = (
        "type",
        "message_len",
        "data_offset",
        "data_len",
        "oob_offset",
        "oob_len",
        "oob_count",
        "ppi_offset",
        "ppi_len",
        "vc",
        "reserved",
    )
    return dict(zip(keys, values, strict=True))


def test_target_layout_selects_ipv4_header_checksum_branch() -> None:
    blob = cases.build_packet(13, True)
    header = parse(blob)
    assert header == {
        "type": 1,
        "message_len": 73,
        "data_offset": 52,
        "data_len": 13,
        "oob_offset": 0,
        "oob_len": 0,
        "oob_count": 0,
        "ppi_offset": 36,
        "ppi_len": 16,
        "vc": 0,
        "reserved": 0,
    }
    size, ppi_type, ppi_offset, checksum = struct.unpack_from("<IIII", blob, 44)
    assert (size, ppi_type, ppi_offset) == (16, 0, 12)
    assert checksum == (1 << 0) | (1 << 4)
    assert len(blob) == header["message_len"]


def test_no_metadata_control_changes_only_layout_and_metadata() -> None:
    blob = cases.build_packet(13, False)
    header = parse(blob)
    assert header["message_len"] == len(blob) == 57
    assert header["data_offset"] == 36
    assert header["ppi_offset"] == header["ppi_len"] == 0
    assert blob[44:] == bytes(13)


def test_boundary_cases_are_complete_and_unique() -> None:
    names = [case.name for case in cases.CASES]
    assert names == [
        "target-len0-ipv4-checksum",
        "target-len13-ipv4-checksum",
        "control-len13-no-checksum",
        "control-len14-ipv4-checksum",
        "control-len64-ipv4-checksum",
    ]
    hashes = {
        case.name: cases.describe(case, cases.build_packet(case.data_len, case.checksum_metadata))[
            "sha256"
        ]
        for case in cases.CASES
    }
    assert hashes == {
        "target-len0-ipv4-checksum": (
            "23e3ad281fdcbfb5c227044f89ff54ef3a991b1fceb1178272ec7599bac73152"
        ),
        "target-len13-ipv4-checksum": (
            "87781924bfe732177b612e9b76f1b1161db232c10b25f56080e88c31b7a3e50c"
        ),
        "control-len13-no-checksum": (
            "755ace5b7b8f7528560c6589493667cad1646ece5432caa9199022999434599c"
        ),
        "control-len14-ipv4-checksum": (
            "373cc69905b0b698e13ab21028646f2c5999596e8377c419e85cf835fca727e3"
        ),
        "control-len64-ipv4-checksum": (
            "dc4bb137ea0432928763ef8c504ce7c36b7f90a8cc910ca6a51b3eaca140cc8e"
        ),
    }


def test_written_manifest_matches_files(tmp_path: Path) -> None:
    manifest = cases.write_fixture_set(tmp_path)
    on_disk = json.loads((tmp_path / "manifest.json").read_text())
    assert on_disk["format"] == "0verse-rndis-fixtures-v1"
    assert on_disk["cases"] == manifest
    for entry in manifest:
        blob = (tmp_path / f"{entry['name']}.rndis").read_bytes()
        assert blob.hex() == entry["hex"]
