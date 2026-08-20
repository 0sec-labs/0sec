from __future__ import annotations

import struct

import pytest

from zeroverse.hvix_hypercalls import (
    HypercallDescriptor,
    parse_descriptor_records,
    pe_image_base,
    rva_to_file_offset,
    validate_descriptors,
)


def _minimal_pe(payload: bytes, *, section_rva: int = 0x1000) -> bytes:
    data = bytearray(0x400 + len(payload))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0xFFFFF80000000000)
    section = optional + 0xF0
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<I", data, section + 8, len(payload))
    struct.pack_into("<I", data, section + 12, section_rva)
    struct.pack_into("<I", data, section + 16, len(payload))
    struct.pack_into("<I", data, section + 20, 0x400)
    data[0x400:] = payload
    return bytes(data)


def test_extracts_descriptor_layout_from_pe_rva() -> None:
    record = struct.pack(
        "<QHHHHHHI",
        0xFFFFF8000028DF90,
        0,
        1,
        24,
        8,
        0,
        16,
        0x44,
    )
    data = _minimal_pe(record)
    offset = rva_to_file_offset(data, 0x1000, len(record))
    descriptors = parse_descriptor_records(data, file_offset=offset, count=1)

    assert pe_image_base(data) == 0xFFFFF80000000000
    assert descriptors == [
        HypercallDescriptor(
            index=0,
            handler_va=0xFFFFF8000028DF90,
            call_code=0,
            flags=1,
            fixed_input_size=24,
            repeat_input_size=8,
            fixed_output_size=0,
            repeat_output_size=16,
            statistic_index=0x44,
        )
    ]
    assert descriptors[0].is_repeated


def test_rejects_uninitialized_or_truncated_rva_ranges() -> None:
    data = _minimal_pe(b"12345678")
    with pytest.raises(ValueError, match=r"not mapped|not present"):
        rva_to_file_offset(data, 0x2000, 1)
    with pytest.raises(ValueError, match="extends beyond"):
        parse_descriptor_records(data, file_offset=len(data) - 4, count=1)


def test_structural_validation_reports_code_and_repeat_mismatches() -> None:
    descriptor = HypercallDescriptor(
        index=3,
        handler_va=0x100,
        call_code=4,
        flags=0,
        fixed_input_size=0,
        repeat_input_size=8,
        fixed_output_size=0,
        repeat_output_size=0,
        statistic_index=0,
    )
    errors = validate_descriptors([descriptor], image_base=0x1000)
    assert len(errors) == 3
    assert any("call code" in error for error in errors)
    assert any("precedes image base" in error for error in errors)
    assert any("repeat sizes" in error for error in errors)
