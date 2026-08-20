from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parents[1] / "scripts/windows/rank-hvix-restore-state-records.py"
_SPEC = importlib.util.spec_from_file_location("rank_hvix_restore_state_records", _SCRIPT)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)


def _fixture() -> tuple[bytes, int]:
    image_base = 0x180000000
    data = bytearray(0x500)
    struct.pack_into("<QQ", data, 0x40, image_base + 0x100, image_base + 0x140)
    struct.pack_into("<I", data, 0x100, 0x20)
    struct.pack_into("<I", data, 0x108, 0)
    struct.pack_into("<Q", data, 0x110, image_base + 0x300)
    struct.pack_into("<i", data, 0x118, 0x1234)
    struct.pack_into("<I", data, 0x140, 0x18)
    struct.pack_into("<I", data, 0x148, 2)
    struct.pack_into("<Q", data, 0x150, image_base + 0x380)
    struct.pack_into("<i", data, 0x158, -2)
    return bytes(data), image_base


def test_extracts_pointer_table_and_signed_record_ids() -> None:
    data, image_base = _fixture()

    descriptors = _MODULE.extract_descriptor_table(
        data,
        table_offset=0x40,
        count=2,
        image_base=image_base,
        rva_to_offset=lambda rva: rva,
    )

    assert descriptors == [
        {
            "descriptor_index": 0,
            "descriptor_va": image_base + 0x100,
            "minimum_size": 0x20,
            "size_mode": 0,
            "handler_va": image_base + 0x300,
            "record_id": 0x1234,
            "record_id_occurrence": 1,
            "record_id_count": 1,
        },
        {
            "descriptor_index": 1,
            "descriptor_va": image_base + 0x140,
            "minimum_size": 0x18,
            "size_mode": 2,
            "handler_va": image_base + 0x380,
            "record_id": -2,
            "record_id_occurrence": 1,
            "record_id_count": 1,
        },
    ]


def test_marks_duplicate_record_ids_and_rejects_invalid_counts() -> None:
    data, image_base = _fixture()
    duplicate = bytearray(data)
    struct.pack_into("<i", duplicate, 0x158, 0x1234)

    descriptors = _MODULE.extract_descriptor_table(
        bytes(duplicate),
        table_offset=0x40,
        count=2,
        image_base=image_base,
        rva_to_offset=lambda rva: rva,
    )
    assert [item["record_id_occurrence"] for item in descriptors] == [1, 2]
    assert [item["record_id_count"] for item in descriptors] == [2, 2]
    with pytest.raises(ValueError, match=r"outside 1\.\.4096"):
        _MODULE.extract_descriptor_table(
            data,
            table_offset=0x40,
            count=0,
            image_base=image_base,
            rva_to_offset=lambda rva: rva,
        )


def test_ranks_variable_record_with_pointer_and_size_signals_first() -> None:
    data, image_base = _fixture()
    descriptors = _MODULE.extract_descriptor_table(
        data,
        table_offset=0x40,
        count=2,
        image_base=image_base,
        rva_to_offset=lambda rva: rva,
    )
    decompiled = {
        f"FUN_{image_base + 0x300:016x}": "return *(uint *)(param_2 + 8);",
        f"FUN_{image_base + 0x380:016x}": """
            count = param_2[2];
            length = *(uint *)(param_2 + 0xc) << 4;
            memcpy(destination, param_2 + 4, length);
            FUN_fffff80000123456(context, param_2);
        """,
    }

    ranked = _MODULE.rank_records(descriptors, decompiled)

    assert [item["descriptor_index"] for item in ranked] == [1, 0]
    assert ranked[0]["signals"]["variable_size"] is True
    assert ranked[0]["signals"]["memory_ops"] == 1
    assert ranked[0]["signals"]["size_shifts"] == 1
