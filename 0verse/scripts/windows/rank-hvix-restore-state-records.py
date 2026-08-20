#!/usr/bin/env python3
"""Extract and rank an HVIX restore-state record descriptor table.

This is a static triage aid, not a vulnerability detector. It parses a
caller-supplied pointer table from a PE32+ image, resolves each descriptor and
handler, and correlates the handlers with an existing 0verse/Ghidra cache.
The target binary is never executed.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

_PARAM_REF = re.compile(r"\bparam_2(?:\s*\[|\s*\+|\b)")
_POINTER_LOAD = re.compile(
    r"\*\s*\(\s*(?:u?int|u?longlong|undefined[1248]|char|byte|short)\s*\*\s*\)"
    r"\s*\(\s*param_2\s*\+"
)
_INDEXED_LOAD = re.compile(r"\bparam_2\s*\[[^]]+\]")
_CALL_WITH_RECORD = re.compile(r"FUN_[0-9a-fA-F]+\s*\([^;\n]*\bparam_2\b")
_MEMORY_OP = re.compile(r"\b(?:memcpy|memmove|memset)\s*\(")
_SIZE_SHIFT = re.compile(r"(?:param_2[^;\n]*(?:<<|>>)|(?:<<|>>)[^;\n]*param_2)")


@dataclass(frozen=True)
class Section:
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int


@dataclass(frozen=True)
class PEImage:
    data: bytes
    image_base: int
    size_of_image: int
    sections: tuple[Section, ...]

    @classmethod
    def parse(cls, path: Path) -> PEImage:
        data = path.read_bytes()
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError(f"not a DOS/PE image: {path}")
        pe_offset = _u32(data, 0x3C)
        if _slice(data, pe_offset, 4) != b"PE\0\0":
            raise ValueError(f"missing PE signature: {path}")
        if _u16(data, pe_offset + 4) != 0x8664:
            raise ValueError(f"not an x86-64 PE image: {path}")
        section_count = _u16(data, pe_offset + 6)
        optional_size = _u16(data, pe_offset + 20)
        optional = pe_offset + 24
        if _u16(data, optional) != 0x20B:
            raise ValueError(f"not PE32+: {path}")
        image_base = _u64(data, optional + 24)
        size_of_image = _u32(data, optional + 56)
        section_table = optional + optional_size
        sections = []
        for index in range(section_count):
            offset = section_table + 40 * index
            virtual_size = _u32(data, offset + 8)
            virtual_address = _u32(data, offset + 12)
            raw_size = _u32(data, offset + 16)
            raw_offset = _u32(data, offset + 20)
            sections.append(Section(virtual_address, virtual_size, raw_size, raw_offset))
        return cls(data, image_base, size_of_image, tuple(sections))

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    raise ValueError(f"RVA {rva:#x} has no file-backed bytes")
                return section.raw_offset + delta
        raise ValueError(f"unmapped RVA {rva:#x}")


def _slice(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"out-of-bounds read offset={offset:#x} size={size:#x}")
    return data[offset : offset + size]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack("<H", _slice(data, offset, 2))[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack("<I", _slice(data, offset, 4))[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack("<i", _slice(data, offset, 4))[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack("<Q", _slice(data, offset, 8))[0]


def extract_descriptor_table(
    data: bytes,
    *,
    table_offset: int,
    count: int,
    image_base: int,
    rva_to_offset: Callable[[int], int],
) -> list[dict[str, int]]:
    if not 1 <= count <= 4096:
        raise ValueError(f"descriptor count outside 1..4096: {count}")
    descriptors = []
    for index in range(count):
        descriptor_va = _u64(data, table_offset + 8 * index)
        descriptor_rva = descriptor_va - image_base
        if descriptor_rva < 0:
            raise ValueError(f"descriptor {index} points below the image")
        descriptor_offset = rva_to_offset(descriptor_rva)
        handler_va = _u64(data, descriptor_offset + 0x10)
        if handler_va < image_base:
            raise ValueError(f"descriptor {index} handler points below the image")
        descriptors.append(
            {
                "descriptor_index": index,
                "descriptor_va": descriptor_va,
                "minimum_size": _u32(data, descriptor_offset),
                "size_mode": _u32(data, descriptor_offset + 8),
                "handler_va": handler_va,
                "record_id": _i32(data, descriptor_offset + 0x18),
            }
        )
    counts = Counter(item["record_id"] for item in descriptors)
    occurrences: Counter[int] = Counter()
    for descriptor in descriptors:
        record_id = descriptor["record_id"]
        occurrences[record_id] += 1
        descriptor["record_id_occurrence"] = occurrences[record_id]
        descriptor["record_id_count"] = counts[record_id]
    return descriptors


def rank_records(
    descriptors: list[dict[str, int]], decompiled: dict[str, str]
) -> list[dict[str, object]]:
    ranked = []
    for descriptor in descriptors:
        handler = f"FUN_{descriptor['handler_va']:016x}"
        source = decompiled.get(handler, "")
        param_refs = len(_PARAM_REF.findall(source))
        pointer_loads = len(_POINTER_LOAD.findall(source))
        indexed_loads = len(_INDEXED_LOAD.findall(source))
        calls_with_record = len(_CALL_WITH_RECORD.findall(source))
        memory_ops = len(_MEMORY_OP.findall(source))
        size_shifts = len(_SIZE_SHIFT.findall(source))
        variable_size = descriptor["size_mode"] >= 2
        score = (
            6 * int(variable_size)
            + min(param_refs, 8)
            + 3 * min(pointer_loads, 4)
            + 2 * min(indexed_loads, 4)
            + 2 * min(calls_with_record, 4)
            + 3 * min(memory_ops, 4)
            + 3 * min(size_shifts, 4)
        )
        ranked.append(
            {
                **descriptor,
                "handler": handler,
                "score": score,
                "decompilation_present": bool(source),
                "signals": {
                    "variable_size": variable_size,
                    "param_refs": param_refs,
                    "pointer_loads": pointer_loads,
                    "indexed_loads": indexed_loads,
                    "calls_with_record": calls_with_record,
                    "memory_ops": memory_ops,
                    "size_shifts": size_shifts,
                },
            }
        )
    return sorted(
        ranked,
        key=lambda item: (
            -int(item["score"]),
            int(item["descriptor_index"]),
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("ghidra_cache", type=Path)
    parser.add_argument("--table-rva", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--count", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")

    image = PEImage.parse(args.binary)
    table_offset = image.rva_to_offset(args.table_rva)
    descriptors = extract_descriptor_table(
        image.data,
        table_offset=table_offset,
        count=args.count,
        image_base=image.image_base,
        rva_to_offset=image.rva_to_offset,
    )
    cache = json.loads(args.ghidra_cache.read_text())
    decompiled = cache.get("meta", {}).get("decompiled_c", {})
    if not isinstance(decompiled, dict):
        raise SystemExit("Ghidra cache has no meta.decompiled_c mapping")
    ranked = rank_records(descriptors, decompiled)[: args.limit]
    if args.json:
        print(json.dumps(ranked, indent=2, sort_keys=True))
    else:
        print("index\trecord_id\tscore\thandler\tmin_size\tmode\tsignals")
        for item in ranked:
            signals = ",".join(f"{key}={value}" for key, value in item["signals"].items())
            print(
                f"{item['descriptor_index']}\t{int(item['record_id']):#x}\t"
                f"{item['score']}\t{item['handler']}\t{item['minimum_size']}\t"
                f"{item['size_mode']}\t{signals}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
