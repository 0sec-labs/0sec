"""Extract the internal Hyper-V hypercall descriptor table from ``hvix64.exe``.

The table is not exported and private symbols are not required.  Callers must
provide the table RVA and entry count recovered for the exact build under
review; the parser deliberately does not signature-scan or guess them.
"""

from __future__ import annotations

import argparse
import json
import struct
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

_RECORD = struct.Struct("<QHHHHHHI")


@dataclass(frozen=True)
class HypercallDescriptor:
    index: int
    handler_va: int
    call_code: int
    flags: int
    fixed_input_size: int
    repeat_input_size: int
    fixed_output_size: int
    repeat_output_size: int
    statistic_index: int

    @property
    def is_repeated(self) -> bool:
        return bool(self.flags & 1)


def _u16(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])


def _u64(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<Q", data, offset)[0])


def pe_image_base(data: bytes) -> int:
    pe = _pe_header_offset(data)
    optional = pe + 24
    if _u16(data, optional) != 0x20B:
        raise ValueError("expected a PE32+ image")
    return _u64(data, optional + 24)


def _pe_header_offset(data: bytes) -> int:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a DOS/PE image")
    pe = _u32(data, 0x3C)
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    return pe


def rva_to_file_offset(data: bytes, rva: int, size: int = 1) -> int:
    """Map an initialized PE RVA range to its on-disk file offset."""

    if rva < 0 or size < 0:
        raise ValueError("RVA and size must be non-negative")
    pe = _pe_header_offset(data)
    section_count = _u16(data, pe + 6)
    optional_size = _u16(data, pe + 20)
    section = pe + 24 + optional_size
    for index in range(section_count):
        header = section + index * 40
        if header + 40 > len(data):
            raise ValueError("truncated PE section table")
        virtual_size = _u32(data, header + 8)
        virtual_address = _u32(data, header + 12)
        raw_size = _u32(data, header + 16)
        raw_offset = _u32(data, header + 20)
        mapped_size = max(virtual_size, raw_size)
        if virtual_address <= rva and rva + size <= virtual_address + mapped_size:
            relative = rva - virtual_address
            if relative + size > raw_size:
                raise ValueError("RVA range is not present in initialized file data")
            result = raw_offset + relative
            if result + size > len(data):
                raise ValueError("RVA range extends beyond the file")
            return result
    raise ValueError(f"RVA range 0x{rva:x}+0x{size:x} is not mapped")


def parse_descriptor_records(
    data: bytes, *, file_offset: int, count: int
) -> list[HypercallDescriptor]:
    if file_offset < 0 or count < 0:
        raise ValueError("file offset and count must be non-negative")
    end = file_offset + count * _RECORD.size
    if end > len(data):
        raise ValueError("descriptor table extends beyond the file")
    result: list[HypercallDescriptor] = []
    for index in range(count):
        values = _RECORD.unpack_from(data, file_offset + index * _RECORD.size)
        result.append(HypercallDescriptor(index, *values))
    return result


def extract_hypercall_descriptors(
    binary: str | Path, *, table_rva: int, count: int
) -> tuple[int, list[HypercallDescriptor]]:
    data = Path(binary).read_bytes()
    size = count * _RECORD.size
    offset = rva_to_file_offset(data, table_rva, size)
    return pe_image_base(data), parse_descriptor_records(data, file_offset=offset, count=count)


def validate_descriptors(
    descriptors: Sequence[HypercallDescriptor], *, image_base: int
) -> list[str]:
    """Return structural errors without assigning security meaning to metadata."""

    errors: list[str] = []
    for item in descriptors:
        if item.call_code != item.index:
            errors.append(f"entry {item.index:#x} carries call code {item.call_code:#x}")
        if item.handler_va < image_base:
            errors.append(f"entry {item.index:#x} handler {item.handler_va:#x} precedes image base")
        if not item.is_repeated and (item.repeat_input_size or item.repeat_output_size):
            errors.append(f"entry {item.index:#x} has repeat sizes without repeat flag")
    return errors


def _int(value: str) -> int:
    return int(value, 0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--table-rva", type=_int, required=True)
    parser.add_argument("--count", type=_int, required=True)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of TSV")
    args = parser.parse_args(argv)

    image_base, descriptors = extract_hypercall_descriptors(
        args.binary, table_rva=args.table_rva, count=args.count
    )
    errors = validate_descriptors(descriptors, image_base=image_base)
    if args.json:
        print(
            json.dumps(
                {
                    "image_base": image_base,
                    "table_rva": args.table_rva,
                    "count": len(descriptors),
                    "record_size": _RECORD.size,
                    "validation_errors": errors,
                    "descriptors": [asdict(item) for item in descriptors],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(
            "index\thandler_va\tcall_code\tflags\tfixed_input\trepeat_input"
            "\tfixed_output\trepeat_output\tstatistic_index"
        )
        for item in descriptors:
            print(
                f"0x{item.index:x}\t0x{item.handler_va:x}\t0x{item.call_code:x}"
                f"\t0x{item.flags:x}\t{item.fixed_input_size}"
                f"\t{item.repeat_input_size}\t{item.fixed_output_size}"
                f"\t{item.repeat_output_size}\t0x{item.statistic_index:x}"
            )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
