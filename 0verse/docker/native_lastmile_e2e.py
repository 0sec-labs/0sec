#!/usr/bin/env python3
"""Native Linux proof for the GDB-backed last-mile reach selector."""

from __future__ import annotations

import os
import subprocess
import tempfile
import zlib
from pathlib import Path

os.environ["ZEROVERSE_EXECUTOR"] = "local"

from zeroverse.fuzz.lastmile import normalize_last_mile_candidate, probe_reaching_inputs

REACH_SOURCE = Path("/opt/0verse-fixtures/native_lastmile_reach.c")
PNG_SOURCE = Path("/opt/0verse-fixtures/native_lastmile_png.c")



def _png_chunk(kind: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(data, zlib.crc32(kind)) & 0xFFFFFFFF
    return len(data).to_bytes(4, "big") + kind + data + crc.to_bytes(4, "big")


def _png_input() -> bytes:
    ihdr = (
        b"\x00\x00\x00\x01"
        b"\x00\x00\x00\x01"
        b"\x08\x00\x00\x00\x00"
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00"))
        + _png_chunk(b"IEND", b"")
    )


def _chunk_data_offset(data: bytes, wanted: bytes) -> int:
    offset = 8
    while offset < len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        kind = data[offset + 4:offset + 8]
        data_offset = offset + 8
        if kind == wanted:
            return data_offset
        offset = data_offset + length + 4
    raise ValueError(f"missing PNG chunk {wanted!r}")


def _build(source: Path, binary: Path) -> None:
    subprocess.run(
        ["cc", "-g", "-O0", "-fno-pie", "-no-pie", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
def main() -> int:
    with tempfile.TemporaryDirectory(prefix="zv_native_lastmile_e2e_") as directory:
        root = Path(directory)
        reach_binary = root / "native-lastmile-target"
        _build(REACH_SOURCE, reach_binary)
        reached = b"RIFFdata"
        reach_result = probe_reaching_inputs(
            reach_binary,
            "parse",
            [reached, b"nope"],
            timeout_s=10.0,
        )

        png_binary = root / "native-lastmile-png"
        _build(PNG_SOURCE, png_binary)
        base = _png_input()
        idat_offset = _chunk_data_offset(base, b"IDAT")
        mutated = bytearray(base)
        mutated[0] = 0
        mutated[26:29] = b"\x01\x01\x02"
        mutated[idat_offset] ^= 0xFF
        normalized = normalize_last_mile_candidate(base, bytes(mutated))
        if normalized.status != "repaired":
            raise RuntimeError(f"PNG normalization did not repair candidate: {normalized}")
        png_result = probe_reaching_inputs(
            png_binary,
            "png_sink",
            [base, bytes(mutated), normalized.data],
            timeout_s=10.0,
        )

    if not reach_result.available:
        raise RuntimeError(f"GDB reach probe unavailable: {reach_result.note}")
    if reach_result.inputs != [reached]:
        raise RuntimeError(
            f"reach probe selected {reach_result.inputs!r}, expected only {reached!r}"
        )
    if not png_result.available:
        raise RuntimeError(f"PNG GDB reach probe unavailable: {png_result.note}")
    if png_result.inputs != [base, normalized.data]:
        raise RuntimeError(
            "PNG normalizer did not preserve only the valid parser path: "
            f"{png_result.inputs!r}"
        )
    print(
        "native last-mile proof: base and normalized PNG reached; "
        "unrepaired mutation lost reach"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
