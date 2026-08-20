"""No-execute PE-driver carver — synthetic-PE unit tests (no binaries, no toolchain)."""

from __future__ import annotations

import hashlib
import struct

from zeroverse.pe_driver_carve import carve_drivers


def _make_pe(subsystem: int, *, machine: int = 0x8664, raw_ptr: int = 0x200,
             raw_size: int = 0x200) -> bytes:
    """Minimal PE32+ image the carver can parse: MZ + PE header + optional header
    (subsystem at +0x44) + one section (raw ptr/size). Total length raw_ptr+raw_size."""
    total = raw_ptr + raw_size
    buf = bytearray(total)
    buf[0:2] = b"MZ"
    e_lfanew = 0x40
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    po = e_lfanew
    buf[po : po + 4] = b"PE\0\0"
    struct.pack_into("<H", buf, po + 4, machine)   # Machine
    struct.pack_into("<H", buf, po + 6, 1)         # NumberOfSections
    szopt = 0xF0
    struct.pack_into("<H", buf, po + 20, szopt)    # SizeOfOptionalHeader
    opt = po + 24
    struct.pack_into("<H", buf, opt, 0x20B)        # PE32+ magic
    struct.pack_into("<H", buf, opt + 0x44, subsystem)  # Subsystem
    sec = opt + szopt
    buf[sec : sec + 8] = b".text\0\0\0"
    struct.pack_into("<I", buf, sec + 16, raw_size)  # SizeOfRawData
    struct.pack_into("<I", buf, sec + 20, raw_ptr)   # PointerToRawData
    return bytes(buf)


def test_carves_embedded_native_driver(tmp_path) -> None:
    driver = _make_pe(subsystem=1)  # IMAGE_SUBSYSTEM_NATIVE
    blob = b"\x00" * 0x100 + driver + b"trailing junk"
    f = tmp_path / "utility.exe"
    f.write_bytes(blob)

    carved = carve_drivers(f)
    assert len(carved) == 1
    c = carved[0]
    assert c.offset == 0x100 and c.is_x64 and c.size == len(driver)
    assert c.sha256 == hashlib.sha256(driver).hexdigest()
    assert c.data == driver  # exact bytes, no trailing junk


def test_skips_non_driver_gui_pe(tmp_path) -> None:
    gui = _make_pe(subsystem=2)  # IMAGE_SUBSYSTEM_WINDOWS_GUI — not a driver
    f = tmp_path / "app.exe"
    f.write_bytes(b"\x00" * 64 + gui)
    assert carve_drivers(f) == []


def test_dedupes_repeated_driver(tmp_path) -> None:
    driver = _make_pe(subsystem=1)
    f = tmp_path / "two.exe"
    f.write_bytes(driver + b"\x90" * 32 + driver)  # same driver twice
    assert len(carve_drivers(f)) == 1
