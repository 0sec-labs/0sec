"""Static installer unpacker — format sniffing, harvest, and the static-only chain.

The live-tool paths (7zz on a real zip; innoextract/unshield when present) are
exercised against locally-crafted fixtures, so the suite needs no network and no
vendor binaries. The static-only invariant is structural: the module's only spawned
processes are the unpacker CLIs; these tests never invoke an installer either.
"""

from __future__ import annotations

import shutil
import struct
import zipfile

import pytest

from zeroverse.installer_unpack import (
    UnpackResult,
    _harvest,
    available_tools,
    sniff_kind,
    unpack_drivers,
)


def _make_pe(subsystem: int, *, machine: int = 0x8664, raw_ptr: int = 0x200,
             raw_size: int = 0x200) -> bytes:
    """Minimal PE32+ image (same builder style as the carver tests)."""
    total = raw_ptr + raw_size
    buf = bytearray(total)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)
    po = 0x40
    buf[po : po + 4] = b"PE\0\0"
    struct.pack_into("<H", buf, po + 4, machine)
    struct.pack_into("<H", buf, po + 6, 1)
    struct.pack_into("<H", buf, po + 20, 0xF0)
    opt = po + 24
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<H", buf, opt + 0x44, subsystem)
    sec = opt + 0xF0
    buf[sec : sec + 8] = b".text\0\0\0"
    struct.pack_into("<I", buf, sec + 16, raw_size)
    struct.pack_into("<I", buf, sec + 20, raw_ptr)
    return bytes(buf)


# --- sniffing ----------------------------------------------------------------


def test_sniff_magic_kinds(tmp_path) -> None:
    cases = {
        "pkg.zip": (b"PK\x03\x04" + b"\x00" * 64, "zip"),
        "pkg.cab": (b"MSCF" + b"\x00" * 64, "cab"),
        "pkg.7z": (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64, "7z"),
        "pkg.rar": (b"Rar!\x1a\x07\x00" + b"\x00" * 64, "rar"),
        "pkg.msi": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64, "msi"),
        "data1.cab": (b"ISc(" + b"\x00" * 64, "installshield-cab"),
    }
    for name, (blob, want) in cases.items():
        p = tmp_path / name
        p.write_bytes(blob)
        assert sniff_kind(p) == want, name


def test_sniff_iso_by_primary_volume_descriptor(tmp_path) -> None:
    blob = bytearray(0x10000)
    blob[0x8001:0x8006] = b"CD001"
    p = tmp_path / "drivercd.iso"
    p.write_bytes(bytes(blob))
    assert sniff_kind(p) == "iso"


def test_sniff_pe_installer_hints(tmp_path) -> None:
    pe = _make_pe(subsystem=2)
    for hint, want in ((b"Nullsoft Install System", "nsis"),
                       (b"Inno Setup", "inno"),
                       (b"InstallShield", "installshield")):
        p = tmp_path / f"setup-{want}.exe"
        p.write_bytes(pe + b"\x00" * 16 + hint)
        assert sniff_kind(p) == want
    plain = tmp_path / "plain.exe"
    plain.write_bytes(pe)
    assert sniff_kind(plain) == "pe"


# --- harvest (no tools needed) ------------------------------------------------


def test_harvest_collects_sys_and_carves(tmp_path) -> None:
    driver = _make_pe(subsystem=1)
    embedded = _make_pe(subsystem=1, raw_size=0x300)  # a different driver image
    (tmp_path / "drv").mkdir()
    (tmp_path / "drv" / "board.sys").write_bytes(driver)
    utility = _make_pe(subsystem=2)
    (tmp_path / "drv" / "utility.exe").write_bytes(utility + b"\x90" * 8 + embedded)
    (tmp_path / "drv" / "readme.txt").write_bytes(b"docs")

    res = UnpackResult(package="pkg", kind="zip")
    out = []
    _harvest(tmp_path, out, set(), "7zz", "zip", res)
    kinds = {(d.source, d.member.split("@")[0].rsplit("/", 1)[-1]) for d in out}
    assert ("7zz", "board.sys") in kinds          # loose .sys picked up
    assert ("carve", "utility.exe") in kinds      # embedded driver carved
    assert len({d.sha256 for d in out}) == 2      # distinct drivers both kept


def test_harvest_dedupes_identical_drivers(tmp_path) -> None:
    driver = _make_pe(subsystem=1)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "board.sys").write_bytes(driver)
    (tmp_path / "b" / "board-copy.sys").write_bytes(driver)  # same bytes, twice
    res = UnpackResult(package="pkg", kind="zip")
    out = []
    _harvest(tmp_path, out, set(), "7zz", "zip", res)
    assert len(out) == 1


def test_harvest_picks_up_innoextract_rename_suffixes(tmp_path) -> None:
    """Multi-arch Inno packages ship same-named members per arch; with
    ``--collisions=rename`` innoextract lands them as ``nptdrv2.sys$0`` —
    the harvest must still see them (measured on Moxa drvmgr 4.2, where the
    default overwrite kept only the ARM64 copy and the x64 driver was lost)."""
    x64 = _make_pe(subsystem=1)
    arm64 = _make_pe(subsystem=1, machine=0xAA64, raw_size=0x300)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "nptdrv2.sys$0").write_bytes(x64)
    (tmp_path / "app" / "nptdrv2.sys").write_bytes(arm64)
    res = UnpackResult(package="pkg", kind="inno")
    out = []
    _harvest(tmp_path, out, set(), "innoextract", "inno", res)
    assert len(out) == 2
    by_member = {d.member.rsplit("/", 1)[-1]: d.machine for d in out}
    assert by_member["nptdrv2.sys$0"] == 0x8664
    assert by_member["nptdrv2.sys"] == 0xAA64


# --- live-tool integration (crafted fixtures, no network) ---------------------


@pytest.mark.skipif(not shutil.which("7zz"), reason="7zz not installed")
def test_unpack_zip_recovers_driver(tmp_path) -> None:
    driver = _make_pe(subsystem=1)
    pkg = tmp_path / "board-driver.zip"
    with zipfile.ZipFile(pkg, "w") as zf:
        zf.writestr("drivers/board64.sys", driver)
        zf.writestr("docs/readme.txt", b"manual")
    res = unpack_drivers(pkg, tmp_path / "out")
    assert res.kind == "zip"
    assert len(res.drivers) == 1
    d = res.drivers[0]
    assert d.source == "7zz" and d.member.endswith("board64.sys")
    assert d.machine == 0x8664
    assert res.extracted_files >= 2


@pytest.mark.skipif(not shutil.which("7zz"), reason="7zz not installed")
def test_unpack_recurses_into_nested_cab(tmp_path) -> None:
    """One level of payload recursion: a .cab inside a .zip holding the .sys."""
    inner = tmp_path / "data1.cab"
    # a real cab would need a writer; 7zz can read a zip-named-cab? No — craft a
    # real CAB via cabarc is unavailable, so nest a ZIP with a .cab suffix: 7zz
    # sniffs content, not extension, on re-extract.
    import zipfile as _zf
    driver = _make_pe(subsystem=1)
    with _zf.ZipFile(inner, "w") as zf:
        zf.writestr("board.sys", driver)
    outer = tmp_path / "pkg.zip"
    with _zf.ZipFile(outer, "w") as zf:
        zf.write(inner, "data1.cab")
    res = unpack_drivers(outer, tmp_path / "out")
    assert any(d.member.endswith("board.sys") for d in res.drivers), res.notes


def test_carve_fallback_on_plain_pe(tmp_path) -> None:
    """A non-installer PE with an embedded driver: no extraction attempted, the
    carver still recovers the driver — the static chain never dead-ends."""
    driver = _make_pe(subsystem=1)
    stub = _make_pe(subsystem=2)
    pkg = tmp_path / "utility.exe"
    pkg.write_bytes(stub + b"\x00" * 32 + driver)
    res = unpack_drivers(pkg, tmp_path / "out")
    assert res.kind == "pe"
    assert any(d.source == "carve" for d in res.drivers)


def test_available_tools_shape() -> None:
    tools = available_tools()
    assert set(tools) == {"7zz", "innoextract", "unshield", "cabextract"}
