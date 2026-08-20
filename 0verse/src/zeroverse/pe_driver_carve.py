"""No-execute carver for kernel drivers embedded in Windows utility binaries.

Many world-accessible OEM/utility drivers ship EMBEDDED as a resource inside the user
-mode utility ``.exe`` (dropped to disk at runtime), not as a loose ``.sys`` in the
installer. To triage them statically we must recover the driver bytes WITHOUT running
the installer. This scans a file for embedded PE images whose subsystem is
``IMAGE_SUBSYSTEM_NATIVE`` (1) — i.e. kernel drivers — and carves each to its exact
on-disk length from the section table. Pure byte parsing; nothing is executed.

Used by the driver-triage campaign to source the vendor-archive vein: download a
freely-distributed vendor utility, carve its embedded driver(s), hash-pin, then triage.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

_IMAGE_SUBSYSTEM_NATIVE = 1


@dataclass
class CarvedDriver:
    offset: int  # byte offset of the embedded PE within the container
    machine: int  # COFF machine (0x8664 x64, 0x14c x86, 0x200 ia64)
    pe32_plus: bool
    size: int  # carved on-disk length
    sha256: str
    data: bytes

    @property
    def is_x64(self) -> bool:
        return self.machine == 0x8664


def _carve_at(data: bytes, base: int) -> CarvedDriver | None:
    """Parse a PE at ``base`` and, if it is a native-subsystem driver, carve it."""
    if data[base : base + 2] != b"MZ" or base + 0x40 > len(data):
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, base + 0x3C)[0]
        po = base + e_lfanew
        if po + 0x18 > len(data) or data[po : po + 4] != b"PE\0\0":
            return None
        machine = struct.unpack_from("<H", data, po + 4)[0]
        nsec = struct.unpack_from("<H", data, po + 6)[0]
        szopt = struct.unpack_from("<H", data, po + 20)[0]
        opt = po + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            return None
        # Subsystem sits at optional-header offset 0x44 for both PE32 and PE32+.
        subsystem = struct.unpack_from("<H", data, opt + 0x44)[0]
        if subsystem != _IMAGE_SUBSYSTEM_NATIVE:
            return None
        if not 1 <= nsec <= 96:
            return None
        sectab = opt + szopt
        end = 0
        for k in range(nsec):
            so = sectab + 40 * k
            if so + 40 > len(data):
                return None
            raw = struct.unpack_from("<I", data, so + 16)[0]
            ptr = struct.unpack_from("<I", data, so + 20)[0]
            if ptr and raw:
                end = max(end, ptr + raw)
        if end <= 0 or base + end > len(data):
            return None
        blob = data[base : base + end]
        return CarvedDriver(
            offset=base, machine=machine, pe32_plus=(magic == 0x20B), size=end,
            sha256=hashlib.sha256(blob).hexdigest(), data=blob,
        )
    except Exception:
        return None


def carve_drivers(path: str | Path) -> list[CarvedDriver]:
    """All distinct native-subsystem driver images embedded in ``path`` (deduped by
    content hash). Never executes the file."""
    data = Path(path).read_bytes()
    out: list[CarvedDriver] = []
    seen: set[str] = set()
    i = 0
    while True:
        j = data.find(b"MZ", i)
        if j < 0:
            break
        i = j + 2
        r = _carve_at(data, j)
        if r and r.sha256 not in seen:
            seen.add(r.sha256)
            out.append(r)
    return out
