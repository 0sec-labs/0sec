"""Stage 1 — ingest / triage.

Dependency-free first pass so ``0verse triage`` works on a bare Python install:
detect container format, architecture, and exploit mitigations straight from the
file bytes. When the ``analyze`` extra (LIEF/capa) is present, richer triage can
layer on top — but the basics never require it.

Formats classified from raw bytes: ELF, Mach-O (thin + universal), and — added in
the M3 second wave (#20) — **PE / PE32+** (Windows). The PE pass reads the
COFF + optional header so a Windows x86-64 binary classifies and routes the same
way an ELF/Mach-O does.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from ._fastpath import contains_any_bytes

# e_machine -> human name (the common ones; extend as needed).
_ELF_MACHINES = {
    0x03: "x86",
    0x3E: "x86-64",
    0x28: "ARM",
    0xB7: "AArch64",
    0x08: "MIPS",
    0xF3: "RISC-V",
    0x14: "PowerPC",
    0x15: "PowerPC64",
}
_ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}

_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PT_INTERP = 3
_PF_X = 0x1

# --- Mach-O constants ------------------------------------------------------
_MACHO_CPU_ABI64 = 0x01000000
_MACHO_CPUS = {
    7: "x86", 12: "ARM", 18: "PowerPC",
    0x01000007: "x86-64", 0x0100000C: "arm64", 0x01000012: "PowerPC64",
}
_MACHO_FILETYPES = {
    1: "OBJECT", 2: "EXEC", 3: "FVMLIB", 4: "CORE", 5: "PRELOAD", 6: "DYLIB",
    7: "DYLINKER", 8: "BUNDLE", 9: "DYLIB_STUB", 10: "DSYM", 11: "KEXT_BUNDLE",
}
_MH_PIE = 0x200000
_MH_ALLOW_STACK_EXECUTION = 0x20000
_MH_NO_HEAP_EXECUTION = 0x01000000

# --- PE constants (#20) ----------------------------------------------------
# IMAGE_FILE_MACHINE_* -> human name. MIPS spellings included for the firmware
# crossover (PE can target MIPS too), though x86-64/ARM64 are the common cases.
_PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0xAA64: "AArch64",
    0x01C0: "ARM",
    0x01C4: "ARM",        # ARMNT (Thumb-2)
    0x0166: "MIPS",       # R4000
    0x0266: "MIPS",       # R16
    0x0366: "MIPS",       # FPU
    0x0466: "MIPS",       # FPU16
    0x0EBC: "EFI-byte-code",
}
_PE_OPT_MAGIC = {0x10B: 32, 0x20B: 64}          # PE32 / PE32+
_IMAGE_FILE_DLL = 0x2000
_IMAGE_FILE_EXECUTABLE = 0x0002
_IMAGE_FILE_SYSTEM = 0x1000
_DLLCH_DYNAMIC_BASE = 0x0040                    # ASLR (≈ PIE)
_DLLCH_NX_COMPAT = 0x0100                       # DEP / NX
_DLLCH_GUARD_CF = 0x4000                        # Control Flow Guard


@dataclass
class Triage:
    path: str
    fmt: str = "unknown"            # ELF | PE | Mach-O | unknown
    arch: str = "unknown"
    bits: int = 0
    endian: str = "unknown"
    kind: str = "unknown"           # EXEC | DYN(PIE) | ...
    stripped: bool | None = None
    mitigations: dict[str, object] = field(default_factory=dict)  # nx / pie / relro / canary
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        m = self.mitigations
        mit = " ".join(
            f"{k}={'on' if v else 'off'}" if isinstance(v, bool) else f"{k}={v}"
            for k, v in m.items()
        )
        return (
            f"{self.fmt} {self.arch} ({self.bits}-bit {self.endian})  "
            f"kind={self.kind}  {mit}"
        )


# --- Linux kernel module (.ko) markers -------------------------------------
# A .ko is a relocatable ELF (ET_REL) carrying the metadata the module loader
# needs. These section/symbol strings survive stripping (the loader requires
# them), so even a stripped vendor/Android .ko classifies — the detection hook
# for the linux-ko seed-bug-classes (see seedbugs.py), mirroring kext->IOKit.
_KMOD_MARKERS = (
    b".modinfo", b".gnu.linkonce.this_module", b"module_layout", b"__this_module",
)


def _looks_like_kmod(data: bytes) -> bool:
    return any(contains_any_bytes(data, _KMOD_MARKERS))


def triage(path: str | Path) -> Triage:
    p = Path(path)
    data = p.read_bytes()
    t = Triage(path=str(p))
    if len(data) < 4:
        t.notes.append("file too small to classify")
        return t

    magic = data[:4]
    if magic == b"\x7fELF":
        _triage_elf(data, t)
    elif magic[:2] == b"MZ":
        _triage_pe(data, t)
    elif magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                   b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        _triage_macho(data, t)
    elif magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        _triage_macho_fat(data, t)
    else:
        t.notes.append(f"unrecognized magic: {magic.hex()}")
    return t


def _triage_elf(data: bytes, t: Triage) -> None:
    t.fmt = "ELF"
    ei_class, ei_data = data[4], data[5]
    t.bits = {1: 32, 2: 64}.get(ei_class, 0)
    t.endian = {1: "little", 2: "big"}.get(ei_data, "unknown")
    end = "<" if ei_data == 1 else ">"

    e_type = struct.unpack_from(end + "H", data, 16)[0]
    e_machine = struct.unpack_from(end + "H", data, 18)[0]
    t.arch = _ELF_MACHINES.get(e_machine, f"machine-0x{e_machine:x}")
    t.kind = _ELF_TYPES.get(e_type, str(e_type))

    # Program-header table -> mitigations.
    if t.bits == 64:
        e_phoff = struct.unpack_from(end + "Q", data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 54)
        ptype_off, pflags_off = 0, 4
    else:
        e_phoff = struct.unpack_from(end + "I", data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 42)
        ptype_off, pflags_off = 0, 24  # ELF32 p_flags sits after p_offset/vaddr/...

    nx = None
    relro = "none"
    has_interp = False
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        if base + e_phentsize > len(data):
            break
        p_type = struct.unpack_from(end + "I", data, base + ptype_off)[0]
        p_flags = struct.unpack_from(end + "I", data, base + pflags_off)[0]
        if p_type == _PT_GNU_STACK:
            nx = not (p_flags & _PF_X)
        elif p_type == _PT_GNU_RELRO:
            relro = "partial"  # full RELRO needs BIND_NOW in .dynamic; refine later
        elif p_type == _PT_INTERP:
            has_interp = True

    # PIE: ET_DYN with an interpreter is a position-independent executable.
    pie = (e_type == 3 and has_interp)
    # Canary + stripped are byte-marker heuristics over the WHOLE file; on a large
    # binary these full scans dominate triage, so the native fast-path finds both
    # in one Aho-Corasick pass (identical booleans to ``x in data``).
    canary, has_symtab = contains_any_bytes(data, (b"__stack_chk_fail", b".symtab"))
    t.stripped = not has_symtab

    t.mitigations = {
        "nx": bool(nx) if nx is not None else False,
        "pie": pie,
        "relro": relro,
        "canary": canary,
    }

    # Linux kernel module (.ko): a relocatable ELF (ET_REL) carrying the module
    # metadata the loader needs. Re-label REL -> KMOD so the seed wiring primes the
    # kernel-module classes (seedbugs.py); the markers survive stripping.
    if e_type == 1 and _looks_like_kmod(data):
        t.kind = "KMOD"
        t.notes.append("Linux kernel module (.ko) — kernel-module LPE hunting surface")


def _triage_pe(data: bytes, t: Triage) -> None:
    """Parse the PE/PE32+ header (#20). Ghidra loads PE natively; this byte-level
    pass gives the dependency-free triage that classifies + routes the target. The
    COFF header's ``Machine`` gives the arch, the optional-header magic the
    bitness, and ``DllCharacteristics`` the NX/ASLR/CFG mitigations."""
    t.fmt = "PE"
    t.endian = "little"  # PE is always little-endian on its supported machines
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        t.notes.append("truncated DOS header")
        return
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        t.notes.append("MZ stub without a PE header (DOS/16-bit?)")
        return

    coff = pe_off + 4
    machine, _nsec = struct.unpack_from("<HH", data, coff)
    characteristics = struct.unpack_from("<H", data, coff + 18)[0]
    t.arch = _PE_MACHINES.get(machine, f"machine-0x{machine:x}")

    opt = coff + 20
    opt_magic = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
    t.bits = _PE_OPT_MAGIC.get(opt_magic, 64 if machine in (0x8664, 0xAA64) else 32)

    if characteristics & _IMAGE_FILE_DLL:
        t.kind = "DLL"
    elif characteristics & _IMAGE_FILE_SYSTEM:
        t.kind = "SYS"  # driver / kernel module
    elif characteristics & _IMAGE_FILE_EXECUTABLE:
        t.kind = "EXEC"
    else:
        t.kind = "OBJECT"

    # DllCharacteristics sits at offset 70 within the optional header for BOTH
    # PE32 and PE32+ (the layout converges at offset 32 onward), so the same
    # offset works regardless of bitness.
    nx = pie = cfg = None
    dch_off = opt + 70
    if dch_off + 2 <= len(data):
        dch = struct.unpack_from("<H", data, dch_off)[0]
        nx = bool(dch & _DLLCH_NX_COMPAT)
        pie = bool(dch & _DLLCH_DYNAMIC_BASE)
        cfg = bool(dch & _DLLCH_GUARD_CF)

    # Stack canary (MSVC /GS) + stripped: cheap byte heuristics. MSVC names the
    # cookie ``__security_cookie``; mingw uses the libssp ``__stack_chk_fail``.
    # One native pass covers all four whole-file markers.
    sec_cookie, stk_chk, has_debug, has_pdb = contains_any_bytes(
        data, (b"__security_cookie", b"__stack_chk_fail", b".debug", b"PDB")
    )
    canary = sec_cookie or stk_chk
    t.stripped = not has_debug and not has_pdb

    t.mitigations = {
        "nx": bool(nx),
        "aslr": bool(pie),     # PE's PIE equivalent (DYNAMIC_BASE / ASLR)
        "cfg": bool(cfg),      # Control Flow Guard
        "canary": canary,
    }
    if t.kind in ("SYS", "DLL"):
        t.notes.append(f"PE {t.kind} — kernel/driver or library surface")


def _triage_macho(data: bytes, t: Triage) -> None:
    """Parse a thin (single-arch) Mach-O header. Covers M3 ``format:macho``:
    executables, objects (``.o``), dylibs, and kernel-extension bundles (kexts) —
    the last is the IOKit hunting surface (see ``seedbugs.py``)."""
    t.fmt = "Mach-O"
    magic = data[:4]
    # Byte-swapped (CIGAM) magics start with 0xfe; native (MAGIC) with 0xc[ef].
    big = magic[0] == 0xFE
    t.endian = "big" if big else "little"
    end = ">" if big else "<"
    t.bits = 64 if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32

    cputype, _cpusub, filetype, _ncmds, _sizeofcmds, flags = struct.unpack_from(
        end + "IIIIII", data, 4
    )
    t.arch = _MACHO_CPUS.get(cputype, f"cpu-0x{cputype:x}")
    t.kind = _MACHO_FILETYPES.get(filetype, str(filetype))

    pie = bool(flags & _MH_PIE) or filetype == 6  # dylibs/kexts are position-independent
    nx = not (flags & _MH_ALLOW_STACK_EXECUTION)
    # Canary / stripped: same cheap byte heuristics as ELF (Mach-O mangles the
    # guard as ___stack_chk_fail; LC_SYMTAB local syms vanish when stripped).
    # ``___stack_chk_fail`` contains ``__stack_chk_fail``, so the second marker is
    # redundant for presence — but keep both for an explicit one-pass scan.
    stk3, stk2, has_main = contains_any_bytes(
        data, (b"___stack_chk_fail", b"__stack_chk_fail", b"_main")
    )
    canary = stk3 or stk2
    t.stripped = not has_main and filetype == 2

    t.mitigations = {"nx": nx, "pie": pie, "canary": canary}
    if t.kind == "KEXT_BUNDLE":
        t.notes.append("kernel extension (kext) — IOKit user-client hunting surface")


def _triage_macho_fat(data: bytes, t: Triage) -> None:
    """A universal ('fat') Mach-O wraps several thin Mach-Os. Report each slice's
    arch; Ghidra/0verse operate on a chosen slice downstream."""
    t.fmt = "Mach-O"
    t.kind = "FAT"
    t.endian = "big" if data[:4] == b"\xca\xfe\xba\xbe" else "little"
    end = ">" if data[:4] == b"\xca\xfe\xba\xbe" else "<"
    nfat = struct.unpack_from(end + "I", data, 4)[0]
    arches: list[str] = []
    for i in range(min(nfat, 16)):
        base = 8 + i * 20
        if base + 8 > len(data):
            break
        cputype = struct.unpack_from(end + "I", data, base)[0]
        arches.append(_MACHO_CPUS.get(cputype, f"cpu-0x{cputype:x}"))
    t.arch = "+".join(arches) if arches else "fat"
    t.notes.append(f"universal Mach-O with {nfat} slice(s): {', '.join(arches)}")
