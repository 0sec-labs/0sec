#!/usr/bin/env python3
"""Generate a minimal valid x86-64 Linux ELF binary for P0 gate test fixtures.

The ELF is a static no-op returning 42. Stripped, small.
Used by `tests/test_p0gate.py` to exercise digest verification without a
vulnerability target.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def make_minimal_elf(path: str | Path) -> str:
    """Write a minimal valid x86-64 Linux ELF and return its SHA-256."""
    # Minimal ELF64: EHDR + PHDR + code.
    # _start: mov eax, 60; mov edi, 42; syscall
    code = bytes([
        0xb8, 0x3c, 0x00, 0x00, 0x00,   # mov eax, 60 (SYS_exit)
        0xbf, 0x2a, 0x00, 0x00, 0x00,   # mov edi, 42
        0x0f, 0x05,                      # syscall
    ])

    # ELF header
    e_ident = bytes([
        0x7f, 0x45, 0x4c, 0x46,  # ELF magic
        0x02,                      # 64-bit
        0x01,                      # little endian
        0x01,                      # ELF version
        0x00,                      # OS/ABI (System V)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # padding
    ])
    e_type = 0x0002       # ET_EXEC
    e_machine = 0x003e    # x86-64
    e_version = 0x00000001
    e_entry = 0x400078    # after headers
    e_phoff = 0x0040      # phdr right after ehdr
    e_shoff = 0x0000      # no section headers
    e_flags = 0x00000000
    e_ehsize = 0x0040     # 64 bytes
    e_phentsize = 0x0038  # 56 bytes per phdr
    e_phnum = 0x0001      # 1 program header
    e_shentsize = 0x0000
    e_shnum = 0x0000
    e_shstrndx = 0x0000

    # Program header: PT_LOAD, read+execute
    p_type = 0x00000001   # PT_LOAD
    p_flags = 0x00000005  # PF_R | PF_X
    p_offset = 0x0000000000000000
    p_vaddr = 0x0000000000400000
    p_paddr = 0x0000000000400000
    p_filesz = 0x0000000000000078 + len(code)
    p_memsz = 0x0000000000000078 + len(code)
    p_align = 0x0000000000001000

    import struct
    ehdr = struct.pack(
        "<16s HHIIIIIHHHHHH",
        e_ident, e_type, e_machine, e_version,
        e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum,
        e_shentsize, e_shnum, e_shstrndx,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        p_type, p_flags, p_offset, p_vaddr,
        p_paddr, p_filesz, p_memsz, p_align,
    )

    # Pad after headers before code
    after_phdr = 0x0040 + 0x0038
    pad = b'\x00' * max(0, (after_phdr - len(ehdr) - len(phdr)))

    data = ehdr + phdr + pad + code

    p = Path(path)
    p.write_bytes(data)
    p.chmod(0o755)

    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    sha = make_minimal_elf(sys.argv[1])
    print(sha)