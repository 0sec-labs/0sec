"""Arch-aware ABI abstraction (M3 breadth keystone, #18/#19; wave-2 #20/#21).

M1/M2 implicitly assumed x86-64 System V: integer/pointer arguments in
``RDI/RSI/RDX/RCX/R8/R9``, return in ``RAX``. Generalizing 0verse to ARM64 and
Mach-O means the calling convention is no longer fixed, so this module supplies
an ``Abi`` keyed off the program's *processor* (recovered into Ghidra's
``ProgramMeta``).

The M3 second wave adds two more conventions:

  * **MSVC x64** (#20, Windows PE x86-64) — same *arch* as SysV x86-64 but a
    distinct convention: integer args in ``RCX/RDX/R8/R9`` (only four register
    args), a 32-byte caller-allocated *shadow space*, caller stack cleanup, and
    ``RAX`` return. It is therefore selected by *format* (PE), not arch.
  * **MIPS o32** (#21, MIPS/ARM firmware) — ``$a0-$a3`` integer args, ``$v0``
    return, return-address in ``$ra``; the firmware lane emulates it with Qiling.

Why the slicer itself barely changes: it walks Ghidra **high P-Code SSA**, which
is def-use over decompiler *variables* (named params/locals), not physical
registers — so pointer-taint summaries carry over to AArch64/MIPS unchanged. The
ABI matters for the stages that *do* touch the machine: harness argument wiring,
the angr ``call_state`` (angr reads ``proj.arch`` itself, but we surface
arg/return storage for reporting), the right cross-arch dynamic vector
(``qemu-aarch64`` user-mode + the matching AFL++ QEMU-mode ``afl-qemu-trace``),
and — new for #21 — the return-address register a Qiling-driven function call
must seed (``ra_reg``).
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Abi:
    """Calling-convention + machine facts for one architecture/convention.

    ``arch`` is the canonical 0verse arch tag (``x86-64`` / ``aarch64`` / ``arm``
    / ``mips`` / ``x86``); ``int_arg_regs`` is the ordered integer/pointer
    argument register file; ``qemu_user`` / ``afl_qemu_cpu`` drive cross-arch
    dynamic execution; ``ra_reg`` is the return-address register a direct
    (Qiling-emulated) function call seeds (empty when the return address lives on
    the stack, as on x86).
    """

    name: str                       # convention name, e.g. "AAPCS64"
    arch: str                       # canonical arch tag
    bits: int
    int_arg_regs: tuple[str, ...]   # ordered int/pointer arg registers ("" = stack)
    ret_reg: str
    pointer_size: int
    qemu_user: str                  # qemu-user binary (qemu-aarch64, ...)
    afl_qemu_cpu: str               # AFL++ CPU_TARGET tag (aarch64, arm, x86_64, i386)
    endian: str = "little"
    ra_reg: str = ""                # return-address register ("" = stack, x86)
    shadow_space: int = 0           # caller-allocated shadow/home space (MSVC x64 = 32)
    caller_cleanup: bool = False    # caller pops args (MSVC x64); else callee/ABI default
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def stack_args(self) -> bool:
        """True when integer args are passed on the stack (32-bit x86 cdecl)."""
        return not self.int_arg_regs


# --- the registry ----------------------------------------------------------

SYSV_X86_64 = Abi(
    name="SysV-x86-64", arch="x86-64", bits=64,
    int_arg_regs=("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    ret_reg="rax", pointer_size=8, qemu_user="qemu-x86_64", afl_qemu_cpu="x86_64",
)

# #20 — Microsoft x64 (Windows PE). Distinct from SysV: only four integer-arg
# registers, a 32-byte shadow space the caller reserves for them, caller stack
# cleanup. Same machine arch (x86-64) so it is resolved by *format* (PE), not the
# processor — see ``abi_for(..., fmt="PE")``.
MSVC_X64 = Abi(
    name="MS-x64", arch="x86-64", bits=64,
    int_arg_regs=("rcx", "rdx", "r8", "r9"),
    ret_reg="rax", pointer_size=8, qemu_user="qemu-x86_64", afl_qemu_cpu="x86_64",
    shadow_space=32, caller_cleanup=True,
    notes=(
        "Microsoft x64: 4 integer-arg regs (rcx/rdx/r8/r9), 32-byte shadow space, "
        "caller-cleanup; PE is not ELF so it is not qemu-user runnable on Linux",
    ),
)

CDECL_X86 = Abi(
    name="cdecl-x86", arch="x86", bits=32,
    int_arg_regs=(),                      # stack-passed
    ret_reg="eax", pointer_size=4, qemu_user="qemu-i386", afl_qemu_cpu="i386",
    caller_cleanup=True,
    notes=("32-bit x86 passes integer args on the stack (cdecl)",),
)

AAPCS64 = Abi(
    name="AAPCS64", arch="aarch64", bits=64,
    int_arg_regs=("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
    ret_reg="x0", pointer_size=8, qemu_user="qemu-aarch64", afl_qemu_cpu="aarch64",
    ra_reg="x30",
)

AAPCS32 = Abi(
    name="AAPCS", arch="arm", bits=32,
    int_arg_regs=("r0", "r1", "r2", "r3"),
    ret_reg="r0", pointer_size=4, qemu_user="qemu-arm", afl_qemu_cpu="arm",
    ra_reg="lr",
)

# #21 — MIPS o32 (the classic 32-bit embedded/firmware convention). ``$a0-$a3``
# integer args, ``$v0`` return, ``$ra`` return-address. Big-endian is the common
# router/firmware spelling (``mips``); little-endian (``mipsel``) reuses the same
# register file with the opposite byte order + qemu-mipsel.
MIPS_O32 = Abi(
    name="o32", arch="mips", bits=32,
    int_arg_regs=("a0", "a1", "a2", "a3"),
    ret_reg="v0", pointer_size=4, qemu_user="qemu-mips", afl_qemu_cpu="mips",
    endian="big", ra_reg="ra",
    notes=("MIPS o32: $a0-$a3 args, $v0 return, $ra return-address",),
)

MIPSEL_O32 = Abi(
    name="o32-el", arch="mipsel", bits=32,
    int_arg_regs=("a0", "a1", "a2", "a3"),
    ret_reg="v0", pointer_size=4, qemu_user="qemu-mipsel", afl_qemu_cpu="mipsel",
    endian="little", ra_reg="ra",
    notes=("little-endian MIPS o32 (mipsel)",),
)

_BY_ARCH: dict[str, Abi] = {
    "x86-64": SYSV_X86_64,
    "x86": CDECL_X86,
    "aarch64": AAPCS64,
    "arm": AAPCS32,
    "mips": MIPS_O32,
    "mipsel": MIPSEL_O32,
}

# Aliases from Ghidra processor strings, ELF e_machine names, Mach-O cputype
# names, PE machine names, and common spellings → canonical arch tag.
# 64-bit-ambiguous spellings (bare "x86", "arm") are resolved with ``bits`` in
# ``normalize_arch``.
_ALIASES: dict[str, str] = {
    "x86_64": "x86-64", "x86-64": "x86-64", "amd64": "x86-64", "em64t": "x86-64",
    "x64": "x86-64",
    "i386": "x86", "i686": "x86", "ia32": "x86",
    "aarch64": "aarch64", "arm64": "aarch64", "armv8": "aarch64",
    "arm64e": "aarch64", "arm64_32": "aarch64",
    "armv7": "arm", "armhf": "arm", "armel": "arm", "thumb": "arm",
    "mips": "mips", "mipseb": "mips", "mips32": "mips", "mipsbe": "mips",
    "mipsel": "mipsel", "mipsle": "mipsel", "mips32el": "mipsel",
    "ppc": "ppc", "powerpc": "ppc", "riscv": "riscv",
}


def normalize_arch(raw: str, bits: int = 0) -> str:
    """Map any processor/machine spelling to a canonical 0verse arch tag.

    ``bits`` disambiguates the spellings that name a family rather than a width:
    Ghidra reports ``x86`` for both 32- and 64-bit, and ``ARM`` covers AArch32 and
    AArch64 in some loaders.
    """
    s = raw.strip().lower().replace(" ", "")
    if s in _ALIASES:
        canon = _ALIASES[s]
        # bare "arm" alias may actually be aarch64 when 64-bit
        if canon == "arm" and bits == 64:
            return "aarch64"
        return canon
    if s in ("x86", "intel", "metapc"):
        return "x86-64" if bits == 64 else "x86"
    if s == "arm":
        return "aarch64" if bits == 64 else "arm"
    if s.startswith("aarch64"):
        return "aarch64"
    if s.startswith("arm"):
        return "aarch64" if bits == 64 else "arm"
    if s.startswith("mips"):
        return "mipsel" if s.endswith(("el", "le")) else "mips"
    return s


def abi_for(arch_or_processor: str, bits: int = 0, fmt: str = "") -> Abi | None:
    """Resolve an ``Abi`` from a Ghidra processor / ELF-machine / arch tag.

    ``fmt`` selects a *format-specific* convention where the arch alone is
    ambiguous: a PE x86-64 program uses the **Microsoft x64** convention
    (``MSVC_X64``), not SysV — same machine, different calling convention. Returns
    ``None`` for arches 0verse does not yet model a convention for (PPC/RISC-V are
    later follow-ups) so callers degrade honestly rather than mis-wire registers.
    """
    arch = normalize_arch(arch_or_processor, bits)
    if fmt == "PE" and arch == "x86-64":
        return MSVC_X64
    return _BY_ARCH.get(arch)


def host_arch() -> str:
    """Canonical arch of the machine 0verse is running on."""
    return normalize_arch(platform.machine())


# --- cross-arch dynamic execution support ----------------------------------

_BINFMT_DIR = Path("/proc/sys/fs/binfmt_misc")


def binfmt_supports(abi: Abi) -> bool:
    """True when the kernel's ``binfmt_misc`` will transparently exec a target of
    this arch via qemu-user (so ``subprocess.run([binary])`` Just Works — the
    oracle/PoV replay path needs no per-call emulator prefix)."""
    entry = _BINFMT_DIR / abi.qemu_user
    try:
        if not entry.is_file():
            return False
        return "enabled" in entry.read_text()
    except OSError:
        return False


def can_execute(abi: Abi | None, *, fmt: str = "ELF") -> bool:
    """Can this host *natively* run a target with ``abi`` (for the dynamic oracle /
    AFL fuzz)?

    True when the format is natively loadable here (ELF) and the arch is either
    the host arch or has a registered qemu-user binfmt handler. Mach-O and PE are
    never natively runnable on Linux, so their dynamic stage degrades to
    static-only (PE additionally has the Qiling firmware/emulation option — see
    ``firmware.maybe_qiling_runner`` — and WinAFL on a Windows host)."""
    if abi is None or fmt != "ELF":
        return False
    if abi.arch == host_arch():
        return True
    return binfmt_supports(abi)
