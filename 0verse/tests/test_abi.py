"""Arch-aware ABI (#18/#19; wave-2 #20/#21): processor/format → calling
convention + cross-arch vector."""

from __future__ import annotations

from zeroverse.abi import (
    AAPCS32,
    AAPCS64,
    MIPS_O32,
    MSVC_X64,
    SYSV_X86_64,
    abi_for,
    can_execute,
    host_arch,
    normalize_arch,
)


def test_normalize_arch_aliases() -> None:
    assert normalize_arch("AARCH64") == "aarch64"
    assert normalize_arch("arm64") == "aarch64"
    assert normalize_arch("ARM", 64) == "aarch64"   # 64-bit ARM family is AArch64
    assert normalize_arch("ARM", 32) == "arm"
    assert normalize_arch("x86", 64) == "x86-64"
    assert normalize_arch("x86", 32) == "x86"
    assert normalize_arch("x86_64") == "x86-64"
    assert normalize_arch("MIPS") == "mips"
    assert normalize_arch("mipsel") == "mipsel"
    assert normalize_arch("mipsle") == "mipsel"


def test_aarch64_aapcs64() -> None:
    abi = abi_for("AARCH64", 64)
    assert abi is AAPCS64
    assert abi.int_arg_regs[:2] == ("x0", "x1")
    assert abi.int_arg_regs[-1] == "x7"
    assert abi.ret_reg == "x0"
    assert abi.pointer_size == 8
    assert abi.qemu_user == "qemu-aarch64"
    assert abi.afl_qemu_cpu == "aarch64"
    assert abi.ra_reg == "x30"
    assert not abi.stack_args


def test_arm32_aapcs() -> None:
    abi = abi_for("ARM", 32)
    assert abi is AAPCS32
    assert abi.int_arg_regs == ("r0", "r1", "r2", "r3")
    assert abi.ret_reg == "r0"
    assert abi.pointer_size == 4
    assert abi.afl_qemu_cpu == "arm"
    assert abi.ra_reg == "lr"


def test_x86_64_sysv() -> None:
    abi = abi_for("x86", 64)
    assert abi is SYSV_X86_64
    assert abi.int_arg_regs[0] == "rdi"
    assert abi.ret_reg == "rax"


def test_x86_32_cdecl_is_stack_args() -> None:
    abi = abi_for("x86", 32)
    assert abi is not None and abi.stack_args


def test_msvc_x64_selected_by_pe_format() -> None:
    # Same machine arch (x86-64) but PE selects the Microsoft x64 convention.
    pe = abi_for("x86", 64, fmt="PE")
    assert pe is MSVC_X64
    assert pe.int_arg_regs == ("rcx", "rdx", "r8", "r9")   # only 4 register args
    assert pe.ret_reg == "rax"
    assert pe.shadow_space == 32
    assert pe.caller_cleanup is True
    # ...and it is genuinely distinct from SysV (RDI/RSI/... 6 register args).
    assert abi_for("x86", 64) is SYSV_X86_64
    assert pe is not SYSV_X86_64


def test_pe_only_overrides_x86_64() -> None:
    # PE fmt does not change a MIPS/ARM resolution (only x86-64 has the SysV/MSVC
    # ambiguity).
    assert abi_for("MIPS", 32, fmt="PE") is MIPS_O32
    assert abi_for("AARCH64", 64, fmt="PE") is AAPCS64


def test_mips_o32() -> None:
    abi = abi_for("mips", 32)
    assert abi is MIPS_O32
    assert abi.int_arg_regs == ("a0", "a1", "a2", "a3")
    assert abi.ret_reg == "v0"
    assert abi.ra_reg == "ra"
    assert abi.pointer_size == 4
    assert abi.endian == "big"
    assert abi.qemu_user == "qemu-mips"


def test_mipsel_little_endian() -> None:
    abi = abi_for("mipsel", 32)
    assert abi is not None
    assert abi.arch == "mipsel"
    assert abi.endian == "little"
    assert abi.qemu_user == "qemu-mipsel"
    assert abi.int_arg_regs == ("a0", "a1", "a2", "a3")


def test_unmodelled_arch_returns_none() -> None:
    assert abi_for("ppc", 32) is None        # later follow-up, degrade honestly
    assert abi_for("riscv", 64) is None


def test_host_arch_is_canonical() -> None:
    assert host_arch() in ("x86-64", "aarch64", "arm", "x86", "mips", "mipsel")


def test_can_execute_macho_and_pe_never_runnable_on_linux() -> None:
    # Neither Mach-O nor PE is natively loadable on Linux → static-only.
    assert can_execute(AAPCS64, fmt="Mach-O") is False
    assert can_execute(MSVC_X64, fmt="PE") is False
    assert can_execute(None, fmt="ELF") is False
