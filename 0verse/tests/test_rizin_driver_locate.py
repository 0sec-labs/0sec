"""Windows kernel-driver LOCATE priority (crutch-free) — pure logic, no toolchain.

A driver inlines its copies, so the libc/interceptor sink anchor is empty and the raw
copy-shape floods (measured: 79% of vmswitch's 3056 funcs). The driver signal is
structural: the ``IRP_MJ_DEVICE_CONTROL`` handler installed at
``DriverObject->MajorFunction[14]`` (offset 0xE0) plus the call-graph REACHABLE from
it. These tests mock r2's JSON so they run anywhere; the live behaviour is measured on
dbutil_2_3.sys (handler #1, memcpy #2), iqvw64e.sys (handler #1, CVE-2015-2291
primitives #3/#4), and vmswitch.sys (3056 funcs -> 97 reachable / 68 tight, in budget).
"""

from __future__ import annotations

import json

from zeroverse.backends.rizin import (
    _driver_dispatch_handlers,
    _is_windows_kernel_driver,
    _windows_driver_priority,
)


class _FakeDriverR2:
    """r2pipe stand-in answering iIj/iij/iej/aflj/pdfj from a synthetic driver model.

    Model: entry0(0x1000) tail-jmps to DriverEntry(0x1100), which installs handler
    0x1200 into MajorFunction[14]; the handler calls sink 0x1300 (an inlined copy);
    0x9000 is an UNRELATED inlined copy that must NOT be prioritised (unreachable).
    The lea at DriverEntry is rendered symbolically (``[fcn.00001200]``) to exercise
    the resolved-``ptr`` keying — a disasm-text match would miss it.
    """

    OPS = {
        0x1000: [{"disasm": "jmp 0x1100", "type": "jmp", "jump": 0x1100}],
        0x1100: [
            {"disasm": "lea rax, [fcn.00001200]", "type": "lea", "ptr": 0x1200},
            {"disasm": "mov qword [rdi + 0xe0], rax", "type": "mov"},
            {"disasm": "ret", "type": "ret"},
        ],
        0x1200: [{"disasm": "call fcn.00001300", "type": "call", "jump": 0x1300},
                 {"disasm": "ret", "type": "ret"}],
        0x1300: [
            {"disasm": "mov rax, qword [rdx + rcx]", "type": "mov"},
            {"disasm": "mov qword [rcx], rax", "type": "mov"},
            {"disasm": "mov rax, qword [rdx + rcx + 8]", "type": "mov"},
            {"disasm": "mov qword [rcx + 8], rax", "type": "mov"},
            {"disasm": "mov rax, qword [rdx + rcx + 0x10]", "type": "mov"},
            {"disasm": "mov qword [rcx + 0x10], rax", "type": "mov"},
            {"disasm": "ret", "type": "ret"},
        ],
        0x9000: [
            {"disasm": "mov rax, qword [rdx + rcx]", "type": "mov"},
            {"disasm": "mov qword [rcx], rax", "type": "mov"},
            {"disasm": "mov rax, qword [rdx + rcx + 8]", "type": "mov"},
            {"disasm": "mov qword [rcx + 8], rax", "type": "mov"},
            {"disasm": "mov rax, qword [rdx + rcx + 0x10]", "type": "mov"},
            {"disasm": "mov qword [rcx + 0x10], rax", "type": "mov"},
            {"disasm": "ret", "type": "ret"},
        ],
    }

    def __init__(self, *, bintype="pe", os="native", libname="ntoskrnl.exe"):
        self._info = {"bintype": bintype, "os": os}
        self._imports = [{"libname": libname, "name": "RtlInitUnicodeString"}]

    def cmd(self, c: str) -> str:
        if c == "iIj":
            return json.dumps(self._info)
        if c == "iij":
            return json.dumps(self._imports)
        if c == "iej":
            return json.dumps([{"vaddr": 0x1000}])
        if c == "aflj":
            return json.dumps([{"addr": a, "name": f"fcn.{a:08x}"} for a in self.OPS])
        if c.startswith("pdfj @ 0x"):
            addr = int(c.split("0x", 1)[1], 16)
            return json.dumps({"ops": self.OPS.get(addr, [])})
        return ""  # af @ ..., anything else: no-op


def test_detects_native_pe_driver() -> None:
    assert _is_windows_kernel_driver(_FakeDriverR2()) is True


def test_detects_driver_by_ntoskrnl_import_when_not_native() -> None:
    assert _is_windows_kernel_driver(_FakeDriverR2(os="windows")) is True


def test_non_pe_is_not_a_driver() -> None:
    assert _is_windows_kernel_driver(_FakeDriverR2(bintype="elf", os="linux",
                                                   libname="libc.so.6")) is False


def test_dispatch_handler_recovered_via_resolved_ptr() -> None:
    """The MajorFunction[14] store is found even though the lea renders as
    ``[fcn.00001200]`` (symbolic) — because we key on the resolved ``ptr``, not text."""
    assert _driver_dispatch_handlers(_FakeDriverR2()) == {0x1200}


def test_priority_tiers_dispatch_then_reachable_sink() -> None:
    prio = _windows_driver_priority(_FakeDriverR2())
    assert prio[0x1200] == 0            # dispatch handler
    assert prio[0x1300] == 1            # copy sink reachable from the handler
    assert 0x1100 not in prio           # DriverEntry installs but isn't handler-reachable


def test_unreachable_copy_sink_is_not_prioritised() -> None:
    """The reachability gate is what tames the copy-shape flood: an inlined copy that
    the dispatch handler cannot reach (0x9000) stays out of the priority set."""
    prio = _windows_driver_priority(_FakeDriverR2())
    assert 0x9000 not in prio


class _FakeFrameworkInstallR2(_FakeDriverR2):
    """A driver that installs its DEVICE_CONTROL handler (0x2100) from a function
    (0x2000) NOT reachable from the PE entry — the vmswitch/NDIS case, where the real
    handler is registered through a framework path the direct-call entry BFS never
    reaches. The anchor must still find it (no entry-reachability filter)."""

    OPS = dict(_FakeDriverR2.OPS)
    OPS[0x2000] = [
        {"disasm": "lea rcx, [fcn.00002100]", "type": "lea", "ptr": 0x2100},
        {"disasm": "mov qword [r8 + 0xe0], rcx", "type": "mov"},
        {"disasm": "ret", "type": "ret"},
    ]
    OPS[0x2100] = [{"disasm": "call fcn.00001300", "type": "call", "jump": 0x1300},
                   {"disasm": "ret", "type": "ret"}]


def test_framework_installed_handler_not_dropped() -> None:
    """Regression guard for the REJECTED entry-reachability precision filter: it dropped
    vmswitch's real handler (installed via NDIS, reach 84) and kept only stubs. Both the
    DriverEntry-installed handler AND the framework-installed one must be recovered."""
    from zeroverse.backends.rizin import _driver_dispatch_handlers

    assert _driver_dispatch_handlers(_FakeFrameworkInstallR2()) == {0x1200, 0x2100}


class _FakeStosqInstallR2(_FakeDriverR2):
    """A driver that installs its dispatch routine (0x1200) by FILLING every
    MajorFunction slot — ``lea rdi,[obj+0x70]; lea rax,[handler]; rep stosq`` — with no
    per-slot ``mov [obj+0xe0], handler`` at all. Measured on viragt64.sys, whose only
    +0xe0 write is an unrelated stack store. DriverEntry (0x1100) is rewritten to the
    fill idiom so the recovery is proven independent of the +0xe0 store path."""

    OPS = dict(_FakeDriverR2.OPS)
    OPS[0x1100] = [
        {"disasm": "lea rdi, [rsi + 0x70]", "type": "lea"},  # &MajorFunction[0]
        {"disasm": "lea rax, [fcn.00001200]", "type": "lea", "ptr": 0x1200},  # handler
        {"disasm": "mov ecx, 0x1c", "type": "mov"},
        {"disasm": "rep stosq qword [rdi], rax", "type": "mov"},
        {"disasm": "ret", "type": "ret"},
    ]


def test_dispatch_handler_recovered_via_stosq_fill() -> None:
    """The MajorFunction fill idiom is recovered even with no +0xe0 store: rax at the
    ``rep stosq`` is the routine written into every slot, including DEVICE_CONTROL[14]."""
    assert _driver_dispatch_handlers(_FakeStosqInstallR2()) == {0x1200}
    prio = _windows_driver_priority(_FakeStosqInstallR2())
    assert prio[0x1200] == 0  # dispatch handler
    assert prio[0x1300] == 1  # copy sink reachable from the filled handler


def test_non_driver_returns_empty_priority() -> None:
    """ELF path is untouched: a non-driver yields no driver priority, so _decompile_all
    falls back to the symbol-free sink-caller anchor unchanged."""
    assert _windows_driver_priority(_FakeDriverR2(bintype="elf", os="linux",
                                                  libname="libc.so.6")) == {}


class _FakeX86DriverR2(_FakeDriverR2):
    """A 32-bit driver in the Moxa Mxsport idiom: DriverEntry installs the
    DEVICE_CONTROL handler as a raw IMMEDIATE at MajorFunction[14] == [obj+0x74]
    (x86 DRIVER_OBJECT is half-width). 0x1800 is the real handler (in-code);
    0x9000 must be rejected (out of the executable sections)."""

    OPS = dict(_FakeDriverR2.OPS)
    OPS[0x1100] = [
        {"disasm": "mov dword [edx + 0x74], 0x9000", "type": "mov", "val": 0x9000},
        {"disasm": "mov dword [edx + 0x74], 0x1800", "type": "mov", "val": 0x1800},
        {"disasm": "ret", "type": "ret"},
    ]
    OPS[0x1800] = [{"disasm": "call fcn.00001300", "type": "call", "jump": 0x1300},
                   {"disasm": "ret", "type": "ret"}]

    def cmd(self, c: str) -> str:
        if c == "ij":
            return json.dumps({"bin": {"bits": 32}})
        if c == "iSj":
            return json.dumps([
                {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "-r-x"},
                {"name": ".data", "vaddr": 0x2000, "vsize": 0x1000, "perm": "-rw-"},
            ])
        return super().cmd(c)


def test_x86_dispatch_handler_recovered_via_immediate_store() -> None:
    """The x86 anchor: MajorFunction[14] is [obj+0x74] and the handler is a raw
    immediate — recovered only when it lands in an executable section (0x9000 is
    out-of-code noise and must NOT be taken)."""
    assert _driver_dispatch_handlers(_FakeX86DriverR2()) == {0x1800}
    prio = _windows_driver_priority(_FakeX86DriverR2())
    assert prio[0x1800] == 0
    assert prio[0x1300] == 1  # reachable copy sink


class _FakeX86StosdFillR2(_FakeDriverR2):
    """x86 MajorFunction fill idiom: ``lea edi,[obj+0x3c]; lea eax,[handler];
    rep stosd`` — eax at the fill covers slot 14 (base 0x3c on x86)."""

    OPS = dict(_FakeDriverR2.OPS)
    OPS[0x1100] = [
        {"disasm": "lea edi, [esi + 0x3c]", "type": "lea"},  # &MajorFunction[0]
        {"disasm": "lea eax, [fcn.00001200]", "type": "lea", "ptr": 0x1200},
        {"disasm": "mov ecx, 0x1c", "type": "mov"},
        {"disasm": "rep stosd dword es:[edi], eax", "type": "mov"},
        {"disasm": "ret", "type": "ret"},
    ]

    def cmd(self, c: str) -> str:
        if c == "ij":
            return json.dumps({"bin": {"bits": 32}})
        return super().cmd(c)


def test_x86_dispatch_handler_recovered_via_stosd_fill() -> None:
    assert _driver_dispatch_handlers(_FakeX86StosdFillR2()) == {0x1200}
