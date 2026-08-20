"""Windows kernel-driver LPE triage — pure-logic tests (no toolchain, no binaries).

The no-ACL reachability pre-filter and the sink ranking are exercised against a mocked
r2 JSON model, so these run anywhere. The live end-to-end behaviour on the three
hash-pinned regression samples (dbutil_2_3 / iqvw64e / viragt64) is asserted separately
by ``test_windows_driver_triage_samples.py``, which skips when the private corpus or r2
is absent.
"""

from __future__ import annotations

import json

from zeroverse.windows_driver_triage import (
    _device_names,
    _rank_sinks,
    prefilter,
)


class _FakeTriageR2:
    """r2 stand-in for the triage stages: answers iij (imports), izzj (strings),
    aflj/pdfj (functions), axtj (xrefs to an address).

    Model: dispatch handler 0x1200 (reachable copy-sink 0x1300); a kernel-primitive
    sink 0x1400 that calls MmMapIoSpace and is reachable from the handler. Imports and
    strings default to the world-accessible pattern (symlink, no secure-create, no SDDL).
    """

    IMPORTS = [
        {"name": "IoCreateDevice", "libname": "ntoskrnl.exe"},
        {"name": "IoCreateSymbolicLink", "libname": "ntoskrnl.exe"},
        {"name": "MmMapIoSpace", "libname": "ntoskrnl.exe", "plt": 0x9100},
    ]
    STRINGS = [
        {"string": r"\\Device\\\\Foo"},
        {"string": r"\\DosDevices\\\\Foo"},
    ]
    OPS = {
        0x1200: [{"disasm": "call fcn.00001300", "type": "call", "jump": 0x1300},
                 {"disasm": "call fcn.00001400", "type": "call", "jump": 0x1400},
                 {"disasm": "ret", "type": "ret"}],
        0x1300: [
            {"disasm": "mov al, byte [rdx + rcx]", "type": "mov"},
            {"disasm": "mov byte [rcx], al", "type": "mov"},
            {"disasm": "mov al, byte [rdx + rcx + 1]", "type": "mov"},
            {"disasm": "mov byte [rcx + 1], al", "type": "mov"},
            {"disasm": "mov al, byte [rdx + rcx + 2]", "type": "mov"},
            {"disasm": "mov byte [rcx + 2], al", "type": "mov"},
            {"disasm": "ret", "type": "ret"},
        ],
        0x1400: [{"disasm": "call qword [sym.imp.ntoskrnl.exe_MmMapIoSpace]", "type": "ucall"},
                 {"disasm": "ret", "type": "ret"}],
        0x1500: [{"disasm": "mov dx, ax", "type": "mov"},
                 {"disasm": "out dx, eax", "type": "out"},  # arbitrary port write
                 {"disasm": "ret", "type": "ret"}],
    }

    def __init__(self, *, imports=None, strings=None):
        self._imports = self.IMPORTS if imports is None else imports
        self._strings = self.STRINGS if strings is None else strings

    def cmd(self, c: str) -> str:
        if c == "iIj":
            return json.dumps({"bintype": "pe", "os": "native"})
        if c == "iij":
            return json.dumps(self._imports)
        if c == "izzj":
            return json.dumps(self._strings)
        if c == "iej":
            return json.dumps([{"vaddr": 0x1200}])
        if c == "aflj":
            return json.dumps([{"addr": a, "name": f"fcn.{a:08x}"} for a in self.OPS])
        if c.startswith("pdfj @ 0x"):
            addr = int(c.split("0x", 1)[1], 16)
            return json.dumps({"ops": self.OPS.get(addr, [])})
        if c.startswith("axtj @ 0x"):
            addr = int(c.split("0x", 1)[1], 16)
            if addr == 0x9100:  # xrefs to MmMapIoSpace: called from 0x1400
                return json.dumps([{"fcn_addr": 0x1400, "from": 0x1400,
                                    "opcode": "call MmMapIoSpace"}])
            return json.dumps([])
        return ""


def test_prefilter_flags_world_accessible_no_acl_driver() -> None:
    v = prefilter(_FakeTriageR2())
    assert v.world_accessible is True
    assert "IoCreateSymbolicLink" in v.security_imports
    assert v.sddl_present is False


def test_prefilter_secure_create_is_not_world_accessible() -> None:
    imports = [*_FakeTriageR2.IMPORTS, {"name": "IoCreateDeviceSecure", "libname": "ntoskrnl.exe"}]
    v = prefilter(_FakeTriageR2(imports=imports))
    assert v.world_accessible is False
    assert "secure device creation" in v.reason


def test_prefilter_admin_only_sddl_is_not_world_accessible() -> None:
    # DACL grants GENERIC_ALL to SYSTEM + Builtin Admins only — a real lock-out.
    strings = [*_FakeTriageR2.STRINGS, {"string": "D:P(A;;GA;;;SY)(A;;GA;;;BA)"}]
    v = prefilter(_FakeTriageR2(strings=strings))
    assert v.world_accessible is False
    assert v.sddl_present is True


def test_prefilter_sddl_granting_users_is_world_accessible() -> None:
    # SDDL present but grants GENERIC_ALL to Users (BU) — still world-accessible
    # (the Rzpnk/Razer pattern; "SDDL present" alone is not a lock).
    strings = [*_FakeTriageR2.STRINGS, {"string": "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;BU)"}]
    v = prefilter(_FakeTriageR2(strings=strings))
    assert v.world_accessible is True
    assert v.sddl_present is True


def test_prefilter_no_symlink_is_not_world_accessible() -> None:
    imports = [{"name": "IoCreateDevice", "libname": "ntoskrnl.exe"}]  # device, no symlink
    v = prefilter(_FakeTriageR2(imports=imports))
    assert v.world_accessible is False
    assert "IoCreateSymbolicLink absent" in v.reason


def test_device_names_normalized() -> None:
    # izzj doubles the backslashes; the reported name is the real object path.
    assert _device_names(_FakeTriageR2()) == [r"\Device\Foo", r"\DosDevices\Foo"]


def test_rank_sinks_surfaces_copy_and_kernel_primitive() -> None:
    # priority map as _windows_driver_priority would emit: handler(0), copy-sink(1),
    # primitive caller reachable(2).
    prio = {0x1200: 0, 0x1300: 1, 0x1400: 2}
    handlers, sinks = _rank_sinks(_FakeTriageR2(), prio)
    assert handlers == [0x1200]
    shapes = {s.addr: s.shape for s in sinks}
    assert shapes[0x1300] == "indexed_copy"
    assert shapes[0x1400] == "kernel_primitive:MmMapIoSpace"
    # both sink classes reachable from the handler are present for review.
    assert {0x1300, 0x1400} <= set(shapes)


def test_rank_sinks_surfaces_port_io_primitive() -> None:
    # the overclock/EC driver class: a reachable function issuing arbitrary port I/O
    # (out dx, eax) is an LPE primitive, surfaced even though it is no copy and no Mm*.
    prio = {0x1200: 0, 0x1500: 2}
    _handlers, sinks = _rank_sinks(_FakeTriageR2(), prio)
    shapes = {s.addr: s.shape for s in sinks}
    assert shapes.get(0x1500) == "port_io:out"


class _FakeHalPortR2(_FakeTriageR2):
    """An x86 board driver whose IOCTL handler calls HAL port-I/O — the Moxa
    Mxsport / ICP-DAS shape: boards don't inline ``in``/``out``, they call
    ``WRITE_PORT_UCHAR``/``READ_PORT_UCHAR``. The reachable caller must surface
    as a kernel_primitive sink (port/value taint is the reviewer's question)."""

    IMPORTS = [
        *_FakeTriageR2.IMPORTS,
        {"name": "WRITE_PORT_UCHAR", "libname": "hal.dll", "plt": 37376},
    ]
    OPS = dict(_FakeTriageR2.OPS)
    OPS[0x1600] = [{"disasm": "call qword [sym.imp.hal.dll_WRITE_PORT_UCHAR]", "type": "ucall"},
                   {"disasm": "ret", "type": "ret"}]

    def cmd(self, c: str) -> str:
        if c.startswith("axtj @ 0x"):
            addr = int(c.split("0x", 1)[1], 16)
            if addr == 0x9200:  # xrefs to WRITE_PORT_UCHAR: called from 0x1600
                return json.dumps([{"fcn_addr": 0x1600, "from": 0x1600,
                                    "opcode": "call WRITE_PORT_UCHAR"}])
            return json.dumps([])
        return super().cmd(c)


def test_rank_sinks_surfaces_hal_port_primitive() -> None:
    prio = {0x1200: 0, 0x1600: 2}
    _handlers, sinks = _rank_sinks(_FakeHalPortR2(), prio)
    shapes = {s.addr: s.shape for s in sinks}
    assert shapes.get(0x1600) == "kernel_primitive:WRITE_PORT_UCHAR"
