"""Windows driver ICFG tiers — the indirect-edge recovery behind the dispatch BFS.

Pure-logic tests over a mocked r2 JSON model shaped like the FXDrv64.sys measurement
(foxconn FOX ONE): the world-accessible MajorFunction[14] handler reaches NOTHING
directly — it indexes a MajorFunction stub array (``lea rax,[table]``), each stub is a
C++ vtable thunk (``mov rax,[rcx]; jmp [rax+off]``) resolved against an
install-stamped vtable, and the real sub-handler dispatches its IOCTLs through an
MSVC relative switch table whose case blocks call the port-I/O leaves. The ICFG tiers
must connect handler -> stub -> vtable member -> switch-case callee with PRECISE
edges only (no address-taken speculation), so a stripped indirect-dispatch driver's
primitive surface is reachable statically.
"""

from __future__ import annotations

import json
import struct

from zeroverse.backends.rizin import (
    _augmented_driver_adjacency,
    _call_adjacency,
    _driver_dispatch_handlers,
    _reachable,
    _windows_driver_priority,
)

_TEXT = (0x1000, 0x2000)
_RDATA = (0x3000, 0x4000)
_DATA = (0x5000, 0x6000)

HANDLER = 0x1200
STUB0, STUB1 = 0x1800, 0x1808
DEFAULT_MF, MJ14, LEAF = 0x1300, 0x1400, 0x1500
CASE = 0x1450
STUB_TABLE = 0x5000
VTABLE = 0x3000
SWITCH_DW = 0x3200


class _FakeIcfgDriverR2:
    """r2 stand-in with stateful ``af`` materialization and raw memory.

    Graph: entry0 -> DriverEntry(0x1100) installs HANDLER at MajorFunction[14].
    HANDLER lea's STUB_TABLE (2 stubs) and ends in an unresolved indirect call.
    STUB1 thunks into VTABLE slot 2 = MJ14 (the DEVICE_CONTROL sub-handler);
    STUB0 thunks into slot 1 = DEFAULT_MF. VTABLE is install-stamped by a
    constructor (0x1900, unreachable from dispatch — evidence is global). MJ14
    dispatches via an MSVC relative switch (dword offsets at SWITCH_DW, base
    MJ14) to CASE, which direct-calls LEAF (the port-I/O primitive site).
    """

    OPS = {
        0x1000: [{"disasm": "jmp 0x1100", "type": "jmp", "jump": 0x1100}],
        0x1100: [
            {"disasm": "lea rax, [fcn.00001200]", "type": "lea", "ptr": HANDLER},
            {"disasm": "mov qword [rdi + 0xe0], rax", "type": "mov"},
            {"disasm": "ret", "type": "ret"},
        ],
        HANDLER: [
            {"disasm": "mov rcx, qword [0x000050f0]", "type": "mov", "ptr": 0x50F0},
            {"disasm": "lea rax, [0x00005000]", "type": "lea", "ptr": STUB_TABLE},
            {"disasm": "mov r9, qword [rax + r9*8]", "type": "mov"},
            {"disasm": "mov r10, qword [rcx]", "type": "mov"},
            {"disasm": "call qword [r10 + 0x18]", "type": "ircall"},
            {"disasm": "ret", "type": "ret"},
        ],
        STUB0: [
            {"disasm": "mov rax, qword [rcx]", "type": "mov"},
            {"disasm": "jmp qword [rax + 0x8]", "type": "ujmp"},
        ],
        STUB1: [
            {"disasm": "mov rax, qword [rcx]", "type": "mov"},
            {"disasm": "jmp qword [rax + 0x10]", "type": "ujmp"},
        ],
        DEFAULT_MF: [{"disasm": "ret", "type": "ret"}],
        MJ14: [
            {"disasm": "cmp eax, 1", "type": "cmp"},
            {"disasm": "ja 0x14ff", "type": "cjmp", "jump": 0x14FF},
            {"disasm": f"lea r8, [0x0000{SWITCH_DW:x}]", "type": "lea", "ptr": SWITCH_DW},
            {"disasm": "movsxd rax, dword [r8 + rax*4]", "type": "mov"},
            {"disasm": f"lea r8, [0x0000{MJ14:x}]", "type": "lea", "ptr": MJ14},
            {"disasm": "add rax, r8", "type": "add"},
            {"disasm": "jmp rax", "type": "rjmp"},
            {"disasm": "ret", "type": "ret"},
        ],
        LEAF: [
            {"disasm": "mov dx, word [rcx]", "type": "mov"},
            {"disasm": "out dx, eax", "type": "io"},
            {"disasm": "ret", "type": "ret"},
        ],
        0x1900: [  # constructor: stamps VTABLE into the object (install evidence)
            {"disasm": f"lea rax, [0x0000{VTABLE:x}]", "type": "lea", "ptr": VTABLE},
            {"disasm": "mov qword [rcx], rax", "type": "mov"},
            {"disasm": "ret", "type": "ret"},
        ],
    }
    CASE_OPS = [
        {"disasm": f"call fcn.0000{LEAF:x}", "type": "call", "jump": LEAF},
        {"disasm": "jmp 0x14ff", "type": "jmp", "jump": 0x14FF},
    ]

    def __init__(self) -> None:
        # stubs start OUT of the function list (nothing calls them directly — r2's
        # aaa never materializes them); ``af`` adds them, like the live cascade.
        self._funcs = {0x1000, 0x1100, HANDLER, DEFAULT_MF, MJ14, LEAF, 0x1900}
        mem = bytearray(_RDATA[1] - _RDATA[0])
        struct.pack_into("<3Q", mem, VTABLE - _RDATA[0], 0x1300, DEFAULT_MF, MJ14)
        struct.pack_into("<i", mem, SWITCH_DW - _RDATA[0], CASE - MJ14)
        self._rdata = bytes(mem)
        dmem = bytearray(_DATA[1] - _DATA[0])
        struct.pack_into("<2Q", dmem, STUB_TABLE - _DATA[0], STUB0, STUB1)
        self._data = bytes(dmem)

    def cmd(self, c: str) -> str:
        if c == "iIj":
            return json.dumps({"bintype": "pe", "os": "native"})
        if c == "iij":
            return json.dumps([{"libname": "ntoskrnl.exe", "name": "IoCreateDevice"}])
        if c == "iej":
            return json.dumps([{"vaddr": 0x1000}])
        if c == "iSj":
            return json.dumps([
                {"name": ".text", "vaddr": _TEXT[0], "vsize": _TEXT[1] - _TEXT[0], "perm": "-r-x"},
                {
                    "name": ".rdata", "vaddr": _RDATA[0],
                    "vsize": _RDATA[1] - _RDATA[0], "perm": "-r--",
                },
                {"name": ".data", "vaddr": _DATA[0], "vsize": _DATA[1] - _DATA[0], "perm": "-rw-"},
                {"name": ".pdata", "vaddr": 0x7000, "vsize": 0x1000, "perm": "-r--"},
            ])
        if c == "aflj":
            return json.dumps([{"addr": a, "name": f"fcn.{a:08x}"} for a in sorted(self._funcs)])
        if c.startswith("af @ 0x"):
            self._funcs.add(int(c.split("0x", 1)[1], 16))
            return ""
        if c.startswith("pdfj @ 0x"):
            addr = int(c.split("0x", 1)[1], 16)
            return json.dumps({"ops": self.OPS.get(addr, [])})
        if c.startswith("pdj ") and " @ 0x" in c:
            addr = int(c.split("0x", 1)[1], 16)
            return json.dumps(self.CASE_OPS if addr == CASE else [])
        if c.startswith("p8 ") and " @ 0x" in c:
            size = int(c.split()[1])
            addr = int(c.split("0x", 1)[1], 16)
            if _RDATA[0] <= addr < _RDATA[1]:
                off = addr - _RDATA[0]
                return self._rdata[off:off + size].hex()
            if _DATA[0] <= addr < _DATA[1]:
                off = addr - _DATA[0]
                return self._data[off:off + size].hex()
            return ""
        return ""


def test_direct_graph_cannot_cross_indirect_dispatch() -> None:
    """The BEFORE state: direct-call reachability leaves the whole IOCTL surface
    behind the indirect dispatch — the measured FXDrv64 wall (1/103 reachable)."""
    r2 = _FakeIcfgDriverR2()
    dispatch = _driver_dispatch_handlers(r2)
    assert dispatch == {HANDLER}
    funcs = json.loads(r2.cmd("aflj"))
    adj, _ = _call_adjacency(r2, funcs, {})
    reach = _reachable(adj, dispatch)
    assert MJ14 not in reach and LEAF not in reach


def test_icfg_tiers_connect_handler_to_primitive_leaf() -> None:
    """The AFTER state: ptr-table (stub array) -> vtable-thunk (install-stamped
    vtable) -> switch-case (MSVC table + orphaned case call) lands the port-I/O
    leaf — precise tiers only, zero address-taken speculation."""
    r2 = _FakeIcfgDriverR2()
    dispatch = _driver_dispatch_handlers(r2)
    funcs = json.loads(r2.cmd("aflj"))
    stats: dict[str, int] = {}
    adj, _ = _augmented_driver_adjacency(r2, dispatch, funcs, {}, stats)
    reach = _reachable(adj, dispatch)
    assert STUB1 in reach          # ptr-table: handler lea's the stub array
    assert MJ14 in reach           # vtable-thunk: stub slot 2 of the installed vtable
    assert LEAF in reach           # switch-case: the case block's direct call
    assert stats.get("ptr-table") and stats.get("vtable-thunk") and stats.get("switch-case")
    assert "addr-taken" not in stats  # precise tiers only — no speculation needed
    # and the stubs were materialized into r2's function list by the fixpoint
    assert STUB1 in r2._funcs


def test_driver_priority_carries_indirect_reachables() -> None:
    """The LOCATE priority set includes the indirectly-dispatched sub-handler and
    its leaf (tier 2), with the dispatch handler at tier 0."""
    prio = _windows_driver_priority(_FakeIcfgDriverR2())
    assert prio[HANDLER] == 0
    assert prio.get(MJ14) == 2
    assert prio.get(LEAF) == 2
    assert 0x1900 not in prio  # the constructor is not dispatch-reachable
