"""rizin / radare2 backend (M5 #27, ``backend:rizin``).

A non-Ghidra decompiler front-end: drives ``r2`` (radare2/rizin) over ``r2pipe``,
decompiles each function with **r2ghidra's ``pdg``** (a self-contained C++ port of
Ghidra's decompiler — no Java, no ``GHIDRA_HOME``), and builds the slicer IL from
that pseudo-C via ``cdecomp``. When ``pdg`` is absent it falls back to r2's native
``pdc`` pseudo-C; either way the engine runs with Ghidra's Java toolchain disabled.

Fidelity vs the Ghidra backend (honest):
  * IL is mined from pseudo-C text, not High P-Code SSA — see ``cdecomp`` for the
    single-def-per-var / no-address caveats. The angr reachability stage is skipped
    (no per-sink addresses), the slice + differential oracle still confirm.
  * Indirect/virtual calls that ``pdg`` renders as ``(*fp)(...)`` carry no callee
    name and are dropped (recorded as unresolved edges where r2 flags them).
"""

from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from typing import Any

from ..abi import normalize_arch
from . import _noise
from .cdecomp import build_il, normalize_c
from .contract import ProgramAdapter, ProgramMeta

# r2 arch tag -> 0verse canonical arch (abi.normalize_arch handles the rest).
_ARCH_MAP = {
    "x86": "x86", "x86-64": "x86-64", "arm": "ARM", "arm64": "AArch64",
    "mips": "MIPS", "ppc": "PowerPC",
}


def r2_available() -> bool:
    """True when both the ``r2`` binary and the ``r2pipe`` module are present."""
    if shutil.which("r2") is None and shutil.which("radare2") is None:
        return False
    try:
        import r2pipe  # noqa: F401
    except Exception:
        return False
    return True


class RizinBackend:
    name = "rizin"

    def available(self) -> bool:
        return r2_available()

    def analyze(self, binary: str | Path, *, timeout: int = 120) -> ProgramAdapter:
        import r2pipe

        r2 = r2pipe.open(str(binary), flags=["-2"])  # -2: silence stderr
        try:
            r2.cmd("e bin.relocs.apply=true")
            r2.cmd("e scr.color=0")
            r2.cmd("aaa")
            meta = self._meta(r2)
            decompiled = self._decompile_all(r2, meta, timeout=timeout)
        finally:
            r2.quit()

        meta.decompiled_c = decompiled
        insts, defs, callgraph = build_il(decompiled)
        meta.callgraph = callgraph
        return ProgramAdapter(insts, defs, {}, {}, {}, meta=meta)

    # --- internals ---------------------------------------------------------

    def _meta(self, r2: Any) -> ProgramMeta:
        meta = ProgramMeta()
        info = _loadj(r2, "ij") or {}
        binj = (info.get("bin") or info) if isinstance(info, dict) else {}
        arch = str(binj.get("arch", ""))
        bits = int(binj.get("bits", 0) or 0)
        meta.processor = _ARCH_MAP.get(arch, arch)
        meta.bits = bits
        meta.arch = normalize_arch(meta.processor, bits) if meta.processor else ""
        imports = _loadj(r2, "iij") or []
        meta.imports = sorted({
            str(i.get("name", "")).lstrip("_") for i in imports if i.get("name")
        })
        exports = _loadj(r2, "iEj") or []
        meta.exports = sorted({str(e.get("name", "")) for e in exports if e.get("name")})
        return meta

    def _decompile_all(
        self, r2: Any, meta: ProgramMeta, *, timeout: int
    ) -> dict[str, str]:
        # Skip the statically-linked sanitizer/libFuzzer/libc++/libc runtime and bound
        # the pass by a wall-clock budget + a hard cap — otherwise a real target's tens
        # of thousands of functions never finish (see backends/_noise.py). Target
        # functions that reference a dangerous sink go first, so a truncated pass still
        # reaches the buggy code.
        #
        # STRIPPED-ROBUST SINK PRIORITY (crutch-free LOCATE): the name-based signals
        # below — ``is_noise_name`` and the per-function callref-name sink test — key
        # entirely on SYMBOL NAMES. On a stripped binary r2 names every function
        # ``fcn.0x…``, so nothing filters as noise AND no function reads as a sink
        # caller: the whole budget is spent on address-ordered libc/runtime functions
        # and the ground-truth parser is never reached. ``_sink_caller_offsets`` below
        # recovers the sink-caller signal WITHOUT symbol names by resolving the dynamic
        # sink stubs (which survive ``strip`` in ``.dynsym``/PLT) and taking the xrefs
        # TO them — so a nameless ``fcn.0x`` that calls ``memcpy@plt`` still sorts to
        # the front of the decompile queue. This is the one signal that keeps LOCATE
        # working when the symbol table is gone.
        hot_offsets = _sink_caller_offsets(r2)
        # A Windows kernel driver has no libc/interceptor copy stubs to anchor on (it
        # inlines memcpy/memmove), so ``_sink_caller_offsets`` returns EMPTY and the
        # global copy-sink shape floods (79% of vmswitch's 3056 funcs). The driver
        # signal instead is the IRP_MJ_DEVICE_CONTROL dispatch handler
        # (``DriverObject->MajorFunction[14]``) and the call-graph REACHABLE from it —
        # a tight, in-budget candidate set (vmswitch: 3056 -> 68). Empty for non-drivers,
        # so the ELF path below is unchanged.
        driver_prio = _windows_driver_priority(r2)
        funcs = _loadj(r2, "aflj") or []
        candidates = []
        for f in funcs:
            name = str(f.get("name", ""))
            offset = f.get("offset", f.get("addr"))  # rizin: "addr"; some builds: "offset"
            if not name or offset is None or name.startswith("sym.imp."):
                continue  # PLT import stubs have no body worth decompiling
            if _noise.is_noise_name(name):
                continue
            if driver_prio:
                # dispatch handler (0) < reachable copy-sink (1) < reachable (2) < rest (3)
                prio = driver_prio.get(offset, 3)
            else:
                # cheap sink priority: rizin's per-function callee refs (if present, needs
                # symbol names) OR the symbol-free xref-to-sink set (survives strip).
                refs = f.get("callrefs") or f.get("refs") or []
                hot = offset in hot_offsets or any(
                    str(r.get("name", "")).split(".")[-1] in _noise.DANGEROUS_SINKS for r in refs
                )
                prio = 0 if hot else 1
            candidates.append((prio, name, offset))
        candidates.sort(key=lambda c: c[0])
        # Budget + cap SCALE with the target's own function count (see _noise.py) so a
        # large target reaches its GT region at the default; env overrides win.
        budget_s = min(_noise.decomp_budget_s(len(candidates)), float(timeout))
        max_funcs = _noise.decomp_max_funcs(len(candidates))
        meta.note = (
            f"decompile: {len(candidates)} target funcs "
            f"(budget {int(budget_s)}s, cap {max_funcs})"
        )
        out: dict[str, str] = {}
        t0 = time.monotonic()
        for _prio, name, offset in candidates:
            over_budget = (time.monotonic() - t0) > budget_s
            if len(out) >= max_funcs or over_budget:
                meta.note += f" [truncated at {len(out)}: budget/cap hit]"
                break
            r2.cmd(f"s {offset}")
            code = self._decompile_one(r2)
            if code:
                out[_clean_func_name(name)] = normalize_c(code)
        return out

    def _decompile_one(self, r2: Any) -> str:
        # Prefer r2ghidra's pdg (Ghidra-grade); fall back to r2's native pdc.
        try:
            raw = r2.cmd("pdgj")
            if raw and raw.strip():
                obj = json.loads(raw)
                code = obj.get("code") if isinstance(obj, dict) else None
                if code:
                    return str(code)
        except Exception:
            pass
        try:
            code = r2.cmd("pdc")
            return str(code) if code else ""
        except Exception:
            return ""


def _sink_caller_offsets(r2: Any) -> set[int]:
    """Entry offsets of functions that reference a dangerous sink, resolved WITHOUT
    symbol names so the signal survives ``strip`` (the crutch-free LOCATE path).

    A stripped binary keeps its dynamic-import stubs (``.dynsym``/PLT is not removed
    by ``strip``), so ``memcpy``/``malloc``/… still resolve to a stub address even
    when every local function is an anonymous ``fcn.0x…``. We take the xrefs TO each
    sink stub and return the enclosing function offsets — the nameless callers of a
    sink, which are the likeliest home of a memory-safety bug and must be decompiled
    before a budget-truncated pass gives up. Best-effort: any r2 hiccup yields an
    empty set and the caller falls back to the name-based priority unchanged.
    """
    offsets: set[int] = set()
    sink_addrs: set[int] = set()
    # (1) Plain dynamic-import sinks (``memcpy@plt`` …): the classic case for a
    # dynamically-linked stripped target (the eventual stripped-PE/IAT regime). PLT
    # stubs live in ``.dynsym`` and survive ``strip``.
    for imp in _loadj(r2, "iij") or []:
        if _norm_import(str(imp.get("name", ""))) not in _noise.DANGEROUS_SINKS:
            continue
        for key in ("plt", "vaddr"):  # xrefs land on the PLT stub; keep both
            addr = imp.get(key)
            if isinstance(addr, int) and addr:
                sink_addrs.add(addr)
    # (2) Sanitizer-interposed sinks (``__asan_memcpy`` / ``__interceptor_memcpy`` …):
    # an OSS-Fuzz ASan build statically interposes every ``memcpy``/``malloc`` call
    # onto these runtime symbols, so the plain-import set above is EMPTY and the
    # stripped GT function sinks below the decompile budget (measured on arvo:64166:
    # WriteCLUT ranks 4839/5494 with no anchor — never decompiled). These interceptor
    # symbols stay named in ``.dynsym`` after ``strip``, so anchoring on them recovers
    # the sink-caller set (WriteCLUT -> rank 180/5494, comfortably in budget). They are
    # noise as *candidates* (``is_noise_name`` drops them) but valid as xref *anchors*.
    for sym in _loadj(r2, "isj") or []:
        raw = str(sym.get("name", ""))
        if not any(s in raw for s in _INTERPOSED_SINK_SUBSTR):
            continue
        addr = sym.get("vaddr")
        if isinstance(addr, int) and addr:
            sink_addrs.add(addr)
    for addr in sink_addrs:
        for xref in _loadj(r2, f"axtj @ {addr}") or []:
            fn = xref.get("fcn_addr")
            if isinstance(fn, int) and fn:
                offsets.add(fn)
    return offsets


# --- Windows kernel-driver LOCATE: dispatch anchor + call-graph reachability ---------
#
# A driver's copy is an inlined intrinsic (measured: dbutil/iqvw64e/vmswitch all import
# ZERO memcpy/memmove), so ``_sink_caller_offsets`` is empty and the raw copy-SHAPE
# floods (79% of vmswitch's 3056 funcs). The signal that survives is structural: the
# ``IRP_MJ_DEVICE_CONTROL`` handler installed at ``DriverObject->MajorFunction[14]``
# (struct offset 0x70 + 14*8 = 0xE0), and the functions REACHABLE from it by an
# intra-driver call/tail-jump edge. That set is tight (vmswitch: 3056 -> 97), so the
# vulnerable IOCTL sink lands in budget (dbutil handler #1, memcpy #2; iqvw64e handler
# #1, the two CVE-2015-2291 primitives #3/#4).

_LEA_DST = re.compile(r"lea (\w+),")
# +0xe0 == MajorFunction base 0x70 + IRP_MJ_DEVICE_CONTROL(14)*8
_MAJORFN_DEVCTL_STORE = re.compile(r"mov qword \[\w+ \+ 0xe0\], (\w+)")
# x86-32: DRIVER_OBJECT is half-width — MajorFunction base is 0x3c, slot 14 = 0x74
# (measured on the Moxa Mxsport/mxport board drivers: ``mov dword [edx+0x74], 0x18e70``,
# handler installed as a raw immediate, sometimes rendered ``fcn.00018e70``).
_MAJORFN_DEVCTL_STORE_X86 = re.compile(r"mov dword \[\w+ \+ 0x74\], (\S+)$")
# The other common install idiom: instead of a per-slot ``mov [obj+0xe0], handler``, a
# driver fills EVERY MajorFunction slot with one dispatch routine —
# ``lea rdi,[DriverObject+0x70]; lea rax,[handler]; mov ecx,0x1c; rep stosq``. Since the
# fill covers slot 14, ``rax`` at the ``rep stos`` is the DEVICE_CONTROL handler. Matched
# statically (measured on viragt64.sys, whose only +0xe0 write is an unrelated stack
# store). ``_MAJORFN_BASE_LEA`` = the ``&MajorFunction[0]`` (base+0x70) load; x86-32 base
# is +0x3c and the fill reg is eax.
_MAJORFN_BASE_LEA = re.compile(r"lea \w+, \[\w+ \+ 0x70\]")
_MAJORFN_BASE_LEA_X86 = re.compile(r"lea \w+, \[\w+ \+ 0x3c\]")
_MAJORFN_FILL = re.compile(r"\brep\s+stos[qd]\b")
_LOAD_IDX = re.compile(r"mov \w+, (?:qword |dword |word |byte )?\[\w+ \+ \w+")
_STORE_PTR = re.compile(r"mov (?:qword |dword |word |byte )?\[\w+.*\], \w+")


def _func_ops(
    r2: Any, addr: int, cache: dict[int, list[dict[str, Any]]] | None = None
) -> list[dict[str, Any]]:
    if cache is not None and addr in cache:
        return cache[addr]
    obj = _loadj(r2, f"pdfj @ 0x{addr:x}")
    ops = obj.get("ops", []) if isinstance(obj, dict) else []
    if cache is not None:
        cache[addr] = ops
    return ops


def _is_windows_kernel_driver(r2: Any) -> bool:
    """PE whose subsystem is native or that imports the kernel (ntoskrnl/hal/ndis/wdf)."""
    info = _loadj(r2, "iIj") or {}
    if str(info.get("bintype", "")).lower() != "pe":
        return False
    if str(info.get("os", "")).lower() == "native":
        return True
    if str(info.get("subsystem", "")).lower() in ("native", "native kernel"):
        return True
    for imp in _loadj(r2, "iij") or []:
        lib = str(imp.get("libname", "")).lower()
        if lib.startswith(("ntoskrnl", "hal.", "ndis", "wdf", "ntddk", "storport", "usbd")):
            return True
    return False


def _bootstrap_driver_functions(r2: Any) -> set[int]:
    """``aaa`` misses DriverEntry (reached only by the PE-entry /GS stub's tail-jmp) and
    the dispatch handler (installed as a pointer, never called). Walk the entry-chain's
    terminal jmps so the MajorFunction store site is analysed as a function. Returns the
    PE entry-point offsets (the roots for the entry-reachability precision filter)."""
    roots = {e.get("vaddr") for e in (_loadj(r2, "iej") or []) if isinstance(e.get("vaddr"), int)}
    seen: set[int] = set()
    frontier = list(roots)
    while frontier:
        a = frontier.pop()
        if not isinstance(a, int) or a in seen:
            continue
        seen.add(a)
        r2.cmd(f"af @ 0x{a:x}")
        ops = _func_ops(r2, a)
        if ops and ops[-1].get("type") == "jmp" and isinstance(ops[-1].get("jump"), int):
            frontier.append(ops[-1]["jump"])
    return roots


def _call_adjacency(
    r2: Any, funcs: list[dict[str, Any]], cache: dict[int, list[dict[str, Any]]] | None = None
) -> tuple[dict[int, set[int]], set[int]]:
    """One pass over the functions: the intra-driver call/tail-jump graph AND the set of
    inlined-copy functions (``rep movs`` or >=3 indexed-load+pointer-store pairs)."""
    addrs = {f.get("addr", f.get("offset")) for f in funcs}
    addrs.discard(None)
    adj: dict[int, set[int]] = {}
    sinks: set[int] = set()
    for f in funcs:
        a = f.get("addr", f.get("offset"))
        if not isinstance(a, int):
            continue
        tg: set[int] = set()
        loads = stores = rep = 0
        for op in _func_ops(r2, a, cache):
            d = str(op.get("disasm", ""))
            j = op.get("jump")
            if isinstance(j, int) and j in addrs and j != a:  # call OR tail-jump to a func
                tg.add(j)
            if "movs" in d and "rep" in d:
                rep += 1
            elif _LOAD_IDX.match(d):
                loads += 1
            elif _STORE_PTR.match(d):
                stores += 1
        adj[a] = tg
        if rep >= 1 or min(loads, stores) >= 3:  # inlined-copy shape
            sinks.add(a)
    return adj, sinks


def _reachable(adj: dict[int, set[int]], roots: set[int]) -> set[int]:
    """Call-graph closure of ``roots`` over adjacency ``adj``."""
    out: set[int] = set(roots)
    frontier = list(roots)
    while frontier:
        for y in adj.get(frontier.pop(), ()):
            if y not in out:
                out.add(y)
                frontier.append(y)
    return out


# --- Windows driver ICFG: static indirect-edge tiers for the dispatch BFS -------------
#
# The direct-call adjacency above cannot cross an indirect dispatch — measured on
# Foxconn FXDrv64: the world-accessible handler reaches 1/103 functions directly; the
# IOCTL sub-handlers sit behind THREE indirect layers (stub table -> C++ vtable thunk
# -> MSVC switch jump-table), and the port-I/O primitive leaves behind a fourth
# (orphaned switch-case blocks). This is the r2-native port of the
# feat/indirect-callgraph-completeness tiers (ptr_tables / install / address-taken) to
# the address-keyed driver graph — same tier ordering and the same precision rule:
# stronger evidence first, speculation only fills a site stronger tiers left empty.
#
# Tier S (switch table): a register-indirect ``jmp`` whose window shows a jump-table
# idiom — absolute qword table (``jmp [r*N + base]``) or the MSVC relative form
# (``movsxd r,[t+idx*4]; add r,base; jmp r``). Case targets are INTRA-function, so the
# win is not the case edge itself but the case block's DIRECT calls, which r2 leaves
# orphaned (the case block is in no function). We linear-sweep each case block and add
# caller -> callee edges for its direct calls.
#
# Tier T (ptr-table with loader): reuse :mod:`zeroverse.ptr_tables` over the data
# sections — a contiguous run / strided column of code pointers (a MajorFunction stub
# array, a C++ vtable) whose LOADER is known (a function lea-ing the table base) wires
# loader -> members precisely (FXDrv64: handler ``lea rax,[0x15010]`` -> 28 stubs).
#
# Tier V (vtable thunk): a function that is just ``mov r,[rcx]; jmp/call [r+off]`` is a
# virtual-dispatch thunk; resolve off against loader-installed tables (first) or any
# recovered contiguous table (capped) -> thunk -> vtable[off/8] (FXDrv64: stub ->
# MJ14's real handler 0x11500).
#
# Tier I (install): ``lea reg,[func]; mov [global],reg`` installs a function pointer a
# later ``call/jmp qword [global]`` resolves — the static install-site analogue of the
# ICFG branch's install edges.
#
# Tier A (address-taken, capped, last resort): only for an indirect site NONE of the
# above resolved, wire the site's function to a bounded pool of address-taken
# functions (lea targets) — the speculative tail, capped so one site can't flood the
# reachable set. Edge provenance is recorded per tier for honest reporting.

_SWITCH_MAX_CASES = 256
_TABLE_LOADER_MEMBER_CAP = 64
_THUNK_CANDIDATE_CAP = 4
_ADDR_TAKEN_PER_SITE = 8
_ICFG_ROUNDS = 4
# Metadata sections whose code-pointer words are NOT dispatch targets (unwind info,
# relocs, CRT init arrays) — scanning them only manufactures false tables.
_TABLE_SECTION_SKIP = (
    ".pdata", ".reloc", ".rsrc", ".idata", ".edata", ".crt", ".stl", ".tls", ".debug",
)

_INDIRECT_JMP_TYPES = {"rjmp", "ujmp"}
_INDIRECT_CALL_TYPES = {"ucall", "ircall"}
# Operand-width-agnostic forms: x86-64 uses qword, x86-32 dword (measured on the
# Moxa/ICP-DAS 2001-2004 board drivers — the industrial slice is 32-bit).
_ABS_JMPTBL_RE = re.compile(
    r"^jmp (qword|dword) \[(?:\w+\*\d+ \+ )?(0x[0-9a-f]+)(?: \+ \w+\*\d+)?\]$")
_IND_MEM_RE = re.compile(r"^(?:jmp|call) (?:qword|dword) \[(\w+) \+ (0x[0-9a-f]+)\]$")
_LEA_ABS_RE = re.compile(r"^lea (\w+), \[(0x[0-9a-f]+)\]$")
_MOVSXD_RE = re.compile(r"^movsxd (\w+), dword \[(\w+) \+ \w+\*4\]$")
_ADD_REG_RE = re.compile(r"^add (\w+), (\w+)$")
_MOV_LOAD_RE = re.compile(r"^mov (\w+), (?:qword|dword) \[(\w+)\]$")
_STORE_ABS_RE = re.compile(r"^mov (?:qword|dword) \[(0x[0-9a-f]+)\], (\w+)$")
_DIRECT_CALL_RE = re.compile(r"^call (0x[0-9a-f]+|fcn\.[0-9a-f]+)")


def _pe_bits(r2: Any) -> int:
    """PE word size from the bin info (32 or 64); 64 when undeterminable — the
    x86-64 tables/stores stay the default so the ELF and mock paths are unchanged."""
    info = _loadj(r2, "ij") or {}
    binj = info.get("bin") if isinstance(info, dict) else None
    bits = binj.get("bits") if isinstance(binj, dict) else None
    return 32 if bits == 32 else 64


def _op_addr(op: dict[str, Any]) -> int | None:
    """Instruction address across r2/rizin pdfj schemas (``addr`` vs ``offset``)."""
    a = op.get("addr", op.get("offset"))
    return a if isinstance(a, int) else None


def _exec_ranges(r2: Any) -> list[tuple[int, int]]:
    """Executable section byte ranges — the code-pointer membership test for table
    recovery (a word is a dispatch target only if it lands in an 'x' section)."""
    out: list[tuple[int, int]] = []
    for s in _loadj(r2, "iSj") or []:
        if "x" not in str(s.get("perm", "")):
            continue
        va, sz = s.get("vaddr"), s.get("vsize")
        if isinstance(va, int) and isinstance(sz, int) and sz > 0:
            out.append((va, va + sz))
    return out


def _in_ranges(v: int, ranges: list[tuple[int, int]]) -> bool:
    return any(lo <= v < hi for lo, hi in ranges)


def _read_bytes(r2: Any, addr: int, size: int) -> bytes:
    """Raw bytes at ``addr`` via p8; empty on any failure (mock-safe)."""
    if size <= 0:
        return b""
    try:
        raw = r2.cmd(f"p8 {size} @ 0x{addr:x}")
        return bytes.fromhex(raw.strip()) if raw and raw.strip() else b""
    except Exception:
        return b""


def _read_words(r2: Any, addr: int, count: int, size: int) -> list[int]:
    data = _read_bytes(r2, addr, count * size)
    fmt = "<Q" if size == 8 else "<I"
    import struct as _st

    return [_st.unpack_from(fmt, data, i * size)[0]
            for i in range(len(data) // size)]


def _driver_ptr_tables(
    r2: Any, code: list[tuple[int, int]], ptr_size: int = 8
) -> list[dict[str, Any]]:
    """Recover function-pointer tables from the data sections (ptr_tables tier).

    Feeds :func:`zeroverse.ptr_tables.detect_tables` every word in a non-metadata
    data section whose value lands in an executable section, and maps the recovered
    member names back to integer addresses (the driver graph is address-keyed).
    ``ptr_size`` is the PE word size — 8 on x86-64, 4 on the x86 board-driver slice.

    The strided-column detector fires on every arithmetic sub-progression of a
    contiguous run too (a 28-pointer vtable yields ~200 "tables" at stride 2..16) —
    harmless as a membership pool, but fatal as dispatch evidence (one stub offset
    "resolves" in dozens of overlapping sub-tables). A strided column whose members
    are all already in a contiguous run is therefore dropped: what remains is a
    genuine struct-field column (the lcms cmsTagTypeHandler shape), not a sub-slice."""
    from ..ptr_tables import detect_tables

    tables: list[dict[str, Any]] = []
    for s in _loadj(r2, "iSj") or []:
        name = str(s.get("name", ""))
        perm = str(s.get("perm", ""))
        va, sz = s.get("vaddr"), s.get("vsize")
        if "x" in perm or "r" not in perm:
            continue
        if name.lower().startswith(_TABLE_SECTION_SKIP):
            continue
        if not (isinstance(va, int) and isinstance(sz, int) and 0 < sz <= (4 << 20)):
            continue
        words = []
        for i, v in enumerate(_read_words(r2, va, sz // ptr_size, ptr_size)):
            if _in_ranges(v, code):
                words.append((va + i * ptr_size, f"0x{v:x}"))
        for t in detect_tables(words, ptr_size=ptr_size, section=name):
            members = [int(m, 16) for m in t["members"] if m.startswith("0x")]
            if members:
                tables.append({"addr": int(t["addr"], 16), "members": members,
                               "kind": t["kind"], "section": name,
                               "writable": "w" in perm})
    contiguous = [t for t in tables if t["kind"] == "contiguous"]
    out = list(contiguous)
    for t in tables:
        if t["kind"] != "contiguous":
            ms = set(t["members"])
            if any(ms <= set(c["members"]) for c in contiguous if c["section"] == t["section"]):
                continue  # sub-progression of a contiguous run — redundant evidence
            out.append(t)
    return out


def _switch_case_targets(
    r2: Any, ops: list[dict[str, Any]], idx: int, code: list[tuple[int, int]]
) -> list[int]:
    """Case targets of a register-indirect jmp at ``ops[idx]``, or [] when the window
    shows no jump-table idiom we parse:
      * absolute:  ``jmp qword [idx*N + 0xBASE]`` — qword entries at 0xBASE;
      * MSVC rel:  ``movsxd r,[t+idx*4]; ...; add r,b; jmp r`` with lea'd constants
        ``t`` (dword table) and ``b`` (image base) — targets are ``b + s32(t[i])``.
    """
    d = str(ops[idx].get("disasm", ""))
    targets: list[int] = []
    m = _ABS_JMPTBL_RE.match(d)
    if m:  # absolute table named by the jmp itself (qword on x64, dword on x86)
        base = int(m.group(2), 16)
        width = 8 if m.group(1) == "qword" else 4
        for v in _read_words(r2, base, _SWITCH_MAX_CASES, width):
            if not _in_ranges(v, code):
                break
            targets.append(v)
        return targets
    if not re.match(r"^jmp \w+$", d):
        return []
    # MSVC relative form: single forward pass over the window, snapshotting each
    # register's lea constant AT the instruction that consumes it — the movsxd's
    # table register and the add's base register are re-lea'd between uses (the
    # FXDrv64 sequence reuses r8 for the byte map, the dword table, and the base).
    window = ops[max(0, idx - 16):idx]
    consts: dict[str, int] = {}
    movsxd_dst = tbl = base_addr = None
    for op in window:
        dd = str(op.get("disasm", ""))
        ms = _MOVSXD_RE.match(dd)
        if ms and ms.group(2) in consts:
            movsxd_dst, tbl = ms.group(1), consts[ms.group(2)]
            continue
        ad = _ADD_REG_RE.match(dd)
        if ad and movsxd_dst == ad.group(1) and ad.group(2) in consts:
            base_addr = consts[ad.group(2)]
            continue
        lm = _LEA_ABS_RE.match(dd)
        if lm:
            consts[lm.group(1)] = int(lm.group(2), 16)
    if tbl is None or base_addr is None:
        return []
    import struct as _st

    for raw in _read_words(r2, tbl, _SWITCH_MAX_CASES, 4):
        v = base_addr + _st.unpack("<i", _st.pack("<I", raw))[0]  # signed offset
        if not _in_ranges(v, code):
            break
        targets.append(v)
    return targets


def _case_block_callees(
    r2: Any, case: int, code: list[tuple[int, int]], max_ops: int = 64
) -> list[int]:
    """Direct-call targets in the switch-case block starting at ``case``.

    r2 leaves case blocks functionless when it can't resolve the switch, so the
    block's ``call fcn.x`` edges never enter any function's op list (FXDrv64: the
    port-I/O leaves are called only from such blocks). A bounded linear sweep from
    the case target recovers them without mutating r2's function state (an ``af`` at
    a mid-function address risks splitting the handler)."""
    out: list[int] = []
    data = _loadj(r2, f"pdj {max_ops} @ 0x{case:x}") or []
    for op in data if isinstance(data, list) else []:
        d = str(op.get("disasm", ""))
        t = str(op.get("type", ""))
        m = _DIRECT_CALL_RE.match(d)
        if t == "call" and m:
            tgt = int(m.group(1)[4:], 16) if m.group(1).startswith("fcn.") else int(m.group(1), 16)
            if _in_ranges(tgt, code):
                out.append(tgt)
        if t in ("ret", "jmp", "ujmp", "rjmp") and out:
            break  # block tail reached after finding calls — don't bleed into the next
    return out


def _driver_icfg_evidence(
    r2: Any,
    funcs: list[dict[str, Any]],
    cache: dict[int, list[dict[str, Any]]],
    tables: list[dict[str, Any]],
) -> tuple[dict[int, list[dict[str, Any]]], set[int]]:
    """Driver-global table evidence, computed once (not per fixpoint round).

    Returns ``(readers, installed)``:
      * ``readers`` — func -> tables it lea's the base of (a function INDEXING a
        dispatch table; tier T wires reader -> members when the reader is reachable).
      * ``installed`` — addrs of tables whose base is lea'd and then STORED into an
        object (``lea reg,[tbl]; mov [obj],reg`` — a C++ constructor stamping a
        vtable). Object-vtable evidence is global: the installer lives on an init
        path the dispatch BFS never reaches, but the thunk it enables resolves
        against exactly these tables (FXDrv64: the 74-entry vtable at 0x141b0 is
        lea-stored in two constructors; the 28-stub array is only ever READ, so it
        is a reader's table, never a thunk candidate)."""
    by_addr: dict[int, dict[str, Any]] = {}
    for t in tables:
        cur = by_addr.get(t["addr"])
        if cur is None or len(t["members"]) > len(cur["members"]):
            by_addr[t["addr"]] = t
    readers: dict[int, list[dict[str, Any]]] = {}
    installed: set[int] = set()
    for f in (f.get("addr", f.get("offset")) for f in funcs):
        if not isinstance(f, int):
            continue
        lea_ptr: dict[str, int] = {}
        for op in _func_ops(r2, f, cache):
            d = str(op.get("disasm", ""))
            if str(op.get("type", "")) == "lea" and isinstance(op.get("ptr"), int):
                ptr = op["ptr"]
                m = _LEA_DST.match(d)
                if m:
                    lea_ptr[m.group(1)] = ptr
                if ptr in by_addr:
                    readers.setdefault(f, []).append(by_addr[ptr])
                continue
            sm = _STORE_PTR.match(d)
            if sm:
                m2 = re.search(r", (\w+)$", d)
                if m2 and lea_ptr.get(m2.group(1)) in by_addr:
                    installed.add(lea_ptr[m2.group(1)])
    return readers, installed


def _driver_tier_edges(
    r2: Any,
    adj: dict[int, set[int]],
    reach: set[int],
    tables: list[dict[str, Any]],
    readers: dict[int, list[dict[str, Any]]],
    installed: set[int],
    code: list[tuple[int, int]],
    cache: dict[int, list[dict[str, Any]]],
    addrs: set[int],
    stats: dict[str, int],
    speculative: bool = False,
    ptr_size: int = 8,
) -> dict[int, set[int]]:
    """One fixpoint round of the ICFG tiers over the dispatch-reachable functions.

    Sources are gated to ``reach`` (the dispatch subtree) so a big driver's init-only
    paths never fan the reachable set out; table EVIDENCE (readers / installed) is
    global, computed once by :func:`_driver_icfg_evidence`. Returns new edges;
    ``stats`` accumulates a per-tier edge count for honest provenance reporting.

    ``speculative`` gates tier A (address-taken guessing): OFF by default because the
    triage claim "primitive reachable from the world-accessible handler" must rest on
    resolved static evidence (table load / vtable slot / switch case / install), not
    on 1-of-N address-taken guesses — measured on FXDrv64 the precise tiers already
    connect handler -> port-I/O, while tier A would add ~120 unverifiable funcs
    (712 guessed edges) to "reachable". Keep it for a future dynamic-grounded pass."""
    edges: dict[int, set[int]] = {}

    def add(src: int, dst: int, tier: str) -> None:
        if dst == src or dst in adj.get(src, ()) or dst in edges.get(src, ()):
            return
        edges.setdefault(src, set()).add(dst)
        stats[tier] = stats.get(tier, 0) + 1

    # Tier T: reachable loader -> table members (a MajorFunction stub array / vtable
    # the function indexes). Materializing members is the caller's job (af + rescan).
    for f in reach:
        for rdr in readers.get(f, ()):
            for mem in rdr["members"][:_TABLE_LOADER_MEMBER_CAP]:
                if _in_ranges(mem, code):
                    add(f, mem, "ptr-table")

    # Per-site tiers over each reachable function's indirect sites.
    addr_taken: set[int] = set()
    if speculative:
        for f in reach:
            for op in _func_ops(r2, f, cache):
                t0, ptr = str(op.get("type", "")), op.get("ptr")
                if t0 == "lea" and isinstance(ptr, int) and _in_ranges(ptr, code):
                    addr_taken.add(ptr)
    for f in reach:
        ops = _func_ops(r2, f, cache)
        lea_ptr: dict[str, int] = {}
        installs: dict[int, int] = {}  # global addr -> installed func (tier I)
        for i, op in enumerate(ops):
            d = str(op.get("disasm", ""))
            t = str(op.get("type", ""))
            lm = _LEA_ABS_RE.match(d)
            if lm:
                lea_ptr[lm.group(1)] = int(lm.group(2), 16)
                continue
            sm = _STORE_ABS_RE.match(d)
            if sm and sm.group(2) in lea_ptr and _in_ranges(lea_ptr[sm.group(2)], code):
                installs[int(sm.group(1), 16)] = lea_ptr[sm.group(2)]
                continue
            resolved = False
            # Tier I: call/jmp through a global an install site filled.
            if t in ("call", "jmp") and isinstance(op.get("ptr"), int) and op["ptr"] in installs:
                add(f, installs[op["ptr"]], "install")
                resolved = True
            # Tier V: vtable thunk — ``mov r,[x]; jmp/call [r+off]``.
            pm = _IND_MEM_RE.match(d)
            if pm:
                off = int(pm.group(2), 16)
                slot = off // ptr_size
                prev = str(ops[i - 1].get("disasm", "")) if i else ""
                mv = _MOV_LOAD_RE.match(prev)
                if mv and mv.group(1) == pm.group(1) and 0 < off <= 0x400:
                    # a thunk indexes a contiguous OBJECT vtable by slot: prefer
                    # install-stamped tables (lea+store evidence); fall back to
                    # contiguous tables in read-only sections (C++ vtables are
                    # const) — never a writable reader's table like the stub array.
                    cands = [t2 for t2 in tables if t2["kind"] == "contiguous"
                             and t2["addr"] in installed and slot < len(t2["members"])]
                    if not cands:
                        cands = [t2 for t2 in tables if t2["kind"] == "contiguous"
                                 and not t2.get("writable")
                                 and slot < len(t2["members"])]
                    for t2 in cands[:_THUNK_CANDIDATE_CAP]:
                        mem = t2["members"][slot]
                        if _in_ranges(mem, code):
                            add(f, mem, "vtable-thunk")
                            resolved = True
            # Tier S: switch jump-table (case blocks + their orphaned direct calls).
            if t in _INDIRECT_JMP_TYPES or (t == "jmp" and not isinstance(op.get("jump"), int)):
                cases = _switch_case_targets(r2, ops, i, code)
                for c in cases:
                    for callee in _case_block_callees(r2, c, code):
                        add(f, callee, "switch-case")
                    if cases:
                        resolved = True
            # Tier A: capped address-taken speculation — ONLY for an unresolved site,
            # and only when the caller opted into speculative edges (see docstring).
            if speculative and t in _INDIRECT_CALL_TYPES and not resolved:
                pool = sorted(a for a in addr_taken
                              if a != f and a not in adj.get(f, ()))[:_ADDR_TAKEN_PER_SITE]
                for a in pool:
                    add(f, a, "addr-taken")
    return edges


def _materialize(r2: Any, targets: set[int], addrs: set[int]) -> None:
    """``af`` each edge target r2 doesn't know as a function (stub-array entries are
    referenced only by a data table, so ``aaa`` never made them functions) — its own
    ops then feed the next tier round."""
    for a in sorted(targets):
        if a not in addrs:
            r2.cmd(f"af @ 0x{a:x}")


def _augmented_driver_adjacency(
    r2: Any,
    dispatch: set[int],
    funcs: list[dict[str, Any]],
    cache: dict[int, list[dict[str, Any]]],
    stats: dict[str, int] | None = None,
    speculative: bool = False,
) -> tuple[dict[int, set[int]], set[int]]:
    """Direct-call adjacency + the ICFG indirect tiers, for the dispatch BFS.

    Fixpoint: tier edges extend the reachable set, which enables new sources, up to
    ``_ICFG_ROUNDS`` rounds. Returns ``(adjacency, copy_sinks)`` — the same shape
    :func:`_call_adjacency` returns, so callers swap one line. ``stats`` (optional)
    accumulates per-tier edge counts (``ptr-table`` / ``vtable-thunk`` /
    ``switch-case`` / ``install`` / ``addr-taken``) for provenance reporting.
    ``speculative`` enables the address-taken guess tier (off by default — the
    triage reachability claim rests on resolved static evidence only)."""
    stats = stats if stats is not None else {}
    adj, sinks = _call_adjacency(r2, funcs, cache)
    if not dispatch:
        return adj, sinks
    code = _exec_ranges(r2)
    if not code:
        return adj, sinks
    ptr_size = _pe_bits(r2) // 8
    tables = _driver_ptr_tables(r2, code, ptr_size)
    readers, installed = _driver_icfg_evidence(r2, funcs, cache, tables)
    tier_edges: dict[int, set[int]] = {}  # accumulated across rounds (adj rebuilds drop them)
    for _ in range(_ICFG_ROUNDS):
        addrs = {a for f in funcs if isinstance(a := f.get("addr", f.get("offset")), int)}
        reach = _reachable(adj, dispatch)
        new = _driver_tier_edges(r2, adj, reach, tables, readers, installed,
                                 code, cache, addrs, stats, speculative,
                                 ptr_size=ptr_size)
        if not new:
            break
        for src, dsts in new.items():
            tier_edges.setdefault(src, set()).update(dsts)
        _materialize(r2, {d for ts in new.values() for d in ts}, addrs)
        # Rebuild the direct adjacency so newly materialized functions contribute
        # their own direct edges, then re-layer ALL recovered tier edges on top.
        funcs = _loadj(r2, "aflj") or funcs
        adj, sinks = _call_adjacency(r2, funcs, cache)
        for src, dsts in tier_edges.items():
            adj.setdefault(src, set()).update(dsts)
    return adj, sinks


def _driver_dispatch_handlers(
    r2: Any, cache: dict[int, list[dict[str, Any]]] | None = None
) -> set[int]:
    """Addresses installed into ``DriverObject->MajorFunction[14]``. Keyed on the
    RESOLVED lea target (``op['ptr']``), not disasm text: once r2 knows a function at
    the target it renders ``lea reg,[fcn.xxxx]`` and a ``[0x..]`` text match would miss.

    NO entry-reachability precision filter. That was tried (require the +0xE0 store site
    to be reachable from the PE entry, to reject a code pointer lea-stored at 0xE0 of an
    unrelated struct) and MEASURED NET-HARMFUL: vmswitch installs its real
    IRP_MJ_DEVICE_CONTROL handler (0x1c007dd80, subtree reach 84) through an
    NDIS/framework path the direct-call entry BFS never reaches, so the filter dropped
    the REAL handler and kept only reach-1 stubs (97 reachable -> 10). The false
    positives it targets are reach-1 stubs that cost ~1 decompile slot each (negligible
    vs the budget), while the risk it creates — dropping a framework-installed handler —
    is the same indirect-call-graph wall that limits the reachability below. So keep all
    +0xE0 handlers; the reachability subtree naturally weights the real one."""
    handlers: set[int] = set()
    bits = _pe_bits(r2)
    # x86 immediate-store validation (``mov dword [edx+0x74], 0x18e70``): the handler
    # arrives as a raw immediate, so it must be validated against the executable
    # sections — a struct field that happens to sit at +0x74 holds a non-code value.
    code = _exec_ranges(r2) if bits == 32 else []
    for f in _loadj(r2, "aflj") or []:
        a = f.get("addr", f.get("offset"))
        if not isinstance(a, int):
            continue
        lea_ptr: dict[str, int] = {}
        saw_majorfn_base = False
        for op in _func_ops(r2, a, cache):
            d = str(op.get("disasm", ""))
            m = _LEA_DST.match(d)
            if m and isinstance(op.get("ptr"), int):
                lea_ptr[m.group(1)] = op["ptr"]
                continue
            if _MAJORFN_BASE_LEA.match(d) or _MAJORFN_BASE_LEA_X86.match(d):
                saw_majorfn_base = True
                continue
            m = _MAJORFN_DEVCTL_STORE.match(d)
            if m and m.group(1) in lea_ptr:
                handlers.add(lea_ptr[m.group(1)])
                continue
            if bits == 32:
                m = _MAJORFN_DEVCTL_STORE_X86.match(d)
                if m:
                    src = m.group(1)
                    h: int | None = None
                    if src in lea_ptr:
                        h = lea_ptr[src]
                    elif src.startswith("fcn."):
                        h = int(src[4:], 16)
                    elif src.startswith("0x"):
                        v = op.get("val")
                        v = v if isinstance(v, int) else int(src, 16)
                        if _in_ranges(v, code):
                            h = v
                    if h is not None:
                        handlers.add(h)
                    continue
            # rep-stos fill: rax/eax (the last lea-loaded code pointer) fills every slot.
            for reg in ("rax", "eax"):
                if saw_majorfn_base and _MAJORFN_FILL.search(d) and reg in lea_ptr:
                    handlers.add(lea_ptr[reg])
    return handlers


def _windows_driver_priority(r2: Any) -> dict[int, int]:
    """Decompile-queue priority for a Windows kernel driver, symbol-free.

    Returns ``{offset: tier}`` — 0 = IRP_MJ_DEVICE_CONTROL dispatch handler, 1 = copy
    sink reachable from a handler, 2 = reachable from a handler — with no entry for the
    rest (the caller ranks them last). Empty dict for non-drivers, so the ELF decompile
    path is byte-for-byte unchanged. Reachability runs over the ICFG-augmented graph
    (:func:`_augmented_driver_adjacency`), so an indirectly-dispatched sub-handler
    (stub table / vtable thunk / switch table) still lands in the priority set."""
    if not _is_windows_kernel_driver(r2):
        return {}
    cache: dict[int, list[dict[str, Any]]] = {}
    _bootstrap_driver_functions(r2)
    dispatch = _driver_dispatch_handlers(r2, cache)
    if not dispatch:
        return {}
    for h in dispatch:  # analysing the handler cascades r2 into its callees
        r2.cmd(f"af @ 0x{h:x}")
        cache.pop(h, None)
    funcs = _loadj(r2, "aflj") or []
    adj, sinks = _augmented_driver_adjacency(r2, dispatch, funcs, cache)
    reach = _reachable(adj, dispatch)
    prio: dict[int, int] = dict.fromkeys(reach, 2)
    for a in reach & sinks:
        prio[a] = 1
    for h in dispatch:
        prio[h] = 0
    return prio


# Sanitizer/interceptor sink markers (matched as substrings of a ``.dynsym`` name):
# the ``__asan_*`` / ``__interceptor_*`` copy+alloc symbols an ASan build routes every
# call through. Kept narrow (copy/alloc families only) so the anchor set stays the
# memory-safety sinks, not every intercepted libc call.
_INTERPOSED_SINK_SUBSTR: tuple[str, ...] = (
    "asan_memcpy", "asan_memmove", "asan_memset", "asan_malloc", "asan_calloc",
    "asan_realloc", "asan_strcpy", "asan_strncpy", "asan_strcat", "asan_stpcpy",
    "interceptor_memcpy", "interceptor_memmove", "interceptor_memset",
    "interceptor_malloc", "interceptor_strcpy", "interceptor_strcat",
)


def _norm_import(name: str) -> str:
    """Bare libc name for sink matching: drop r2's ``sym.imp.``/``imp.`` decoration
    and any GLIBC version suffix (``memcpy@GLIBC_2.14`` -> ``memcpy``)."""
    for p in ("sym.imp.", "imp.", "sym."):
        if name.startswith(p):
            name = name[len(p):]
    return name.split("@", 1)[0].lstrip("_")


def _clean_func_name(name: str) -> str:
    """``sym.main`` → ``main``; keep a recognizable tail for fcn.* stubs."""
    for p in ("sym.imp.", "sym.", "dbg.", "flirt."):
        if name.startswith(p):
            return name[len(p):]
    return name


def _loadj(r2: Any, cmd: str) -> Any:
    try:
        raw = r2.cmd(cmd)
        return json.loads(raw) if raw and raw.strip() else None
    except Exception:
        return None
