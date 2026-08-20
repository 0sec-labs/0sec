"""Ghidra backend — the default, free (Apache-2.0) ILAdapter.

Two halves:
  * ``GhidraAdapter.from_json`` — load a Ghidra export (the JSON schema below) and
    answer every ILAdapter query. **Implemented today**, so the slicer runs over
    Ghidra-shaped data and is testable without a Ghidra install.
  * ``GhidraAdapter.analyze`` — drive ``analyzeHeadless`` + ``docker/ghidra_export.py``
    to produce that JSON from a binary. Pending the export script (M1 issue).

Export JSON schema (lists, since JSON has no tuple keys)::

    {
      "functions": ["main", ...],
      "insts": [{"id": 1, "func": "main", "addr": 4096, "kind": "CALL",
                 "operands": [], "text": "", "var": null,
                 "dest": "read", "args": [20, 21, 22], "mem_version": null}],
      "defs":     [[["buf", "main"], 1]],     # (var, func) -> def inst id
      "mem_defs": [[10, [5, 6]]],             # load id -> store ids
      "callers":  [[["main", 0], [[100, 101]]]],   # (func, param_idx) -> [(call,arg)]
      "returns":  [[10, [12]]]                # call id -> ret ids
    }
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..abi import Abi, abi_for
from ..atomic_store import (
    AtomicObjectStore,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
)
from ..il import Inst, Kind
from ..receipts import backend_toolchain_identity
from . import _noise

PYGHIDRA_INSTALL_HINT = (
    "the pyghidra bridge is not importable — install it with "
    "`uv sync --extra ghidra` (PyPI, version-pinned to the Dockerfile's Ghidra) "
    "or from the wheel bundled with your own install "
    "(`$GHIDRA_HOME/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl`). "
    "See docs/GHIDRA-SETUP.md"
)

_GHIDRA_CACHE_SCHEMA = "zeroverse.ghidra-cache/v2"
_GHIDRA_EXPORT_SCHEMA = "zeroverse.ghidra-export/v1"


@dataclass
class ProgramMeta:
    """Whole-program facts recovered alongside the P-Code (M1 issue #1).

    Emitted honestly: ``unresolved_edges`` lists call sites whose target Ghidra
    could not resolve (indirect/virtual calls, jump tables) so downstream stages
    know the call graph is *partial*, never silently complete.

    ``processor`` / ``arch`` / ``bits`` carry the program's machine (M3): Ghidra's
    high P-Code SSA is arch-neutral, but the ABI (arg/return storage, cross-arch
    dynamic vector) is keyed off the processor — see ``abi()``.
    """

    decompiled_c: dict[str, str] = field(default_factory=dict)   # func -> pseudo-C
    imports: list[str] = field(default_factory=list)             # external symbols
    exports: list[str] = field(default_factory=list)             # exported functions
    callgraph: dict[str, list[str]] = field(default_factory=dict)  # caller -> callees
    unresolved_edges: list[dict[str, Any]] = field(default_factory=list)
    # Indirect/virtual-call resolution inputs (M1 #1 — consumed by ``localize``):
    #   address_taken: functions whose address is used as a *value* (fn-pointer /
    #     callback), so a candidate target of an indirect call. Empty is fine — the
    #     resolver falls back to a textual scan of ``decompiled_c``.
    #   ptr_tables: recovered function-pointer tables (vtables / jump tables /
    #     dispatch arrays) in read-only data. Each entry:
    #       {"section": ".data.rel.ro", "addr": "0x..", "members": [fn, ...],
    #        "loaders": [caller, ...]}  (``loaders`` optional).
    address_taken: list[str] = field(default_factory=list)
    ptr_tables: list[dict[str, Any]] = field(default_factory=list)
    processor: str = ""           # Ghidra processor, e.g. "AARCH64" / "x86" / "ARM"
    arch: str = ""                # canonical 0verse arch tag (abi.normalize_arch)
    bits: int = 0
    image_base: int = 0           # Ghidra load base — subtract from a function's addr
                                  # to get its load-base-relative (runtime dlopen) offset
    note: str = ""                # honest decompile-coverage note (budget/cap/truncation)
    # Recovered struct layouts (DWARF / Ghidra DataTypeManager).
    structs: list[dict[str, Any]] = field(default_factory=list)

    def abi(self) -> Abi | None:
        """Resolve the calling-convention ``Abi`` for this program (or None)."""
        key = self.arch or self.processor
        return abi_for(key, self.bits) if key else None


def _ghidra_install_identity(home: str) -> dict[str, Any]:
    root = Path(home).expanduser().resolve(strict=False)
    fingerprints: dict[str, str] = {}
    for relative in (
        "Ghidra/application.properties",
        "application.properties",
        "support/analyzeHeadless",
    ):
        candidate = root / relative
        if candidate.is_file():
            with contextlib.suppress(OSError):
                fingerprints[relative] = sha256_file(candidate)
    return {
        "root": str(root),
        "files": fingerprints,
        **backend_toolchain_identity("ghidra", str(root)),
    }


def _ghidra_cache_identity(binary: str | Path, home: str, timeout: int) -> dict[str, Any]:
    return {
        "schema": _GHIDRA_CACHE_SCHEMA,
        "export_schema": _GHIDRA_EXPORT_SCHEMA,
        "input_sha256": sha256_file(binary),
        "ghidra": _ghidra_install_identity(home),
        "extractor_sha256": sha256_file(__file__),
        "options": {
            "timeout": timeout,
            _noise.ENV_BUDGET: os.environ.get(_noise.ENV_BUDGET),
            _noise.ENV_MAX_FUNCS: os.environ.get(_noise.ENV_MAX_FUNCS),
        },
    }


def _valid_ghidra_cache(value: dict[str, Any], identity: dict[str, Any]) -> bool:
    if value.get("schema") != _GHIDRA_CACHE_SCHEMA or value.get("identity") != identity:
        return False
    payload = value.get("payload")
    digest = value.get("payload_sha256")
    if not isinstance(payload, dict) or not isinstance(digest, str):
        return False
    if sha256_bytes(canonical_json_bytes(payload)) != digest:
        return False
    return isinstance(payload.get("insts"), list) and isinstance(
        payload.get("meta"), dict
    )


class GhidraAdapter:
    def __init__(
        self,
        insts: list[Inst],
        defs: dict[tuple[str, str], int],
        mem_defs: dict[int, list[int]],
        callers: dict[tuple[str, int], list[tuple[int, int]]],
        returns: dict[int, list[int]],
        meta: ProgramMeta | None = None,
    ) -> None:
        self._by_id = {i.id: i for i in insts}
        self._defs = defs
        self._mem = mem_defs
        self._callers = callers
        self._returns = returns
        self.meta = meta or ProgramMeta()

    # --- construction ------------------------------------------------------

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> GhidraAdapter:
        insts = [
            Inst(
                id=int(d["id"]),
                func=str(d["func"]),
                addr=int(d.get("addr", 0)),
                kind=Kind[str(d["kind"])],
                operands=[int(x) for x in d.get("operands", [])],
                text=str(d.get("text", "")),
                var=d.get("var"),
                dest=d.get("dest"),
                args=[int(x) for x in d.get("args", [])],
                arg_vars=list(d.get("arg_vars", [])),
                mem_version=d.get("mem_version"),
            )
            for d in data.get("insts", [])
        ]
        defs = {(str(k[0]), str(k[1])): int(v) for k, v in data.get("defs", [])}
        mem = {int(k): [int(x) for x in v] for k, v in data.get("mem_defs", [])}
        callers = {
            (str(k[0]), int(k[1])): [(int(a), int(b)) for a, b in v]
            for k, v in data.get("callers", [])
        }
        returns = {int(k): [int(x) for x in v] for k, v in data.get("returns", [])}
        md = data.get("meta", {})
        meta = ProgramMeta(
            decompiled_c=dict(md.get("decompiled_c", {})),
            imports=list(md.get("imports", [])),
            exports=list(md.get("exports", [])),
            callgraph={k: list(v) for k, v in md.get("callgraph", {}).items()},
            unresolved_edges=list(md.get("unresolved_edges", [])),
            address_taken=list(md.get("address_taken", [])),
            ptr_tables=[dict(t) for t in md.get("ptr_tables", [])],
            processor=str(md.get("processor", "")),
            arch=str(md.get("arch", "")),
            bits=int(md.get("bits", 0)),
            image_base=int(md.get("image_base", 0)),
            note=str(md.get("note", "")),
            structs=list(md.get("structs", [])),
        )
        return cls(insts, defs, mem, callers, returns, meta=meta)

    @classmethod
    def from_export(cls, json_path: str | Path) -> GhidraAdapter:
        return cls.from_json(json.loads(Path(json_path).read_text()))

    @classmethod
    def analyze(
        cls,
        binary: str | Path,
        *,
        ghidra_home: str | None = None,
        timeout: int = 120,
        cache_dir: str | Path | None = None,
    ) -> GhidraAdapter:
        """Decompile `binary` with Ghidra (via PyGhidra) and build the adapter from
        the HighFunction **P-Code SSA**. Requires the Ghidra toolchain — run inside
        the 0verse Docker image. Def-use is encoded directly into instruction
        operands (Varnode.getDef), so the abstract IL carries SSA flow without a
        separate defs map.

        The export is cached keyed by the binary's content hash (decompilation
        dominates runtime and the same program is re-queried by #2/#3/#4), so a
        re-run is a JSON load. Set ``ZEROVERSE_NO_CACHE=1`` to force a fresh run.
        """
        home = ghidra_home or os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
        if not home:
            raise RuntimeError(
                "GHIDRA_HOME/GHIDRA_INSTALL_DIR not set (use the 0verse Docker image)"
            )
        identity = _ghidra_cache_identity(binary, home, timeout)
        key = sha256_bytes(canonical_json_bytes(identity))
        cdir = Path(cache_dir or os.environ.get("ZEROVERSE_CACHE", ".0verse-cache"))
        store = AtomicObjectStore(cdir, namespace="ghidra")
        cache_enabled = not os.environ.get("ZEROVERSE_NO_CACHE")
        if cache_enabled:
            cached = store.load(
                key,
                validator=lambda value: _valid_ghidra_cache(value, identity),
            )
            if cached is not None:
                try:
                    return cls.from_json(cached["payload"])
                except (KeyError, TypeError, ValueError):
                    pass

        try:
            import pyghidra  # heavy; imported lazily so the package loads without Ghidra
        except ImportError as exc:  # a Ghidra install without its bridge (#296)
            raise RuntimeError(
                f"Ghidra is installed at {home} but {PYGHIDRA_INSTALL_HINT}"
            ) from exc

        pyghidra.start(install_dir=home)
        insts, meta = _extract(binary, timeout)
        adapter = cls(insts, {}, {}, {}, {}, meta=meta)
        if cache_enabled:
            payload = json.loads(adapter.to_json())
            cache_value = {
                "schema": _GHIDRA_CACHE_SCHEMA,
                "identity": identity,
                "payload_sha256": sha256_bytes(canonical_json_bytes(payload)),
                "payload": payload,
            }
            with contextlib.suppress(OSError):
                store.store(
                    key,
                    cache_value,
                    validator=lambda value: _valid_ghidra_cache(value, identity),
                )
        return adapter

    # --- export ------------------------------------------------------------

    def to_json(self) -> str:
        """Serialize to the export schema (so a decompile can be cached/replayed)."""
        m = self.meta
        return json.dumps({
            "functions": self.functions(),
            "insts": [
                {"id": i.id, "func": i.func, "addr": i.addr, "kind": i.kind.name,
                 "operands": i.operands, "text": i.text, "var": i.var, "dest": i.dest,
                 "args": i.args, "arg_vars": i.arg_vars, "mem_version": i.mem_version}
                for i in self._by_id.values()
            ],
            "defs": [[list(k), v] for k, v in self._defs.items()],
            "mem_defs": [[k, v] for k, v in self._mem.items()],
            "callers": [[list(k), v] for k, v in self._callers.items()],
            "returns": [[k, v] for k, v in self._returns.items()],
            "meta": {
                "decompiled_c": m.decompiled_c, "imports": m.imports, "exports": m.exports,
                "callgraph": m.callgraph, "unresolved_edges": m.unresolved_edges,
                "address_taken": m.address_taken, "ptr_tables": m.ptr_tables,
                "processor": m.processor, "arch": m.arch, "bits": m.bits,
                "image_base": m.image_base,
                "note": m.note, "structs": m.structs,
            },
        }, indent=2)

    # --- ILAdapter ---------------------------------------------------------

    def inst(self, inst_id: int) -> Inst:
        return self._by_id[inst_id]

    def get_def(self, var: str, func: str) -> int | None:
        return self._defs.get((var, func))

    def get_memory_defs(self, load: Inst) -> list[int]:
        return self._mem.get(load.id, [])

    def get_callers(self, func: str, param_index: int) -> list[tuple[int, int]]:
        return self._callers.get((func, param_index), [])

    def get_callee_returns(self, call: Inst) -> list[int]:
        return self._returns.get(call.id, [])

    def functions(self) -> list[str]:
        return sorted({i.func for i in self._by_id.values()})

    def all_insts(self) -> list[Inst]:
        return list(self._by_id.values())


# --- PyGhidra P-Code extraction -------------------------------------------

def _map_kind(mnem: str, ninputs: int) -> Kind:
    if mnem in ("CALL", "CALLIND", "CALLOTHER"):
        return Kind.CALL
    if mnem == "LOAD":
        return Kind.LOAD
    if mnem == "STORE":
        return Kind.STORE
    if mnem == "MULTIEQUAL":
        return Kind.PHI
    if mnem == "RETURN":
        return Kind.RET
    if mnem in ("COPY", "CAST", "SUBPIECE", "INDIRECT"):  # passthrough: keep operands
        return Kind.OTHER
    if mnem.startswith(("INT_", "FLOAT_", "BOOL_", "PTR")):
        return Kind.BINOP if ninputs >= 2 else Kind.UNOP
    return Kind.OTHER


def _var_name(vn: Any) -> str | None:
    """The decompiler's variable name for a varnode (so the same stack buffer
    passed to two calls matches by name — the basis of the memory-flow pass)."""
    try:
        high = vn.getHigh()
        if high is not None:
            name = high.getName()
            if name:
                return str(name)
    except Exception:  # Ghidra interop, best-effort
        return None
    return None


def _is_default_name(name: str) -> bool:
    """Ghidra's auto-generated names (no real symbol recovered)."""
    return name.startswith(("FUN_", "SUB_", "LAB_", "UNK_"))


def _resolve_func_name(f: Any, fm: Any, monitor: Any, _depth: int = 0) -> str:
    """Best symbolic name for a called function. Follows thunks *and* unnamed
    PLT / ``.plt.sec`` stubs (a stub calls the real external — the case that
    leaves ``read`` showing as ``FUN_00401060`` under default analysis)."""
    name = str(f.getName())
    if not _is_default_name(name):
        return name
    try:
        if f.isThunk():
            t = f.getThunkedFunction(True)
            if t is not None and t is not f:
                return _resolve_func_name(t, fm, monitor, _depth + 1)
        if _depth < 4:
            callees = list(f.getCalledFunctions(monitor))
            if len(callees) == 1 and callees[0] is not f:
                return _resolve_func_name(callees[0], fm, monitor, _depth + 1)
    except Exception:  # Ghidra interop: best-effort
        return name
    return name


def _callee_name(target: Any, fm: Any, program: Any, monitor: Any) -> tuple[str | None, bool]:
    """Return ``(name, resolved)``. ``resolved=False`` flags an indirect/unknown
    target (CALLIND, jump table) so the caller can record an unresolved edge."""
    try:
        if target.isConstant() or target.isAddress():
            addr = target.getAddress()
            f = fm.getFunctionAt(addr)
            if f is not None:
                return _resolve_func_name(f, fm, monitor), True
            sym = program.getSymbolTable().getPrimarySymbol(addr)
            if sym is not None:
                return str(sym.getName()), True
    except Exception:  # Ghidra interop: best-effort name resolution
        return None, False
    return None, False


# --- targeted decompilation (scale to real binaries) -----------------------
#
# A real ASan+libFuzzer target statically links the sanitizer runtime, libFuzzer,
# libc++ and libc — tens of thousands of functions, almost none of which can hold
# the target bug. Decompiling *every* function is what made Ghidra time out on real
# binaries (the toy single-function extracts hid it). We skip that runtime/library
# noise by symbol name and bound the whole pass by a wall-clock budget + a hard
# function cap, decompiling the target's own code first.

def _is_noise_func(func: Any) -> bool:
    """True for a runtime/library function that cannot hold the target bug — skip it
    so the budget is spent on the target's own code."""
    try:
        if func.isExternal():
            return True
        name = str(func.getName())
    except Exception:  # Ghidra interop: on any doubt, don't skip
        return False
    return _noise.is_noise_name(name)


def _sink_calling_functions(program: Any, fm: Any) -> set[int]:
    """Entry-point offsets of functions that reference a dangerous sink — a cheap
    xref lookup (no decompilation) used to order the decompile queue.

    Resolves sink stubs two ways so the signal survives ``strip`` (crutch-free
    LOCATE): (1) the plain ``memcpy``/``malloc``/… names (dynamically-linked target,
    the eventual stripped-PE/IAT case); (2) the ``__asan_*``/``__interceptor_*``
    interposed symbols an OSS-Fuzz ASan build routes every copy/alloc through — on
    such a build the plain names DON'T EXIST (ASan interposes them), so without this
    the stripped ground-truth function reads as a non-sink-caller and falls below the
    decompile budget. Both symbol families stay in ``.dynsym`` after ``strip``.
    Measured on arvo:64166 (lcms): the interposed anchor is what marks WriteCLUT a
    sink caller when the binary is stripped."""
    out: set[int] = set()
    try:
        st = program.getSymbolTable()
        rm = program.getReferenceManager()

        def _admit(addr: Any) -> None:
            for ref in rm.getReferencesTo(addr):
                fn = fm.getFunctionContaining(ref.getFromAddress())
                if fn is not None:
                    out.add(int(fn.getEntryPoint().getOffset()))

        for name in _noise.DANGEROUS_SINKS:            # (1) plain sink names
            for sym in st.getSymbols(name):
                _admit(sym.getAddress())
        try:                                            # (2) ASan/interceptor sinks
            for sym in st.getAllSymbols(True):
                nm = str(sym.getName())
                if any(s in nm for s in _INTERPOSED_SINK_SUBSTR):
                    _admit(sym.getAddress())
        except Exception:
            pass
    except Exception:  # Ghidra interop: prioritization is best-effort, never fatal
        pass
    return out


# Sanitizer/interceptor sink markers (substring-matched on a ``.dynsym`` symbol name):
# the ``__asan_*`` / ``__interceptor_*`` copy+alloc symbols an ASan build routes every
# call through. Narrow to the copy/alloc families so the anchor set stays memory-safety
# sinks. Mirrors backends/rizin.py::_INTERPOSED_SINK_SUBSTR.
_INTERPOSED_SINK_SUBSTR: tuple[str, ...] = (
    "asan_memcpy", "asan_memmove", "asan_memset", "asan_malloc", "asan_calloc",
    "asan_realloc", "asan_strcpy", "asan_strncpy", "asan_strcat", "asan_stpcpy",
    "interceptor_memcpy", "interceptor_memmove", "interceptor_memset",
    "interceptor_malloc", "interceptor_strcpy", "interceptor_strcat",
)


def _fuzz_reachable_functions(fm: Any, monitor: Any) -> set[int]:
    """Entry-point offsets of functions reachable from ``LLVMFuzzerTestOneInput`` by a
    static call-graph BFS (Ghidra's ``getCalledFunctions`` — no decompilation needed).

    The target bug lives in the subtree the fuzzer actually drives, so on a large
    ASan+libFuzzer target where the budget truncates, decompiling this subtree FIRST
    is what gets the ground-truth function (e.g. libraw ``parseAdobeRAFMakernote`` ->
    ``checked_buffer::sget4`` -> ``sget4_static``) decompiled at all. Sink-calling is a
    secondary key within it. Best-effort: returns empty on any interop hiccup (the
    caller then falls back to the sink-caller-only order), and only captures direct
    edges (indirect/virtual dispatch is still handled by the sink-caller order and the
    address-taken re-admission downstream)."""
    out: set[int] = set()
    try:
        roots = list(fm.getFunctions(True))
        entry = None
        for f in roots:
            if str(f.getName()) == _noise.LIBFUZZER_ENTRY:
                entry = f
                break
        if entry is None:
            return out
        seen: set[int] = set()
        stack = [entry]
        while stack:
            fn = stack.pop()
            off = int(fn.getEntryPoint().getOffset())
            if off in seen:
                continue
            seen.add(off)
            out.add(off)
            try:
                callees = fn.getCalledFunctions(monitor)
            except Exception:
                callees = []
            for c in callees:
                try:
                    if int(c.getEntryPoint().getOffset()) not in seen:
                        stack.append(c)
                except Exception:
                    continue
    except Exception:  # BFS is best-effort prioritization, never fatal
        return set()
    return out


# --- Windows kernel-driver LOCATE (mirrors backends/rizin.py) -------------------------
#
# A driver inlines its copies, so ``_sink_calling_functions`` is empty and the raw
# copy-shape floods (measured on the r2 backend: 79% of vmswitch's 3056 funcs). The
# signal that survives is structural: the ``IRP_MJ_DEVICE_CONTROL`` handler installed
# at ``DriverObject->MajorFunction[14]`` (struct offset 0x70 + 14*8 = 0xE0) and the
# functions REACHABLE from it (vmswitch: 3056 -> 97). BENCH-VALIDATION PENDING: the
# algorithm and numbers are validated on the r2/rizin backend; this Ghidra mirror is
# defensively wrapped (any interop hiccup -> empty -> the ELF sink/fuzz order is used
# unchanged), and the integrator should confirm it fires via ``analyzeHeadless`` on a
# stripped .sys (dbutil_2_3.sys handler #1 / iqvw64e.sys handler #1) before relying on it.

_KERNEL_LIBS = ("ntoskrnl", "hal.dll", "hal.", "ndis", "wdf", "storport", "usbd", "ntddk")


def _is_windows_kernel_driver_ghidra(program: Any) -> bool:
    """PE that imports the kernel (ntoskrnl/hal/ndis/wdf/…). Bench-verified: keys on the
    external LIBRARY names — ``getExternalSymbols()`` returns the imported FUNCTION names
    (IoCreateDevice, …), not the library, so an earlier lib-name match on those silently
    failed detection while the anchor itself worked."""
    try:
        if "PE" not in str(program.getExecutableFormat()):
            return False
        try:
            libs = [str(x).lower() for x in program.getExternalManager().getExternalLibraryNames()]
        except Exception:
            libs = []
        if any(any(k in lib for k in _KERNEL_LIBS) for lib in libs):
            return True
        # fallback: an external symbol's parent namespace is its library
        for sym in program.getSymbolTable().getExternalSymbols():
            try:
                ns = str(sym.getParentNamespace().getName()).lower()
            except Exception:
                ns = ""
            if any(k in ns for k in _KERNEL_LIBS):
                return True
        return False
    except Exception:
        return False


def _driver_dispatch_handlers_ghidra(program: Any, fm: Any) -> set[int]:
    """Addresses installed into ``DriverObject->MajorFunction[14]`` (displacement 0xE0):
    a ``LEA reg,[handler]`` (whose reference gives the resolved handler — the Ghidra
    analogue of r2's ``op['ptr']``) feeding a ``MOV [base+0xE0], reg`` store."""
    handlers: set[int] = set()
    try:
        listing = program.getListing()
        rm = program.getReferenceManager()
        for func in fm.getFunctions(True):
            lea_ref: dict[str, int] = {}
            it = listing.getInstructions(func.getBody(), True)
            while it.hasNext():
                ins = it.next()
                mnem = str(ins.getMnemonicString()).lower()
                if mnem == "lea":
                    reg = str(ins.getRegister(0)) if ins.getNumOperands() > 0 else ""
                    tgt = None
                    for ref in rm.getReferencesFrom(ins.getAddress()):
                        ta = ref.getToAddress()
                        if ta is not None:
                            tgt = int(ta.getOffset())
                            break
                    if reg and tgt is not None:
                        lea_ref[reg] = tgt
                elif mnem == "mov":
                    # store to [base + 0xE0]: a scalar operand equal to 0xE0 and a
                    # register source that was just LEA'd to a code address.
                    disps = {int(s.getValue()) for s in _instr_scalars(ins)}
                    if 0xE0 in disps:
                        for i in range(ins.getNumOperands()):
                            reg = ins.getRegister(i)
                            if reg is not None and str(reg) in lea_ref:
                                handlers.add(lea_ref[str(reg)])
    except Exception:  # instruction interop is best-effort, never fatal
        return set()
    return handlers


def _instr_scalars(ins: Any) -> list[Any]:
    """Scalar (immediate/displacement) operands of an instruction, e.g. the ``0xE0`` in
    ``mov [rdi + 0xe0], rax``. Best-effort over Ghidra's operand objects."""
    out: list[Any] = []
    try:
        for i in range(ins.getNumOperands()):
            for obj in ins.getOpObjects(i):
                if obj.__class__.__name__ == "Scalar" or hasattr(obj, "getUnsignedValue"):
                    out.append(obj)
    except Exception:
        return []
    return out


def _reachable_from(program: Any, fm: Any, monitor: Any, roots: set[int]) -> set[int]:
    """Entry offsets reachable from ``roots`` by a direct-call BFS — mirrors
    ``_fuzz_reachable_functions`` but rooted at the dispatch handlers instead of the
    libFuzzer entry. This bounded set (vmswitch: 3056 -> 97) is the driver's in-budget
    candidate set. Direct edges only; indirect IOCTL dispatch (a fn-pointer table) is
    the same C++ call-graph gap noted for the fuzz BFS."""
    out: set[int] = set()
    try:
        space = program.getAddressFactory().getDefaultAddressSpace()
        seen: set[int] = set()
        pending = list(roots)
        while pending:
            off = pending.pop()
            if off in seen:
                continue
            seen.add(off)
            out.add(off)
            fn = fm.getFunctionAt(space.getAddress(off))
            if fn is None:
                continue
            try:
                callees = fn.getCalledFunctions(monitor)
            except Exception:
                callees = []
            for c in callees:
                try:
                    co = int(c.getEntryPoint().getOffset())
                    if co not in seen:
                        pending.append(co)
                except Exception:
                    continue
    except Exception:
        return set()
    return out


def _windows_driver_priority_ghidra(program: Any, fm: Any, monitor: Any) -> dict[int, int]:
    """``{entry_offset: tier}`` — 0 = DEVICE_CONTROL dispatch handler, 1 = reachable from
    a handler. Empty for non-drivers, so the ELF sink/fuzz order is used unchanged.
    Mirror of rizin ``_windows_driver_priority``; the copy-sink sub-ranking that the r2
    path applies WITHIN the reachable set is omitted here (Ghidra operand-type parsing is
    less certain without a bench run) — the reachable set is already in budget, so the
    IOCTL sink is decompiled regardless; the sub-ranking is a follow-up refinement."""
    if not _is_windows_kernel_driver_ghidra(program):
        return {}
    dispatch = _driver_dispatch_handlers_ghidra(program, fm)
    if not dispatch:
        return {}
    reach = _reachable_from(program, fm, monitor, dispatch)
    prio: dict[int, int] = dict.fromkeys(reach, 1)
    for h in dispatch:
        prio[h] = 0
    return prio
_RO_SECTIONS = (".data.rel.ro", ".rodata", ".got", ".data.rel.ro.local")
_MIN_TABLE_LEN = 2   # a "table" is >=2 contiguous function pointers


def _recover_address_taken(program: Any, fm: Any) -> list[str]:
    """Functions whose entry address is referenced as *data* (a function pointer
    written into a table / passed as a callback), not by a CALL. Best-effort over
    Ghidra's ReferenceManager; returns [] on any failure so it is a pure no-op when
    the toolchain/refs are unavailable. The integrator confirms this fires on bench.
    """
    out: set[str] = set()
    try:
        rm = program.getReferenceManager()
        for f in fm.getFunctions(True):
            try:
                entry = f.getEntryPoint()
                for ref in rm.getReferencesTo(entry):
                    rt = ref.getReferenceType()
                    # data/pointer reference (not a call/branch) => address taken
                    if rt is not None and (rt.isData() or not rt.isCall()) and not rt.isFlow():
                        out.add(str(f.getName()))
                        break
            except Exception:  # per-function best-effort
                continue
    except Exception:  # Ghidra interop: whole pass is best-effort
        return []
    return sorted(out)


def _recover_ptr_tables(program: Any, fm: Any) -> list[dict[str, Any]]:
    """Best-effort recovery of function-pointer tables (vtables / dispatch arrays)
    in read-only data: contiguous runs of pointers whose targets are function
    entry points. Returns [] on any failure (pure no-op without the toolchain).

    NOTE for the integrator: this walks ``program.getListing().getDefinedData()``,
    so it only sees pointers Ghidra has *typed* as pointers. On a stripped binary
    the auto-analyzer must have run pointer/data reference analysis first; if tables
    come back empty, run Ghidra's "Aggressive Instruction Finder" + data-ref
    analysis, or supply ``ptr_tables`` out-of-band. Members are keyed by function
    name; ``loaders`` is left empty here (the resolver falls back to indirect-call
    sites), and can be filled later by xref'ing the table's own address.
    """
    tables: list[dict[str, Any]] = []
    try:
        listing = program.getListing()
        mem = program.getMemory()

        def _section_of(addr: Any) -> str:
            blk = mem.getBlock(addr)
            return str(blk.getName()) if blk is not None else ""

        run: list[str] = []
        run_start: Any = None
        prev_end: Any = None
        section = ""
        it = listing.getDefinedData(True)
        while it.hasNext():
            data = it.next()
            addr = data.getAddress()
            sec = _section_of(addr)
            target_fn: str | None = None
            if sec in _RO_SECTIONS and data.isPointer():
                try:
                    ref = data.getValue()  # the pointed-to Address
                    f = fm.getFunctionAt(ref) if ref is not None else None
                    if f is not None:
                        target_fn = str(f.getName())
                except Exception:
                    target_fn = None
            contiguous = (
                run
                and prev_end is not None
                and sec == section
                and addr.equals(prev_end)
            )
            if target_fn is not None and (not run or contiguous):
                if not run:
                    run_start, section = addr, sec
                run.append(target_fn)
                prev_end = addr.add(data.getLength())
            else:
                if len(run) >= _MIN_TABLE_LEN:
                    tables.append({"section": section, "addr": str(run_start),
                                   "members": list(run), "loaders": []})
                if target_fn is not None:
                    run, run_start, section = [target_fn], addr, sec
                    prev_end = addr.add(data.getLength())
                else:
                    run, run_start, prev_end = [], None, None
        if len(run) >= _MIN_TABLE_LEN:
            tables.append({"section": section, "addr": str(run_start),
                           "members": list(run), "loaders": []})
    except Exception:  # Ghidra interop: whole pass is best-effort
        return []
    return tables


def _extract(binary: str | Path, timeout: int) -> tuple[list[Inst], ProgramMeta]:
    import shutil
    import tempfile
    from collections.abc import Iterator

    import pyghidra

    @contextlib.contextmanager
    def _open_program(path: Path) -> Iterator[Any]:
        # pyghidra derives the Ghidra project location from the binary's parent,
        # and ProjectLocator rejects dot-prefixed path elements — exactly how the
        # windows analysis bundle stages its hidden temp dir. Give the project an
        # explicit, non-hidden home instead.
        project_dir = Path(tempfile.mkdtemp(prefix="ghidra-project-"))
        try:
            with pyghidra.open_program(str(path), project_location=project_dir) as flat:
                yield flat
        finally:
            shutil.rmtree(project_dir, ignore_errors=True)

    insts: list[Inst] = []
    meta = ProgramMeta()
    counter = 0
    with _open_program(Path(binary)) as flat:
        program = flat.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        decomp = DecompInterface()
        decomp.openProgram(program)
        fm = program.getFunctionManager()

        # M3 — recover the machine so the ABI / cross-arch dynamic vector is known.
        try:
            from ..abi import normalize_arch

            lang = program.getLanguage()
            meta.processor = str(lang.getProcessor())
            meta.bits = int(lang.getLanguageDescription().getSize())
            meta.arch = normalize_arch(meta.processor, meta.bits)
        except Exception:  # Ghidra interop: machine metadata is best-effort
            pass

        # Load base — the authoritative offset to subtract from a function's address
        # to get its load-base-relative (runtime dlopen) offset for the addr-mode harness.
        with contextlib.suppress(Exception):
            meta.image_base = int(program.getImageBase().getOffset())

        # Harvest recovered struct layouts (DWARF -> Ghidra DataTypeManager) so the LLM
        # scan can remap raw offset accesses (`*(uint *)(p + 8)`) to named fields — the
        # type info compilation strips from the pseudo-C. Empty for stripped binaries.
        try:
            from ..structtypes import harvest_structs

            meta.structs = harvest_structs(program)
        except Exception:  # struct context is best-effort enrichment, never fatal
            meta.structs = []

        st = program.getSymbolTable()
        meta.imports = sorted({str(s.getName()) for s in st.getExternalSymbols()})
        meta.exports = sorted(
            str(f.getName()) for f in fm.getFunctions(True)
            if f.isGlobal() and not f.isThunk() and not _is_default_name(str(f.getName()))
        )

        # Decompile the target's own functions first, bounded by a wall-clock budget
        # and a hard cap — never the whole statically-linked runtime (see above). The
        # budget/cap are computed below from the candidate count (`_noise.decomp_*`),
        # which scales with target size and honors the env overrides verbatim.
        per_func = min(int(timeout), 30)          # no single function stalls the pass
        candidates = [
            f for f in fm.getFunctions(True)
            if not f.isThunk() and not _is_noise_func(f)
        ]
        # PRIORITIZE the decompile queue with two cheap, no-decompile signals:
        #  (1) FUZZ-REACHABLE — functions reachable from ``LLVMFuzzerTestOneInput`` by a
        #      static call-graph BFS. The target bug lives in the subtree the fuzzer
        #      drives, so on a large target where the budget truncates, decompiling
        #      this subtree first is what gets the GT function decompiled at all.
        #  (2) SINK-CALLING — references a dangerous sink (memcpy/malloc/strcpy/…), the
        #      likelier home of a memory-safety bug; used as the secondary key.
        # Order: a UNION front tier of {sink-calling + fuzz-reachable}, sink-callers
        # FIRST within it. Both are strong bug-locality signals, but sink-calling is
        # the stronger one for a memory-safety bug (the function directly touches a
        # copy/alloc), AND — crucially for a stripped target — the fuzz-reachable BFS
        # only follows DIRECT call edges, so a GT function reached by INDIRECT dispatch
        # (a registered handler / vtable / fn-pointer table — the C++ call-graph gap)
        # is NOT fuzz-reachable and, under the old fuzz-first order, sorted behind ALL
        # ~660 fuzz-reachable funcs → below the budget. Measured on arvo:64166 (lcms):
        # WriteCLUT is indirect-dispatched (not fuzz-reachable) but IS a sink caller;
        # fuzz-first needed cap 1500 to reach it, sink-first lands it under ~400.
        # Within the sink tier the attack-surface name hint still orders large product
        # binaries that have no libFuzzer root.
        sink_callers = _sink_calling_functions(program, fm)
        fuzz_reach = _fuzz_reachable_functions(fm, monitor)
        # A Windows kernel driver has no libc/interceptor copy stubs and no libFuzzer
        # root, so both signals above are empty; its bug lives behind the
        # IRP_MJ_DEVICE_CONTROL dispatch handler. When this fires it is the primary key;
        # empty for non-drivers, so the ELF order below is unchanged. (Bench-validate.)
        driver_prio = _windows_driver_priority_ghidra(program, fm, monitor)
        candidates.sort(
            key=lambda f: (
                driver_prio.get(int(f.getEntryPoint().getOffset()), 9) if driver_prio else 0,
                0 if (int(f.getEntryPoint().getOffset()) in sink_callers
                      or int(f.getEntryPoint().getOffset()) in fuzz_reach) else 1,
                0 if int(f.getEntryPoint().getOffset()) in sink_callers else 1,
                _noise.attack_surface_priority(str(f.getName())),
                0 if int(f.getEntryPoint().getOffset()) in fuzz_reach else 1,
            )
        )
        # Budget + cap SCALE with the target's own function count so a large target
        # (libraw: 2316 funcs) gets enough wall-clock to reach its GT region at the
        # default; small binaries keep the old flat behavior. Env overrides win.
        budget_s = min(_noise.decomp_budget_s(len(candidates)), float(timeout))
        max_funcs = _noise.decomp_max_funcs(len(candidates))
        meta.note = (
            f"decompile: {len(candidates)} target funcs "
            f"({len(fuzz_reach)} fuzz-reachable, {len(sink_callers)} sink-calling, "
            f"prioritized; budget {int(budget_s)}s, cap {max_funcs})"
        )
        t0 = time.monotonic()
        n_done = 0
        for func in candidates:
            elapsed = time.monotonic() - t0
            remaining = budget_s - elapsed
            if n_done >= max_funcs or remaining < 1.0:
                meta.note += f" [truncated at {n_done}: budget/cap hit]"
                break
            n_done += 1
            res = decomp.decompileFunction(
                func,
                min(per_func, int(remaining)),
                monitor,
            )
            high = res.getHighFunction() if res is not None else None
            if high is None:
                continue
            fname = str(func.getName())
            try:
                dc = res.getDecompiledFunction()
                if dc is not None:
                    meta.decompiled_c[fname] = str(dc.getC())
            except Exception:  # decompiled C is best-effort context
                pass
            ops = []
            it = high.getPcodeOps()
            while it.hasNext():
                ops.append(it.next())
            ids: dict[str, int] = {}
            for op in ops:
                counter += 1
                ids[str(op.getSeqnum())] = counter
            callees: list[str] = []
            for op in ops:
                oid = ids[str(op.getSeqnum())]
                mnem = str(op.getMnemonic())
                ninputs = op.getNumInputs()
                kind = _map_kind(mnem, ninputs)
                start = 1 if kind is Kind.CALL else 0
                operands: list[int] = []
                for i in range(start, ninputs):
                    d = op.getInput(i).getDef()
                    if d is not None:
                        dk = str(d.getSeqnum())
                        if dk in ids:
                            operands.append(ids[dk])
                dest: str | None = None
                args: list[int] = []
                arg_vars: list[str | None] = []
                try:
                    addr = int(op.getSeqnum().getTarget().getOffset())
                except Exception:  # some ops lack a target address
                    addr = 0
                if kind is Kind.CALL and ninputs >= 1:
                    dest, resolved = _callee_name(op.getInput(0), fm, program, monitor)
                    args, operands = operands, []
                    arg_vars = [_var_name(op.getInput(i)) for i in range(1, ninputs)]
                    if dest:
                        callees.append(dest)
                    if not resolved or mnem in ("CALLIND", "CALLOTHER"):
                        # ``arity`` (recovered argument count at the site) lets the
                        # indirect resolver do arity-ish target matching (localize.py).
                        meta.unresolved_edges.append(
                            {"func": fname, "addr": hex(addr), "op": mnem,
                             "arity": len(args)})
                insts.append(
                    Inst(id=oid, func=fname, addr=addr, kind=kind, operands=operands,
                         dest=dest, args=args, arg_vars=arg_vars)
                )
            if callees:
                meta.callgraph[fname] = sorted(set(callees))

        # Whole-program indirect-call resolution inputs (best-effort, no-op on
        # failure). These feed localize.resolve_indirect_edges downstream so taint
        # can cross function-pointer / vtable dispatch the direct call graph misses.
        meta.address_taken = _recover_address_taken(program, fm)
        meta.ptr_tables = _recover_ptr_tables(program, fm)
    return insts, meta


# --- DecompilerBackend wrapper (M5 #27) ------------------------------------

def ghidra_install_dir() -> str:
    """The configured Ghidra install root (``GHIDRA_HOME``/``GHIDRA_INSTALL_DIR``),
    or ``""`` when neither is set."""
    return os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR") or ""


def pyghidra_installed() -> bool:
    """True when the ``pyghidra`` CPython bridge is importable (#296).

    Probed with ``find_spec`` so asking the question never starts a JVM. This is a
    *capability* probe, not a configuration probe: a host can have Ghidra unpacked
    and ``GHIDRA_HOME`` exported and still be unable to decompile a single byte
    because the bridge module is absent — which is exactly how a broken
    environment used to report itself as a 0-confirm capability result.
    """
    if "pyghidra" in sys.modules:  # already imported (or injected by a test double)
        return True
    try:
        return importlib.util.find_spec("pyghidra") is not None
    except (ImportError, ValueError):  # namespace-package / broken-install edge
        return False


class GhidraBackend:
    """``DecompilerBackend`` adapter for the Ghidra (PyGhidra) path — the default,
    highest-fidelity backend. ``available()`` is True only when the whole toolchain
    is usable: the Ghidra install is reachable (``GHIDRA_HOME``/
    ``GHIDRA_INSTALL_DIR``) *and* the ``pyghidra`` bridge that drives it is
    importable. Both halves are required to decompile anything, so both are
    probed — an install without the bridge is unavailable, not degraded (#296)."""

    name = "ghidra"

    def available(self) -> bool:
        return bool(ghidra_install_dir()) and pyghidra_installed()

    def analyze(self, binary: str | Path, *, timeout: int = 120) -> GhidraAdapter:
        return GhidraAdapter.analyze(binary, timeout=timeout)
