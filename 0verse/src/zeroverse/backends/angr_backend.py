"""angr backend (M5 #27, ``backend:angr``).

A pure-Python, pip-installable non-Ghidra front-end: CLE loads the binary (arch,
imports, exports), angr's ``Decompiler`` analysis renders per-function pseudo-C,
and ``cdecomp`` mines the slicer IL from it. No native toolchain at all — the
``symbolic`` extra (``angr``) is the only dependency, so this is the most portable
fallback (CI, containers, locked-down hosts).

Fidelity (honest): angr's decompiler is younger than Ghidra's and fails on a
meaningful fraction of functions (it raises / emits partial C); each function is
attempted independently and failures are skipped, so coverage is a subset. The
same pseudo-C IL caveats as the rizin backend apply (``cdecomp``): no SSA-grade
def-use, no per-sink addresses (angr reachability stage skipped), indirect calls
dropped. Recommended order: Ghidra → rizin → angr.
"""

from __future__ import annotations

import contextlib
import time
from pathlib import Path
from typing import Any

from ..abi import normalize_arch
from .cdecomp import build_il
from .contract import ProgramAdapter, ProgramMeta

# angr/CLE arch name -> 0verse canonical arch.
_ARCH_MAP = {
    "X86": "x86", "AMD64": "x86-64", "ARMEL": "ARM", "ARMHF": "ARM",
    "AARCH64": "AArch64", "MIPS32": "MIPS", "MIPS64": "MIPS", "PPC32": "PowerPC",
}


def angr_importable() -> bool:
    try:
        import angr  # noqa: F401
    except Exception:
        return False
    return True


class AngrBackend:
    name = "angr"

    def available(self) -> bool:
        return angr_importable()

    def analyze(self, binary: str | Path, *, timeout: int = 120) -> ProgramAdapter:
        import logging

        import angr
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)

        proj = angr.Project(str(binary), auto_load_libs=False)
        meta = self._meta(proj)
        decompiled = self._decompile_all(proj, timeout=timeout)
        meta.decompiled_c = decompiled
        insts, defs, callgraph = build_il(decompiled)
        meta.callgraph = callgraph
        return ProgramAdapter(insts, defs, {}, {}, {}, meta=meta)

    # --- internals ---------------------------------------------------------

    def _meta(self, proj: Any) -> ProgramMeta:
        meta = ProgramMeta()
        arch = str(getattr(proj.arch, "name", ""))
        meta.processor = _ARCH_MAP.get(arch, arch)
        meta.bits = int(getattr(proj.arch, "bits", 0) or 0)
        meta.arch = normalize_arch(meta.processor, meta.bits) if meta.processor else ""
        main = proj.loader.main_object
        with contextlib.suppress(Exception):
            meta.imports = sorted({str(n).lstrip("_") for n in main.imports})
        with contextlib.suppress(Exception):
            meta.exports = sorted({
                str(s.name) for s in main.symbols
                if getattr(s, "is_export", False) and s.name
            })
        return meta

    def _decompile_all(self, proj: Any, *, timeout: int) -> dict[str, str]:
        out: dict[str, str] = {}
        started = time.monotonic()
        try:
            cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
            proj.analyses.CompleteCallingConventions(recover_variables=True)
        except Exception:
            return out
        for func in list(cfg.functions.values()):
            if time.monotonic() - started >= timeout:
                break
            if func.is_plt or func.is_simprocedure or func.alignment:
                continue
            name = str(func.name)
            code = self._decompile_one(proj, cfg, func)
            if code:
                out[name] = code
        return out

    def _decompile_one(self, proj: Any, cfg: Any, func: Any) -> str:
        try:
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        except Exception:
            return ""
        codegen = getattr(dec, "codegen", None)
        text = getattr(codegen, "text", None) if codegen is not None else None
        return str(text) if text else ""
