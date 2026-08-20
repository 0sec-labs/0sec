"""Backend contract + auto-selector (M5 #27).

Makes the decompiler a *replaceable* component. The slicer/pipeline never name a
concrete backend; they call a backend that satisfies ``DecompilerBackend`` and
consume a ``ProgramAdapter`` (an ``ILAdapter`` carrying ``ProgramMeta``). Three
backends register here:

  * ``ghidra`` — High P-Code SSA via PyGhidra (default, highest fidelity).
  * ``rizin`` — rizin/radare2 + r2ghidra ``pdg`` pseudo-C (no Java/GHIDRA_HOME).
  * ``angr``  — CLE load + angr's decompiler (pure-Python, pip-installable).

``select`` resolves ``ZEROVERSE_BACKEND=auto|ghidra|rizin|angr``: *auto* prefers
Ghidra and falls back to rizin, then angr, when a higher one is unavailable.

The non-Ghidra backends recover a lower-fidelity IL from pseudo-C text (see
``cdecomp``); ``ProgramMeta`` and the ``ILAdapter`` query surface are identical, so
``analyze.scan`` + the bug-class lenses run unchanged. Honest degradations are
documented per backend.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..il import Inst

# ``ProgramMeta`` is the canonical contract type (re-exported below); the two
# probes back the Ghidra branch of ``selection_note``.
from .ghidra import (
    PYGHIDRA_INSTALL_HINT,
    ProgramMeta,
    ghidra_install_dir,
    pyghidra_installed,
)

__all__ = [
    "BackendUnavailableError",
    "DecompilerBackend",
    "ProgramAdapter",
    "ProgramMeta",
    "analyze",
    "analyze_selected",
    "available_backends",
    "ensure_explicit_backend",
    "resolve_choice",
    "select",
    "selection_note",
]


class BackendUnavailableError(RuntimeError):
    """An *explicitly requested* decompiler backend cannot initialize (#297).

    Raised instead of degrading, because a run that silently swaps the demanded
    engine for nothing at all still emits a well-formed, plausible-looking
    zero-finding result — indistinguishable from a genuine capability measurement.
    """


class ProgramAdapter:
    """Generic ``ILAdapter`` carrying ``ProgramMeta`` — the value every backend
    returns. Same query surface as ``GhidraAdapter`` (which keeps its own copy so
    the Ghidra path stays self-contained); this one is built by the rizin/angr
    backends from the lighter ``cdecomp`` IL."""

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


@runtime_checkable
class DecompilerBackend(Protocol):
    """A decompiler front-end: ``ingest → ProgramMeta + per-function IL`` the slicer
    consumes. Implementations are cheap to construct; ``available()`` probes the
    toolchain, ``analyze()`` does the work."""

    name: str

    def available(self) -> bool:
        """True if this backend's toolchain is usable on this host right now."""
        ...

    def analyze(self, binary: str | Path, *, timeout: int = 120) -> object:
        """Decompile ``binary`` and return an ``ILAdapter`` carrying ``ProgramMeta``
        (a ``ProgramAdapter`` or ``GhidraAdapter``)."""
        ...


# --- backend registry ------------------------------------------------------

def _backends() -> list[DecompilerBackend]:
    """Concrete backends in *preference* order (highest fidelity first). Imported
    lazily so the package loads without any engine installed."""
    from .angr_backend import AngrBackend
    from .ghidra import GhidraBackend
    from .rizin import RizinBackend

    return [GhidraBackend(), RizinBackend(), AngrBackend()]


def available_backends() -> list[str]:
    """Names of backends usable on this host, in preference order."""
    return [b.name for b in _backends() if b.available()]


def resolve_choice(name: str | None = None) -> str:
    """The backend choice actually in effect: an explicit name, or ``auto``.

    Callers need this to tell a *preference* (``auto``, may degrade) from a
    *demand* (a named backend, must not degrade) — including when the demand
    arrives through ``$ZEROVERSE_BACKEND`` rather than a flag.
    """
    return (name or os.environ.get("ZEROVERSE_BACKEND") or "auto").strip().lower() or "auto"


def select(name: str | None = None) -> DecompilerBackend | None:
    """Resolve the backend for ``name`` (or ``$ZEROVERSE_BACKEND``, default auto).

    * explicit ``ghidra``/``rizin``/``angr`` → that backend iff available, else None.
    * ``auto`` → the first available backend in preference order, else None.
    """
    choice = resolve_choice(name)
    backends = _backends()
    if choice == "auto":
        for b in backends:
            if b.available():
                return b
        return None
    for b in backends:
        if b.name == choice:
            return b if b.available() else None
    return None


def analyze(binary: str | Path, *, name: str | None = None, timeout: int = 120) -> object | None:
    """Pick a backend and decompile, or return None when none is available.

    Used by the pipeline in place of the old Ghidra-only hook.
    """
    backend = select(name)
    if backend is None:
        return None
    adapter = backend.analyze(binary, timeout=timeout)
    with contextlib.suppress(Exception):
        adapter._backend = backend.name  # type: ignore[attr-defined]
    return adapter


def analyze_selected(
    backend: DecompilerBackend,
    binary: str | Path,
    *,
    timeout: int = 120,
) -> object:
    """Analyze with an already-probed backend without re-running selection."""
    adapter = backend.analyze(binary, timeout=timeout)
    with contextlib.suppress(Exception):
        adapter._backend = backend.name  # type: ignore[attr-defined]
    return adapter


def selection_note(name: str | None = None) -> str:
    """Human note when ``analyze`` returns None (no backend available).

    The Ghidra branch names *which* half of the toolchain is missing: "install
    Ghidra" and "install the bridge that drives it" are different fixes, and
    conflating them is what made a bridge-less box look like a configured one.
    """
    choice = resolve_choice(name)
    if choice == "ghidra":
        if not ghidra_install_dir():
            return ("Ghidra toolchain not found (GHIDRA_HOME/GHIDRA_INSTALL_DIR unset) — "
                    "run inside the 0verse Docker image, or set ZEROVERSE_BACKEND=rizin|angr "
                    "for the non-Ghidra fallback")
        if not pyghidra_installed():
            return (f"Ghidra is installed at {ghidra_install_dir()} but "
                    f"{PYGHIDRA_INSTALL_HINT}")
        return (f"Ghidra at {ghidra_install_dir()} and the pyghidra bridge both look "
                "present, but the backend did not initialize — set "
                "ZEROVERSE_BACKEND=rizin|angr for the non-Ghidra fallback")
    if choice in ("rizin", "angr"):
        return (f"ZEROVERSE_BACKEND={choice} requested but its toolchain is "
                "unavailable (rizin needs r2 + r2pipe; angr needs the symbolic extra)")
    return ("no decompiler backend available — install one of: Ghidra (set "
            "GHIDRA_HOME and install the pyghidra bridge), rizin/radare2 (+ r2pipe), "
            "or angr")


def ensure_explicit_backend(name: str | None = None) -> None:
    """Fail loudly when an *explicitly requested* backend cannot initialize (#297).

    ``auto`` is a preference and may degrade to a lower-fidelity backend — that is
    the whole point of the fallback chain. Naming a backend is a demand, and an
    unmet demand must stop the run: a degraded run still produces a complete,
    well-formed result table, so the only signal that nothing was analyzed is a
    field nobody reads. Raises ``BackendUnavailableError``; no-ops for ``auto``.
    """
    choice = resolve_choice(name)
    if choice == "auto":
        return
    if select(choice) is None:
        raise BackendUnavailableError(selection_note(choice))
