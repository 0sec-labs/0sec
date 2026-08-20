"""Engine-agnostic IL model + the ILAdapter interface.

The slicer (``slicer.py``) traverses this abstract IL; concrete backends
(Ghidra P-Code HighFunction, angr DDG, optionally Binary Ninja MLIL) implement
``ILAdapter`` to answer the queries the slicer needs. This is the seam mole keeps
between ``core/slice.py`` and Binary-Ninja-specific code — here it's a formal
interface so the *same* slicer runs over either backend (DESIGN-NOTES Decision 4).

A ``MockAdapter`` (in-memory IL) lets us test the slicer with zero heavy deps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Protocol, runtime_checkable


class Kind(Enum):
    VAR = auto()      # use of an SSA variable (resolve via get_def)
    PHI = auto()      # SSA phi (all operands are defs)
    CALL = auto()     # call: .dest symbol, .args operand ids
    LOAD = auto()     # memory load (resolve via get_memory_defs)
    STORE = auto()    # memory store
    BINOP = auto()
    UNOP = auto()
    RET = auto()
    CONST = auto()    # terminal
    PARAM = auto()    # function parameter (resolve via get_callers)
    OTHER = auto()


@dataclass
class Inst:
    """One IL instruction node. ``operands`` are the ids of instructions that
    directly feed this one (its backward neighbours for structural recursion)."""

    id: int
    func: str
    addr: int
    kind: Kind
    operands: list[int] = field(default_factory=list)
    text: str = ""
    var: str | None = None          # for VAR/PARAM
    dest: str | None = None         # for CALL: callee symbol
    args: list[int] = field(default_factory=list)   # for CALL: def-op id per arg
    arg_vars: list[str | None] = field(default_factory=list)  # CALL: var name per arg (memory flow)
    mem_version: int | None = None  # for LOAD/STORE


@runtime_checkable
class ILAdapter(Protocol):
    """What a decompiler backend must answer for the slicer to run."""

    def inst(self, inst_id: int) -> Inst: ...
    def get_def(self, var: str, func: str) -> int | None: ...
    def get_memory_defs(self, load: Inst) -> list[int]: ...
    # (caller_call_inst_id, arg_operand_id) for each call site reaching `func`'s param
    def get_callers(self, func: str, param_index: int) -> list[tuple[int, int]]: ...
    def get_callee_returns(self, call: Inst) -> list[int]: ...
    def functions(self) -> list[str]: ...


class MockAdapter:
    """In-memory ILAdapter for tests. You hand it a list of Inst plus def/caller
    maps; it implements the interface so the real slicer can be exercised."""

    def __init__(
        self,
        insts: list[Inst],
        defs: dict[tuple[str, str], int] | None = None,     # (var, func) -> inst id
        mem_defs: dict[int, list[int]] | None = None,        # load id -> store ids
        callers: dict[tuple[str, int], list[tuple[int, int]]] | None = None,
        returns: dict[int, list[int]] | None = None,         # call id -> ret ids
    ) -> None:
        self._by_id = {i.id: i for i in insts}
        self._defs = defs or {}
        self._mem = mem_defs or {}
        self._callers = callers or {}
        self._returns = returns or {}

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
