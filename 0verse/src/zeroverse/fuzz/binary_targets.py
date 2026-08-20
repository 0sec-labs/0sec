"""Rank + harness the INTERNAL parsers of a stripped binary (the firmware case).

A real stripped shared object has hundreds of ``FUN_<addr>`` functions Ghidra
recovered with no symbol; fuzzing them blind is noise. This module triages them to
the INPUT-REACHABLE parsers worth driving through the address-mode harness
(``harness.func_offset``):

  * reachability: a forward call-graph closure from the EXPORTED entry points inward
    — an internal function reached from an exported parse/load/decode entry takes
    attacker input; an unreachable helper does not.
  * parser shape: the intra-procedural ``localize.parse_signal`` (indexes a buffer
    parameter, assembles multi-byte lengths, loops to a param bound, feeds a memory
    sink) — where OOB/overflow bugs live.
  * ABI shape: a ``(buffer, length)``-style signature is the drivable fuzz entry.

Output is a ranked list so the pipeline harnesses the top-N internal parsers, not
all of them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..localize import _loop_bounded_by_param, _param_indexed, parse_signal
from .harness import (
    GHIDRA_IMAGE_BASE,
    HarnessSpec,
    TargetSignature,
    recover_signature,
)


def infer_param_roles(sig: TargetSignature | None, body: str) -> list[str] | None:
    """Infer dlsym param roles from the decompiled body, for STRIPPED targets where
    Ghidra types the buffer pointer as a bare integer (``long`` / ``undefined8``) so
    the positional heuristic can't tell buffer from length. The param that is
    indexed / pointer-arith'd in the body is the fuzz buffer (``input``); the loop-
    bound param is the ``length``. Casting the fuzz pointer to the buffer param's
    type — even ``(long)`` — passes the address correctly (a pointer and a 64-bit
    integer share the same argument register). Returns ``None`` when no buffer param
    can be identified (fall back to the positional heuristic)."""
    if sig is None or sig.is_void_params or not body:
        return None
    names = [n for _, n in sig.params]
    buf_idx: int | None = None
    # Prefer a real pointer param; else the integer param the body indexes/derefs.
    for i, (t, _n) in enumerate(sig.params):
        if "*" in t:
            buf_idx = i
            break
    if buf_idx is None:
        for i, n in enumerate(names):
            if n and _param_indexed(body, frozenset({n})):
                buf_idx = i
                break
    if buf_idx is None:
        return None
    roles = ["zero"] * len(sig.params)
    roles[buf_idx] = "input"
    # length = a non-buffer param used as a loop bound; else the first other integer.
    len_idx: int | None = None
    for i, (t, n) in enumerate(sig.params):
        if i == buf_idx or "*" in t:
            continue
        if n and _loop_bounded_by_param(body, frozenset({n})):
            len_idx = i
            break
    if len_idx is None:
        for i, (t, _n) in enumerate(sig.params):
            if i != buf_idx and "*" not in t:
                len_idx = i
                break
    if len_idx is not None:
        roles[len_idx] = "length"
    return roles


@dataclass
class InternalTarget:
    """A ranked internal (non-exported) function candidate for harnessing."""

    func: str                       # Ghidra name, e.g. FUN_00102560
    offset: int                     # load-base-relative offset (entry - image_base)
    signature: TargetSignature | None
    score: float
    reachable: bool
    why: str
    param_roles: list[str] | None = None  # inferred buffer/length wiring (drives the call)


def _params_of(sig: TargetSignature | None) -> frozenset[str]:
    if sig is None:
        return frozenset()
    return frozenset(n for _, n in sig.params if n)


def _has_buffer_and_length(sig: TargetSignature | None) -> bool:
    """A drivable fuzz entry: at least one pointer param (the buffer) and one
    non-pointer param (a plausible length)."""
    if sig is None or sig.is_void_params:
        return False
    return bool(sig.pointer_params) and any("*" not in t for t, _ in sig.params)


def reachable_from_exports(
    callgraph: dict[str, list[str]], entries: list[str] | set[str]
) -> set[str]:
    """Forward call-graph closure from the exported ``entries`` — every function an
    exported entry point can transitively call (i.e. can be fed attacker input)."""
    seen: set[str] = set()
    stack = list(entries)
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(c for c in callgraph.get(n, ()) if c not in seen)
    return seen


def rank_internal_targets(
    functions: list[str],
    decompiled_c: dict[str, str],
    callgraph: dict[str, list[str]],
    *,
    exported_entries: list[str] | set[str],
    image_base: int = GHIDRA_IMAGE_BASE,
    top_n: int = 8,
) -> list[InternalTarget]:
    """Rank the internal ``FUN_<addr>`` functions by how likely they are an
    input-reachable parser worth fuzzing. Highest score first."""
    reachable = reachable_from_exports(callgraph, exported_entries)
    out: list[InternalTarget] = []
    for func in functions:
        if not func.startswith("FUN_"):
            continue  # named/exported — the dlsym path handles those
        try:
            entry = int(func[4:], 16)
        except ValueError:
            continue
        body = decompiled_c.get(func, "")
        sig = recover_signature(func, body)
        params = _params_of(sig)
        is_reachable = func in reachable
        shape = parse_signal(body, params) if body else 0.0
        buflen = _has_buffer_and_length(sig)
        # Reachability is the dominant gate (an unreachable helper is not attacker-
        # driven), parser shape and a (buf,len) ABI add on top.
        score = (3.0 if is_reachable else 0.0) + shape + (1.0 if buflen else 0.0)
        why: list[str] = []
        why.append("reachable-from-export" if is_reachable else "UNREACHABLE")
        if shape >= 3.0:
            why.append(f"parser-shape({shape:.1f})")
        elif shape > 0.0:
            why.append(f"weak-shape({shape:.1f})")
        if buflen:
            why.append("(buf,len)-sig")
        out.append(InternalTarget(
            func=func, offset=entry - image_base, signature=sig,
            score=score, reachable=is_reachable, why=", ".join(why),
            param_roles=infer_param_roles(sig, body),
        ))
    out.sort(key=lambda t: (t.score, t.reachable), reverse=True)
    return out[:top_n]


def exported_entries_of(functions: list[str]) -> list[str]:
    """The exported entry points among Ghidra's recovered functions: the NAMED ones
    (a stripped object names only its dynamic exports; everything else is FUN_)."""
    return [f for f in functions if not f.startswith("FUN_")]


def rank_from_adapter(adapter: Any, *, top_n: int = 8) -> list[InternalTarget]:
    """Push-button ranking from a ``GhidraAdapter``: auto image base (from the export),
    exported entries = the named functions, ranked internal parsers out."""
    meta = adapter.meta
    functions = adapter.functions()
    image_base = getattr(meta, "image_base", 0) or GHIDRA_IMAGE_BASE
    return rank_internal_targets(
        functions, getattr(meta, "decompiled_c", {}) or {},
        getattr(meta, "callgraph", {}) or {},
        exported_entries=exported_entries_of(functions),
        image_base=image_base, top_n=top_n,
    )


def internal_harness_specs_ranked(
    adapter: Any, lib: str | Path, *, top_n: int = 8, max_input: int = 4096,
) -> list[HarnessSpec]:
    """The push-button flow: point at a Ghidra-analyzed stripped ``lib`` and get
    address-mode ``HarnessSpec``s for the top-N input-reachable internal parsers."""
    return [
        HarnessSpec(
            func=t.func, signature=t.signature, lib=Path(lib),
            func_offset=t.offset, param_roles=t.param_roles, max_input=max_input,
        )
        for t in rank_from_adapter(adapter, top_n=top_n)
    ]
