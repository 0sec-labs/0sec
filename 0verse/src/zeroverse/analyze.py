"""Stage 4 — turn a decompiled program (any ILAdapter) + the taint model into
source→sink findings, via the backward slicer.

Picks CALL instructions whose callee matches an enabled source/sink in the model,
then reports a finding wherever a sink's backward slice reaches a source.

The foxguard static pre-pass (#3) runs as a second, independent high-recall
generator over the decompiled C; its hits join the queue as *hypotheses* (origin
``foxguard``), unioned with the #2 slice findings (origin ``slice``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .backends import _noise
from .il import ILAdapter, Inst, Kind
from .slicer import BackwardSlicer, find_source_to_sink
from .taint import TaintModel


@dataclass
class Finding:
    source: str           # e.g. "getenv"
    sink: str             # e.g. "system"
    function: str
    source_addr: int
    sink_addr: int
    path_len: int
    origin: str = "slice"   # "slice" (#2 backward slice) | "foxguard" (#3 static pre-pass)


# 0-based arg index holding the buffer that carries tainted data, for memory flow.
_SOURCE_BUF_ARG = {
    "read": 1, "recv": 1, "recvfrom": 1, "fgets": 0, "gets": 0, "fread": 0, "scanf": 1,
}
_SINK_BUF_ARG = {  # the tainted INPUT buffer of the sink (the copy source)
    "strcpy": 1, "strcat": 1, "memcpy": 1, "stpcpy": 1,
}


def _sym(dest: str | None) -> str | None:
    """Normalize a Ghidra callee name to a bare symbol (strip namespace/leading _)."""
    if not dest:
        return None
    return dest.split("::")[-1].lstrip("_")


def _arg_var(inst: Inst, idx: int) -> str | None:
    return inst.arg_vars[idx] if 0 <= idx < len(inst.arg_vars) else None


@dataclass
class PtrTaint:
    """Pointer / out-param taint summary (mole ``get_ptr_map``, DESIGN-NOTES #4).

    A source like ``read(fd, buf, n)`` taints memory *through* its buffer pointer
    arg; a sink like ``strcpy(dst, src)`` reads tainted memory through ``src``.
    This summary names the buffer variable each call touches so the memory-flow
    pass can connect a source's out-param to a sink's in-param by shared name."""

    call_id: int
    func: str
    symbol: str
    role: str            # "source" | "sink"
    buf_arg: int         # 0-based pointer arg index
    buf_var: str | None  # decompiler variable name of that pointer


def ptr_taint_summary(insts: list[Inst], name_of: dict[int, str]) -> list[PtrTaint]:
    """Build the pointer/out-param taint summary for every tainted call site."""
    out: list[PtrTaint] = []
    for i in insts:
        if i.kind is not Kind.CALL:
            continue
        sym = name_of.get(i.id)
        if sym is None:
            continue
        if sym in _SOURCE_BUF_ARG:
            idx = _SOURCE_BUF_ARG[sym]
            out.append(PtrTaint(i.id, i.func, sym, "source", idx, _arg_var(i, idx)))
        if sym in _SINK_BUF_ARG:
            idx = _SINK_BUF_ARG[sym]
            out.append(PtrTaint(i.id, i.func, sym, "sink", idx, _arg_var(i, idx)))
    return out


def scan(adapter: ILAdapter, model: TaintModel, insts: list[Inst]) -> list[Finding]:
    by_id = {i.id: i for i in insts}
    src_ids: list[int] = []
    snk_ids: list[int] = []
    name: dict[int, str] = {}
    for i in insts:
        if i.kind is not Kind.CALL:
            continue
        sym = _sym(i.dest)
        tf = model.by_symbol(sym) if sym else None
        if tf is None or sym is None:
            continue
        if tf.source and tf.source.enabled:
            src_ids.append(i.id)
            name[i.id] = sym
        if tf.sink and tf.sink.enabled:
            snk_ids.append(i.id)
            name[i.id] = sym

    slicer = BackwardSlicer(adapter)
    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()

    # (a) value flow — source's return value reaches the sink (e.g. getenv -> system)
    for pf in find_source_to_sink(slicer, src_ids, snk_ids):
        snk, src = by_id[pf.sink_id], by_id[pf.source_id]
        seen.add((src.addr, snk.addr))
        findings.append(Finding(
            source=name[pf.source_id], sink=name[pf.sink_id], function=snk.func,
            source_addr=src.addr, sink_addr=snk.addr, path_len=len(pf.nodes),
        ))

    # (b) memory flow — source fills a buffer (out-param) that the sink later
    # copies from (e.g. read(fd, buf, n) -> strcpy(dst, buf)), connected by the
    # pointer/out-param taint summary's shared buffer variable.
    summary = ptr_taint_summary(insts, name)
    src_ptrs = [p for p in summary if p.role == "source" and p.buf_var]
    snk_ptrs = [p for p in summary if p.role == "sink" and p.buf_var]
    for s in src_ptrs:
        sc = by_id[s.call_id]
        for k in snk_ptrs:
            kc = by_id[k.call_id]
            if kc.func != sc.func or kc.addr <= sc.addr:
                continue
            if k.buf_var == s.buf_var and (sc.addr, kc.addr) not in seen:
                seen.add((sc.addr, kc.addr))
                findings.append(Finding(
                    source=s.symbol, sink=k.symbol, function=kc.func,
                    source_addr=sc.addr, sink_addr=kc.addr, path_len=0,
                ))
    return findings


# --- libFuzzer target-vs-driver focusing (reachability + noise) ------------
#
# A real ASan+libFuzzer target statically links the libFuzzer *driver*, which
# CALLS the target harness (``LLVMFuzzerTestOneInput``). The target library is
# REACHABLE from that harness; the driver is NOT (it sits *above* the entry). So a
# finding in a driver function is a false positive. Two complementary filters:
#   1. drop findings whose function is runtime/driver noise by name (``_noise``);
#   2. keep only findings whose function is reachable from ``LLVMFuzzerTestOneInput``
#      in the recovered call graph (the principled filter).
# Both are gated so a small / non-libFuzzer binary (the toy corpus) is untouched.

_LIBFUZZER_MARKERS = frozenset({
    "LLVMFuzzerTestOneInput", "LLVMFuzzerRunDriver", "FuzzerDriver",
    "ExecuteCallback", "RunOneTest",
})


def _reachable(callgraph: dict[str, list[str]], roots: list[str]) -> set[str]:
    """Forward transitive closure of ``roots`` over ``caller -> callees``."""
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(c for c in callgraph.get(n, ()) if c not in seen)
    return seen


def _address_taken(candidates: set[str], decompiled_c: dict[str, str]) -> set[str]:
    """Functions whose name is used as a *value* (function pointer / callback arg),
    not called — reachable via an indirect dispatch the resolved callgraph misses
    (e.g. a ``cmsSAMPLER16`` passed to ``cmsStageSampleCLut16bit``). Re-admitting them
    prevents pruning a real bug in an indirectly-dispatched function. Over-approximate
    on purpose: the noise filter has already removed runtime/driver functions, so the
    only names admitted here are genuine target callbacks."""
    if not candidates:
        return set()
    blob = "\n".join(decompiled_c.values())
    taken: set[str] = set()
    for fn in candidates:
        if len(fn) < 4:  # skip short/ambiguous names to avoid spurious matches
            continue
        # Cheap substring prefilter first: if the name does not occur literally in the
        # blob, the ``\bfn\b`` regex cannot match either — and ``str in`` is a C-level
        # memmem, orders of magnitude faster than a regex scan of a multi-MB blob per
        # candidate (that scan dominated ToolBox/list_candidates runtime on real
        # targets). Only pay the precise word-boundary regex for names that appear.
        if fn not in blob:
            continue
        # the name as a bare token NOT immediately followed by '(' => used as a value
        if re.search(rf"\b{re.escape(fn)}\b(?!\s*\()", blob):
            taken.add(fn)
    return taken


def reachable_functions(meta: Any) -> set[str] | None:
    """The set of functions to keep findings in, or ``None`` to disable filtering.

    ``None`` means "don't filter" — returned whenever a trustworthy root can't be
    established, so non-libFuzzer and toy binaries are unaffected. For a libFuzzer
    target we root at ``LLVMFuzzerTestOneInput`` (target code is reachable from it,
    the driver is not). We deliberately do NOT fall back to ``main`` for a libFuzzer
    binary whose entry is missing from the graph: ``main`` reaches only the driver
    island (the call into the target is indirect), which would invert the filter."""
    callgraph = getattr(meta, "callgraph", None) or {}
    if not callgraph:
        return None
    nodes = set(callgraph) | {c for callees in callgraph.values() for c in callees}
    if _noise.LIBFUZZER_ENTRY in nodes:
        reach = _reachable(callgraph, [_noise.LIBFUZZER_ENTRY])
        # Re-admit indirect-callback targets the resolved callgraph can't reach — a
        # real bug dispatched via a function pointer (e.g. a cmsSAMPLER16) would
        # otherwise be wrongly pruned. Candidates are the real (bodied) functions
        # not already reachable; the noise filter has removed driver/runtime code.
        dc: dict[str, str] = getattr(meta, "decompiled_c", None) or {}
        return reach | _address_taken((nodes - reach) & set(dc), dc)
    # No entry node. If this still looks like a libFuzzer target, don't filter by
    # reachability (the noise filter carries it) — never fall back to ``main``.
    imports = set(getattr(meta, "imports", []) or [])
    if (nodes | imports) & _LIBFUZZER_MARKERS:
        return None
    # Non-libFuzzer binary: fall back to reachable-from-exports/main so a normal
    # program's dead code is dropped. Gated to a strict subset by the caller.
    exports = [e for e in (getattr(meta, "exports", []) or []) if e in nodes]
    roots = exports or (["main"] if "main" in nodes else [])
    if not roots:
        return None
    return _reachable(callgraph, roots)


def filter_findings(findings: list[Finding], meta: Any) -> tuple[list[Finding], str]:
    """Focus a libFuzzer target's findings on its own library code (see above).

    Returns ``(kept, note)``. Best-effort and conservative: it only ever *drops*
    findings that are runtime/driver noise or provably outside the entry's reachable
    set, and never fires on a binary where every finding is already reachable (the
    toy corpus)."""
    n_in = len(findings)
    # 1. name-based noise (libFuzzer driver internals + runtime).
    kept = [f for f in findings if not _noise.is_noise_name(f.function)]
    n_noise = n_in - len(kept)

    # 2. reachability from the libFuzzer entry (or exports/main for a normal binary).
    n_reach = 0
    reach = reachable_functions(meta)
    if reach is not None:
        funcs = {f.function for f in kept}
        in_reach = funcs & reach
        # Only filter when reachability is INFORMATIVE: some finding functions fall
        # outside the reachable set (strict subset) and at least one stays inside.
        # Otherwise (everything reachable, or the root recovered nothing useful)
        # leave the set alone — protects small / non-libFuzzer binaries.
        if in_reach and in_reach < funcs:
            keep_set = reach | {_noise.LIBFUZZER_ENTRY}
            reached = [f for f in kept if f.function in keep_set]
            n_reach = len(kept) - len(reached)
            kept = reached

    if not (n_noise or n_reach):
        return findings, ""
    note = (
        f"libFuzzer focus: dropped {n_noise + n_reach} driver/unreachable finding(s) "
        f"({n_noise} noise-named, {n_reach} unreachable from {_noise.LIBFUZZER_ENTRY})"
    )
    return kept, note


# --- #3 foxguard static pre-pass union -------------------------------------

def foxguard_union(
    findings: list[Finding], decompiled_c: dict[str, str], *, max_hyps: int = 20
) -> tuple[list[Finding], str]:
    """Run the foxguard static pre-pass over the decompiled C and union its hits
    into the finding queue as hypotheses (origin ``foxguard``). Returns the
    extended list plus a human note. Graceful: a missing/failed foxguard leaves
    ``findings`` unchanged. Dedups against #2 findings by ``function`` so divergent
    (foxguard-only) functions are kept as signal, exact overlaps are not doubled."""
    from .static_prepass import run_over_decompiled  # lazy: optional external tool

    result = run_over_decompiled(decompiled_c)
    if not result.hypotheses:
        return findings, result.note

    covered = {f.function for f in findings}
    extra: list[Finding] = []
    for h in result.hypotheses:
        if h.function in covered:
            continue  # #2 already flagged this function — not a divergence
        covered.add(h.function)
        extra.append(Finding(
            source="foxguard", sink=_short_rule(h.rule_id), function=h.function,
            source_addr=0, sink_addr=0, path_len=0, origin="foxguard",
        ))
        if len(extra) >= max_hyps:
            break
    return [*findings, *extra], result.note


def _short_rule(rule_id: str) -> str:
    return rule_id.rsplit(".", 1)[-1] if rule_id else "foxguard"
