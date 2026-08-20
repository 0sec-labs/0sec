"""Input-taint / attacker-reachability localization — rank functions by how close
they sit to attacker-controlled input, not by how write/loop-heavy they look.

The binding constraint on the agentic scanner is *localization*: the LLM's reasoning
is already robust (it finds the bug on a legible decompile), but on a real ELF with
thousands of functions it never gets pointed at the buggy one. The prior ranker
(``agentic._memop_score``) rewards functions that do lots of stores/loops — which on
a C++ target surfaces container internals, allocators, and math kernels, burying the
actual parser that touches the fuzzer's bytes.

This module ranks by **data-flow proximity to the untrusted-input entry**:

  1. Find the entry that receives attacker bytes — ``LLVMFuzzerTestOneInput(const
     uint8_t *data, size_t size)`` (its two params ARE the taint source), or a
     ``main(argc, argv)`` fallback.
  2. Propagate a taint value forward through the recovered call graph: the entry is
     fully tainted, and taint flows to a callee that takes a pointer parameter
     (decaying with depth), so functions that sit on the path the input travels
     accumulate taint.
  3. Add a light *intra-procedural* parse signal: does the function index/deref a
     parameter pointer, assemble multi-byte integers from bytes (``x << 8 | y`` —
     the fingerprint of binary-format parsing), loop bounded by a size parameter, or
     hand a parameter buffer to ``memcpy``/a parser? Parsers of attacker data light
     all of these up regardless of whether they happen to contain a store-in-a-loop.

Taint proximity DOMINATES; the old memop score is folded in only as a weak tiebreak
so a bug that also happens to be store-heavy still floats up. Large fuzz-reachable
functions are admitted unconditionally with a size bonus, because a real vuln is
often *inlined* into a giant parent (libraw's ``parseAdobeRAFMakernote`` vanished
into a 59 KB ``parseFujiMakernotes``); ``read_region`` then lets the agent navigate
that blob a window at a time instead of truncating it.

Pure and Ghidra-free: everything here is string/graph analysis over an already
-recovered ``ProgramMeta``, so it is exercised by mock unit tests with no toolchain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .agentic import _has_param_ptr_arith, _memop_score, _signature_params
from .backends import _noise
from .deasan import deasan_all, is_asan_instrumented

# --- taint source detection -------------------------------------------------

# A ``main`` harness is the fallback taint root when there is no libFuzzer entry: its
# argv/stdin is the untrusted channel.
_MAIN_ENTRIES: tuple[str, ...] = ("main", "LLVMFuzzerTestOneInput")


def find_entry(decompiled: dict[str, str], callgraph: dict[str, list[str]]) -> str | None:
    """The function that first receives attacker-controlled input. Prefers the
    libFuzzer entry (its ``data``/``size`` params are the taint source); falls back to
    ``main``. Returns ``None`` when neither is present (a bare single-function extract
    or a non-standard harness) — callers then treat every reachable function as
    in-scope rather than anchoring the propagation."""
    if _noise.LIBFUZZER_ENTRY in decompiled:
        return _noise.LIBFUZZER_ENTRY
    nodes = set(callgraph) | {c for cs in callgraph.values() for c in cs}
    if _noise.LIBFUZZER_ENTRY in nodes:
        return _noise.LIBFUZZER_ENTRY
    if "main" in decompiled or "main" in nodes:
        return "main"
    return None


# --- reachability gate on candidate selection -------------------------------
#
# A function with NO path from the input entry (``LLVMFuzzerTestOneInput`` / ``main``)
# in the AUGMENTED call graph (direct + recovered indirect edges) AND whose address is
# never taken cannot be triggered by attacker input — it is not an input-triggered bug,
# so it must not surface as a candidate/frontier hypothesis. The concrete leak this
# closes: libc++'s ``_Large_integer_to_chars`` (a <charconv> helper with no known callers
# and not fuzz-reachable) became a bug hypothesis in a real hunt.
#
# CONSERVATIVE by construction — the speculative indirect-edge recovery is INCOMPLETE, so
# static reachability UNDER-approximates the true reachable set. We therefore exclude a
# function ONLY when we can compute a concrete reachable set AND the function is
# confidently outside it (not reachable, not address-taken). When there is no input entry,
# no recovered call graph, or the entry has no recorded edges, reachability "can't be
# computed" and we DECLINE to filter (return ``None`` / ``True``) rather than risk exiling
# a genuinely (indirectly) reached bug.


def input_reachable_set(meta: Any) -> set[str] | None:
    """The set of functions confidently reachable from the input entry, or ``None`` when
    reachability cannot be computed (caller must then NOT filter anything).

    Built over the AUGMENTED call graph (``indirect_calls.augmented_callgraph`` = direct
    edges + speculative indirect/vtable edges) as a forward closure from the entry found
    by :func:`find_entry`, then UNIONED with the address-taken functions (candidate
    indirect-call targets whose true edges the recovery may not have wired). Only a
    function ABSENT from a non-``None`` return is confidently input-unreachable."""
    decompiled: dict[str, str] = getattr(meta, "decompiled_c", {}) or {}
    try:
        from .indirect_calls import augmented_callgraph

        callgraph = augmented_callgraph(meta)
    except Exception:
        callgraph = {k: list(v) for k, v in (getattr(meta, "callgraph", {}) or {}).items()}
    # No edges recovered at all -> we cannot decide reachability; do not filter.
    if not callgraph:
        return None
    entry = find_entry(decompiled, callgraph)
    if entry is None:
        return None
    nodes = set(callgraph) | {c for cs in callgraph.values() for c in cs}
    # Entry has a body but no recorded outgoing/incoming edges -> the graph around it is
    # unrecovered; treating everything else as unreachable would over-filter. Decline.
    if entry not in nodes:
        return None
    seen: set[str] = set()
    stack = [entry]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(c for c in callgraph.get(n, ()) if c not in seen)
    # Address-taken functions are candidate targets of indirect sites whose real edges the
    # speculative recovery may have missed — admit them so a genuinely indirectly-reached
    # bug is never excluded (recall over precision, deliberately).
    try:
        from .indirect_calls import address_taken

        seen |= address_taken(meta)
    except Exception:
        pass
    return seen


def input_reachable(meta: Any, fn: str) -> bool:
    """True unless ``fn`` is CONFIDENTLY unreachable from the input entry.

    ``False`` only when a concrete reachable set is computable (an entry + a real call
    graph exist) AND ``fn`` is neither in the augmented-graph forward closure from the
    entry nor address-taken. When reachability can't be computed, returns ``True`` — the
    conservative escape that never over-filters an under-approximated graph."""
    reach = input_reachable_set(meta)
    if reach is None:
        return True
    return fn in reach


# --- intra-procedural parse signal ------------------------------------------

# Multi-byte integer assembly from a byte stream: ``b0 << 8 | b1``, ``<< 0x10`` … The
# single strongest fingerprint of binary-format parsing (endian decode of lengths,
# tags, offsets). Ghidra always spaces the operator.
_BYTE_ASSEMBLY = re.compile(r"(?:<<|>>)\s*(?:8|0x8|0x10|0x18|0x20|16|24|32)\b")
# A subscript whose base is a bare identifier: ``data[i]`` / ``buf[uVar5]``.
_SUBSCRIPT_BASE = re.compile(r"([A-Za-z_]\w*)\s*\[")


def _param_indexed(body: str, params: frozenset[str]) -> bool:
    """Does the function index or offset-deref one of its pointer parameters — the
    hallmark of walking a caller-owned buffer (``param[i]`` or ``*(T *)(param + k)``)?"""
    if _has_param_ptr_arith(body, params):
        return True
    return any(m.group(1) in params for m in _SUBSCRIPT_BASE.finditer(body))


def _loop_bounded_by_param(body: str, params: frozenset[str]) -> bool:
    """A comparison against a parameter inside a body that also loops — the shape of a
    cursor walked to an attacker-supplied length/size (``while (i < size)``)."""
    if not params:
        return False
    if not re.search(r"\b(?:for|while)\b|\bdo\s*\{", body):
        return False
    for p in params:
        pe = re.escape(p)
        if re.search(rf"[<>]=?\s*\(?\s*(?:\([^)]*\)\s*)?{pe}\b", body):
            return True
        if re.search(rf"\b{pe}\s*[<>]=?", body):
            return True
    return False


def _param_to_sink(body: str, params: frozenset[str]) -> bool:
    """A parameter buffer handed to a memory sink (``memcpy(dst, param, n)`` etc.) —
    the classic overflow feed where the length is attacker-derived."""
    for m in re.finditer(
        r"\b(?:memcpy|memmove|mempcpy|strcpy|strncpy|strcat|memset)\s*\(([^;]*)", body
    ):
        args = m.group(1)
        for p in params:
            if re.search(rf"\b{re.escape(p)}\b", args):
                return True
    return False


def parse_signal(body: str, params: frozenset[str]) -> float:
    """0..N intra-procedural "this function parses attacker bytes" score. Independent
    of the store-in-a-loop shape the memop ranker keys on: a pure read-side parser
    (assemble a length from bytes, then index) scores high here and ~0 there."""
    score = 0.0
    indexes_param = _param_indexed(body, params)
    if indexes_param:
        score += 3.0
    n_asm = len(_BYTE_ASSEMBLY.findall(body))
    if n_asm:
        # multi-byte assembly is the parse signal only when the bytes come FROM a
        # buffer the function indexes — otherwise it is local integer math (number
        # formatting, hashing) that also shifts by 8/16/24, so weight it down.
        weight = 1.25 if indexes_param else 0.5
        score += min(n_asm, 4) * weight  # up to +5 for heavy endian decode off a buffer
    if _loop_bounded_by_param(body, params):
        score += 2.0
    if _param_to_sink(body, params):
        score += 2.5
    return score


# --- forward taint propagation over the call graph --------------------------

_DECAY = 0.6  # taint attenuation per call-graph hop
_MAX_DEPTH = 12  # cap the BFS so a deep recursive graph terminates cheaply
_MIN_TAINT = 0.02  # prune negligible taint


def propagate_taint(
    decompiled: dict[str, str],
    callgraph: dict[str, list[str]],
    entry: str | None,
    params_of: dict[str, frozenset[str]],
) -> dict[str, float]:
    """Forward taint from ``entry`` over ``callgraph``. The entry is fully tainted;
    taint flows to a callee that takes a pointer/parameter (attacker data is passed
    down), decaying by ``_DECAY`` per hop, and *accumulates* — a function invoked from
    several tainted parsers is more likely on the input path than one called once from
    deep in a math kernel. Returns ``fn -> taint`` (only reachable, tainted nodes)."""
    taint: dict[str, float] = {}
    if entry is None:
        return taint
    # BFS by depth so accumulation is order-independent up to the decay envelope.
    frontier: dict[str, float] = {entry: 1.0}
    taint[entry] = 1.0
    for _depth in range(_MAX_DEPTH):
        nxt: dict[str, float] = {}
        for fn, t in frontier.items():
            flow = t * _DECAY
            if flow < _MIN_TAINT:
                continue
            for callee in callgraph.get(fn, ()):
                # taint flows only where the callee can actually receive a buffer/len.
                # A callee we decompiled but whose signature has NO parameters is a
                # leaf that cannot carry attacker data down — skip it. A callee absent
                # from ``decompiled`` (external/undecompiled) has an unknown signature,
                # so we let taint flow conservatively rather than cut the path.
                if callee in decompiled and not params_of.get(callee):
                    continue
                taint[callee] = taint.get(callee, 0.0) + flow
                nxt[callee] = nxt.get(callee, 0.0) + flow
        if not nxt:
            break
        frontier = nxt
    return taint


# --- combined localization ranking ------------------------------------------

# Weights: taint proximity DOMINATES. parse_signal (0..~12) and taint (0..~a few) are
# the primary axes; the legacy memop score is folded in at low weight only to break
# ties among comparably-tainted parsers.
_W_TAINT = 4.0
_W_PARSE = 1.0
_W_MEMOP = 0.15
# Inlined-blob admission: a large fuzz-reachable function likely CONTAINS an inlined
# vuln even if its shape is diffuse. Give a size bonus so the parent floats up.
_INLINE_BYTES = 8000
_INLINE_BONUS = 4.0


@dataclass
class Localized:
    """One ranked candidate with its component scores, for an auditable report."""

    function: str
    score: float
    taint: float
    parse: float
    memop: float
    size: int
    reachable: bool


def localize_scored(meta: Any) -> list[Localized]:
    """Rank every non-noise function by input-taint proximity. Returns the full sorted
    list (highest first) with component scores exposed so a caller can report the rank
    of a specific ground-truth function."""
    raw: dict[str, str] = getattr(meta, "decompiled_c", {}) or {}
    asan = any(is_asan_instrumented(b) for b in raw.values())
    decompiled = deasan_all(raw) if asan else raw
    callgraph: dict[str, list[str]] = getattr(meta, "callgraph", {}) or {}

    params_of: dict[str, frozenset[str]] = {
        fn: _signature_params(body) for fn, body in decompiled.items()
    }
    entry = find_entry(decompiled, callgraph)
    taint = propagate_taint(decompiled, callgraph, entry, params_of)

    out: list[Localized] = []
    for fn, body in decompiled.items():
        if _noise.is_noise_name(fn) or len(body) < 60:
            continue
        params = params_of.get(fn, frozenset())
        t = taint.get(fn, 0.0)
        reachable = fn in taint if entry is not None else True
        ps = parse_signal(body, params)
        mem = _memop_score(
            body,
            reachable=reachable,
            calls_sink=_noise.calls_sink(body),
            params=params,
        )
        size = len(body)
        score = _W_TAINT * t + _W_PARSE * ps + _W_MEMOP * mem
        if reachable and size >= _INLINE_BYTES:
            # scale the bonus gently with size so a 59 KB blob outranks an 8 KB one
            score += _INLINE_BONUS + min((size - _INLINE_BYTES) / 20000.0, 3.0)
        # a reachable function with zero taint (entry present but no path found — e.g.
        # an indirect-callback target) still gets a small floor so parsers reached only
        # through function pointers are not exiled below unreachable noise.
        if entry is not None and not reachable and ps > 0:
            score += _W_PARSE * 0.5 * ps
        out.append(Localized(fn, score, t, ps, mem, size, reachable))
    out.sort(key=lambda item: (-item.score, item.function))
    return out


def localize_candidates(meta: Any, limit: int = 15) -> list[str]:
    """The taint-ranked candidate function names (highest input-proximity first)."""
    return [item.function for item in localize_scored(meta)[:limit]]


def rank_of(meta: Any, function: str) -> tuple[int, int]:
    """1-based rank of ``function`` in the localized list and the list length. Rank is
    ``len+1`` (i.e. "not ranked") when the function was filtered out as noise/too-short
    or is absent. For reporting the before/after localization number honestly."""
    scored = localize_scored(meta)
    for i, item in enumerate(scored, 1):
        if item.function == function:
            return i, len(scored)
    return len(scored) + 1, len(scored)


# --- inlined-region navigation ----------------------------------------------


def read_region(
    body: str,
    *,
    around: str | None = None,
    offset: int | None = None,
    window: int = 2400,
    occurrence: int = 1,
) -> str:
    """Return a WINDOW-character slice of a (possibly huge) function body centered on a
    landmark, so a 59 KB inlined blob is navigable instead of truncated at 6 KB.

    Anchor by either ``around`` (a substring — a callee name, a sink like ``memcpy``,
    a struct-field offset like ``0x164``; the ``occurrence``-th match is centered) or a
    raw character ``offset``. The slice is snapped to line boundaries and annotated
    with the character span and a hint that more lies on either side, so the agent can
    page through by asking for the next offset.

    ANTI-DROWNING: a missing landmark is NOT a dead end. When ``around`` is absent from
    the body, we FALL BACK to sequential windowed chunks from the head (returning the
    first window plus a "N more window(s); call read_region(offset=…) to continue" hint)
    so a 14 KB heavily-inlined body stays navigable instead of stalling the walk."""
    n = len(body)
    if n <= window and around is None and offset is None:
        return body

    def _render(center: int, note: str, *, prefix: str = "") -> str:
        half = window // 2
        lo = max(0, center - half)
        hi = min(n, center + half)
        # snap to line boundaries for readability
        if lo > 0:
            nl = body.rfind("\n", 0, lo)
            lo = nl + 1 if nl >= 0 else lo
        if hi < n:
            nl = body.find("\n", hi)
            hi = nl if nl >= 0 else hi
        slice_ = body[lo:hi]
        head = "" if lo == 0 else f"/* ... {lo} chars before ... */\n"
        remaining = n - hi
        if remaining > 0:
            n_more = (remaining + window - 1) // window
            tail = (
                f"\n/* ... {remaining} chars after — {n_more} more window(s); "
                f"call read_region(offset={hi}) to continue ... */"
            )
        else:
            tail = ""
        return (
            f"{prefix}[region of a {n}-char function — {note}; showing chars {lo}..{hi}]\n"
            f"{head}{slice_}{tail}"
        )

    if around:
        idx = -1
        start = 0
        for _ in range(max(occurrence, 1)):
            idx = body.find(around, start)
            if idx < 0:
                break
            start = idx + 1
        if idx < 0:
            first = body.find(around)
            if first < 0:
                # ANTI-DROWNING FALLBACK: the landmark is absent, but a huge inlined
                # body must not become a dead end. Page it from the head with sequential
                # windows so the model can still navigate it via read_region(offset=…).
                n_windows = (n + window - 1) // window
                prefix = (
                    f"landmark {around!r} not found in this {n}-char function body — "
                    f"falling back to SEQUENTIAL windows (window 1 of {n_windows}). "
                    f"Page forward with read_region(offset=…) using the offset in the "
                    f"tail hint, or retry with a different landmark (a callee name, a "
                    f"sink like 'memcpy', or an offset like '0x1a').\n"
                )
                return _render(
                    window // 2, "head of function (landmark-miss fallback)", prefix=prefix
                )
            # the landmark IS present, just fewer times than requested.
            return (
                f"only {body.count(around)} occurrence(s) of {around!r}; "
                f"requested #{occurrence}. Re-request with a smaller occurrence."
            )
        center = idx + len(around) // 2
        return _render(center, f"centered on occurrence #{occurrence} of {around!r} (char {idx})")
    if offset is not None:
        center = max(0, min(int(offset), n))
        return _render(center, f"centered on char offset {center}")
    return _render(window // 2, "head of function")
