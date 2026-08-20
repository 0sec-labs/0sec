"""Agentic tool-loop scanner — the LLM *drives* the investigation of a binary.

The single-shot pseudo-C scan (``llm_scan.py``) pre-bakes context: it picks a
function, attaches the struct layouts *we* think are relevant, and asks the model
for one verdict. That works when our heuristics guess right, but it forecloses the
model's own line of inquiry — it cannot pull up a callee, resolve a raw offset to a
struct field, or check who invokes a suspicious function unless we handed it that
up front.

This module inverts the control flow (Big-Sleep style): the model is given a small
catalog of **tools** over a ``ProgramMeta`` and a starting function, and it decides
what to look at. It resolves ``*(cVar2 + 0x10 + uVar5 * 4)`` to ``nSamples[15]`` by
*calling* ``find_structs_for_pointer`` itself — the struct context is discovered,
not pre-baked. A ReAct-style JSON loop implements this over ``complete_json`` (the
Codex backend has no native tool-calling): each turn the model returns either a
tool call or a final verdict; we execute the tool, append the observation, and
loop. Every call + observation is logged so a run is fully auditable.

Honest & general: the tools are offset-driven and library-agnostic (never keyed to
lcms), the model still only PROPOSES a hypothesis (a downstream oracle confirms),
and the whole thing is gated behind an injected ``llm`` so the deterministic
MockLLM CI path needs neither codex nor Ghidra.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .bugclasses import loop_oob_lens
from .deasan import deasan_all, is_asan_instrumented
from .structtypes import base_offset_groups, format_struct, select_structs

# --- the action schema the model returns each turn --------------------------
#
# ReAct over ``complete_json``: EITHER a tool call OR a final verdict. Kept loose
# (only ``action`` required, no ``additionalProperties: false``) because the fields
# that matter depend on the branch — a "call" carries ``tool``/``args``; a "verdict"
# carries the bug fields. The schema is embedded in the prompt as guidance; parsing
# is lenient so a slightly-off shape still routes.
ACTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "thought": {"type": "string", "description": "brief reasoning for this step"},
        "action": {"type": "string", "enum": ["call", "verdict"]},
        # action == "call"
        "tool": {"type": "string", "description": "tool name (when action=call)"},
        "args": {"type": "object", "description": "tool arguments (when action=call)"},
        # action == "verdict"
        "is_bug": {"type": "boolean"},
        "cwe": {"type": "string"},
        "sink": {"type": "string"},
        "source": {"type": "string"},
        "explanation": {"type": "string"},
    },
    "required": ["action"],
}


@dataclass
class TrajStep:
    """One turn of the loop: the model's thought/action and the observation we fed
    back. ``observation`` is empty on the final verdict step."""

    step: int
    thought: str
    action: str
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    observation: str = ""


@dataclass
class AgentVerdict:
    """The model's final memory-safety judgment for the starting function."""

    is_bug: bool
    cwe: str
    sink: str
    source: str
    explanation: str


@dataclass
class VerdictReview:
    """The outcome of the adversarial second pass (``verify_finding``) over a POSITIVE
    finding. A SKEPTIC re-investigates the sink + its callers trying to REFUTE the bug.

    ``upheld`` is True when the finding survives the audit (no guard covers the asserted
    access) and False when it is REFUTED (a concrete bounds check / clamp / early-return
    was found that makes the access safe). ``checked_guard`` is that concrete guard when
    refuted (empty when upheld); ``reason`` is the skeptic's explanation."""

    upheld: bool
    reason: str
    checked_guard: str = ""


@dataclass
class AgentResult:
    """A full auditable run: the starting function, every step, and the verdict (or
    None if the loop exhausted its budget without one)."""

    start_function: str
    steps: list[TrajStep]
    verdict: AgentVerdict | None
    stop_reason: str  # "verdict" | "max_steps" | "loop-guard" | "error"
    # How the start was chosen (set by ``explore``): "" (seeded ``run_agent``),
    # "input-entry" (attacker-input entry point), "provided" (caller-specified), or
    # "fallback-ranked" (no entry recovered — top taint candidate, said honestly).
    entry_source: str = ""
    # Functions the model actually read during the run (exploration coverage), ordered
    # by first visit. Empty for a run that never read a body.
    visited: list[str] = field(default_factory=list)
    # The adversarial-verification outcome (set by ``explore`` when ``adversarial=True``
    # and the loop returned a POSITIVE verdict). ``None`` when no positive finding was
    # produced or the pass was disabled. When ``review.upheld`` is False the returned
    # ``verdict`` has already been DOWNGRADED to ``is_bug=False``.
    review: VerdictReview | None = None
    # The PoV adjudication outcome (set by ``adjudicate.adjudicate_result`` as a
    # separate post-step when a poc is available for a POSITIVE finding). ``None``
    # until adjudicated. Typed loosely to avoid an import cycle with ``adjudicate``;
    # it holds an ``adjudicate.Adjudication``. ``explore`` never sets this — PoV
    # confirmation is a deterministic step the integrator/pipeline runs afterward.
    adjudication: Any = None

    def transcript(self) -> str:
        """Render the trajectory verbatim for a report."""
        head = f"=== agentic run on {self.start_function!r} ==="
        if self.entry_source:
            head += f" [entry_source={self.entry_source}]"
        lines: list[str] = [head]
        if self.visited:
            lines.append(f"visited ({len(self.visited)}): " + ", ".join(self.visited))
        for s in self.steps:
            lines.append(f"\n[step {s.step}] thought: {s.thought}")
            if s.action == "call":
                lines.append(f"  -> call {s.tool}({json.dumps(s.args)})")
                lines.append(f"  observation:\n{_indent(s.observation)}")
            else:
                lines.append("  -> verdict")
        if self.verdict is not None:
            v = self.verdict
            lines.append(
                f"\nVERDICT is_bug={v.is_bug} cwe={v.cwe!r} sink={v.sink!r} "
                f"source={v.source!r}\n  {v.explanation}"
            )
        if self.review is not None:
            r = self.review
            lines.append(
                "\n[adversarial-verification] "
                + ("UPHELD" if r.upheld else "REFUTED")
                + f": {r.reason}"
                + (f"\n  guard: {r.checked_guard}" if r.checked_guard else "")
            )
        lines.append(f"\n[stop: {self.stop_reason}]")
        return "\n".join(lines)


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + ln for ln in text.splitlines()) or prefix + "(empty)"


def _as_int(value: Any, *, default: int = 0) -> int:
    """Coerce a tool arg to int (the model may emit ``"0"``/``0``/``0x10``). Falls back
    to ``default`` on anything unparseable so a bad arg costs a turn, not a crash."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except (ValueError, TypeError):
        return default


# --- tool surface over a ProgramMeta ----------------------------------------

_MAX_BODY_CHARS = 6000  # cap a single function body fed back to the model

# Allocator calls whose result is a heap buffer whose size is the call argument. Kept
# library-agnostic: libc (malloc/calloc/realloc/…), the lcms pool (_cmsMalloc*), glib,
# alloca, and the Ghidra-mangled C++ `operator new`.
_ALLOC_FUNCS: tuple[str, ...] = (
    "calloc",
    "reallocarray",
    "realloc",
    "malloc",
    "alloca",
    "valloc",
    "_cmsMalloc",
    "_cmsMallocZero",
    "_cmsCalloc",
    "_cmsDupMem",
    "xmalloc",
    "xcalloc",
    "g_malloc0",
    "g_malloc",
    "g_realloc",
    "operator_new",
    "operator.new",
)
# Allocators taking (count, element_size) — the product is the byte size (overflow-prone).
_COUNT_SIZE_ALLOCS: frozenset[str] = frozenset({"calloc", "reallocarray", "_cmsCalloc", "xcalloc"})


# --- broad memory-op candidate ranking -------------------------------------
#
# The loop-OOB lens keys on ONE shape (a loop-count-vs-fixed-array store). Real bugs
# take other shapes (a bounds-check-ordering OOB read, an unclamped index, pointer
# arithmetic on a caller-owned buffer) it never surfaces — depending on it alone
# re-introduces the pattern-matching bottleneck the LLM is meant to replace. So we
# also offer a BROADER, ranked (not filtered) source: functions that perform
# interesting memory operations, so the model has leads even when the lens is empty.
_IDX_WRITE = re.compile(r"[A-Za-z_]\w*\s*\[[^\]]+\]\s*=(?!=)")
# any array-subscript expression (a read or write). Linear (no overlapping
# quantifiers) — the previous read-specific pattern backtracked catastrophically on
# the large bodies ASan produces, dominating the ranker's runtime.
_SUBSCRIPT = re.compile(r"[A-Za-z_]\w*\s*\[[^\]]+\]")
_PTR_WRITE = re.compile(r"\*\s*\([^)]*\*\s*\)\s*\([^)]*\)\s*=(?!=)")
_CAST_INDEX = re.compile(r"\[\s*\(\s*(?:u?int|u?long|u?short|u?char|byte)\b")
_MEMOP_LOOP = re.compile(r"\b(?:for|while)\b|\bdo\s*\{")
_INDIRECT_CALL = re.compile(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)\s*\(")
_PTR_DEREF = re.compile(r"\*\s*\([^)]*\*\s*\)\s*\(")


def _has_param_ptr_arith(body: str, params: frozenset[str]) -> bool:
    """Cheap substring test for pointer arithmetic on a caller-owned parameter —
    ``*(T *)(param_1 + 8)``. Ghidra pseudo-C always spaces binary operators, so
    ``(<param> + `` / ``(<param> - `` catch it without a per-call dynamic regex (which
    was the ranker's hot spot on thousands of functions)."""
    return any(p and (f"({p} + " in body or f"({p} - " in body) for p in params)


def _memop_score(body: str, *, reachable: bool, calls_sink: bool, params: frozenset[str]) -> float:
    """Deterministic 0..N "how likely to hide a memory-safety bug" score over a
    decompiled body — a superset of the loop-OOB shape. Rewards indexed reads AND
    writes, pointer arithmetic (especially on caller-owned parameters), cast indices,
    cursor loops, indirect dispatch, and sink calls. Used to RANK, never to filter, so
    a bug of any shape still surfaces as a lead."""
    score = 0.0
    if calls_sink:
        score += 3.0
    idx_write = bool(_IDX_WRITE.search(body))
    # a subscript that is not the write we already counted reads as an indexed read
    idx_read = bool(_SUBSCRIPT.search(body)) and not idx_write
    ptr_write = bool(_PTR_WRITE.search(body))
    ptr_deref = bool(_PTR_DEREF.search(body))
    cast_index = bool(_CAST_INDEX.search(body))
    loop = bool(_MEMOP_LOOP.search(body))
    if idx_write:
        score += 2.5
    if idx_read:
        score += 1.5
    if ptr_write:
        score += 1.5
    if ptr_deref:
        score += 1.0
    if cast_index:
        score += 1.5
    if loop:
        score += 1.0
    # a store OR an indexed read inside a loop is the classic OOB shape
    if (idx_write or ptr_write or idx_read) and loop:
        score += 3.0
        if cast_index:
            score += 1.0
    # pointer arithmetic on a caller-owned PARAMETER — the buffer whose bound lives in
    # the caller (the bounds-check-ordering / unchecked-length read shape).
    if _has_param_ptr_arith(body, params):
        score += 2.0
    if _INDIRECT_CALL.search(body):
        score += 1.0
    if reachable:
        score += 1.0
    score += min(len(body) / 800.0, 2.0)
    return score


def _balanced_args(text: str, open_idx: int) -> str:
    """Return the argument string inside the parenthesis opening at ``open_idx`` in
    ``text``, respecting nesting: ``malloc((n + 1) * 4)`` -> ``(n + 1) * 4``. Falls
    back to the remainder if the parens are unbalanced (truncated decompile line)."""
    depth = 0
    start = open_idx + 1
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start:i].strip()
    return text[start:].strip()


def _signature_params(body: str) -> frozenset[str]:
    """Parameter names from a decompiled function's signature — the identifiers in the
    ``(...)`` before the opening ``{``. Each parameter's name is its last identifier
    token (``char *cVar2`` -> ``cVar2``); ``void`` / empty lists yield nothing."""
    head = body.split("{", 1)[0]
    lp = head.find("(")
    if lp < 0:
        return frozenset()
    rp = head.rfind(")")
    inner = head[lp + 1 : rp if rp > lp else None]
    names: set[str] = set()
    for part in inner.split(","):
        toks = re.findall(r"[A-Za-z_]\w*", part)
        if toks and toks[-1] not in {"void", "int", "char", "short", "long"}:
            names.add(toks[-1])
    return frozenset(names)


# --- argument provenance (the sink -> parent data-flow lever) ----------------
#
# The failure this closes: a bounds-checked leaf sink (``libraw_sget4_static`` /
# ``memcpy`` into a right-sized buffer) is judged locally SAFE, and the agent
# concludes "no bug" — but the real flaw is the OFFSET/SIZE argument handed to that
# sink, computed with bad arithmetic in a *caller* (libraw's ``parseAdobeRAFMakernote``
# feeds ``tiff_sget``/``libraw_sget4`` an offset from unchecked arithmetic on a
# header field). ``arg_provenance`` reports, for a given call site inside a function,
# how the ``arg_index``-th argument is computed IN THAT FUNCTION — the identifiers
# feeding it and each one's recovered origin (a parameter, a struct-field load, a
# loop induction var, arithmetic on those, or a callee's return) — so the model can
# ask "is this offset/length attacker-derived and unclamped here, or bounded?".
#
# This is text/heuristic data-flow over the decompiled body: it names the shape of
# the computation, it does NOT prove the value is out of range (that stays the
# oracle's job). See the module honesty note in ``arg_provenance``'s docstring.

# Cast/type tokens that appear inside decompiled expressions but are not variables.
_TYPE_TOKENS: frozenset[str] = frozenset(
    {
        "void",
        "char",
        "uchar",
        "short",
        "ushort",
        "int",
        "uint",
        "long",
        "ulong",
        "byte",
        "sbyte",
        "bool",
        "float",
        "double",
        "size_t",
        "ssize_t",
        "code",
    }
)
# undefined4 / uint3 / unkbyte9 … recovered width tokens, also not variables.
_TYPE_WIDTH_RE = re.compile(
    r"^(?:undefined\d*|unk(?:byte|uint|int)\d+|u?int\d+|u?long\d+|u?short\d+|u?char\d+)$"
)
# A `* (` deref or `* )` cast-close: masked out before we look for a multiply, so the
# pointer star is never mistaken for the arithmetic operator.
_STAR_NOISE = re.compile(r"\*\s*[()]")
# A struct-field / caller-memory load: `*(T *)(base + 0x8)` or `*(T *)(base - 4)`.
_FIELD_LOAD = re.compile(
    r"\*\s*\([^)]*\*+\s*\)\s*\(\s*([A-Za-z_]\w*)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)"
)


@dataclass
class ArgFactor:
    """One identifier feeding an argument expression, with its recovered origin.

    ``origin`` is one of: ``parameter`` (a signature param — caller-controlled),
    ``derived-from-parameter`` (assigned from an expression mentioning a param),
    ``struct-field`` (loaded from ``*(T *)(base + off)`` — caller-provided memory,
    e.g. a length/count field), ``loop-induction`` (incremented in a loop),
    ``call-return`` (assigned from a callee — provenance continues there),
    ``local-arith`` (a local temporary from other arithmetic), ``constant`` (a pure
    literal), or ``unknown`` (no assignment recovered in this body)."""

    name: str
    origin: str
    detail: str


@dataclass
class ArgProvenance:
    """Structured provenance of one call-site argument, computed by text data-flow.

    ``found`` is False (with ``error`` set) when the call site or the argument index
    is not present. Otherwise the flags summarize the computation so the LLM can
    reason: does this offset/size derive from an attacker-controlled parameter or a
    struct length field, and is it transformed by unclamped arithmetic?"""

    function: str
    sink_call: str
    arg_index: int
    found: bool
    expression: str = ""
    operators: list[str] = field(default_factory=list)
    factors: list[ArgFactor] = field(default_factory=list)
    from_parameter: bool = False
    from_struct_field: bool = False
    from_loop_induction: bool = False
    has_arithmetic: bool = False
    error: str = ""


_NUM_LITERAL = re.compile(r"\b0[xX][0-9a-fA-F]+|\b\d[\w.]*")


def _expr_identifiers(expr: str) -> list[str]:
    """Ordered, de-duplicated variable identifiers in a C expression — minus cast/type
    keywords and numeric literals (``(uint)cVar2 + 0x10`` -> ``['cVar2']``). Hex/decimal
    literals are masked first so ``0x20`` never yields a spurious ``x20`` token."""
    expr = _NUM_LITERAL.sub(" ", expr)
    ids: list[str] = []
    for tok in re.findall(r"[A-Za-z_]\w*", expr):
        if tok in _TYPE_TOKENS or _TYPE_WIDTH_RE.match(tok):
            continue
        if tok not in ids:
            ids.append(tok)
    return ids


def _arith_ops(expr: str) -> list[str]:
    """Arithmetic operators present in an argument expression, ignoring the pointer
    ``*`` of a deref/cast. These are the ``+``/``*``/``<<`` the guidance warns about —
    a raw parameter reshaped into an offset/length."""
    masked = _STAR_NOISE.sub("  ", expr)
    ops: list[str] = []
    if "<<" in masked:
        ops.append("left-shift(<<)")
    if re.search(r"[\w\)]\s*\*\s*[\w\(]", masked):
        ops.append("multiply(*)")
    if re.search(r"[\w\)]\s*\+\s*[\w\(]", masked):
        ops.append("add(+)")
    if re.search(r"[\w\)]\s*-\s*[\w\(]", masked):
        ops.append("subtract(-)")
    return ops


def _is_loop_induction(ident: str, body: str) -> bool:
    """Is ``ident`` a loop induction variable — incremented (``i = i + 1`` / ``i++`` /
    ``++i``) inside a body that loops?"""
    if not re.search(r"\b(?:for|while)\b|\bdo\s*\{", body):
        return False
    ie = re.escape(ident)
    return bool(
        re.search(rf"\b{ie}\s*=\s*{ie}\s*\+", body)
        or re.search(rf"\+\+\s*{ie}\b|\b{ie}\s*\+\+", body)
    )


def _classify_factor(ident: str, body: str, params: frozenset[str]) -> ArgFactor:
    """Recover where ``ident`` comes from within ``body`` (one level of tracing)."""
    if ident in params:
        return ArgFactor(ident, "parameter", "a function parameter (caller-controlled)")
    if _is_loop_induction(ident, body):
        return ArgFactor(ident, "loop-induction", "incremented inside a loop (induction variable)")
    m = re.search(rf"\b{re.escape(ident)}\s*=\s*([^;]+);", body)
    rhs = m.group(1).strip() if m else None
    if rhs is not None:
        fld = _FIELD_LOAD.match(rhs)
        if fld is not None:
            return ArgFactor(
                ident,
                "struct-field",
                f"loaded from *({fld.group(1)} {fld.group(2)} {fld.group(3)}) — a "
                "struct field / caller-provided memory (often a length or count)",
            )
        if any(re.search(rf"\b{re.escape(p)}\b", rhs) for p in params):
            return ArgFactor(ident, "derived-from-parameter", f"= {rhs}")
        cm = re.match(r"\(?\s*[A-Za-z_][\w ]*\*?\s*\)?\s*([A-Za-z_]\w*)\s*\(", rhs)
        if cm is not None:
            callee = cm.group(1)
            return ArgFactor(
                ident,
                "call-return",
                f"= {rhs} — value returned by {callee}(); provenance continues in "
                f"that callee (pivot with read_function/arg_provenance there)",
            )
        return ArgFactor(ident, "local-arith", f"= {rhs}")
    return ArgFactor(ident, "unknown", "no assignment found in this function body")


def analyze_arg_provenance(
    function: str,
    body: str,
    sink_call: str,
    arg_index: int,
    params: frozenset[str],
    *,
    occurrence: int = 1,
) -> ArgProvenance:
    """Compute how the ``arg_index``-th argument of the ``occurrence``-th call to
    ``sink_call`` inside ``body`` is derived. Pure text analysis — see
    ``ToolBox.arg_provenance`` for the honesty caveat. No-op-safe: an absent call site
    or out-of-range index returns ``found=False`` with an explanatory ``error``."""
    starts = [m.end() - 1 for m in re.finditer(rf"\b{re.escape(sink_call)}\s*\(", body)]
    if not starts:
        return ArgProvenance(
            function,
            sink_call,
            arg_index,
            False,
            error=(
                f"no call to {sink_call}(...) found in {function!r} — check the "
                "function actually calls it (see callees)."
            ),
        )
    occ = max(1, occurrence)
    if occ > len(starts):
        return ArgProvenance(
            function,
            sink_call,
            arg_index,
            False,
            error=(
                f"{function!r} has {len(starts)} call(s) to {sink_call}; "
                f"requested occurrence #{occ}."
            ),
        )
    argstr = _balanced_args(body, starts[occ - 1])
    args = _split_top_level(argstr)
    if arg_index < 0 or arg_index >= len(args):
        return ArgProvenance(
            function,
            sink_call,
            arg_index,
            False,
            error=(
                f"the call {sink_call}({argstr}) in {function!r} has {len(args)} "
                f"argument(s); index {arg_index} is out of range."
            ),
        )
    expr = args[arg_index].strip()
    ops = _arith_ops(expr)
    factors = [_classify_factor(i, body, params) for i in _expr_identifiers(expr)]
    # The offset/size is often precomputed into a temporary — the arg is a bare
    # `iVar2` whose ASSIGNMENT holds the arithmetic (`iVar2 = base + n * 4`). Fold the
    # ops from each traced assignment in so the "reshaped by arithmetic" signal (and
    # the strong upstream-pivot assessment) still fires on that common shape.
    for f in factors:
        if f.origin in ("derived-from-parameter", "local-arith"):
            for op in _arith_ops(f.detail):
                if op not in ops:
                    ops.append(op)
    from_param = any(f.origin in ("parameter", "derived-from-parameter") for f in factors)
    from_field = any(f.origin == "struct-field" for f in factors)
    from_loop = any(f.origin == "loop-induction" for f in factors)
    return ArgProvenance(
        function=function,
        sink_call=sink_call,
        arg_index=arg_index,
        found=True,
        expression=expr,
        operators=ops,
        factors=factors,
        from_parameter=from_param,
        from_struct_field=from_field,
        from_loop_induction=from_loop,
        has_arithmetic=bool(ops),
    )


def _split_top_level(argstr: str) -> list[str]:
    """Split a call's argument string at top-level commas, respecting ``()``/``[]``
    nesting so ``memcpy(dst, base + i*4, n)`` yields three args, not four."""
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in argstr:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur or out:
        out.append("".join(cur).strip())
    return [a for a in out if a != ""] or ([argstr.strip()] if argstr.strip() else [])


def format_arg_provenance(p: ArgProvenance) -> str:
    """Render an ``ArgProvenance`` into the observation the model reads — the raw
    expression, the arithmetic applied, each feeding value's origin, and a concrete
    assessment that steers the sink->parent pivot."""
    if not p.found:
        return f"arg_provenance: {p.error}"
    lines = [
        f"arg[{p.arg_index}] of the call {p.sink_call}(...) in {p.function!r} is computed as:",
        f"    {p.expression}",
    ]
    lines.append(
        "arithmetic applied: "
        + (", ".join(p.operators) if p.operators else "none — the value is passed through directly")
    )
    if p.factors:
        lines.append("feeding values:")
        for f in p.factors:
            lines.append(f"  - {f.name}: {f.origin} — {f.detail}")
    else:
        lines.append("feeding values: (a literal constant — no variables)")

    # Assessment — the sink->parent steer. Order by danger.
    if p.from_parameter and p.has_arithmetic:
        assess = (
            "ASSESSMENT: this offset/size is a CALLER-CONTROLLED parameter reshaped by "
            "arithmetic with no clamp visible in this function. Even if the sink is "
            "bounds-checked for its OWN buffer, a caller can drive this argument "
            "OUT-OF-RANGE. PIVOT UPSTREAM: run callers(" + repr(p.function) + "), then "
            "for each caller run arg_provenance(caller, " + repr(p.function) + ", "
            "<this arg index>) to see the true range of the value passed in — the bug "
            "is likely the caller's arithmetic, not this sink."
        )
    elif p.from_parameter:
        assess = (
            "ASSESSMENT: this argument is passed through from a CALLER-CONTROLLED "
            "parameter; its range is set by the caller. PIVOT UPSTREAM: walk "
            "callers(" + repr(p.function) + ") and run arg_provenance there to bound it."
        )
    elif p.from_struct_field:
        assess = (
            "ASSESSMENT: this offset/size derives from a STRUCT FIELD / caller-provided "
            "memory (often a length or count parsed from the input). Check that field "
            "is validated before this call; if it is attacker-controlled and unclamped, "
            "the sink receives an out-of-range offset/length."
        )
    elif p.from_loop_induction and not p.has_arithmetic:
        assess = (
            "ASSESSMENT: this argument is a LOOP INDUCTION variable — bounded by the "
            "loop condition. Verify the loop's upper bound is the true buffer size "
            "(an unclamped count field as the bound is the classic OOB)."
        )
    elif not p.factors:
        assess = "ASSESSMENT: a constant — bounded and not attacker-influenced by itself."
    else:
        assess = (
            "ASSESSMENT: provenance is a local computation with no direct parameter/"
            "field dependency recovered here. If it still looks input-derived, trace "
            "the feeding temporaries or pivot to callers."
        )
    lines.append(assess)
    return "\n".join(lines)


# --- input-format hints (the light, no-dynamic prior) ------------------------
#
# From the RAW bytes of a PoC, recover the container/format and return a set of
# keyword hints (format + domain terms). ``explore`` uses these as a SOFT prior to
# float functions whose NAMES match (e.g. a Fuji RAF PoC -> ["fuji","raf",
# "makernote"] floats ``parseAdobeRAFMakernote`` up the frontier). It is never a
# filter — the LLM can still read any function. Library-agnostic: the table maps a
# format to generic format/domain vocabulary, never to a specific decompiled program.
#
# Detection is by magic-byte prefix, plus a couple of offset-anchored signatures
# (ICC's ``acsp`` at byte 36). Ordered most-specific-first so a RAF (which also embeds
# TIFF/Exif) is recognized as Fuji, not generic TIFF. Robust to short/empty input:
# an unrecognized or too-short buffer yields ``[]`` (no prior applied).

# (prefix bytes, keyword list) — checked in order, first match wins.
_FORMAT_PREFIXES: tuple[tuple[bytes, tuple[str, ...]], ...] = (
    # Fuji RAF raw — magic "FUJIFILMCCD-RAW". The makernote parser is the libraw sink.
    (b"FUJIFILM", ("fuji", "fujifilm", "raf", "raw", "makernote", "ifd")),
    # PNG — 8-byte signature.
    (b"\x89PNG\r\n\x1a\n", ("png", "idat", "chunk", "zlib", "inflate", "scanline", "filter")),
    # JPEG / JFIF / Exif.
    (b"\xff\xd8\xff", ("jpeg", "jpg", "jfif", "exif", "huffman", "scan", "marker", "makernote")),
    # GIF.
    (b"GIF87a", ("gif", "lzw", "frame", "palette")),
    (b"GIF89a", ("gif", "lzw", "frame", "palette")),
    # OpenEXR — magic 0x76 0x2f 0x31 0x01.
    (b"\x76\x2f\x31\x01", ("exr", "openexr", "channel", "scanline", "tile", "compress", "half")),
    # PDF.
    (b"%PDF", ("pdf", "xref", "stream", "object", "filter")),
    # RIFF container (WebP / WAV / AVI).
    (b"RIFF", ("riff", "webp", "wav", "avi", "chunk", "vp8")),
    # Ogg.
    (b"OggS", ("ogg", "vorbis", "opus", "page", "packet")),
    # Matroska / WebM (EBML).
    (b"\x1aE\xdf\xa3", ("ebml", "matroska", "webm", "cluster", "block")),
    # gzip / zlib-wrapped.
    (b"\x1f\x8b", ("gzip", "deflate", "inflate", "zlib")),
    # zip / office-openxml.
    (b"PK\x03\x04", ("zip", "deflate", "inflate", "central", "entry")),
    # ELF (a binary loader target).
    (b"\x7fELF", ("elf", "section", "segment", "symbol", "relocation")),
    # TIFF (little- and big-endian) and TIFF-based camera RAW (CR2/NEF/DNG/ARW).
    (b"II\x2a\x00", ("tiff", "ifd", "exif", "makernote", "tag", "raw", "dng")),
    (b"MM\x00\x2a", ("tiff", "ifd", "exif", "makernote", "tag", "raw", "dng")),
    # sfnt fonts — the harfbuzz breadth target: OTF (CFF/CFF2 outlines), TrueType,
    # collections, WOFF. Font parsing/sanitize/subset is where the CFF2 OOB lives.
    (b"OTTO", ("font", "sfnt", "otf", "cff", "cff2", "sanitize", "table", "subset", "glyph")),
    (
        b"\x00\x01\x00\x00",
        ("font", "sfnt", "ttf", "truetype", "glyf", "sanitize", "table", "glyph"),
    ),
    (b"true", ("font", "sfnt", "ttf", "truetype", "glyf", "sanitize", "table")),
    (b"ttcf", ("font", "sfnt", "ttc", "collection", "sanitize", "table")),
    (b"wOFF", ("font", "woff", "sfnt", "sanitize", "table")),
    (b"wOF2", ("font", "woff2", "sfnt", "sanitize", "table")),
    # BMP / DIB (2-byte magic; kept last so it never shadows a longer signature).
    (b"BM", ("bmp", "bitmap", "dib", "palette")),
)

# EMBEDDED (secondary) format markers — ASCII/byte signatures that appear INSIDE a
# container (not at offset 0) and route into a distinct sub-parser where the bug often
# lives. The libraw GT is a case in point: a TIFF ``II`` container with an embedded
# "Adobe" makernote → the buggy code is ``parseAdobeRAFMakernote``, invisible to
# outer-magic detection. Scanned in a bounded window; case-sensitive vendor strings.
_EMBEDDED_MARKERS: tuple[tuple[bytes, tuple[str, ...]], ...] = (
    (b"Adobe", ("adobe", "makernote", "raf", "fuji")),
    (b"MakerNote", ("makernote", "exif", "ifd")),
    (b"FUJIFILM", ("fuji", "fujifilm", "raf", "makernote")),
    (b"Nikon", ("nikon", "makernote", "nef")),
    (b"Canon", ("canon", "makernote", "cr2", "crw")),
    (b"OLYMP", ("olympus", "makernote", "orf")),
    (b"Panasonic", ("panasonic", "makernote", "rw2")),
    (b"SONY", ("sony", "makernote", "arw")),
    (b"PENTAX", ("pentax", "makernote", "pef")),
    (b"Exif\x00", ("exif", "ifd", "makernote", "tag")),
    # sfnt table tags — a font's outer magic is TrueType/OTTO but the bug often lives
    # in a specific table's parser (e.g. the CFF2 OOB inside a `\x00\x01\x00\x00` sfnt).
    (b"CFF2", ("cff2", "cff", "charstring", "sanitize", "subr")),
    (b"CFF ", ("cff", "charstring", "sanitize", "subr")),
    (b"glyf", ("glyf", "glyph", "sanitize", "contour")),
    (b"GSUB", ("gsub", "gpos", "layout", "sanitize", "lookup")),
    (b"http://ns.adobe.com/xap", ("xmp", "metadata", "adobe")),
    (b"ICC_PROFILE", ("icc", "iccprofile", "profile", "colorspace")),
    (b"Photoshop", ("photoshop", "iptc", "8bim", "resource")),
)


def input_format_hints(poc_bytes: bytes) -> list[str]:
    """Recover keyword hints for a PoC input from its magic bytes.

    Returns a library-agnostic list of format/domain keywords (e.g. a Fuji RAF PoC ->
    ``["fuji","fujifilm","raf","raw","makernote","ifd"]``) that ``explore`` can pass as
    ``format_hints`` to bias — never filter — frontier ranking toward functions whose
    names match. Detection is by magic-byte prefix, the offset-anchored ICC signature
    (``acsp`` at byte 36), AND a scan for EMBEDDED format markers — many real bugs live
    in a *secondary* parser reached only for an embedded sub-format (e.g. an Adobe/Fuji
    MakerNote inside a TIFF ``II``/``MM`` container: the outer magic is TIFF but the
    buggy code is the makernote parser). Robust to short/empty/unknown input: returns
    ``[]`` (no prior applied) rather than guessing."""
    if not poc_bytes:
        return []
    b = bytes(poc_bytes)
    kws: list[str] = []
    seen: set[str] = set()

    def _add(words: list[str]) -> None:
        for w in words:
            if w not in seen:
                seen.add(w)
                kws.append(w)

    # ICC color profile: 'acsp' signature at byte offset 36 (no fixed prefix).
    if len(b) >= 40 and b[36:40] == b"acsp":
        _add(["icc", "iccprofile", "profile", "tag", "acsp", "colorspace", "curve"])
    else:
        for magic, words in _FORMAT_PREFIXES:
            if b.startswith(magic):
                _add(list(words))
                break
    # Embedded/secondary format markers — ASCII signatures that appear INSIDE a
    # container and route into a distinct (often buggy) sub-parser. Scanned in a
    # bounded window so a huge input is cheap. Case-sensitive vendor strings.
    window = b[:65536]
    for marker, words in _EMBEDDED_MARKERS:
        if marker in window:
            _add(list(words))
    return kws


class ToolBox:
    """The plain-python tools the agent drives, over one ``ProgramMeta``. Every tool
    returns a *string* observation (what the model reads next turn). Errors are
    returned as observations, never raised, so a bad call just costs one turn."""

    def __init__(self, meta: Any) -> None:
        self.meta = meta
        raw: dict[str, str] = getattr(meta, "decompiled_c", {}) or {}
        # Strip ASan/coverage instrumentation up front so every tool observation, the
        # candidate lens, and the memory-op ranker all see the REAL program logic —
        # not shadow-byte arithmetic and ``__asan_report_*`` branches. A no-op on
        # stripped / non-ASan targets (deasan returns those bodies unchanged).
        self._asan_funcs = sum(1 for b in raw.values() if is_asan_instrumented(b))
        self.decompiled: dict[str, str] = deasan_all(raw) if self._asan_funcs else raw
        # Navigation runs over the AUGMENTED call graph: the direct edges Ghidra
        # resolved, PLUS speculative indirect/vtable edges recovered from
        # address-taken functions + fn-pointer tables (indirect_calls). Real targets
        # dispatch parsers through function pointers, so without these the explorer
        # cannot follow the call that reaches the bug. Speculative edges are bounded
        # (only from indirect call sites, only to address-taken targets, per-site cap)
        # and this is SENSES for exploration, not a ranker. Falls back to the raw
        # graph if recovery fails.
        try:
            from .indirect_calls import augmented_callgraph

            self.callgraph: dict[str, list[str]] = augmented_callgraph(meta)
        except Exception:
            self.callgraph = getattr(meta, "callgraph", {}) or {}
        self.structs: list[dict[str, Any]] = getattr(meta, "structs", None) or []
        self._rev: dict[str, list[str]] | None = None
        self._candidates: list[str] | None = None
        self._memops: list[str] | None = None
        self._localized: list[str] | None = None
        # Reachability gate: the set of functions confidently reachable from the input
        # entry over the augmented call graph (direct + indirect edges) plus address-taken.
        # ``None`` means reachability could NOT be computed (no entry / no graph) -> the
        # gate then filters NOTHING (conservative escape). Computed lazily & cached.
        self._input_reach: set[str] | None = None
        self._input_reach_done = False
        # Exploration state (used by ``explore``): the attacker-input entry the walk
        # started at, and the ordered set of functions the model has actually READ
        # (its coverage frontier). ``run_agent`` populates ``visited`` too — harmless —
        # but only ``explore`` reads it back through the ``unexplored`` frontier tool.
        self.entry: str | None = None
        self.visited: list[str] = []
        self._visited_set: set[str] = set()
        self._reach: dict[str, set[str] | None] = {}
        # Optional exploration priors (set by ``explore``):
        #   * ``reachable_hint`` — the set of function names KNOWN TO EXECUTE on the
        #     target input (a dynamic coverage trace). When set, ``unexplored`` restricts
        #     and prioritizes the frontier to this executed set (narrowing a huge static-
        #     reachable set to the dozens actually hit). ``None`` -> current static
        #     behavior, unchanged.
        #   * ``format_hints`` — magic-byte-derived format keywords (see
        #     ``input_format_hints``). A SOFT prior that floats functions whose names
        #     match up the frontier order; never a filter. Empty -> no prior.
        self.reachable_hint: set[str] | None = None
        self.format_hints: list[str] = []

    # -- catalog --------------------------------------------------------------
    CATALOG: tuple[tuple[str, str, str], ...] = (
        (
            "read_function",
            "read_function(name)",
            "Return the decompiled pseudo-C of a function. If not found, returns "
            "close-name suggestions.",
        ),
        (
            "get_struct",
            "get_struct(name)",
            "Return a recovered struct layout (fields + byte offsets, array bounds "
            "flagged) from the program's type info.",
        ),
        (
            "find_structs_for_pointer",
            "find_structs_for_pointer(function, base_var)",
            "Resolve raw offset arithmetic. Given a pointer temporary (e.g. 'cVar2') "
            "used in FUNCTION with accesses like *(cVar2 + 0x10 + i*4), return the "
            "recovered struct(s) whose field offsets best match those displacements, "
            "so you can read '+8' as a named field and '+0x10' as a fixed-size array.",
        ),
        (
            "callers",
            "callers(name)",
            "Functions that call NAME (from the recovered call graph). May be empty "
            "for indirect/callback targets reached through a function pointer.",
        ),
        (
            "callees",
            "callees(name)",
            "Functions that NAME calls (from the recovered call graph).",
        ),
        (
            "search_functions",
            "search_functions(substr)",
            "Function names containing SUBSTR (case-insensitive).",
        ),
        (
            "list_candidates",
            "list_candidates()",
            "Suspicious starting points, from TWO sources: (1) the loop-OOB static "
            "lens (one specific shape), and (2) a broader rank of functions reachable "
            "from the fuzz entry that perform interesting memory operations (indexed "
            "reads/writes, pointer arithmetic on parameters, sink calls). The broad "
            "list is RANKED not filtered — investigate several, the bug need not be "
            "the top one.",
        ),
        (
            "localize_candidates",
            "localize_candidates()",
            "Functions ranked by DATA-FLOW PROXIMITY to attacker-controlled input "
            "(the fuzzer's data/size), highest first. Taint is propagated forward from "
            "the input entry through the call graph and combined with an intra-function "
            "parse signal (indexes a parameter buffer, assembles multi-byte ints from "
            "bytes, loops to a size parameter, feeds a parameter to memcpy). Prefer this "
            "over list_candidates for a COLD start: the top entries are the parsers that "
            "actually touch untrusted bytes. Large functions are included even if "
            "diffuse — the bug may be INLINED into them (use read_region to navigate).",
        ),
        (
            "read_region",
            "read_region(name, around=<substr>, offset=<int>)",
            "Read a WINDOW-sized slice of a large function body, centered on a landmark "
            "(a callee name, a sink like 'memcpy', or an offset like '0x164') via "
            "'around', or on a raw character 'offset'. Use this when read_function "
            "truncates a huge function (an inlined 50KB+ parent): page to the region "
            "around a suspicious sink/callee instead of reading a truncated head.",
        ),
        (
            "buffer_size",
            "buffer_size(function, pointer_var)",
            "Trace where a pointer/buffer POINTER_VAR in FUNCTION comes from and "
            "recover its size: a local stack array (declared element count), a "
            "malloc/calloc/_cmsMalloc result (the size expression/argument), or a "
            "function parameter (caller-owned; size unknown here — callers listed so "
            "you can pivot). Use this on the destination of a write or the base of an "
            "indexed access to check the index/length against the true allocation. "
            "Returns 'unknown' honestly when provenance cannot be recovered.",
        ),
        (
            "arg_provenance",
            "arg_provenance(function, sink_call, arg_index)",
            "Trace how the ARG_INDEX-th argument of a call to SINK_CALL inside FUNCTION "
            "is computed: the variables feeding it and each one's origin (a parameter, "
            "a struct-field load, a loop induction var, arithmetic +/*/<< on those, or "
            "a callee's return). Use this on the OFFSET/SIZE argument of a sink that "
            "looks locally safe: a bounds-checked leaf sink can still be driven out of "
            "range by a CALLER that computes the offset/length with bad arithmetic. If "
            "the argument is a caller-controlled parameter reshaped by unclamped "
            "arithmetic, PIVOT to callers and run arg_provenance there — the bug is "
            "usually the parent's computation, not the safe sink. arg_index is 0-based.",
        ),
    )

    # -- exploration-mode tools ----------------------------------------------
    #
    # Extra tools the LLM-driven ``explore`` loop advertises on top of CATALOG. They
    # exist to make ranking OPTIONAL and exploration SYSTEMATIC: ``suggest_suspicious``
    # is the demoted ranker (a HINT the model may consult, never a forced start or a
    # filter), and ``unexplored`` is the coverage frontier (input-reachable functions
    # not yet read). They dispatch through ``call`` like any tool; ``run_agent`` simply
    # does not list them, so the seeded mode's surface is unchanged.
    EXPLORE_CATALOG: tuple[tuple[str, str, str], ...] = (
        (
            "suggest_suspicious",
            "suggest_suspicious()",
            "OPTIONAL HINT: heuristically-ranked leads (functions close to attacker "
            "input by taint, plus functions with bug-prone memory-op shapes). These are "
            "leads you MAY consult — NOT a filter and NOT where you must start. You can "
            "read_function ANY function and follow ANY call edge regardless of rank; the "
            "real bug may not be listed. Use it when you run out of edges to follow.",
        ),
        (
            "unexplored",
            "unexplored()",
            "Coverage frontier: the input-reachable functions you have NOT yet read, "
            "ranked by proximity to attacker input (closest first). Call it to explore "
            "SYSTEMATICALLY — to see what reachable surface remains before you conclude, "
            "rather than navigating at random. Reports how many functions you have "
            "visited so far.",
        ),
    )

    def catalog_text(self) -> str:
        return "\n".join(f"- {sig}: {desc}" for _n, sig, desc in self.CATALOG)

    def explore_catalog_text(self) -> str:
        """The full tool menu for exploration mode: the shared CATALOG plus the
        exploration-only HINT/frontier tools."""
        rows = list(self.CATALOG) + list(self.EXPLORE_CATALOG)
        return "\n".join(f"- {sig}: {desc}" for _n, sig, desc in rows)

    def tool_names(self) -> frozenset[str]:
        return frozenset(n for n, _s, _d in (self.CATALOG + self.EXPLORE_CATALOG))

    # -- dispatch -------------------------------------------------------------
    def call(self, tool: str, args: dict[str, Any]) -> str:
        args = args or {}
        try:
            if tool == "read_function":
                return self.read_function(str(args.get("name", "")))
            if tool == "get_struct":
                return self.get_struct(str(args.get("name", "")))
            if tool == "find_structs_for_pointer":
                return self.find_structs_for_pointer(
                    str(args.get("function", "")), str(args.get("base_var", ""))
                )
            if tool == "callers":
                return self.callers(str(args.get("name", "")))
            if tool == "callees":
                return self.callees(str(args.get("name", "")))
            if tool == "search_functions":
                return self.search_functions(str(args.get("substr", "")))
            if tool == "list_candidates":
                return self.list_candidates()
            if tool == "localize_candidates":
                return self.localize_candidates_text()
            if tool == "suggest_suspicious":
                return self.suggest_suspicious()
            if tool == "unexplored":
                return self.unexplored()
            if tool == "read_region":
                return self.read_region(
                    str(args.get("name", "")),
                    around=(str(args["around"]) if args.get("around") is not None else None),
                    offset=(int(args["offset"]) if args.get("offset") is not None else None),
                )
            if tool == "buffer_size":
                return self.buffer_size(
                    str(args.get("function", "")), str(args.get("pointer_var", ""))
                )
            if tool == "arg_provenance":
                return self.arg_provenance(
                    str(args.get("function", "")),
                    str(args.get("sink_call", "")),
                    _as_int(args.get("arg_index", 0)),
                    occurrence=_as_int(args.get("occurrence", 1), default=1),
                )
            return f"error: unknown tool {tool!r}. Available tools: " + ", ".join(
                sorted(self.tool_names())
            )
        except Exception as exc:  # a tool bug must not sink the loop
            return f"error: tool {tool!r} raised {type(exc).__name__}: {exc}"

    # -- tools ----------------------------------------------------------------
    def _mark_visited(self, name: str) -> None:
        """Record that the model has read ``name`` (exploration coverage). Idempotent
        and order-preserving so the frontier tool can report what is left."""
        if name and name not in self._visited_set:
            self._visited_set.add(name)
            self.visited.append(name)

    def read_function(self, name: str) -> str:
        body = self.decompiled.get(name)
        if body is None:
            sugg = difflib.get_close_matches(name, self.decompiled.keys(), n=5, cutoff=0.4)
            hint = f" Did you mean: {', '.join(sugg)}?" if sugg else ""
            return f"not found: no function named {name!r}.{hint}"
        self._mark_visited(name)
        if len(body) > _MAX_BODY_CHARS:
            body = (
                body[:_MAX_BODY_CHARS]
                + f"\n/* ...truncated at {_MAX_BODY_CHARS} of {len(body)} chars. "
                f"This is a large function (the bug may be INLINED here). Use "
                f"read_region({name!r}, around=<sink/callee/offset>) to read the rest "
                f"around a landmark. */"
            )
        return body

    def get_struct(self, name: str) -> str:
        for s in self.structs:
            if str(s.get("name", "")) == name:
                return format_struct(s)
        names = [str(s.get("name", "")) for s in self.structs]
        sugg = difflib.get_close_matches(name, names, n=5, cutoff=0.3)
        hint = f" Close names: {', '.join(sugg)}." if sugg else ""
        if not self.structs:
            return f"not found: no recovered struct types in this program.{hint}"
        return f"not found: no struct named {name!r}.{hint}"

    def find_structs_for_pointer(self, function: str, base_var: str) -> str:
        body = self.decompiled.get(function)
        if body is None:
            return f"error: function {function!r} not found — read_function first."
        if not self.structs:
            return (
                "no recovered struct types in this program (stripped / no DWARF); "
                "cannot resolve offsets to named fields."
            )
        groups = base_offset_groups(body)
        offs = groups.get(base_var)
        if not offs:
            known = ", ".join(sorted(groups)) or "(none)"
            return (
                f"no offset arithmetic on base var {base_var!r} in {function!r}. "
                f"Pointers with '+N' displacements here: {known}."
            )
        scored: list[tuple[tuple[int, int], dict[str, Any], set[int]]] = []
        for s in self.structs:
            foffs = {int(f["offset"]) for f in s.get("fields", [])}
            matched = {o for o in offs if o in foffs and o != 0}
            if not matched:
                continue
            arr_offs = {int(f["offset"]) for f in s.get("fields", []) if f.get("is_array")}
            array_hits = len(matched & arr_offs)
            scored.append(((len(matched), array_hits), s, matched))
        if not scored:
            # Fall back to the whole-body selector (also matches structs named in the
            # signature), so the model still gets something to reason about.
            picked = select_structs(body, self.structs)
            if not picked:
                shown = ", ".join(hex(o) for o in sorted(offs))
                return (
                    f"offsets applied to {base_var!r}: {{{shown}}} — no recovered "
                    f"struct's fields match these displacements."
                )
            defs = "\n\n".join(format_struct(s) for s in picked[:3])
            return (
                f"no direct offset match for {base_var!r}; nearest structs by "
                f"whole-function match:\n\n{defs}"
            )
        scored.sort(key=lambda t: (-t[0][0], -t[0][1], str(t[1].get("name", ""))))
        shown = ", ".join(hex(o) for o in sorted(offs))
        parts = [
            f"base var {base_var!r} in {function!r} is dereferenced at offsets "
            f"{{{shown}}}. Best-matching recovered struct(s):"
        ]
        for (nmatched, _arr), s, matched in scored[:3]:
            mtext = ", ".join(hex(o) for o in sorted(matched))
            parts.append(f"\n// matches {nmatched} field offset(s): {mtext}\n" + format_struct(s))
        return "\n".join(parts)

    def buffer_size(self, function: str, pointer_var: str) -> str:
        """Trace the provenance of ``pointer_var`` in ``function`` and recover the
        underlying allocation size. Classifies the buffer as a local stack array
        (declared element count), a heap allocation (the ``malloc``/``calloc``/
        ``_cmsMalloc`` size expression), or a caller-owned parameter (size unknown
        here — callers listed for a pivot). Honest: returns 'unknown' rather than
        guessing when none of these provenance shapes is recoverable.

        Targets the OOB-write / OOB-index shape that struct-field lookup can't
        resolve: when the destination of a store (or the base of an indexed access)
        is a bare pointer with no struct layout, its *allocation size* is the real
        bound to check the index/length against."""
        body = self.decompiled.get(function)
        if body is None:
            return f"error: function {function!r} not found — read_function first."
        if not pointer_var:
            return "error: empty pointer_var."
        var = pointer_var

        findings: list[str] = []

        # (1) LOCAL STACK ARRAY — Ghidra declares these as `T name [N];`. The element
        # count N is an exact, on-stack bound (an index >= N is OOB).
        decl = re.search(
            rf"^[ \t]*([A-Za-z_][\w ]*?)\b{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*;",
            body,
            re.M,
        )
        if decl is not None:
            etype = decl.group(1).strip() or "byte"
            count = int(decl.group(2))
            return (
                f"{var!r} in {function!r} is a LOCAL STACK ARRAY: declared "
                f"`{etype} {var}[{count}]` — a fixed {count}-element on-stack buffer. "
                f"Any index/length that can reach >= {count} is out of bounds "
                f"(stack-buffer-overflow)."
            )

        # (2) HEAP ALLOCATION — assignment `var = ...alloc(size...)`, possibly through a
        # cast `(char *)`. Recover the SIZE EXPRESSION so the model can check it against
        # the index. calloc/reallocarray take (count, size): report both factors.
        for m in re.finditer(rf"\b{re.escape(var)}\s*=\s*([^;]+);", body):
            rhs = m.group(1).strip()
            for fn in _ALLOC_FUNCS:
                cm = re.search(rf"\b{re.escape(fn)}\s*\(", rhs)
                if cm is None:
                    continue
                arg = _balanced_args(rhs, cm.end() - 1)
                pretty = fn.replace("operator_new", "operator new")
                note = ""
                if fn in _COUNT_SIZE_ALLOCS:
                    note = (
                        " (count, size) — the allocation is count*size bytes; an "
                        "overflow in that product yields an undersized buffer"
                    )
                findings.append(
                    f"{var!r} in {function!r} is a HEAP ALLOCATION: "
                    f"`{var} = {pretty}({arg})`{note}. The buffer size is the "
                    f"argument expression {arg!r} — check the index/length against it "
                    f"(if the size can be smaller than the max index reached, it is "
                    f"a heap-buffer-overflow)."
                )
                break
            if findings:
                break
        if findings:
            return findings[0]

        # (3) CALLER-OWNED PARAMETER — the var is in the signature and never (re)bound
        # to a local allocation. Its size lives in the caller; surface the callers so
        # the agent can pivot and recover it there.
        if var in _signature_params(body):
            cs = self.callers(function)
            return (
                f"{var!r} is a PARAMETER of {function!r} — caller-owned; its size is "
                f"NOT determinable in this function. The bound is set by whoever "
                f"allocates it. To recover it, pivot to a caller and run buffer_size "
                f"there on the argument passed in this position. {cs}"
            )

        # (4) Assigned from a load / other expression — honest partial answer.
        first_rhs = None
        am = re.search(rf"\b{re.escape(var)}\s*=\s*([^;]+);", body)
        if am is not None:
            first_rhs = am.group(1).strip()
        if first_rhs is not None:
            return (
                f"provenance of {var!r} in {function!r} is UNKNOWN: it is assigned "
                f"`{var} = {first_rhs}` — not a recognizable allocation or stack "
                f"array (likely a load of a pointer stored in a struct/global, or a "
                f"pointer walked from another buffer). Size cannot be recovered here; "
                f"try find_structs_for_pointer, or trace the base it derives from."
            )
        return (
            f"provenance of {var!r} in {function!r} is UNKNOWN: no stack-array "
            f"declaration, no allocation assignment, and not a parameter was found "
            f"for it in the decompiled body. It may be an outer-scope temporary; "
            f"size cannot be recovered."
        )

    def arg_provenance(
        self, function: str, sink_call: str, arg_index: int, *, occurrence: int = 1
    ) -> str:
        """Report how the ``arg_index``-th argument of a call to ``sink_call`` inside
        ``function`` is computed — the sink->parent data-flow lever.

        A leaf memory sink can bounds-check its OWN buffer yet still be handed an
        out-of-range offset/length by a caller whose arithmetic on an attacker input is
        unchecked (libraw: ``parseAdobeRAFMakernote`` computes the offset it feeds
        ``tiff_sget``/``libraw_sget4``, and THAT is the bug — the sinks are safe). This
        surfaces the shape of the computation so the model knows when to pivot upstream.

        HONESTY: this is text/heuristic data-flow over one decompiled body. It names
        what feeds the argument (parameter / struct field / loop var / arithmetic) and
        traces assignments ONE level; it does NOT do real inter-procedural data-flow,
        resolve aliases, or prove the value is out of range — a downstream oracle does
        that. Treat a positive as a lead to pivot on, not a confirmed bug."""
        body = self.decompiled.get(function)
        if body is None:
            return f"error: function {function!r} not found — read_function first."
        if not sink_call:
            return "error: empty sink_call."
        params = _signature_params(body)
        prov = analyze_arg_provenance(
            function, body, sink_call, arg_index, params, occurrence=occurrence
        )
        return format_arg_provenance(prov)

    def callers(self, name: str) -> str:
        if self._rev is None:
            rev: dict[str, list[str]] = {}
            for caller, callees in self.callgraph.items():
                for callee in callees:
                    rev.setdefault(callee, []).append(caller)
            self._rev = rev
        cs = self._rev.get(name, [])
        if not cs:
            return (
                f"no known callers of {name!r} in the recovered call graph — it may "
                f"be an entry point or an indirect-callback target reached through a "
                f"function pointer (treat its inputs as untrusted)."
            )
        return f"callers of {name!r}: " + ", ".join(sorted(cs))

    def callees(self, name: str) -> str:
        cs = self.callgraph.get(name)
        if not cs:
            return f"{name!r} has no recorded callees (or is not in the call graph)."
        return f"callees of {name!r}: " + ", ".join(sorted(set(cs)))

    def search_functions(self, substr: str) -> str:
        if not substr:
            return "error: empty search substring."
        low = substr.lower()
        hits = sorted(fn for fn in self.decompiled if low in fn.lower())
        if not hits:
            return f"no function name contains {substr!r}."
        if len(hits) > 40:
            return f"{len(hits)} matches (showing 40): " + ", ".join(hits[:40])
        return "matches: " + ", ".join(hits)

    def rank_memops(self, limit: int = 15) -> list[str]:
        """Broad, ranked (not filtered) memory-op candidate functions: those reachable
        from the fuzz entry that perform interesting memory operations, ordered by the
        ``_memop_score`` heuristic. Deasan'd bodies + noise-name filtering keep ASan
        runtime functions from dominating. The lead source the LLM uses when the narrow
        loop-OOB lens is empty (or as extra leads alongside it). Cached — the full
        scoring is computed once per ToolBox."""
        if self._memops is None:
            self._memops = self._compute_memop_ranking()
        return self._memops[:limit]

    def _input_reachable_set(self) -> set[str] | None:
        """Cached confidently-reachable-from-input set (augmented graph + address-taken),
        or ``None`` when reachability can't be computed — in which case the gate filters
        nothing. Delegates to ``localize.input_reachable_set`` so the candidate/frontier
        surfaces and the standalone ``input_reachable`` gate share one definition."""
        if not self._input_reach_done:
            try:
                from .localize import input_reachable_set

                self._input_reach = input_reachable_set(self.meta)
            except Exception:
                self._input_reach = None
            self._input_reach_done = True
        return self._input_reach

    def _drop_input_unreachable(self, names: list[str]) -> list[str]:
        """Filter out functions CONFIDENTLY unreachable from the input entry. A no-op
        (returns the list unchanged) when reachability can't be computed — so an
        incomplete indirect-edge graph never over-filters a real candidate."""
        reach = self._input_reachable_set()
        if reach is None:
            return names
        return [n for n in names if n in reach]

    def _fuzz_reachable(self) -> set[str] | None:
        """Functions reachable from the libFuzzer entry by a forward call-graph
        closure. A cheap BFS over ``meta.callgraph`` — deliberately NOT
        ``analyze.reachable_functions`` (whose address-taken re-admission regex-scans a
        multi-MB blob per candidate and cost minutes on real targets). For a soft
        ranking bonus the closure is precision enough; ``None`` when the entry is
        absent (non-libFuzzer / toy) so ranking then treats every function as in-scope."""
        from .backends import _noise

        entry = _noise.LIBFUZZER_ENTRY
        nodes = set(self.callgraph) | {c for cs in self.callgraph.values() for c in cs}
        if entry not in nodes:
            return None
        seen: set[str] = set()
        stack = [entry]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(c for c in self.callgraph.get(n, ()) if c not in seen)
        return seen

    def _compute_memop_ranking(self) -> list[str]:
        from .backends import _noise

        try:
            reach = self._fuzz_reachable()
        except Exception:
            reach = None
        scored: list[tuple[float, str]] = []
        for fn, body in self.decompiled.items():
            if _noise.is_noise_name(fn) or len(body) < 60:
                continue
            is_reach = True if reach is None else (fn in reach)
            params = _signature_params(body)
            s = _memop_score(
                body,
                reachable=is_reach,
                calls_sink=_noise.calls_sink(body),
                params=params,
            )
            scored.append((s, fn))
        scored.sort(key=lambda t: (-t[0], t[1]))
        return [fn for _s, fn in scored]

    def list_candidates(self) -> str:
        if self._candidates is None:
            try:
                findings = loop_oob_lens(self.decompiled, self.callgraph)
            except Exception:
                findings = []
            self._candidates = [f.function for f in findings]
        lens_seen: list[str] = []
        for fn in self._candidates:
            if fn not in lens_seen:
                lens_seen.append(fn)
        try:
            memops = self.rank_memops(limit=15)
        except Exception:
            memops = []
        # Reachability gate: a function with no path from the input entry (augmented graph)
        # and not address-taken cannot be an input-triggered bug — drop it from BOTH
        # displayed sources so a library helper like ``_Large_integer_to_chars`` never
        # surfaces as a candidate. No-op when reachability can't be computed.
        lens_seen = self._drop_input_unreachable(lens_seen)
        memops = self._drop_input_unreachable(memops)
        # keep the two signals distinct and labeled — the lens is a strong specific
        # hint; the broad rank keeps the model from over-trusting one shape.
        parts: list[str] = []
        if lens_seen:
            parts.append("loop-OOB lens candidates: " + ", ".join(lens_seen))
        else:
            parts.append("loop-OOB lens: no candidates (this shape not present).")
        if memops:
            parts.append(
                "broad memory-op candidates (reachable from fuzz entry, ranked): "
                + ", ".join(memops)
            )
        if not lens_seen and not memops:
            return "no candidate functions surfaced by the lens or the memory-op rank."
        return "\n".join(parts)

    def localize_candidates(self, limit: int = 15) -> list[str]:
        """Taint-ranked candidate function names (input-proximity first). Cached."""
        if self._localized is None:
            from .localize import localize_candidates as _lc

            try:
                self._localized = _lc(self.meta, limit=50)
            except Exception:
                self._localized = []
            # Reachability gate: drop candidates confidently unreachable from the input
            # entry (augmented graph + address-taken) so a library helper with no input
            # path never surfaces as a taint-ranked lead. No-op when uncomputable.
            self._localized = self._drop_input_unreachable(self._localized)
        return self._localized[:limit]

    def localize_candidates_text(self) -> str:
        cands = self.localize_candidates(limit=15)
        if not cands:
            return (
                "no taint-ranked candidates (no input entry recovered, or no "
                "reachable functions). Fall back to list_candidates."
            )
        return "input-taint ranked candidates (closest to attacker input first): " + ", ".join(
            cands
        )

    # -- exploration: demoted ranker (a HINT) + coverage frontier -------------
    def suggest_suspicious(self, limit: int = 12) -> str:
        """The demoted ranker, presented as an OPTIONAL HINT. Returns both lead sources
        (taint proximity and memory-op shape) with an explicit banner that they are NOT
        a filter and NOT a forced start — the model may read any function and follow any
        edge regardless of rank. This is the same ranking machinery ``run_agent`` once
        used to PICK the start; in exploration mode it only advises."""
        parts: list[str] = []
        try:
            taint = self.localize_candidates(limit=limit)
        except Exception:
            taint = []
        if taint:
            parts.append(
                "taint-proximity leads (closest to attacker input first): " + ", ".join(taint)
            )
        try:
            memops = self.rank_memops(limit=limit)
        except Exception:
            memops = []
        if memops:
            parts.append("memory-op-shape leads (ranked): " + ", ".join(memops))
        if not parts:
            return (
                "no heuristic leads surfaced (untainted / tiny program). Explore by "
                "following callees() from the entry and reading what receives input."
            )
        banner = (
            "HINT ONLY — heuristic leads you MAY consult. NOT a filter and NOT where you "
            "must start: read_function ANY function and follow ANY call edge regardless "
            "of rank. The real bug may not be on this list.\n"
        )
        return banner + "\n".join(parts)

    def _reachable_from(self, entry: str | None) -> set[str] | None:
        """Forward call-graph closure from ``entry`` (the functions attacker input can
        reach). ``None`` when ``entry`` is absent from both the graph and the decompile
        (no anchor — every function is then treated as in-scope). Cached per entry."""
        if not entry:
            return None
        if entry in self._reach:
            return self._reach[entry]
        nodes = set(self.callgraph) | {c for cs in self.callgraph.values() for c in cs}
        if entry not in nodes:
            # entry has a body but no recorded edges: it reaches only itself.
            result: set[str] | None = {entry} if entry in self.decompiled else None
            self._reach[entry] = result
            return result
        seen: set[str] = set()
        stack = [entry]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(c for c in self.callgraph.get(n, ()) if c not in seen)
        self._reach[entry] = seen
        return seen

    def _format_kws(self) -> list[str]:
        """The active format-hint keywords, lowercased and length-filtered (>=3 chars so
        a 2-char token never matches half the program). Empty when no hints are set."""
        return [k.lower() for k in self.format_hints if len(k) >= 3]

    def _rank_frontier(self, pool: list[str]) -> list[str]:
        """Order a frontier pool by, in priority: (1) the format-hint prior — functions
        whose NAME matches the active input-format keywords, GRADED by HOW MANY distinct
        keywords match (a soft prior, never a filter); (2) taint proximity to attacker
        input; (3) name (stable tiebreak).

        The grading (not a binary matches/doesn't tier) is the harfbuzz-breadth fix.
        There, two high-taint DRAW-path funcs outranked the SANITIZE-path sink because a
        BINARY hint tier let raw taint break the tie whenever both incidentally matched a
        keyword. Counting distinct hits makes a format/operation-SPECIFIC name dominate:
        ``sanitize_blob<OT::cff2>`` matches both ``cff2`` and ``sanitize`` (score 2) and
        so ranks ABOVE a draw/getter that only grazes one generic term like ``glyph``
        (score 1) EVEN when the draw path is closer in taint. Any match (score>=1) still
        beats no match (score 0).

        With NO format hints every score is 0, so the leading key is a uniform constant
        and the order is byte-identical to the plain taint-proximity sort — the no-hint
        path is unchanged."""
        order = {fn: i for i, fn in enumerate(self.localize_candidates(limit=200))}
        kws = self._format_kws()

        def hint_score(fn: str) -> int:
            low = fn.lower()
            return sum(1 for k in kws if k in low)

        # -hint_score: MORE keyword hits sort first; ties fall to taint proximity then name.
        return sorted(pool, key=lambda f: (-hint_score(f), order.get(f, 10**6), f))

    def unexplored(self, limit: int = 20) -> str:
        """The coverage frontier: input-reachable functions the model has NOT yet read,
        ranked by taint proximity (closest to attacker input first) so exploration is
        systematic. Falls back to all non-noise functions when no entry anchors the
        reachable set. Honest when the frontier is exhausted.

        Two optional priors sharpen it (both set by ``explore``): a DYNAMIC coverage
        trace (``reachable_hint``) restricts and prioritizes the frontier to the
        functions actually EXECUTED on the target input (the real path, not every static
        branch); a magic-byte FORMAT prior (``format_hints``) floats functions whose
        names match the input's format up the order. Neither is a wall — the model can
        still read any function by name."""
        from .backends import _noise

        hint = self.reachable_hint
        reach = self._reachable_from(self.entry)
        dynamic = False
        if hint:
            # DYNAMIC reachability: restrict the frontier to functions KNOWN TO EXECUTE
            # on this specific input. Narrows a huge static-reachable set (libraw ~825)
            # to the dozens actually hit (which include the format-specific parsers).
            scope = "functions KNOWN TO EXECUTE on the target input (dynamic coverage trace)"
            pool = [
                fn
                for fn in hint
                if fn in self.decompiled
                and fn not in self._visited_set
                and not _noise.is_noise_name(fn)
                and len(self.decompiled.get(fn, "")) >= 60
            ]
            dynamic = True
        elif reach is None:
            scope = "non-noise functions (no input entry to anchor reachability)"
            pool = [
                fn
                for fn, body in self.decompiled.items()
                if fn not in self._visited_set and not _noise.is_noise_name(fn) and len(body) >= 60
            ]
        else:
            scope = f"functions reachable from the entry {self.entry!r}"
            pool = [
                fn
                for fn in reach
                if fn in self.decompiled
                and fn not in self._visited_set
                and not _noise.is_noise_name(fn)
                and len(self.decompiled.get(fn, "")) >= 60
            ]
        if not pool:
            tail = "use suggest_suspicious (or read_function on any name) for leads outside " + (
                "the executed set (e.g. a bug on a branch the trace did not cover)."
                if dynamic
                else "the reachable set (e.g. indirect-callback targets the call graph misses)."
            )
            return (
                f"frontier EXHAUSTED: no unread {scope} remain "
                f"(visited {len(self.visited)} so far). Either conclude honestly, or " + tail
            )
        ranked = self._rank_frontier(pool)
        shown = ranked[:limit]
        more = "" if len(ranked) <= limit else f" (+{len(ranked) - limit} more)"
        if dynamic:
            head = (
                f"UNEXPLORED frontier — {scope}; these are the REAL path the input takes "
                "(prioritize them over static branches), not yet read"
            )
        else:
            head = f"UNEXPLORED frontier — {scope}, not yet read"
        fmt_note = ""
        if self._format_kws():
            fmt_note = (
                f"\n(format-hint prior: names matching {self.format_hints} floated up — "
                "a soft prior, not a filter)"
            )
        return (
            f"{head}, ranked by input proximity:\n"
            + ", ".join(shown)
            + more
            + fmt_note
            + f"\n(visited so far: {len(self.visited)} — "
            + (", ".join(self.visited) if self.visited else "none")
            + ")"
        )

    def read_region(
        self, name: str, *, around: str | None = None, offset: int | None = None
    ) -> str:
        from .localize import read_region as _rr

        body = self.decompiled.get(name)
        if body is None:
            sugg = difflib.get_close_matches(name, self.decompiled.keys(), n=5, cutoff=0.4)
            hint = f" Did you mean: {', '.join(sugg)}?" if sugg else ""
            return f"not found: no function named {name!r}.{hint}"
        self._mark_visited(name)
        return _rr(body, around=around, offset=offset)


# --- the ReAct loop ---------------------------------------------------------

_SYSTEM = (
    "You are a binary vulnerability-research agent investigating ONE function of a "
    "program for a MEMORY-SAFETY bug (out-of-bounds read/write, use-after-free, "
    "integer/heap/stack overflow) reachable from untrusted input. You do NOT get a "
    "pre-baked context: you INVESTIGATE by calling tools, then return a verdict.\n\n"
    "This is Ghidra decompiler output, not source. Reason about the recovered "
    "SEMANTICS, never the surface syntax:\n"
    "- Field accesses are lowered to raw pointer arithmetic: `params->nInputs` "
    "becomes `*(uint *)(cVar2 + 8)` and an array member `params->nSamples[i]` "
    "becomes `*(short *)(cVar2 + 0x10 + i*4)`. When you see offset arithmetic on a "
    "pointer indexed by a loop variable, call `find_structs_for_pointer(function, "
    "base_var)` to resolve which struct it is and whether the offset lands on a "
    "FIXED-SIZE ARRAY — that array's element count is the real bound.\n"
    "- A loop `for(i < *(cVar2+8)) read *(cVar2 + 0x10 + i*4)` reads a fixed array "
    "at +0x10 using a COUNT read from +8. If the count field can exceed the array's "
    "fixed length, the read/write is out-of-bounds.\n"
    "- When the offending access is on a BARE pointer with no struct layout — a "
    "store `*(dst + i) = ...` or an index `buf[i]` into a plain buffer — the real "
    "bound is that buffer's ALLOCATION SIZE. Call `buffer_size(function, "
    "pointer_var)` to recover it: a local stack array's element count, a "
    "malloc/calloc size expression, or (for a parameter) 'caller-owned' with the "
    "callers to pivot to. Compare the max index/length written against that size — "
    "a write past it is CWE-787 (a read past it is CWE-125).\n"
    "- Names are mangled temporaries (uVarN/iVarN/cVarN/local_NN) — judge what the "
    "code DOES. Indices are often casts `[(int)x]`; loops are cursors "
    "`do{...}while(cur != end)`; dispatch is indirect `(*pcVarN)(...)`.\n\n"
    "SINK LOOKS LOCALLY SAFE? DO NOT conclude is_bug=false yet. The commonest miss is "
    "a leaf sink that bounds-checks ITS OWN buffer (a safe memcpy, a validated "
    "reader like libraw's tiff_sget/libraw_sget4) but is handed an OFFSET or LENGTH "
    "computed with bad arithmetic in a CALLER. The read is bounded by X — but is X "
    "(the offset/length) computed safely in EVERY caller, or can a caller pass an "
    "out-of-range value? Before a negative verdict on a function whose accesses look "
    "checked:\n"
    "  1. Identify the offset/size argument each memory sink here consumes.\n"
    "  2. Call callers(function) to get the parents that invoke it.\n"
    "  3. For each caller, call arg_provenance(caller, function, arg_index) on that "
    "offset/size argument to see how the caller computes it. If it is a "
    "caller-controlled parameter or a struct length field reshaped by unclamped "
    "arithmetic (+/*/<<), that caller is the likely bug — keep pivoting UPSTREAM "
    "(callers of the caller) until the value is provably bounded or you reach the "
    "input entry.\n"
    "  Conclude is_bug=false only when the offset/length is bounded in every caller "
    "(or the function has no callers / is reached by indirect dispatch — then treat "
    "its inputs as untrusted and judge locally).\n\n"
    "EACH TURN return ONE JSON object, either:\n"
    '  {"thought": "...", "action": "call", "tool": "<name>", "args": {...}}\n'
    "to inspect the program with a tool, OR:\n"
    '  {"thought": "...", "action": "verdict", "is_bug": true|false, '
    '"cwe": "CWE-...", "sink": "the offending access", "source": "untrusted input", '
    '"explanation": "..."}\n'
    "to conclude. Investigate BEFORE concluding: resolve the structs behind any "
    "offset arithmetic and confirm the bound vs the array size. Decide honestly — a "
    "false positive is worse than a miss; if accesses are provably bounded, return "
    "is_bug=false. You only PROPOSE a hypothesis; a separate oracle proves it. When "
    "is_bug=true, name the exact CWE, the sink (the offending indexed access), and "
    "the root cause (e.g. fixed N-element array indexed by an unclamped attacker "
    "count). Return only the JSON object."
)

_EXPLORE_SYSTEM = (
    "You are a binary vulnerability-research agent doing COLD exploration of a program "
    "for a MEMORY-SAFETY bug (out-of-bounds read/write, use-after-free, integer/heap/"
    "stack overflow) reachable from untrusted input. You are NOT handed a suspect "
    "function to judge. Instead, untrusted input enters the program at a known ENTRY, "
    "and you EXPLORE outward from there the way a human reverse engineer does: you "
    "FOLLOW THE DATA to the bug.\n\n"
    "Your method, each step:\n"
    "- Look at the code you are in and ask which of its callees receive INPUT-DERIVED "
    "values — buffers, lengths, counts, offsets parsed from the input. Use "
    "callees(fn) to see the edges and read_function to descend into the ones that "
    "actually touch attacker data. You may read ANY function by name and follow ANY "
    "edge; nothing restricts you to a ranked list.\n"
    "- Navigate toward the functions that perform INDEXING, ARITHMETIC, or COPIES on "
    "attacker-influenced values with the LEAST validation — that is where the bug "
    "lives. A routine that assembles a length/count from bytes and then indexes or "
    "copies into a buffer is the classic target.\n"
    "- Form a hypothesis, then go DEEPER to confirm it. Resolve struct offsets with "
    "find_structs_for_pointer, recover a buffer's true size with buffer_size, and "
    "trace how an offset/length argument is computed with arg_provenance. If a memory "
    "sink looks locally SAFE because it clamps its OWN buffer, do NOT stop: a leaf that "
    "reads/writes through a CALLER-OWNED pointer (a parameter, not a buffer it sized "
    "itself) is UNCONFIRMED, not safe — you MUST descend to the caller that computes the "
    "offset/length/pointer: callers(fn), then arg_provenance(caller, fn, arg_index), and "
    "pivot UPSTREAM until the value is provably bounded or you reach the input entry. "
    "Consider BOTH failure directions: an UPPER-bound check (offset < size) does NOT "
    "prevent UNDERFLOW — a negative or wrapped offset/index reads/writes BEFORE the "
    "buffer (very common with signed arithmetic, `x - n`, or unchecked subtraction on a "
    "parsed value). A check that guards only one end is not a bound.\n"
    "- Track POINTER LIFETIME, not just bounds — memory safety is TEMPORAL as well as "
    "spatial. When a pointer is FREED or RELEASED — free/_cmsFree/g_free/kfree, C++ "
    "`operator.delete`, a refcount drop (*_put/*_release/*_unref/kref_put/_cmsUnref), or "
    "`q = realloc(p, …)` which frees AND may move `p` — treat that pointer as DANGLING and "
    "check every later use on the REACHABLE path: a deref/index/copy of it is a "
    "use-after-free (CWE-416); a second free of it is a double-free (CWE-415). Watch the "
    "shapes decompiled control flow makes easy to miss — a free in an error/cleanup branch "
    "then a use on the fall-through, a free inside a loop then a use on the NEXT iteration, "
    "and a retained ALIAS of a realloc'd/freed pointer. Only an intervening reassignment "
    "(`p = NULL` / `p = <new>`) between the free and the use makes the later use safe; a "
    "use that merely LOOKS after the free line but is guarded by such a reassignment is not "
    "the bug. Follow the same input-reachability discipline: the free and the use must both "
    "be reachable from untrusted input.\n"
    "- Explore SYSTEMATICALLY, not at random: call unexplored() to see which "
    "input-reachable functions you have not read yet (ranked by input proximity) so "
    "you cover the reachable surface before concluding. suggest_suspicious() offers "
    "OPTIONAL heuristic leads — a HINT you MAY consult, never a filter and never a "
    "forced start.\n"
    "- SURVEY BEFORE YOU DIVE. Before committing to deeply read one function, glance at "
    "the NAMES/signatures of the top few frontier candidates (unexplored()) and prefer "
    "the one whose name matches the input's FORMAT or the security-relevant OPERATION "
    "(parse/sanitize/decode/deserialize/subset) OVER the one that is merely closest by "
    "raw call-proximity. The highest input-proximity function is frequently the WRONG "
    "path — a DRAW/RENDER/getter (`_get_path`/`_get_bounds`) rather than the "
    "PARSE/SANITIZE path where untrusted bytes are validated and the bug lives; the "
    "format-hint prior already floats the right-named functions up the frontier, so "
    "trust it over proximity when they disagree. When the function you pick is HUGE and "
    "heavy with instrumentation, do NOT read it whole and DROWN in the inlined body: use "
    "read_region(name, around=<the specific sink/callee/offset>) to read just the region "
    "around the access you care about (a memcpy, an index, a named callee), and if a "
    "landmark is missing, PAGE through it with read_region(offset=…) rather than "
    "abandoning it. And on a REPEAT/STUCK signal, do NOT re-list the frontier — PICK AN "
    "UNREAD hint-matching frontier function and read_function it.\n\n"
    "This is Ghidra decompiler output, not source. Field accesses are lowered to raw "
    "pointer arithmetic (`params->nSamples[i]` -> `*(short *)(cVar2 + 0x10 + i*4)`); "
    "names are mangled temporaries (uVarN/iVarN/local_NN); indices are casts "
    "`[(int)x]`; loops are cursors `do{...}while(cur != end)`; dispatch is indirect "
    "`(*pcVarN)(...)`. Judge what the code DOES, never its surface syntax.\n\n"
    "EACH TURN return ONE JSON object, either:\n"
    '  {"thought": "...", "action": "call", "tool": "<name>", "args": {...}}\n'
    "to navigate/inspect, OR:\n"
    '  {"thought": "...", "action": "verdict", "is_bug": true|false, "cwe": "CWE-...", '
    '"sink": "the offending access", "source": "how untrusted input reaches it", '
    '"explanation": "the input->sink path you followed"}\n'
    "to conclude. Conclude ONLY when you have found a CONCRETE out-of-bounds/overflow or "
    "use-after-free/double-free (name the sink, the exact CWE, and the input path you "
    "followed — for a temporal bug, both the free site and the later use), or "
    "when you have exhausted the reachable input-influenced surface (unexplored() is "
    "empty or only provably-bounded code remains) — then return is_bug=false honestly. "
    "A false positive is worse than a miss. You only PROPOSE a hypothesis; a separate "
    "oracle proves it. Return only the JSON object."
)

_MAX_REPEAT = 3  # identical (tool,args) calls before we abort the loop

# --- transcript budget ------------------------------------------------------
#
# ``_drive_loop`` re-sends the WHOLE transcript as a single user message every
# turn, so an unbounded one is quadratic: ``schedule.ScheduledLLM`` charges
# ``estimate_tokens(prompt)`` on every call, and its response cache keys on that
# same growing prompt, so a cache hit inside a loop is structurally impossible.
# Observations are whole decompiled function bodies (up to ``_MAX_BODY_CHARS``),
# so they are what dominates.
#
# Policy: the most recent ``_OBS_KEEP_FULL`` observations stay verbatim; older
# ones are MIDDLE-truncated. Head-only slicing would keep a decompiled function's
# prologue and throw away its returns, trailing copies and closing bound checks —
# for this scanner the tail carries as much as the head.
_OBS_KEEP_FULL = 3
_OBS_TRUNC_CHARS = 1200
# Thoughts are the thing this transcript exists to retain and are short (the
# schema asks for "brief reasoning"), so they are NEVER dropped by recency — only
# individually capped, as a guard against a pathologically verbose model. At the
# 20-step explore budget the worst case is 20*1200 = 24k chars of thought against
# 3*6000 + 17*1200 = 38.4k chars of observation, versus 120k unbounded today.
_THOUGHT_MAX_CHARS = 1200
# Turn-count bound: when the prompt transcript exceeds this many complete turns,
# the oldest ones are dropped entirely (not just observation-truncated) to keep
# the prompt from growing without bound and destroying response-cache locality.
# Observations are the dominant cost (see above), so this bound is generous — it
# fires only for unusually long walks (explore default is 20). The bound is
# private by default; test code overrides it via ``_drive_loop(…,
# max_prompt_turns=…)``.
_MAX_PROMPT_TURNS = 30


def _middle_truncate(text: str, limit: int) -> str:
    """Truncate to ``limit`` chars keeping the HEAD and the TAIL, with an explicit
    marker for what went. Head-only slicing is the wrong policy for decompiled
    code and for tool output generally — the verdict lives at the end."""
    if limit <= 0 or len(text) <= limit:
        return text
    head_len = limit // 2
    tail_len = limit - head_len
    dropped = len(text) - limit
    return (
        f"{text[:head_len]}"
        f"\n… [{dropped} characters truncated from the middle] …\n"
        f"{text[len(text) - tail_len:]}"
    )


@dataclass
class _Turn:
    """One block appended to the transcript. The observation is held SEPARATELY
    from the action record so the renderer can shrink an old observation without
    losing which tool was called with which args (that record is small and is
    what keeps the walk coherent)."""

    text: str
    obs: str = ""


def _thought_line(thought: str) -> str:
    """The model's own reasoning, replayed back into its context. Empty thought →
    empty string, so a model that omits the field costs no filler."""
    t = _middle_truncate(thought.strip(), _THOUGHT_MAX_CHARS)
    return f"thought: {t}\n" if t else ""


def _render_transcript(
    header: str, turns: list[_Turn], *, max_turns: int = _MAX_PROMPT_TURNS
) -> str:
    """Rebuild the prompt from the header + turn log, applying the observation
    recency cap AND oldest-turn compaction. Rebuilt per turn rather than accumulated
    into a string, because a string cannot be retroactively shrunk.

    When the number of turns exceeds ``max_turns``, the OLDEST complete turn records
    are dropped so that only the ``max_turns`` most recent ones survive. The compaction
    is always on complete turns (never splits a thought/action/observation). A notice
    is injected into the prompt at the compaction point."""
    if max_turns > 0 and len(turns) > max_turns:
        dropped = len(turns) - max_turns
        turns = turns[-max_turns:]
        compaction_notice = f"\n[... {dropped} older turn(s) omitted ...]\n"
    else:
        compaction_notice = ""

    obs_positions = [i for i, t in enumerate(turns) if t.obs]
    keep_full = set(obs_positions[-_OBS_KEEP_FULL:]) if _OBS_KEEP_FULL > 0 else set()
    parts = [header]
    if compaction_notice:
        parts.append(compaction_notice)
    for i, t in enumerate(turns):
        parts.append(t.text)
        if t.obs:
            obs = t.obs if i in keep_full else _middle_truncate(t.obs, _OBS_TRUNC_CHARS)
            parts.append(f"observation:\n{obs}\n")
    return "".join(parts)


def _fmt_args(args: dict[str, Any]) -> str:
    return json.dumps(args or {}, sort_keys=True)


# The tools that actually PROVE/refute a memory-safety suspicion on a specific sink
# (offset provenance + true buffer size + struct layout). Running one of these CLEARS
# the "flagged but unproven" state that arms the behavioral confirmation gate.
_PROVING_TOOLS = frozenset(
    {"arg_provenance", "buffer_size", "find_structs_for_pointer", "get_struct"}
)
# Spatial OOB/overflow CWEs — the classes arg_provenance/buffer_size prove. A confident
# TRUE verdict for one of these with ZERO proving tools run is an unverified claim.
_SPATIAL_CWES = ("125", "787", "121", "122", "124", "119", "190", "191", "680", "823")
_CONFIRM_NUDGE = (
    "[confirmation required] You have an UNPROVEN memory-safety suspicion (offset / "
    "underflow / caller-owned pointer / unchecked read) that you flagged but never "
    "proved. Do NOT drop it and do NOT keep re-listing the frontier. Prove the EXACT "
    "access your OWN suspicion named — the specific read/write and its offset/index "
    "(e.g. the sget4/read offset you flagged). Do NOT substitute a different, "
    "easier-looking sink you noticed along the way (an adjacent memcpy length, another "
    "copy): if the decompiler obscured THAT one, prove the access your suspicion "
    "actually named instead. Run arg_provenance(...) on THAT offset/length argument AND "
    "buffer_size(...) on THAT buffer, trace the offset UPSTREAM to its source (callers + "
    "arg_provenance), then EITHER prove the out-of-bounds access (is_bug=true with the "
    "concrete arithmetic — a negative/wrapped offset reads BEFORE the buffer) OR "
    "explicitly refute it (show the clamp). Prove or refute — never drop a suspicion."
)
_PROVE_POSITIVE_NUDGE = (
    "[proof required] You are about to conclude is_bug=TRUE but you ran ZERO proving "
    "tools — this is an UNVERIFIED claim, and a confident wrong-bug true-positive is a "
    "false report (worse than a miss). Before asserting the bug, PROVE it: run "
    "arg_provenance(...) on the offending index/offset/length argument at the sink you "
    "named AND buffer_size(...) on the target buffer, and trace the attacker-controlled "
    "value to its source. State the CONCRETE arithmetic that puts the access out of "
    "bounds (the index/offset value vs. the true buffer size). If you CAN establish it, "
    "return is_bug=true with that arithmetic in the explanation; if you CANNOT, RETRACT "
    "to is_bug=false. Do not assert a memory-safety bug you have not proven."
)
# An UNPROVEN memory-safety suspicion voiced in a verdict/thought. Deliberately keyed on
# hedging/danger language, so the gate fires on "read without a bounds check / did not
# prove / negative offset" but NOT on a confident clean refutation.
_SUSPICION_RE = re.compile(
    r"underflow|wrapped offset|negative (?:offset|index|value)|out[- ]of[- ]range|"
    r"caller-owned|caller-controlled|did ?n[o']?t prove|not proven|unproven|"
    r"blindly read|without (?:a )?(?:bounds?|length|size|range)[- ]?check|"
    r"cannot (?:rule out|exclude)|could not (?:prove|confirm)|unable to prove",
    re.I,
)


def _drive_loop(
    tools: ToolBox,
    llm: Any,
    system: str,
    header: str,
    max_steps: int,
    *,
    max_prompt_turns: int = _MAX_PROMPT_TURNS,
) -> tuple[list[TrajStep], AgentVerdict | None, str]:
    """The shared ReAct engine behind both ``run_agent`` (seeded) and ``explore``
    (cold). Given a fully-formed opening ``header`` (tool catalog + starting body), it
    runs at most ``max_steps`` turns over ``llm.complete_json(system, prompt, schema)``:
    each turn is either a tool call (executed via ``tools.call``, observation fed back)
    or a final verdict. On the last turn the model is told it must conclude. Identical
    repeated calls are short-circuited with the cached observation + a nudge and abort
    the run after ``_MAX_REPEAT`` repeats so a stuck model cannot burn budget forever.
    Returns ``(steps, verdict, stop_reason)``.

    RETAINED REASONING: every turn replays the model's OWN ``thought`` back into the
    transcript alongside the action and observation. Without it the model saw its past
    actions and raw decompiler output but not one word of its own reasoning, and
    re-derived its hypothesis from scratch for up to 20 turns. The transcript is
    bounded by an observation recency cap (see ``_render_transcript``) so retaining
    reasoning does not cost context — older observations pay for it.

    ``max_prompt_turns`` controls oldest-turn compaction: when total turns exceed
    this count, the oldest complete turns are dropped from the prompt. The default
    (``_MAX_PROMPT_TURNS``) is generous for the 20-step explore budget; pass a
    smaller value to force compaction in tests."""
    steps: list[TrajStep] = []
    verdict: AgentVerdict | None = None
    stop_reason = "max_steps"
    turns: list[_Turn] = []
    conversation: Any | None = None
    begin_conversation = getattr(llm, "begin_conversation", None)
    if callable(begin_conversation):
        try:
            conversation = begin_conversation(system, header, ACTION_SCHEMA)
        except Exception:
            # Provider-native history is an optimization. Retain the proven
            # text transcript path when a provider cannot create it.
            conversation = None
    call_cache: dict[str, str] = {}
    repeat_count = 0
    # Confirmation gate (BEHAVIORAL): the model often FLAGS a sink as unchecked in a
    # mid-walk THOUGHT ("no local size check", "blindly read a caller-owned pointer")
    # and then drifts away and returns a confident `false` without ever proving it. We
    # persist that "flagged but unproven" state across the whole walk (raised by a
    # suspicion in any thought, cleared only by a proving-tool call) and, on a `false`
    # verdict, force ONE proving follow-through — regardless of the verdict's wording or
    # which turn it lands on. Firing bumps the step budget so there's room to prove even
    # if the model was on its last turn.
    confirm_nudged = False
    flagged_unproven = False
    n_proving = 0  # proving-tool calls made (arg_provenance/buffer_size/…)
    step_budget = max_steps

    i = -1
    while (i := i + 1) < step_budget:
        last_turn = i == step_budget - 1
        prompt = (
            _render_transcript(header, turns, max_turns=max_prompt_turns)
            if conversation is None
            else ""
        )
        if last_turn:
            final_turn_nudge = (
                "\n\n[FINAL TURN] You must now return a verdict (action='verdict'), "
                "not a tool call. Conclude with your best honest judgment."
            )
            if conversation is None:
                prompt += final_turn_nudge
            else:
                conversation.append_user(final_turn_nudge)
        try:
            raw = (
                conversation.complete_json()
                if conversation is not None
                else llm.complete_json(system, prompt, ACTION_SCHEMA)
            )
        except Exception as exc:
            steps.append(TrajStep(i, f"llm error: {type(exc).__name__}: {exc}", "error"))
            stop_reason = "error"
            break

        thought = str(raw.get("thought", "")).strip()
        action = str(raw.get("action", "")).strip().lower()
        # Behavioral gate: a THOUGHT that flags a sink as unchecked/caller-owned raises
        # the "unproven suspicion" flag (a proving-tool call clears it, below).
        # NOTE (retained reasoning): this greps THIS turn's ``thought`` only, never the
        # transcript, so replaying past thoughts back into context cannot make the gate
        # re-fire on stale text. The indirect effect — a replayed suspicion nudging the
        # model to restate it in a later thought and re-latching ``flagged_unproven`` —
        # is bounded by the ``confirm_nudged`` once-guard and is the gate working as
        # designed (an unproven suspicion the model is still carrying).
        if _SUSPICION_RE.search(thought.lower()):
            flagged_unproven = True

        # A verdict (explicit, or inferred from bug fields with no tool named).
        is_verdict = action == "verdict" or (
            action != "call" and "is_bug" in raw and "tool" not in raw
        )
        if is_verdict:
            v = AgentVerdict(
                is_bug=bool(raw.get("is_bug", False)),
                cwe=str(raw.get("cwe", "")).strip(),
                sink=str(raw.get("sink", "")).strip(),
                source=str(raw.get("source", "")).strip(),
                explanation=str(raw.get("explanation", "")).strip(),
            )
            # Confirmation gate — refuse a `false` verdict that voiced an UNPROVEN
            # suspicion (offset/underflow/caller-owned pointer / "did not prove") but
            # never ran the proving tools. Nudge ONCE to prove-or-refute; then accept.
            blob = f"{v.explanation} {v.sink} {thought}".lower()
            # Fire on a `false` verdict when EITHER the verdict wording hedges OR a sink
            # was flagged unchecked in an earlier thought and never proven (the
            # behavioral trigger — catches a confident-worded false that drifted away
            # from a real mid-walk suspicion). Not gated on the turn: firing bumps the
            # budget so there's room to prove. Once-guard bounds it.
            unproven = flagged_unproven or _SUSPICION_RE.search(blob) is not None
            # SYMMETRIC gate — prove-or-refute in BOTH directions:
            #   false + unproven suspicion  → prove or explicitly refute (dropped-lead)
            #   true  + zero proving tools  → prove or retract (confident WRONG-bug
            #     true-positives were the dominant libraw failure mode: is_bug=True with
            #     0 proving calls, an un-verified claim). A True verdict that DID run
            #     proving tools is a genuine hypothesis for the oracle — not gated.
            gate_false = (not v.is_bug) and unproven
            # Only gate a TRUE verdict for a SPATIAL OOB/overflow claim — that's what
            # arg_provenance/buffer_size actually prove. UAF/temporal (CWE-416/415) and
            # other classes are proven differently, so a 0-proving True there is fine.
            spatial = any(c in v.cwe for c in _SPATIAL_CWES)
            gate_true = v.is_bug and n_proving == 0 and spatial
            if not confirm_nudged and (gate_false or gate_true):
                confirm_nudged = True
                step_budget += 4  # grant proving turns even if this was the last turn
                repeat_count = 0  # a redirect to proving is not a stuck loop
                nudge = _CONFIRM_NUDGE if gate_false else _PROVE_POSITIVE_NUDGE
                steps.append(TrajStep(i, thought, "confirm-gate", observation=nudge))
                turns.append(
                    _Turn(text=f"\n\n[your step {i}]\n{_thought_line(thought)}\n{nudge}\n")
                )
                if conversation is not None:
                    conversation.append_user(nudge)
                continue
            verdict = v
            steps.append(TrajStep(i, thought, "verdict"))
            stop_reason = "verdict"
            break

        # Otherwise a tool call.
        tool = str(raw.get("tool", "")).strip()
        args = raw.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        key = f"{tool}:{_fmt_args(args)}"
        if key in call_cache:
            repeat_count += 1
            obs = (
                "[repeat] you already called this exact tool with these args. "
                "Previous result:\n"
                + call_cache[key]
                + "\n\nTry a DIFFERENT tool or return a verdict."
            )
            if repeat_count >= _MAX_REPEAT:
                # Non-verdict termination: if a sink was flagged unchecked but never
                # proven, do NOT silently abort with verdict=None — that bypasses the
                # confirmation gate. Redirect the stuck walk to PROVE the flagged sink
                # (once), just like the verdict-path gate.
                if flagged_unproven and not confirm_nudged:
                    confirm_nudged = True
                    step_budget += 4
                    repeat_count = 0
                    steps.append(TrajStep(i, thought, "confirm-gate", observation=_CONFIRM_NUDGE))
                    turns.append(
                        _Turn(
                            text=f"\n\n[your step {i}]\n{_thought_line(thought)}"
                            f"\n{_CONFIRM_NUDGE}\n"
                        )
                    )
                    if conversation is not None:
                        conversation.append_user(_CONFIRM_NUDGE)
                    continue
                steps.append(TrajStep(i, thought, "call", tool, args, obs))
                stop_reason = "loop-guard"
                break
        else:
            obs = tools.call(tool, args)
            call_cache[key] = obs
            if tool in _PROVING_TOOLS:
                flagged_unproven = False  # a proving tool ran — suspicion is being resolved
                n_proving += 1

        steps.append(TrajStep(i, thought, "call", tool, args, obs))
        # ``thought`` goes on its OWN labelled line rather than inside the action
        # dict: the JSON object is the exact wire record of the action (tool + args)
        # and stays machine-shaped and greppable, while a multi-sentence thought
        # JSON-escaped into it would be one unreadable line. Separating them also
        # lets the renderer age observations without touching the reasoning.
        turns.append(
            _Turn(
                text=(
                    f"\n\n[your step {i}]\n{_thought_line(thought)}"
                    f"action: {json.dumps({'action': 'call', 'tool': tool, 'args': args})}\n"
                ),
                obs=obs,
            )
        )
        if conversation is not None:
            conversation.append_user(
                f"Tool {tool}({json.dumps(args)}) returned:\n{obs}"
            )

    return steps, verdict, stop_reason


def run_agent(
    meta: Any,
    start_function: str | None,
    llm: Any,
    *,
    max_steps: int = 8,
    system: str = _SYSTEM,
) -> AgentResult:
    """Drive the ReAct tool loop on ``start_function`` (SEEDED mode) and return the full
    auditable trajectory + final verdict.

    ``llm`` must expose ``complete_json(system, prompt, schema)`` (CodexOAuthLLM or a
    scripted mock). The loop runs at most ``max_steps`` turns; on the last turn the
    model is told it must return a verdict. Identical repeated tool calls are
    short-circuited (cached observation + nudge) and abort the run after
    ``_MAX_REPEAT`` repeats so a stuck model cannot burn budget indefinitely.

    This is the seeded entry point: a ranker (or a human) picks ``start_function`` and
    the model judges THAT function (pivoting to callers as needed). For the cold,
    exploration-first entry point that starts at the attacker-input entry and follows
    the data, see ``explore``."""
    tools = ToolBox(meta)

    # COLD mode: no starting function given → begin at the top taint-ranked candidate
    # (the parser closest to attacker input), so the agent needs no human seed.
    if start_function is None:
        cold = tools.localize_candidates(limit=1)
        if not cold:
            return AgentResult("", [], None, "error")
        start_function = cold[0]

    body = tools.decompiled.get(start_function)
    if body is None:
        # Nothing to investigate — return a clean no-verdict result.
        obs = tools.read_function(start_function)
        steps = [
            TrajStep(
                0,
                "start function not found",
                "call",
                "read_function",
                {"name": start_function},
                obs,
            )
        ]
        return AgentResult(start_function, steps, None, "error")

    catalog = tools.catalog_text()
    header = (
        f"Investigate function {start_function!r} for a memory-safety bug.\n\n"
        f"Available tools:\n{catalog}\n\n"
        f"--- decompiled pseudo-C of {start_function} ---\n"
        f"{tools.read_function(start_function)}\n"
    )
    steps, verdict, stop_reason = _drive_loop(tools, llm, system, header, max_steps)
    return AgentResult(start_function, steps, verdict, stop_reason, visited=list(tools.visited))


# --- adversarial verification (the false-positive refutation pass) ----------
#
# The failure this closes: the explorer returns a CONFIDENT ``is_bug=True`` that is a
# FALSE POSITIVE — it "proved" a wrong conclusion because it MISSED/OMITTED a guard
# that is actually PRESENT in the decompiled body. The measured case: harfbuzz
# ``CFFIndex::operator[]`` flagged CWE-125 OOB read, but the real ``operator[]`` HAS
# the offset bounds check (`if (offset1 < offset0 || offset1 > offset_at(count))
# return`) the model claimed was missing. The confirm-gate cannot catch this — the
# model already "proved" its own (wrong) conclusion. So we add a SECOND, ADVERSARIAL
# pass whose ONLY job is to REFUTE a positive finding before it stands: a skeptic
# re-reads the SAME code hunting for the guard the first pass missed.

_VERIFY_SYSTEM = (
    "You are a SKEPTIC — an adversarial reviewer auditing a memory-safety bug report "
    "that another agent already concluded is a REAL bug. Assume the report is a FALSE "
    "POSITIVE until proven otherwise. Your job is to REFUTE it: find the bounds check, "
    "clamp, mask, early-return, or guard — IN THE SINK FUNCTION ITSELF OR IN ANY CALLER "
    "on the path to it — that makes the asserted out-of-bounds access actually SAFE.\n\n"
    "The original finding names a sink (the offending read/write), a CWE, and the input "
    "source. Re-investigate it from scratch and HOSTILELY:\n"
    "- read_function the sink function and read the FULL body around the exact access "
    "named (use read_region if it is large). The commonest false positive is a guard "
    "the first pass MISSED or OMITTED while reasoning over the decompiled rendering — a "
    "range check a few lines above the access (`if (off < 0 || off > end) return;`), a "
    "min()/clamp on the index, a mask (`x & 0xff`), or an early-return on an invalid "
    "length. LOOK HARD for it before you accept the bug.\n"
    "- Use arg_provenance and buffer_size on the EXACT offset/index/length/buffer the "
    "finding named, to check whether that value is in fact bounded (a checked length, a "
    "clamped index, a fixed allocation the index provably cannot exceed).\n"
    "- Walk callers(sink) and read each caller: the guard is often in the PARENT that "
    "validates the offset/length before calling the sink (the sink then trusts it). If "
    "EVERY path that reaches the sink clamps or validates the value, the finding is "
    "REFUTED.\n\n"
    "This is Ghidra decompiler output: field accesses are raw pointer arithmetic, names "
    "are mangled temporaries, indices are casts. Judge what the code DOES.\n\n"
    "DEFAULT TO REFUTED. Only UPHOLD the bug if, after actively hunting for the guard in "
    "the sink AND its callers, you can STILL point to a CONCRETE unchecked out-of-bounds "
    "access — a specific index/offset/length that reaches the memory op with no clamp on "
    "ANY reaching path.\n\n"
    "EACH TURN return ONE JSON object, either a tool call:\n"
    '  {"thought": "...", "action": "call", "tool": "<name>", "args": {...}}\n'
    "or your verdict:\n"
    '  {"thought": "...", "action": "verdict", "is_bug": <is the bug still real?>, '
    '"cwe": "<same CWE or blank>", "sink": "<REFUTING (is_bug=false): the exact guard '
    "/ bounds check that makes the access safe; UPHOLDING (is_bug=true): the "
    'still-unchecked access>", "source": "...", "explanation": "why the finding is '
    'refuted (name the guard) or upheld (why no guard covers the access)"}\n'
    "Set is_bug=false to REFUTE (the asserted access is actually guarded — put the "
    "concrete guard in `sink`) or is_bug=true to UPHOLD (a concrete unchecked access "
    "remains after you looked). Return only the JSON object.\n\n"
    "HONEST LIMIT: you read the SAME decompiled code as the first pass. You can catch a "
    "guard that is PRESENT but was missed; you CANNOT recover a guard the decompiler "
    "dropped entirely. If the guard is simply not in the recovered code, do NOT "
    "hallucinate one — uphold."
)


def _locate_sink_function(verdict: AgentVerdict, decompiled: dict[str, str]) -> str | None:
    """Best-effort recovery of the FUNCTION that contains the finding's sink, from the
    verdict text alone (``verify_finding`` gets no separate function name). Scans the
    sink / explanation / source strings for any decompiled function name appearing as a
    whole token, preferring the LONGEST match (a specific ``parseAdobeRAFMakernote`` over
    a generic substring). Returns ``None`` when no name is mentioned — the skeptic then
    navigates by name itself."""
    text = " ".join([verdict.sink or "", verdict.explanation or "", verdict.source or ""])
    best: str | None = None
    for name in decompiled:
        if not name:
            continue
        if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text) and (
            best is None or len(name) > len(best)
        ):
            best = name
    return best


_MAX_EVIDENCE_CALLS = 6  # proving-tool observations handed to the skeptic
_EVIDENCE_OBS_CHARS = 900  # per observation, middle-truncated


def _explorer_evidence_block(
    visited: list[str] | None, steps: list[TrajStep] | None
) -> list[str]:
    """Render the explorer's OBSERVATIONS — what it read and what the proving tools
    actually returned — for the skeptic's header.

    This is deliberately EVIDENCE, never VERDICT. The explorer's ``thought`` text and
    its narrative argument are excluded: handing the skeptic the explorer's reasoning
    is how an adversarial reviewer becomes a rubber stamp. What it gets is the raw
    tool output plus, more usefully, the NEGATIVE space — which functions the explorer
    never opened, because a guard the first pass missed is most often in code the
    first pass never read."""
    visited = visited or []
    steps = steps or []
    if not visited and not steps:
        return []

    lines = [
        "",
        "--- WHAT THE EXPLORER OBSERVED (evidence, NOT conclusions) ---",
        "The explorer's 20-step walk produced the raw tool output below. It is given "
        "to you so you do not have to re-derive the map from zero — NOT as proof of "
        "anything. The explorer concluded is_bug=true from these same observations and "
        "is presumed WRONG until you can no longer refute it. Its error, if any, is "
        "IN here: a tool it ran and MISREAD, or a body it read and skimmed past the "
        "guard in. Re-run any tool whose output your verdict depends on — a fresh "
        "result from your own call outranks anything quoted here.",
        "",
    ]
    if visited:
        lines += [
            f"Functions the explorer read ({len(visited)}): " + ", ".join(visited),
            "NOTE: a guard that the first pass MISSED is most often in a function it "
            "never opened. Walk callers() of the sink and read the ones ABSENT from "
            "that list first — that is the cheapest place to find your refutation.",
            "",
        ]

    proving = [
        s for s in steps if s.action == "call" and s.tool in _PROVING_TOOLS and s.observation
    ]
    if proving:
        lines.append(
            f"Proving-tool calls the explorer made ({len(proving)}; last "
            f"{min(len(proving), _MAX_EVIDENCE_CALLS)} shown). Running a proving tool "
            "is not the same as proving anything — check whether the output actually "
            "supports the claim:"
        )
        for s in proving[-_MAX_EVIDENCE_CALLS:]:
            lines += [
                f"  {s.tool}({_fmt_args(s.args)}) ->",
                _indent(_middle_truncate(s.observation, _EVIDENCE_OBS_CHARS), "    "),
            ]
        lines.append("")
    else:
        lines += [
            "The explorer ran NO proving tools (arg_provenance / buffer_size / struct "
            "recovery) at all. Its out-of-bounds arithmetic is therefore asserted, not "
            "computed. Establish the real buffer size and the real offset yourself.",
            "",
        ]
    lines.append("--- END OF EXPLORER OBSERVATIONS ---")
    lines.append("")
    return lines


def verify_finding(
    meta: Any,
    verdict: AgentVerdict,
    llm: Any,
    *,
    max_steps: int = 8,
    explorer_visited: list[str] | None = None,
    explorer_steps: list[TrajStep] | None = None,
) -> VerdictReview:
    """ADVERSARIAL second pass over a POSITIVE finding — the false-positive refutation.

    Given a verdict the explorer concluded ``is_bug=True``, run a SKEPTIC over the SAME
    ``ToolBox``/``_drive_loop`` machinery with an adversarial system prompt: it re-reads
    the named sink function and its CALLERS trying to find the bounds check / clamp /
    early-return / guard that makes the asserted access safe. Because it reads the SAME
    decompiled code, it catches guards that are PRESENT but were MISSED/OMITTED by the
    first pass (the harfbuzz ``CFFIndex::operator[]`` case).

    Returns a ``VerdictReview``. The skeptic's own verdict is mapped so that only an
    EXPLICIT, CONCRETELY-CITED refutation downgrades a finding:

      * skeptic ``is_bug=false`` WITH a non-empty guard in ``sink`` -> REFUTED
        (``upheld=False``, the guard recorded in ``checked_guard``);
      * skeptic ``is_bug=true`` (still sees the bug) -> UPHELD;
      * skeptic ``is_bug=false`` but names NO concrete guard, OR the loop reaches no
        conclusion -> UPHELD (kept).

    That asymmetry is the deliberate BALANCE: the skeptic's *prompt* defaults to refuted
    (it must actively hunt the guard), but the *wiring* refuses to discard a real bug on
    a hand-wave — a refutation must point at a concrete guard, so an over-eager skeptic
    that merely asserts "probably fine" does not get to drop the finding.

    ``explorer_visited`` / ``explorer_steps`` carry the first pass's OBSERVATIONS — the
    functions it read and what its proving tools actually returned. Without them the
    skeptic restarted from four strings and spent 8 steps re-walking what took the
    explorer 20. It is handed the evidence and NOT the verdict (see
    ``_explorer_evidence_block``); the ToolBox stays FRESH and its call cache is
    deliberately NOT seeded, so any tool the skeptic re-runs re-executes against the
    program rather than replaying the explorer's answer.

    HONEST LIMIT: reading the same decompilation, this recovers a guard the first pass
    MISSED; it CANNOT recover a guard the decompiler DROPPED entirely (that stays a
    residual false-positive/negative risk). It also costs a second LLM pass (~2x tokens)
    but only on POSITIVE findings."""
    tools = ToolBox(meta)
    sink_fn = _locate_sink_function(verdict, tools.decompiled)
    catalog = tools.catalog_text()

    lines = [
        "ADVERSARIAL VERIFICATION. Another agent concluded the following memory-safety "
        "finding is a REAL bug. Treat it as a FALSE POSITIVE and try to REFUTE it — find "
        "the guard that makes the asserted access safe.",
        "",
        f"  claimed CWE:    {verdict.cwe or '(unspecified)'}",
        f"  claimed sink:   {verdict.sink or '(unspecified)'}",
        f"  claimed source: {verdict.source or '(unspecified)'}",
        f"  reasoning:      {verdict.explanation or '(none given)'}",
        "",
    ]
    if sink_fn is not None:
        lines += [
            f"The offending access appears to be in {sink_fn!r}. Read it IN FULL, hunt "
            "for the bounds check / clamp / early-return that guards the access, and walk "
            "callers to see if a parent validates the offset/length before the call.",
            "",
            f"--- decompiled pseudo-C of {sink_fn} (the claimed sink function) ---",
            tools.read_function(sink_fn),
            "",
        ]
    else:
        lines += [
            "Locate the sink function by name (search_functions / read_function), read it "
            "IN FULL, hunt for the guard, and walk its callers.",
            "",
        ]
    lines += _explorer_evidence_block(explorer_visited, explorer_steps)
    lines.append(f"Available tools:\n{catalog}")
    header = "\n".join(lines)

    _steps, rv, _stop = _drive_loop(tools, llm, _VERIFY_SYSTEM, header, max_steps)

    if rv is None:
        return VerdictReview(
            upheld=True,
            reason=(
                "skeptic reached no conclusion within its budget; the finding is "
                "not refuted and stands (kept)."
            ),
        )
    if rv.is_bug:
        return VerdictReview(
            upheld=True,
            reason=(
                rv.explanation
                or "skeptic hunted for a guard in the sink and its callers and still "
                "found a concrete unchecked access; the finding stands."
            ),
        )
    guard = (rv.sink or "").strip()
    if not guard:
        return VerdictReview(
            upheld=True,
            reason=(
                "skeptic argued the finding is safe but named NO concrete guard; per "
                "the balance rule an uncited refutation does not downgrade a finding "
                "(kept)."
            ),
        )
    return VerdictReview(
        upheld=False,
        reason=(rv.explanation or "skeptic located a guard that makes the asserted access safe."),
        checked_guard=guard,
    )


def explore(
    meta: Any,
    llm: Any,
    *,
    max_steps: int = 20,
    entry: str | None = None,
    system: str = _EXPLORE_SYSTEM,
    reachable_hint: set[str] | None = None,
    format_hints: list[str] | None = None,
    adversarial: bool = True,
) -> AgentResult:
    """EXPLORATION-FIRST (cold) mode: start at the attacker-input entry and let the LLM
    FOLLOW THE DATA to the bug, using the navigation tools as its senses.

    This inverts the seeded ``run_agent`` control flow. There, a heuristic ranker PICKS
    a suspect function and hands it to the model — when the ranker is wrong (the real
    bug ranks ~#200) the model never sees the right code, so the heuristic is a ceiling.
    Here the model instead begins where untrusted input actually enters and navigates
    outward through the callees that receive input-derived values toward the least-
    checked memory operations. Ranking is demoted to an OPTIONAL hint tool
    (``suggest_suspicious``); a coverage frontier (``unexplored``) keeps the walk
    systematic. The model may read ANY function and follow ANY edge regardless of rank.

    Entry selection (honest): use ``entry`` if given and decompiled; else
    ``find_entry`` (the libFuzzer/main input entry); else — only when NO entry is
    recoverable — fall back to the top taint-ranked candidate and record that in
    ``entry_source`` ("fallback-ranked") so the report is honest that the walk did not
    truly start at an input source.

    Two optional, complementary priors focus the walk on the branch that actually
    processes the input (both wire into the frontier, never a filter — the model can
    always read/follow anything):

    * ``reachable_hint`` — the set of function names KNOWN TO EXECUTE on the target
      input (a dynamic coverage trace: SanitizerCoverage, drcov, or a Ghidra emulation
      trace). ``unexplored()`` then restricts and prioritizes the frontier to that
      executed set, narrowing a huge static-reachable surface (libraw ~825) to the
      dozens actually hit — the real path the input takes. The LLM still must REASON
      about which executed function holds the bug; the trace does not name it. Using the
      executed-FUNCTION SET is legitimate dynamic triage (like a fuzzer-crash workflow);
      using the crash STACK would be cheating (it names the bug) and is NOT what this is.
    * ``format_hints`` — magic-byte-derived keywords (see ``input_format_hints``) that
      float functions whose NAMES match the input's format up the frontier order. A soft
      prior only.

    The loop is bounded (``max_steps`` defaults to 20 — exploration needs depth) and
    keeps the repeat-guard intact. Returns the full auditable trajectory, the visited
    frontier, how the entry was chosen, and the verdict (or ``None``)."""
    from .localize import find_entry

    tools = ToolBox(meta)
    tools.reachable_hint = set(reachable_hint) if reachable_hint else None
    tools.format_hints = list(format_hints) if format_hints else []

    # -- choose where input enters -------------------------------------------
    chosen: str | None = None
    entry_source = ""
    if entry and entry in tools.decompiled:
        chosen, entry_source = entry, "provided"
    else:
        found = find_entry(tools.decompiled, tools.callgraph)
        if found is not None and found in tools.decompiled:
            chosen, entry_source = found, "input-entry"
        else:
            # No decompiled entry point — fall back to the top ranked candidate, but
            # SAY SO (entry_source records the honesty caveat).
            cold = tools.localize_candidates(limit=1)
            if not cold:
                return AgentResult("", [], None, "error", entry_source="none")
            chosen, entry_source = cold[0], "fallback-ranked"

    tools.entry = chosen
    body = tools.read_function(chosen)  # also marks the entry visited

    if entry_source == "input-entry":
        note = (
            f"UNTRUSTED INPUT ENTERS THE PROGRAM AT {chosen!r} (the recovered input "
            f"entry point; its parameters are the attacker-controlled data/size). "
        )
    elif entry_source == "provided":
        note = (
            f"You are starting exploration at {chosen!r} (caller-specified entry); "
            f"treat its inputs as untrusted. "
        )
    else:
        note = (
            f"NO input entry point (LLVMFuzzerTestOneInput/main) was recovered in this "
            f"program, so exploration FALLS BACK to the top taint-ranked candidate "
            f"{chosen!r} as the start — this is NOT a true input source; treat its "
            f"parameters as untrusted and explore outward. "
        )

    # -- optional prior notes (dynamic coverage + input format) ---------------
    prior_note = ""
    if tools.reachable_hint:
        n_exec = sum(1 for f in tools.reachable_hint if f in tools.decompiled)
        prior_note += (
            f"\n\nDYNAMIC COVERAGE AVAILABLE: {n_exec} functions are known to EXECUTE on "
            "this specific input (a coverage trace). unexplored() restricts and "
            "prioritizes the frontier to that executed set — walk the REAL path the "
            "input takes, not every static branch. You must still REASON about which "
            "executed function holds the bug (the trace does NOT name it); you may still "
            "read any function by name."
        )
    if tools.format_hints:
        prior_note += (
            f"\n\nINPUT FORMAT: the PoC's magic bytes identify it as "
            f"{', '.join(tools.format_hints)} data. Functions whose names match these "
            "terms are floated up in the frontier ranking — a soft prior, NOT a filter."
        )

    catalog = tools.explore_catalog_text()
    header = (
        note + "Explore from here: follow the attacker-controlled data through the callees "
        "that receive it, toward the least-checked indexing/arithmetic/copy operations. "
        "Use unexplored() to cover the reachable surface and suggest_suspicious() only "
        "as an optional hint. Conclude only when you find a concrete overflow/OOB or "
        "have exhausted the reachable input-influenced surface." + prior_note + "\n\n"
        f"Available tools:\n{catalog}\n\n"
        f"--- decompiled pseudo-C of {chosen} (the exploration entry) ---\n{body}\n"
    )
    steps, verdict, stop_reason = _drive_loop(tools, llm, system, header, max_steps)

    # ADVERSARIAL VERIFICATION: a confident POSITIVE finding gets a SECOND, skeptical
    # pass that tries to REFUTE it before it stands (the false-positive fix). A False /
    # no-verdict result needs no refutation and is returned unchanged. Gated so tests
    # (and callers who want the raw first-pass verdict) can disable it.
    review: VerdictReview | None = None
    if adversarial and verdict is not None and verdict.is_bug:
        # Hand the skeptic what the explorer OBSERVED (functions read + proving-tool
        # output) so it does not re-walk 20 steps of map-building with an 8-step
        # budget. Not what the explorer concluded — see ``_explorer_evidence_block``.
        review = verify_finding(
            meta,
            verdict,
            llm,
            explorer_visited=list(tools.visited),
            explorer_steps=steps,
        )
        if not review.upheld:
            # Downgrade the finding and record the refuting guard in the explanation.
            guard_note = (
                f" Guard that makes the asserted access safe: {review.checked_guard}"
                if review.checked_guard
                else ""
            )
            verdict = AgentVerdict(
                is_bug=False,
                cwe=verdict.cwe,
                sink=verdict.sink,
                source=verdict.source,
                explanation=(
                    verdict.explanation
                    + "\n\n[ADVERSARIAL-VERIFICATION: REFUTED] "
                    + review.reason
                    + guard_note
                ),
            )

    return AgentResult(
        chosen,
        steps,
        verdict,
        stop_reason,
        entry_source=entry_source,
        visited=list(tools.visited),
        review=review,
    )
