"""Decompiled-C → abstract-IL extractor (M5 #27).

The Ghidra backend builds the slicer's IL from Ghidra's **High P-Code SSA** —
true def-use Varnodes. A non-Ghidra backend (rizin/r2ghidra ``pdg`` or angr's
decompiler) only hands us **pseudo-C text**, so this module recovers a *lighter*
IL from that text: per-function call sites with their argument variables, plus a
single-def-per-variable use→def map mined from ``lhs = callee(...)`` assignments.

Fidelity gap — be honest:
  * No real SSA: one ``defs[(var, func)]`` entry per variable, last writer wins.
    Re-assigned variables and phi-merges are lost (Ghidra recovers them).
  * No per-instruction addresses (the text has none), so the angr reachability
    stage (#5), which keys on ``sink_addr``/function-entry, is skipped for this
    backend — the slice + oracle still run.
  * Recall is bounded by the decompiler's call recovery: indirect calls
    (``(*fp)(...)``) carry no callee name and are dropped.

What it DOES recover faithfully enough to slice + confirm: direct libc-name call
sites, their positional argument variable names (the basis of the memory-flow
pass: ``read(fd, buf, n) → strcpy(dst, buf)`` shares ``buf``), and return-value
flow (``p = getenv("X"); system(p);``) via the assignment def-map.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..il import Inst, Kind

# Names that look like calls but are control flow / operators, never callees.
_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "case", "goto", "default", "typedef", "struct", "union", "enum",
    "__assert_fail", "CONCAT11", "CONCAT22", "CONCAT44", "SUB84", "SUB164",
    "ZEXT48", "ZEXT416", "SEXT48", "CARRY4", "SBORROW4",
})

# Identifier prefixes r2/r2ghidra/angr attach to recovered symbols; stripped so the
# taint model + bug-class lenses match clean libc names (``read``, ``strcpy``).
_PREFIX_RE = re.compile(r"\b(?:sym\.imp\.|sym\.|imp\.|dbg\.|reloc\.|_imp_)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_CALL_HEAD_RE = re.compile(r"([A-Za-z_][\w.]*)\s*\(")


def normalize_c(code: str) -> str:
    """Strip decompiler symbol prefixes so libc names are bare (``sym.imp.read`` →
    ``read``). Idempotent; safe to apply to already-clean angr output."""
    return _PREFIX_RE.sub("", code)


def normalize_name(name: str) -> str:
    """Bare callee symbol for a (possibly prefixed) recovered name."""
    return _PREFIX_RE.sub("", name).split(".")[-1]


def _split_top_commas(s: str) -> list[str]:
    """Split an argument list on commas at paren/bracket depth 0."""
    out: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(s):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return [a for a in (x.strip() for x in out) if a]


def _match_args(s: str, open_idx: int) -> tuple[str, int]:
    """Given ``s`` and the index of an opening ``(``, return (inner, end_idx) where
    inner is the balanced argument text and end_idx is the index past the ``)``."""
    depth = 0
    for i in range(open_idx, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return s[open_idx + 1:i], i + 1
    return s[open_idx + 1:], len(s)


def _find_call(expr: str) -> tuple[str, str, int, int] | None:
    """Leftmost ``name(...)`` in ``expr`` at the top level. Returns
    (name, inner_args, start, end) or None. Skips control keywords."""
    for m in _CALL_HEAD_RE.finditer(expr):
        name = m.group(1)
        bare = name.split(".")[-1]
        if bare in _KEYWORDS:
            continue
        inner, end = _match_args(expr, m.end() - 1)
        return name, inner, m.start(), end
    return None


def _simple_var(arg: str) -> str | None:
    """If ``arg`` is a simple (possibly &/\\*/cast-decorated) identifier, return the
    bare variable name; else None. ``&buf`` → ``buf``, ``(char *)p`` → ``p``."""
    a = arg.strip()
    a = re.sub(r"^\((?:[\w\s*]+)\)\s*", "", a)  # drop a leading cast
    a = a.lstrip("&*")
    m = _IDENT_RE.fullmatch(a)
    if m and a not in _KEYWORDS:
        return a
    return None


@dataclass
class _Ctx:
    func: str
    counter: int
    insts: list[Inst]
    defs: dict[tuple[str, str], int]
    callgraph: dict[str, list[str]]
    var_def: dict[str, int] = field(default_factory=dict)

    def _new(self) -> int:
        self.counter += 1
        return self.counter

    def build_call(self, name: str, inner: str) -> int:
        arg_ids: list[int] = []
        arg_vars: list[str | None] = []
        for arg in _split_top_commas(inner):
            sub = _find_call(arg)
            if sub is not None and sub[2] == 0 and _CALL_HEAD_RE.match(arg):
                # the argument is itself a call — wire its node as the operand so
                # the slicer walks into it (``system(getenv("X"))``).
                arg_ids.append(self.build_call(sub[0], sub[1]))
                arg_vars.append(None)
                continue
            var = _simple_var(arg)
            if var is not None:
                vid = self._new()
                self.insts.append(Inst(id=vid, func=self.func, addr=0, kind=Kind.VAR, var=var))
                d = self.var_def.get(var)
                if d is not None:
                    self.defs[(var, self.func)] = d
                arg_ids.append(vid)
                arg_vars.append(var)
            else:
                cid = self._new()
                self.insts.append(Inst(id=cid, func=self.func, addr=0, kind=Kind.CONST, text=arg))
                arg_ids.append(cid)
                arg_vars.append(None)
        call_id = self._new()
        dest = normalize_name(name)
        # Synthetic *ordinal* address = creation order. We have no real VA from
        # pseudo-C text; the slicer's memory-flow pass only needs source-before-sink
        # ordering, which call-creation order guarantees. (The contract `offset` is
        # therefore an intra-run ordinal for non-Ghidra backends, not a VA — and the
        # angr reachability stage, which needs real VAs, is disabled for them.)
        self.insts.append(Inst(
            id=call_id, func=self.func, addr=call_id, kind=Kind.CALL,
            dest=dest, args=arg_ids, arg_vars=arg_vars,
        ))
        self.callgraph.setdefault(self.func, [])
        if dest not in self.callgraph[self.func]:
            self.callgraph[self.func].append(dest)
        return call_id


_ASSIGN_RE = re.compile(r"^\s*(?:[A-Za-z_][\w \t*]*?\b)?([A-Za-z_]\w*)\s*=\s*(?![=])(.+)$")


def _lhs_var(stmt: str) -> tuple[str, str] | None:
    """Detect a top-level assignment ``... lhs = rhs``. Returns (lhs, rhs) or None.
    Rejects ``==``/``<=``/``>=``/``!=`` and compound ops by requiring a lone ``=``."""
    # find the first '=' that is not part of a comparison/compound operator
    depth = 0
    for i, ch in enumerate(stmt):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "=" and depth == 0:
            prev = stmt[i - 1] if i else ""
            nxt = stmt[i + 1] if i + 1 < len(stmt) else ""
            if prev in "=<>!+-*/%&|^" or nxt == "=":
                continue
            lhs_raw, rhs = stmt[:i], stmt[i + 1:]
            m = re.search(r"([A-Za-z_]\w*)\s*$", lhs_raw)
            if m:
                return m.group(1), rhs.strip()
            return None
    return None


def build_il(
    decompiled: dict[str, str], *, counter_start: int = 0
) -> tuple[list[Inst], dict[tuple[str, str], int], dict[str, list[str]]]:
    """Build (insts, defs, callgraph) from a ``{func: pseudo_c}`` map.

    The IL is consumed by the same ``BackwardSlicer`` / ``analyze.scan`` the Ghidra
    backend feeds — only the *source* of the IL differs.
    """
    insts: list[Inst] = []
    defs: dict[tuple[str, str], int] = {}
    callgraph: dict[str, list[str]] = {}
    counter = counter_start
    for func, body in decompiled.items():
        ctx = _Ctx(func=func, counter=counter, insts=insts, defs=defs, callgraph=callgraph)
        for raw in re.split(r"[;\n{}]", normalize_c(body)):
            stmt = raw.strip()
            if not stmt or stmt.startswith(("//", "/*", "*", "#")):
                continue
            assign = _lhs_var(stmt)
            top_call = _find_call(stmt)
            if assign is not None:
                lhs, rhs = assign
                rhs_call = _find_call(rhs)
                if rhs_call is not None:
                    cid = ctx.build_call(rhs_call[0], rhs_call[1])
                    ctx.var_def[lhs] = cid
                    continue
                rhs_var = _simple_var(rhs)
                if rhs_var is not None and rhs_var in ctx.var_def:
                    ctx.var_def[lhs] = ctx.var_def[rhs_var]  # copy propagation
                    continue
            if top_call is not None:
                ctx.build_call(top_call[0], top_call[1])
        counter = ctx.counter
    return insts, defs, callgraph
