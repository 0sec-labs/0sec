"""G1 structural-grounding gate for 0verse findings (opt-in, ``ZEROVERSE_GROUND``).

0verse already grounds the CONCLUSION of a finding (did it crash? -> the PoV
oracle) but nothing grounds the PREMISE the LLM used to pick a *severity*: "this
function calls the dangerous sink", "the sink is reachable from an attacker-facing
entry", "this object is freed here". A decompiler that mis-types a pointer and
halves a struct offset can make the LLM read a false premise and inflate severity
on an unconfirmed finding.

This module ports the G1 structural-grounding gate
(``research/g1-structural-grounding/`` in the 0sec monorepo) and binds it to the
call graph 0verse ALREADY recovered in ``backends.ghidra.ProgramMeta.callgraph``
(the disassembly-level ``FunctionManager`` graph, authoritative over pseudo-C) —
no second Ghidra run, no KD dependency.

Contract (unchanged from G1):
  GROUNDED  -> premise confirmed; the finding may keep its proposed severity.
  REFUTED   -> a load-bearing premise is provably false; the severity is floored
               to ``info`` (a reproducing PoV can still override downstream).
  UNKNOWN   -> no oracle can resolve a load-bearing premise; severity is capped at
               ``low`` and can never auto-promote to ``medium``/``high``.

Design note: the implicit premises are marked load-bearing ONLY when the oracle
can actually speak (the function is in the recovered call graph; exports exist).
On a partial/stripped graph an unresolvable premise is informational, so a poor
call graph never mass-caps the corpus — it mirrors 0verse's own
``unresolved_edges`` honesty.
"""

from __future__ import annotations

import os
import re
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


def grounding_enabled() -> bool:
    """Return whether structural grounding is enabled.

    Grounding defaults to on and can only lower unconfirmed-hypothesis severity;
    it never blocks a proof of vulnerability.
    """
    return os.environ.get("ZEROVERSE_GROUND", "1").strip().lower() not in (
        "", "0", "false", "no",
    )


class ClaimVerdict(StrEnum):
    GROUNDED = "GROUNDED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"


# 0verse's native severity ladder (agent.VERDICT_SCHEMA enum order).
_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _rank(sev: str) -> int:
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return 0


def _cap(sev: str, ceiling: str) -> str:
    return sev if _rank(sev) <= _rank(ceiling) else ceiling


# ---------------------------------------------------------------------------
# The oracle: 0verse's already-recovered disassembly call graph.
# ---------------------------------------------------------------------------

# Free primitives across the surfaces 0verse targets (ELF/Mach-O/PE, kernel + user).
# Matched on the exact recovered symbol name; extend per target as needed.
_FREE_NAMES = frozenset({
    "free", "cfree", "kfree", "kfree_sensitive", "kvfree", "vfree", "kmem_cache_free",
    "g_free", "realloc", "reallocarray",
    "ExFreePool", "ExFreePoolWithTag", "RtlFreeHeap", "HeapFree", "LocalFree", "GlobalFree",
    "IoFreeMdl", "AfdFreePollInfo",
    "operator delete", "operator.delete", "_ZdlPv", "delete",
    "CFRelease", "objc_release",
})


def _is_free_name(name: str) -> bool:
    n = name.lstrip("_").split("@")[0]
    if n in _FREE_NAMES or name in _FREE_NAMES:
        return True
    # Unknown symbols are not deallocation evidence merely because they contain
    # "free": AfdGetFreeConnection and free_space are getters/accounting terms.
    # Admit only conservative wrapper forms; add platform primitives explicitly
    # above as they are observed.
    if re.fullmatch(r"[a-z][a-z0-9_]*_(?:free|dealloc)", n):
        return True
    match = re.fullmatch(
        r"(?P<prefix>[A-Z][A-Za-z0-9]*?)(?:Free|Dealloc)[A-Z][A-Za-z0-9]*",
        n,
    )
    if not match:
        return False
    prefix_words = re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z][a-z0-9]*", match["prefix"])
    return not prefix_words or prefix_words[-1].lower() not in {
        "get", "is", "has", "query", "find", "count", "check", "set",
    }


@dataclass
class CallGraph:
    """The G1 STATIC oracle, built from ``ProgramMeta``."""

    callees: dict[str, set[str]]
    exports: set[str] = field(default_factory=set)
    free_primitives: set[str] = field(default_factory=set)
    # Callers with at least one unresolved indirect/virtual call site. Positive
    # facts from their recovered direct edges remain trustworthy, but a missing
    # edge/path is UNKNOWN rather than proof of absence.
    incomplete_callers: set[str] = field(default_factory=set)
    _universe: set[str] | None = None

    def knows(self, fn: str) -> bool:
        return fn in self.callees

    def has_symbol(self, name: str) -> bool:
        """Is ``name`` anywhere in the graph (a caller or any callee)? A
        reachability target absent from the whole universe (a synthetic bug-class
        label, an inlined op, a symbol Ghidra named differently) cannot be
        REFUTED — the oracle simply can't speak to it."""
        if self._universe is None:
            u = set(self.callees)
            for cs in self.callees.values():
                u |= cs
            self._universe = u
        return name in self._universe

    def has_edge(self, caller: str, callee: str) -> bool | None:
        """True/False if the caller is analysed, else None (can't say)."""
        if caller not in self.callees:
            return None
        if callee in self.callees[caller]:
            return True
        if caller in self.incomplete_callers:
            return None
        return False

    def reaches(
        self, entry: str, target: str, max_depth: int = 64
    ) -> tuple[bool | None, list[str] | None]:
        """BFS over the call graph. (reachable|None, path|None); None if entry unknown."""
        if entry not in self.callees:
            return None, None
        if entry == target:
            return True, [entry]
        seen = {entry}
        incomplete = False
        q: deque[tuple[str, list[str]]] = deque([(entry, [entry])])
        while q:
            node, path = q.popleft()
            if len(path) > max_depth:
                incomplete = True
                continue
            if node in self.incomplete_callers:
                incomplete = True
            for callee in sorted(self.callees.get(node, ())):
                if callee == target:
                    return True, [*path, callee]
                if callee not in seen:
                    seen.add(callee)
                    q.append((callee, [*path, callee]))
        return (None, None) if incomplete else (False, None)

    def reaches_any_free(self, entry: str) -> tuple[bool | None, str | None, list[str] | None]:
        """(reaches_free|None, free_name, path); None if entry unknown."""
        if entry not in self.callees:
            return None, None, None
        seen = {entry}
        incomplete = False
        q: deque[tuple[str, list[str]]] = deque([(entry, [entry])])
        while q:
            node, path = q.popleft()
            if node in self.incomplete_callers:
                incomplete = True
            for callee in sorted(self.callees.get(node, ())):
                if callee in self.free_primitives or _is_free_name(callee):
                    return True, callee, [*path, callee]
                if callee not in seen:
                    seen.add(callee)
                    q.append((callee, [*path, callee]))
        return (None, None, None) if incomplete else (False, None, None)

    def reaches_from_any_export(self, target: str) -> tuple[bool | None, list[str] | None]:
        """(reachable|None, path). None when there is no usable export oracle."""
        if target in self.exports:
            return True, [target]
        if not self.exports:
            return None, None
        incomplete = False
        for e in sorted(self.exports):
            ok, path = self.reaches(e, target)
            if ok:
                return True, path
            if ok is None:
                incomplete = True
        return (None, None) if incomplete else (False, None)


def callgraph_from_meta(meta: Any) -> CallGraph:
    """Build the STATIC oracle from ``ProgramMeta`` — no new Ghidra run."""
    raw = getattr(meta, "callgraph", None) or {}
    callees = {k: set(v) for k, v in raw.items()}
    exports = set(getattr(meta, "exports", None) or [])
    imports = set(getattr(meta, "imports", None) or [])
    incomplete_callers = {
        str(edge.get("func", ""))
        for edge in (getattr(meta, "unresolved_edges", None) or [])
        if edge.get("func")
    }
    all_callees = set().union(*callees.values()) if callees else set()
    frees = {n for n in (imports | all_callees) if _is_free_name(n)}
    return CallGraph(
        callees=callees,
        exports=exports,
        free_primitives=frees,
        incomplete_callers=incomplete_callers,
        _universe=set(callees) | all_callees | imports | exports,
    )


# ---------------------------------------------------------------------------
# Claims + adjudication.
# ---------------------------------------------------------------------------


@dataclass
class Claim:
    # call_edge | reachability | reachability_export | free_site | offset_field | lock_coverage
    claim_type: str
    operands: dict[str, Any]
    load_bearing: bool = True
    text: str = ""
    source: str = "implicit"   # "implicit" (gate-derived) | "llm" (parsed @claim)


@dataclass
class AdjudicatedClaim:
    claim: Claim
    verdict: ClaimVerdict
    fact: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim.text or self.claim.claim_type,
            "type": self.claim.claim_type,
            "load_bearing": self.claim.load_bearing,
            "verdict": self.verdict.value,
            "fact": self.fact,
        }


def _adj_call_edge(cg: CallGraph, op: dict[str, Any]) -> tuple[ClaimVerdict, str]:
    caller, callee = op.get("caller", ""), op.get("callee", "")
    ans = cg.has_edge(caller, callee)
    if ans is None:
        return ClaimVerdict.UNKNOWN, f"caller '{caller}' not in recovered call graph"
    if ans:
        return ClaimVerdict.GROUNDED, f"call graph confirms {caller} -> {callee}"
    if not cg.has_symbol(callee):
        return ClaimVerdict.UNKNOWN, f"callee '{callee}' not a known symbol — undecidable"
    return ClaimVerdict.REFUTED, (
        f"{caller} does not call {callee} in the disassembly call graph "
        f"(pseudo-C artifact); real callees: {sorted(cg.callees.get(caller, ()))[:8]}"
    )


def _adj_reachability(cg: CallGraph, op: dict[str, Any]) -> tuple[ClaimVerdict, str]:
    entry, sink = op.get("from", ""), op.get("to", "")
    reachable, path = cg.reaches(entry, sink)
    if reachable is None:
        return ClaimVerdict.UNKNOWN, f"entry '{entry}' not in the analysed call graph"
    if reachable:
        return ClaimVerdict.GROUNDED, "path: " + " -> ".join(path or [])
    if not cg.has_symbol(sink):
        # target is not a real symbol anywhere in the graph (synthetic bug-class
        # label, inlined op, differently-named symbol) -> the oracle can't refute it.
        return ClaimVerdict.UNKNOWN, f"target '{sink}' not a known symbol — undecidable"
    return ClaimVerdict.REFUTED, f"no call-graph path from {entry} to {sink}"


def _adj_reachability_export(cg: CallGraph, op: dict[str, Any]) -> tuple[ClaimVerdict, str]:
    target = op.get("target", "")
    reachable, path = cg.reaches_from_any_export(target)
    if reachable is None:
        return ClaimVerdict.UNKNOWN, "no export set recovered — attacker reach unprovable"
    if reachable:
        return ClaimVerdict.GROUNDED, "reachable from export: " + " -> ".join(path or [])
    # Graph is partial (indirect/unresolved edges may hide the path): do NOT refute
    # the finding out of existence, only decline to ground the reachability premise.
    return ClaimVerdict.UNKNOWN, f"no export path to {target} found (call graph is partial)"


def _adj_free_site(cg: CallGraph, op: dict[str, Any]) -> tuple[ClaimVerdict, str]:
    func = op.get("func", "") or op.get("site", "")
    reaches, name, path = cg.reaches_any_free(func)
    if reaches is None:
        return ClaimVerdict.UNKNOWN, f"'{func}' not in the analysed call graph"
    if reaches:
        return ClaimVerdict.GROUNDED, f"reaches free {name}: " + " -> ".join(path or [])
    return ClaimVerdict.REFUTED, f"{func} reaches no free primitive in the call graph"


def _adj_no_oracle(cg: CallGraph, op: dict[str, Any]) -> tuple[ClaimVerdict, str]:
    # offset_field / lock_coverage need a per-instruction operand (or KD) oracle
    # 0verse does not have per-binary today (design doc v2). Cap, never ground.
    return ClaimVerdict.UNKNOWN, "no offset oracle available (needs P-Code operand export)"


_ADJUDICATORS = {
    "call_edge": _adj_call_edge,
    "reachability": _adj_reachability,
    "reachability_export": _adj_reachability_export,
    "free_site": _adj_free_site,
    "offset_field": _adj_no_oracle,
    "lock_coverage": _adj_no_oracle,
}


def adjudicate(claim: Claim, cg: CallGraph) -> AdjudicatedClaim:
    adj = _ADJUDICATORS.get(claim.claim_type)
    if adj is None:
        return AdjudicatedClaim(claim, ClaimVerdict.UNKNOWN,
                                f"no adjudicator for claim_type '{claim.claim_type}'")
    verdict, fact = adj(cg, claim.operands)
    return AdjudicatedClaim(claim, verdict, fact)


# ---------------------------------------------------------------------------
# @claim parsing (the G1 claim_contract boundary, minimal port).
# ---------------------------------------------------------------------------

_CLAIM_LINE = re.compile(r"^\s*@claim\s+(\w+)\s+(.*)$")
_KV = re.compile(r"(\w+)=(\S+)")
_INT_FIELDS = {"claimed_offset", "claimed_rundown_off", "context_off"}
_REQUIRED = {
    "call_edge": {"caller", "callee"},
    "reachability": {"from", "to"},
    "free_site": {"func"},
    "offset_field": {"func", "claimed_offset"},
    "lock_coverage": {"func", "claimed_rundown_off", "context_off"},
}


def _coerce(k: str, v: str) -> Any:
    if k in _INT_FIELDS:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    if k == "load_bearing":
        return v.lower() in ("true", "1", "yes")
    return v


def parse_claims(text: str) -> list[Claim]:
    """Parse ``@claim`` lines the LLM emitted in its explanation into typed claims."""
    claims: list[Claim] = []
    for raw in (text or "").splitlines():
        m = _CLAIM_LINE.match(raw)
        if not m:
            continue
        ctype, rest = m.group(1), m.group(2)
        try:
            kv = {k: _coerce(k, v) for k, v in _KV.findall(rest)}
        except (TypeError, ValueError):
            # This is model-authored text. A malformed typed operand is an
            # untrusted claim to drop, never a reason to abort the pipeline.
            continue
        load_bearing = bool(kv.pop("load_bearing", True))
        req = _REQUIRED.get(ctype)
        if req is None or not req.issubset(kv.keys()):
            continue  # malformed @claim is dropped, not trusted
        claims.append(Claim(ctype, kv, load_bearing, raw.strip().replace("@claim ", ""),
                            source="llm"))
    return claims


# ---------------------------------------------------------------------------
# The gate.
# ---------------------------------------------------------------------------

_UAF_MARKERS = ("uaf", "use-after-free", "use_after_free", "double-free",
                "double_free", "cwe-416", "cwe-415")


def _is_uaf_class(bug_class: str) -> bool:
    b = (bug_class or "").lower()
    return any(m in b for m in _UAF_MARKERS)


def implicit_claims(finding: Any, verdict: Any, cg: CallGraph) -> list[Claim]:
    """Derive the structural premises the reported severity rests on, from the
    slice + call graph. Load-bearing ONLY where the oracle can actually speak."""
    fn = getattr(finding, "function", "") or ""
    sink = getattr(finding, "sink", "") or ""
    origin = getattr(finding, "origin", "slice") or "slice"
    # Load-bearing only when the function's calls are actually MODELED (non-empty
    # callee set). A known-but-leaf/unmodeled entry can't refute anything, so its
    # premises stay informational — a poor graph never floors a real finding.
    has_edges = bool(cg.callees.get(fn))
    claims: list[Claim] = []

    # 1) core premise: the dangerous sink is reachable from the finding's function.
    #    0verse SLICE findings are source->sink call slices that can span several
    #    hops, so the honest implicit premise is REACHABILITY (function ->* sink),
    #    not a direct call edge — a direct-edge check would falsely refute every
    #    legitimate multi-hop finding (e.g. amdxdna_sched_job_run ->* to_gobj).
    #    ONLY for slice findings: bugclass-lens / foxguard findings carry a
    #    SYNTHETIC sink label (e.g. "off-by-one:...") that is not a call target, so
    #    a reachability check against it would always (wrongly) refute. A finer
    #    direct-call premise is grounded via an explicit @claim call_edge instead.
    if sink and origin == "slice" and ":" not in sink:
        claims.append(Claim("reachability", {"from": fn, "to": sink},
                            load_bearing=has_edges, text=f"{fn} ->* {sink}"))

    # 2) severity premise: the function is reachable from an attacker-facing export.
    #    Load-bearing only when we have a usable export oracle and modeled calls.
    have_reach_oracle = bool(cg.exports) and has_edges
    claims.append(Claim("reachability_export", {"target": fn},
                        load_bearing=have_reach_oracle, text=f"<export> ->* {fn}"))

    # 3) UAF/double-free premise: does the function reach a free primitive?
    #    EVIDENCE-ONLY (non-load-bearing) on the implicit path: call-graph free
    #    recognition is inherently incomplete (inlined frees, indirect/unresolved
    #    free calls), so a "reaches no free" result must not floor a real finding.
    #    The reachability-to-sink premise (1) carries the load; an explicit
    #    @claim free_site the LLM stakes stays load-bearing (see parse_claims).
    if _is_uaf_class(getattr(verdict, "bug_class", "")):
        claims.append(Claim("free_site", {"func": fn},
                            load_bearing=False, text=f"free reachable in {fn}"))
    return claims


@dataclass
class GroundingResult:
    proposed_severity: str
    final_severity: str
    status: str                       # grounded | capped | refuted
    adjudicated: list[AdjudicatedClaim]
    reprompt: list[str]

    @property
    def changed(self) -> bool:
        return self.final_severity != self.proposed_severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "proposed_severity": self.proposed_severity,
            "final_severity": self.final_severity,
            "claims": [a.to_dict() for a in self.adjudicated],
            "reprompt": self.reprompt,
        }


def gate(proposed_severity: str, claims: list[Claim], cg: CallGraph) -> GroundingResult:
    adjudicated = [adjudicate(c, cg) for c in claims]
    sev = proposed_severity
    reprompt: list[str] = []
    refuted_lb = False
    capped = False
    for a in adjudicated:
        if a.verdict == ClaimVerdict.REFUTED:
            reprompt.append(a.fact)
            if a.claim.load_bearing:
                refuted_lb = True
        elif a.verdict == ClaimVerdict.UNKNOWN and a.claim.load_bearing:
            if _rank(sev) > _rank("low"):
                sev = _cap(sev, "low")
                capped = True
    if refuted_lb:
        # A refuted load-bearing premise floors the hypothesis. A reproducing PoV
        # can still override this downstream (execution truth beats a static graph).
        sev = "info"
        status = "refuted"
    elif capped:
        status = "capped"
    else:
        status = "grounded"
    return GroundingResult(proposed_severity, sev, status, adjudicated, reprompt)


def ground_verdict(finding: Any, verdict: Any, cg: CallGraph) -> GroundingResult:
    """Full pass: implicit premises + any ``@claim`` the LLM emitted, gated."""
    claims = implicit_claims(finding, verdict, cg)
    claims += parse_claims(getattr(verdict, "explanation", ""))
    return gate(getattr(verdict, "severity", "info"), claims, cg)
