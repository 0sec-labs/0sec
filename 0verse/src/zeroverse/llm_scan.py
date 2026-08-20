"""LLM-driven bug-finding over decompiled pseudo-C (the Big-Sleep lever, binary-native).

The regex-shape lenses (``bugclasses.py``) match on the *syntax* of the decompiled
code — a named libc sink, a recognizable copy shape. That misses real bugs because
the decompiler mangles the source shape: an array index becomes a ``(int)`` cast, a
bounded ``for`` becomes a ``do{...}while(cur != end)`` cursor loop, and a virtual
dispatch becomes an indirect call through a function pointer. A raw out-of-bounds
*store* like ``In[(int)pcVar4] = *(cmsUInt16Number *)(...)`` inside such a cursor
loop, reached only through an indirect ``cmsSAMPLER16`` callback, has **no** libc
sink and **no** recognizable shape — every name/shape lens walks right past it, and
static reachability misses the function entirely (the dispatch edge is unresolved).

So we let the model *read* the pseudo-C and judge memory-safety directly, reasoning
about the recovered semantics rather than the mangled syntax. Its judgment is a
**hypothesis** — exactly like the slice/foxguard/bugclass generators. PoV-is-truth
still holds: the LLM never confirms; a downstream oracle discharges the hypothesis
with a reproducing crash (DESIGN-NOTES Decision 1). A clear negative with analysis
is a real result; a fabricated "bug" is not.

This runs as a *complement* to the regex lenses (it scans the reachable target
functions they did NOT already flag) and is gated to the real-LLM lane
(``ZEROVERSE_LLM_SCAN``) so the deterministic MockLLM CI path is unaffected.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from .analyze import Finding, reachable_functions
from .backends import _noise
from .deasan import deasan
from .structtypes import struct_context

# JSON the model must return — a per-function memory-safety verdict. Distinct from
# agent.VERDICT_SCHEMA (which triages an already-located source->sink path): here the
# model both *locates* the flaw in the body and classifies it.
PSEUDOC_SCAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "is_bug": {"type": "boolean"},
        "cwe": {"type": "string"},
        "vulnerable_line": {"type": "string"},
        "source": {"type": "string"},
        "sink": {"type": "string"},
        "explanation": {"type": "string"},
    },
    "required": ["is_bug", "cwe", "vulnerable_line", "source", "sink", "explanation"],
    "additionalProperties": False,
}


_SYSTEM = (
    "You are a binary vulnerability-research assistant reviewing a SINGLE function "
    "of Ghidra decompiler pseudo-C for a MEMORY-SAFETY bug (out-of-bounds write or "
    "read, use-after-free, integer/heap/stack overflow) reachable from untrusted "
    "input.\n\n"
    "CRITICAL — this is decompiler output, not source. Reason about the recovered "
    "SEMANTICS, never the surface syntax:\n"
    "- Names are mangled: undefined4/uint/puVarN/local_NN/iVarN/pcVarN are recovered "
    "temporaries, not meaningful identifiers. Judge what the code DOES.\n"
    "- Array indices are often casts: `In[(int)pcVar4]`, `buf[(uint)i]` — a signed "
    "cast or a wide type can index far past the allocation. Ask whether the index is "
    "bounded before the access.\n"
    "- Loops are lowered to cursors: `do { ... } while (cur != end)` or pointer "
    "walks terminated by `!=`, not a counted `for`. An off-by-one or a cursor that "
    "overshoots the buffer end is an OOB access even with no explicit length.\n"
    "- Dispatch is often indirect: a callback invoked as `(*pcVarN)(...)` or "
    "registered as a sampler/handler. The function may look isolated but runs on "
    "attacker-influenced data. Treat table/callback inputs as untrusted.\n"
    "- A raw store `dst[idx] = val` or `*(T *)(base + off) = val` with an "
    "attacker-influenced idx/off IS a sink — there need not be a memcpy/strcpy call.\n\n"
    "Decide honestly. If the function bounds its accesses or the index is provably "
    "constrained, return is_bug=false — a wrong positive is worse than a miss. When "
    "is_bug=true, quote the exact vulnerable line, name the CWE (e.g. CWE-787 "
    "out-of-bounds write), the untrusted `source`, the `sink` (the offending "
    "access), and explain the OOB in one or two sentences. You only PROPOSE a "
    "hypothesis; a separate oracle proves exploitability. Return only the JSON."
)


@dataclass
class LlmScanFinding:
    """One per-function verdict from the pseudo-C scan (rich; the pipeline projects
    positives to ``analyze.Finding``). Kept whole so a bench experiment can report
    the model's exact reasoning + located line."""

    function: str
    is_bug: bool
    cwe: str
    vulnerable_line: str
    source: str
    sink: str
    explanation: str


# --- candidate selection ----------------------------------------------------

# Minimum body size (chars) — skip thunks/trampolines/one-liners that cannot hold a
# real memory-safety bug and would just burn budget.
_MIN_BODY = 60

# A raw memory *store* through a computed/cast index or a cast pointer — the exact
# shape a libc-sink lens misses (`In[(int)pcVar4] = ...`, `*(short *)(p + i) = ...`).
_INDEX_WRITE = re.compile(r"[A-Za-z_]\w*\s*\[[^\]]+\]\s*=(?!=)")
_PTR_WRITE = re.compile(r"\*\s*\([^)]*\*\s*\)\s*\([^)]*\)\s*=(?!=)")
_CAST_INDEX = re.compile(r"\[\s*\((?:int|uint|long|ulong|short|char)\b")
_LOOP = re.compile(r"\b(?:for|while)\b|\bdo\s*\{")
_INDIRECT_CALL = re.compile(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)\s*\(")


def _danger_score(body: str, *, reachable: bool, calls_sink: bool) -> float:
    """Deterministic 0..N ranking heuristic over the decompiled body. Higher means
    "more likely to hide a memory-safety bug", so a budget-truncated scan spends its
    calls on the promising functions first.

    Reachability is a *bonus*, never a gate: the flagship target class here (an
    OOB store in an indirectly-dispatched sampler callback) is precisely what static
    reachability drops — the dispatch edge is unresolved — so gating on it would
    exclude the very bug the LLM scan exists to catch."""
    score = 0.0
    if calls_sink:
        score += 3.0
    index_write = bool(_INDEX_WRITE.search(body))
    ptr_write = bool(_PTR_WRITE.search(body))
    cast_index = bool(_CAST_INDEX.search(body))
    loop = bool(_LOOP.search(body))
    if index_write:
        score += 2.5
    if ptr_write:
        score += 1.5
    if cast_index:
        score += 1.5
    if loop:
        score += 1.0
    # The decompiled-OOB-store signature: a store through a (often cast) index that
    # runs inside a cursor/counted loop, with NO libc sink to name it. This is the
    # exact shape the name/shape lenses miss (lcms ``In[(int)pcVar4] = ...`` in a
    # ``do{}while(cur != end)``), so when the store + loop co-occur we lift it to
    # compete with a sink-caller — a raw unbounded cursor store is at least as likely
    # to be an OOB write as a bounded ``memcpy`` call.
    if (index_write or ptr_write) and loop:
        score += 3.0
        if cast_index:
            score += 1.0
    if _INDIRECT_CALL.search(body):
        score += 1.0
    # Reachability is a mild bonus only — the flagship target class is dispatched
    # indirectly (reachable=False), so it must not be buried under reachable code.
    if reachable:
        score += 1.0
    # Size bonus, saturating — larger functions have more room for a flaw, but we
    # don't want a single huge function to dominate purely on length.
    score += min(len(body) / 800.0, 2.0)
    return score


def select_candidates(
    meta: Any, *, budget: int, skip: set[str] | None = None
) -> list[str]:
    """Deterministically pick up to ``budget`` function names from ``meta.decompiled_c``
    worth scanning: non-noise, non-trivial, not already flagged by the regex lenses
    (``skip``), ranked by the danger heuristic (sink-callers / cast-index stores /
    cursor loops / reachable first). Ties break by name for a stable order."""
    decompiled: dict[str, str] = getattr(meta, "decompiled_c", {}) or {}
    skip = skip or set()
    reach = reachable_functions(meta)  # set, or None to disable reachability weighting

    scored: list[tuple[float, str]] = []
    for fn, body in decompiled.items():
        if fn in skip or _noise.is_noise_name(fn) or len(body) < _MIN_BODY:
            continue
        # rank on the deasan'd body so ASan shadow/report noise doesn't distort the
        # danger heuristic (and clean builds are unaffected).
        cbody = deasan(body)
        is_reach = True if reach is None else (fn in reach)
        s = _danger_score(cbody, reachable=is_reach, calls_sink=_noise.calls_sink(cbody))
        scored.append((s, fn))
    # Sort by score desc, then name asc — deterministic given deterministic input.
    scored.sort(key=lambda t: (-t[0], t[1]))
    return [fn for _s, fn in scored[:budget]]


# --- the scan ---------------------------------------------------------------

def _prompt(function: str, body: str, ctx: str = "") -> str:
    return f"Function: {function}\n\n--- decompiled pseudo-C ---\n{body}\n{ctx}"


def scan_function(
    function: str,
    body: str,
    llm: Any,
    *,
    structs: list[Any] | None = None,
) -> LlmScanFinding | None:
    """Ask the model to judge one function. Best-effort: any backend failure or
    malformed verdict degrades to ``None`` (skip), never crashes the run.

    ``structs`` is the program's recovered struct layouts (from
    ``ProgramMeta.structs`` / ``structtypes.harvest_structs``). When supplied, the
    layouts whose field offsets match the raw ``+ N`` accesses in ``body`` are
    appended to the prompt so the model can map ``*(uint *)(p + 8)`` back to a named
    field and see fixed-size array bounds — the ingredient compilation strips. It is a
    strict no-op when ``structs`` is None/empty or nothing matches (toy/stripped
    binaries), so existing behavior is unchanged."""
    # Strip ASan/coverage instrumentation so the model reasons about the real logic,
    # not shadow-byte arithmetic and __asan_report_* branches (no-op on clean builds).
    body = deasan(body)
    ctx = struct_context(body, structs)
    try:
        raw = llm.complete_json(_SYSTEM, _prompt(function, body, ctx), PSEUDOC_SCAN_SCHEMA)
    except Exception:
        return None
    try:
        return LlmScanFinding(
            function=function,
            is_bug=bool(raw["is_bug"]),
            cwe=str(raw.get("cwe", "")),
            vulnerable_line=str(raw.get("vulnerable_line", "")),
            source=str(raw.get("source", "")),
            sink=str(raw.get("sink", "")),
            explanation=str(raw.get("explanation", "")),
        )
    except (KeyError, TypeError):
        return None


def llm_scan_functions(
    meta: Any, llm: Any, *, budget: int = 20, skip: set[str] | None = None
) -> list[LlmScanFinding]:
    """Scan the top-``budget`` candidate functions in ``meta.decompiled_c`` and return
    every per-function verdict (positives AND negatives — the caller filters). The
    candidate set is reachable/sink-caller/store-heavy prioritized, non-noise, and
    excludes ``skip`` (the functions the regex lenses already flagged)."""
    candidates = select_candidates(meta, budget=budget, skip=skip)
    decompiled: dict[str, str] = getattr(meta, "decompiled_c", {}) or {}
    structs: list[Any] = getattr(meta, "structs", None) or []
    out: list[LlmScanFinding] = []
    for fn in candidates:
        r = scan_function(fn, decompiled[fn], llm, structs=structs)
        if r is not None:
            out.append(r)
    return out


# --- projection to a 0verse Finding (hypothesis) ----------------------------

def to_finding(r: LlmScanFinding) -> Finding:
    """Project a positive LLM verdict to an ``analyze.Finding`` hypothesis. Addresses
    are 0 (the model reasons over text, not VAs) so the address-keyed angr/oracle
    stages skip it — it stays a hypothesis until a downstream oracle confirms it,
    which for this origin means it is reported honestly as unconfirmed."""
    return Finding(
        source=(r.source.strip()[:80] or "untrusted-input"),
        sink=(r.sink.strip()[:80] or (r.cwe.strip() or "mem-access")),
        function=r.function,
        source_addr=0,
        sink_addr=0,
        path_len=0,
        origin="llm-pseudoc",
    )


# --- pipeline gate + stage driver -------------------------------------------

def scan_enabled(llm: Any) -> bool:
    """Run the stage only on the real-LLM lane AND when opted in via
    ``ZEROVERSE_LLM_SCAN`` (truthy). ``llm is None`` is the mock/CI path (the
    pipeline substitutes MockLLM later), so the stage is a no-op there — the
    deterministic CI suite is unaffected and no codex budget is spent."""
    if llm is None:
        return False
    val = os.environ.get("ZEROVERSE_LLM_SCAN", "").strip().lower()
    return val not in ("", "0", "false", "no", "off")


def _budget() -> int:
    try:
        return max(1, int(os.environ.get("ZEROVERSE_LLM_SCAN_BUDGET", "20")))
    except ValueError:
        return 20


def llm_scan_stage(
    findings: list[Finding], meta: Any, llm: Any, *, budget: int | None = None
) -> tuple[list[Finding], str]:
    """Pipeline stage ``llm-pseudoc-scan``: complement the regex lenses by letting the
    model read the decompiled pseudo-C of the reachable target functions they did NOT
    flag, and union its positive judgments as ``origin='llm-pseudoc'`` hypotheses.

    Returns ``(findings, note)``. Gated + best-effort: disabled off the real-LLM lane
    (returns the input unchanged, empty note); any failure degrades to a no-op."""
    if not scan_enabled(llm) or not (getattr(meta, "decompiled_c", {}) or {}):
        return findings, ""
    b = budget if budget is not None else _budget()
    covered = {f.function for f in findings}
    try:
        results = llm_scan_functions(meta, llm, budget=b, skip=covered)
    except Exception as exc:  # never break a run on the optional consult
        return findings, f"llm-pseudoc-scan: skipped ({type(exc).__name__})"
    scanned = len(results)
    positives = [r for r in results if r.is_bug]
    new: list[Finding] = []
    for r in positives:
        if r.function in covered:
            continue
        covered.add(r.function)
        new.append(to_finding(r))
    if not scanned:
        return findings, ""
    if not new:
        return findings, f"llm-pseudoc-scan: {scanned} function(s) scanned, no bug hypotheses"
    funcs = ", ".join(f.function for f in new)
    note = (
        f"llm-pseudoc-scan: {len(new)} bug hypothes(e)s over {scanned} decompiled "
        f"function(s) the regex lenses missed [{funcs}]"
    )
    return [*findings, *new], note
