"""Stage 5 — LLM triage of a static finding (provider-agnostic).

The LLM is a *worker*, not the adjudicator (DESIGN-NOTES Decision 1): it takes a
source→sink finding plus decompiled context and returns a *hypothesis* verdict —
is this plausibly a real, reachable bug, what class, how severe, and a candidate
triggering input. Whether the bug is **actually** exploitable is decided later by
the deterministic PoV oracle (oracle.py), never here. The agent only *proposes*;
nothing it says is true until #5 (angr) or #6 (the crash oracle) discharges it.

Two-stage funnel (guidance §#4, RoboDuck's cheap→expensive pattern): a cheap,
deterministic classifier scores the whole #2+#3 hypothesis queue; only the
top-ranked slices escalate to the (expensive) LLM agent. This keeps frontier
tokens on the hard root-cause step and is free/deterministic in CI via mock mode.

This module is deliberately provider-neutral: it depends only on the ``LLM``
Protocol. A Claude implementation ships in ``zeroverse.llm.anthropic_llm``; any
OpenAI-compatible or local backend can implement the same interface. ``MockLLM``
lets the pipeline run and be tested with no API key.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .analyze import Finding
from .grounding import grounding_enabled

# JSON Schema the model must return (adapted from mole's VulnerabilityReport).
VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "is_real": {"type": "boolean"},
        "bug_class": {"type": "string"},
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "explanation": {"type": "string"},
        "input_example": {"type": "string"},
    },
    "required": ["is_real", "bug_class", "severity", "explanation", "input_example"],
    "additionalProperties": False,
}


@dataclass
class Verdict:
    is_real: bool             # hypothesis only — confirmed later by the PoV oracle
    bug_class: str
    severity: str
    explanation: str
    input_example: str

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Verdict:
        return cls(
            is_real=bool(d["is_real"]),
            bug_class=str(d["bug_class"]),
            severity=str(d["severity"]),
            explanation=str(d["explanation"]),
            input_example=str(d.get("input_example", "")),
        )


class LLM(Protocol):
    """Minimal provider-neutral interface: return JSON validated against `schema`."""

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]: ...


_SYSTEM = (
    "You are a binary vulnerability-research assistant. You are given a static "
    "source->sink data-flow path recovered from a decompiled binary, plus the "
    "decompiled code. Decide whether the path is a plausible, reachable "
    "memory-safety or injection vulnerability. You do NOT need to prove "
    "exploitability — a separate dynamic stage produces a reproducing crash. "
    "Identify user-controlled inputs, check for sanitizers or infeasible control "
    "flow that would make it a false positive, classify the bug (CWE-style), rate "
    "severity, and propose a concrete example input that would exercise the path. "
    "You may only PROPOSE a hypothesis; never claim the bug overflows or is "
    "reachable — the angr and crash-oracle stages decide that. Return only the "
    "structured verdict."
)


# G1 grounding (opt-in): make the LLM DECLARE its structural premises as typed
# @claim lines so the interceptor can adjudicate them against the real call graph.
# This is not adjudication by the LLM — it still only proposes; the gate decides
# each premise GROUNDED/REFUTED/UNKNOWN. See grounding.py / docs/GROUNDING.md.
_CLAIM_EMISSION = (
    "\n\nSTRUCTURAL CLAIMS: your severity must rest only on premises you state "
    "explicitly. For EVERY structural premise your rating depends on, emit a typed "
    "@claim line inside your explanation (one per line). A grounding gate checks "
    "each against the real disassembly call graph before your severity is accepted; "
    "a refuted premise floors the finding. Use the REAL function/symbol names from "
    "the decompiled code (never a bug-class label). Emit only what you rely on:\n"
    "  @claim call_edge caller=<F> callee=<G>            (F calls G DIRECTLY)\n"
    "  @claim free_site func=<F>                         (F frees the object)\n"
    "  @claim offset_field func=<F> claimed_offset=0xNN  (a struct field is at this offset)\n"
    "Do not assert program structure in prose without a matching @claim."
)


def _variant_framing(seed_bug_class: str) -> str:
    """Big-Sleep variant-analysis framing: seed a known bug class and hunt its
    siblings — far higher signal than open-ended search (guidance §#4)."""
    return (
        f"\n\nVARIANT ANALYSIS: a confirmed {seed_bug_class} was already found in "
        "this target. Treat this path as a suspected *sibling* of that bug — look "
        "for the same root-cause pattern (same unchecked length/index/lifetime) "
        "reached through a different source or call site."
    )


class TriageAgent:
    def __init__(self, llm: LLM, *, seed_bug_class: str | None = None) -> None:
        self.llm = llm
        self.seed_bug_class = seed_bug_class

    def triage(self, finding: Finding, decompiled: str) -> Verdict:
        system = _SYSTEM
        if self.seed_bug_class:
            system += _variant_framing(self.seed_bug_class)
        if grounding_enabled():
            system += _CLAIM_EMISSION
        prompt = self._prompt(finding, decompiled)
        try:
            raw = self.llm.complete_json(system, prompt, VERDICT_SCHEMA)
            return Verdict.from_json(raw)
        except Exception as exc:  # degrade on ANY backend failure
            # A real model can rate-limit, time out, or emit unrecoverable output.
            # Degrade to a structural hypothesis instead of crashing the run; the
            # PoV oracle still gates confirmation, so nothing is over-claimed.
            return _degraded_verdict(finding, exc)

    @staticmethod
    def _prompt(f: Finding, decompiled: str) -> str:
        return (
            f"Function: {f.function}\n"
            f"Source: {f.source} @ {hex(f.source_addr)}\n"
            f"Sink:   {f.sink} @ {hex(f.sink_addr)}\n"
            f"Origin: {f.origin}\n"
            f"Backward-slice path length: {f.path_len} instructions\n\n"
            f"--- Decompiled code ---\n{decompiled}\n"
        )


# --- cheap classifier (the funnel's first stage) ---------------------------

# Deterministic danger weights, so ranking is free and CI-stable. The cheap stage
# never adjudicates — it only ORDERS the queue so the expensive LLM sees the most
# promising slices first.
_SINK_WEIGHT = {
    "system": 1.0, "popen": 1.0, "execl": 0.95, "execlp": 0.95, "execve": 0.95,
    "execv": 0.95, "execvp": 0.95, "gets": 0.95, "strcpy": 0.9, "stpcpy": 0.9,
    "sprintf": 0.9, "strcat": 0.85, "memcpy": 0.8, "scanf": 0.6,
}
_SOURCE_WEIGHT = {  # attacker-proximity of the source
    "recv": 1.0, "recvfrom": 1.0, "read": 0.85, "fgets": 0.8, "gets": 0.8,
    "getenv": 0.8, "argv": 0.75, "scanf": 0.7, "fread": 0.7,
}


def cheap_score(f: Finding) -> float:
    """A free, deterministic 0..1 danger score used to rank the hypothesis queue."""
    sink = _SINK_WEIGHT.get(f.sink, 0.3)
    source = _SOURCE_WEIGHT.get(f.source, 0.4)
    score = 0.6 * sink + 0.4 * source
    if f.path_len == 0:        # direct memory/value flow — tighter, higher signal
        score += 0.05
    return max(0.0, min(1.0, score))


@dataclass
class RankedHypothesis:
    finding: Finding
    score: float
    escalated: bool        # did this slice reach the expensive LLM agent?
    verdict: Verdict


def _cheap_verdict(f: Finding, score: float) -> Verdict:
    """Verdict for a slice that ranked below the escalation cutoff: a low-cost,
    structural guess — still only a *proposal*, flagged as not LLM-escalated."""
    real = score >= 0.5
    severity = "high" if score >= 0.85 else "medium" if score >= 0.6 else "low"
    return Verdict(
        is_real=real,
        bug_class=f"suspected ({f.sink})",
        severity=severity if real else "info",
        explanation=f"cheap-ranked (score={score:.2f}), not LLM-escalated",
        input_example="",
    )


def _degraded_verdict(f: Finding, exc: Exception) -> Verdict:
    """Honest fallback when the LLM backend fails mid-triage: a structural guess
    from the cheap danger score, explicitly flagged as un-adjudicated. Never a
    fabricated confirmation — the oracle decides truth downstream."""
    score = cheap_score(f)
    real = score >= 0.5
    severity = "high" if score >= 0.85 else "medium" if score >= 0.6 else "low"
    return Verdict(
        is_real=real,
        bug_class=f"suspected ({f.sink})",
        severity=severity if real else "info",
        explanation=(
            f"LLM triage unavailable ({type(exc).__name__}: {str(exc)[:120]}); "
            f"degraded to cheap structural score={score:.2f} — hypothesis only"
        ),
        input_example="",
    )


class TriageFunnel:
    """Cheap→expensive triage over the whole hypothesis queue (#2 slices + #3
    foxguard hits). Ranks every candidate with ``cheap_score``; only the top
    ``escalate_top`` above ``escalate_threshold`` reach the LLM agent. The rest
    get a cheap structural verdict. Deterministic given a deterministic LLM."""

    def __init__(
        self,
        llm: LLM,
        *,
        escalate_top: int = 8,
        escalate_threshold: float = 0.45,
        seed_bug_class: str | None = None,
        rank_bonus: Callable[[Finding], float] | None = None,
    ) -> None:
        self.agent = TriageAgent(llm, seed_bug_class=seed_bug_class)
        self.escalate_top = escalate_top
        self.escalate_threshold = escalate_threshold
        # M7 #43 flywheel: an optional, opt-in ordering bonus that lifts findings
        # matching a known-fruitful past pattern. It influences ONLY queue order +
        # escalation gating — never the verdict (memory primes, the oracle confirms).
        self.rank_bonus = rank_bonus

    def _eff(self, f: Finding) -> float:
        return cheap_score(f) + (self.rank_bonus(f) if self.rank_bonus is not None else 0.0)

    def run(
        self, findings: list[Finding], context_for: Any
    ) -> list[RankedHypothesis]:
        # Rank the queue cheaply (stable sort: effective score desc, then names). The
        # effective score adds the flywheel bonus when primed; with no bonus it is
        # identical to the bare cheap score, so cold runs are unchanged.
        ranked = sorted(
            findings, key=lambda f: (-self._eff(f), f.sink, f.source, f.sink_addr)
        )
        out: list[RankedHypothesis] = []
        for rank, f in enumerate(ranked):
            score = cheap_score(f)            # the verdict still keys on the bare score
            escalate = rank < self.escalate_top and self._eff(f) >= self.escalate_threshold
            verdict = (
                self.agent.triage(f, context_for(f)) if escalate
                else _cheap_verdict(f, score)
            )
            out.append(RankedHypothesis(f, score, escalate, verdict))
        return out


_COPY_SINKS = ("strcpy", "strcat", "memcpy", "stpcpy", "gets", "sprintf")


def _fix_line(line: str, sink: str) -> str | None:
    """Rewrite a single vulnerable call line into a bounded / safe-API form.
    Returns the replacement line, or None when the pattern is not recognized."""
    indent = line[: len(line) - len(line.lstrip())]
    if sink in ("strcpy", "stpcpy"):
        m = re.search(rf"{sink}\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)", line)
        if m:
            d, s = m.group(1), m.group(2)
            return (f"{indent}strncpy({d}, {s}, sizeof({d}) - 1); "
                    f"{d}[sizeof({d}) - 1] = '\\0';")
    if sink == "strcat":
        m = re.search(r"strcat\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)", line)
        if m:
            d, s = m.group(1), m.group(2)
            return (f"{indent}strncat({d}, {s}, sizeof({d}) - strlen({d}) - 1);")
    if sink == "gets":
        m = re.search(r"gets\s*\(\s*([A-Za-z_]\w*)\s*\)", line)
        if m:
            d = m.group(1)
            return f"{indent}fgets({d}, sizeof({d}), stdin);"
    if sink == "sprintf":
        m = re.search(r"sprintf\s*\(\s*([A-Za-z_]\w*)\s*,(.+)\)\s*;", line)
        if m:
            d, rest = m.group(1), m.group(2)
            return f"{indent}snprintf({d}, sizeof({d}),{rest});"
    if sink in ("system", "popen"):
        m = re.search(rf"{sink}\s*\(\s*([A-Za-z_]\w*)", line)
        if m:
            v = m.group(1)
            return (f"{indent}/* 0verse fix: do not pass untrusted input to a shell */ "
                    f"(void){v};")
    return None


def mock_patch_diff(prompt: str) -> str:
    """Deterministic patch generator for ``MockLLM`` — finds the vulnerable call in
    the source carried by the prompt and emits a unified diff that fixes the root
    cause (bound the copy / safe API). Returns "" when nothing matches (the patch
    loop then reflects). The fix is real; verification stays the oracle's job."""
    import difflib

    sink_m = re.search(r"^SINK:\s*(\w+)", prompt, re.M)
    file_m = re.search(r"^SOURCE FILE:\s*(\S+)", prompt, re.M)
    src_m = re.search(r"--- BEGIN SOURCE ---\n(.*)\n--- END SOURCE ---", prompt, re.S)
    if not (sink_m and file_m and src_m):
        return ""
    sink, rel, src = sink_m.group(1), file_m.group(1), src_m.group(1)
    lines = src.split("\n")
    for i, ln in enumerate(lines):
        if re.search(rf"\b{re.escape(sink)}\s*\(", ln):
            fixed = _fix_line(ln, sink)
            if fixed is None:
                continue
            new = [*lines[:i], fixed, *lines[i + 1:]]
            diff = difflib.unified_diff(
                [x + "\n" for x in lines], [x + "\n" for x in new],
                fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="\n",
            )
            return "".join(diff)
    return ""


class MockLLM:
    """No-API stand-in. Returns a deterministic verdict from the finding's shape so
    the pipeline and tests run without network: command-injection (env -> system),
    buffer-overflow (input -> unbounded copy), and tainted format-string are flagged
    real; others filtered. A real LLM backend (``llm.anthropic_llm``) replaces this."""

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        # M7 patch stage (#45): when a patch schema is requested, synthesize a
        # deterministic *real* unified diff that bounds the vulnerable copy. The
        # diff is genuine — the oracle's verify_patch re-runs the PoV to decide
        # whether it actually closes the bug (nothing is faked here).
        if "diff" in schema.get("properties", {}):
            return {"diff": mock_patch_diff(prompt),
                    "rationale": "mock root-cause fix (bound the copy / safe API)"}
        m = re.search(r"Sink:\s+(\w+)", prompt)
        sink = m.group(1) if m else ""
        if sink in ("system", "popen") and "getenv" in prompt:
            return self._v(True, "CWE-78 OS command injection", "high", 'CMD="; id"')
        if sink in _COPY_SINKS:
            return self._v(True, "CWE-120 buffer overflow", "high", "A" * 64)
        # tainted format string: the fmtstring lens already proved the format
        # operand is a variable (not a literal). Its confirming oracle self-
        # generates the differential %s/%n probe — no candidate input needed — so
        # flag it real like the other oracle-confirmable classes above.
        if "Origin: bugclass:fmtstring" in prompt:
            return self._v(True, "CWE-134 format string", "high", "")
        return self._v(False, "unknown", "info", "")

    @staticmethod
    def _v(is_real: bool, bug_class: str, severity: str, example: str) -> dict[str, Any]:
        return {
            "is_real": is_real, "bug_class": bug_class, "severity": severity,
            "explanation": "mock verdict (no LLM configured)", "input_example": example,
        }

    def complete_text(self, system: str, prompt: str) -> str:
        return json.dumps(self.complete_json(system, prompt, VERDICT_SCHEMA))
