"""Rule-based confidence scoring over an agentic finding's *trajectory*.

Reliability wall #1: on a messy real decompiled function the bare
``AgentVerdict.is_bug=True`` signal is NEAR-ALWAYS-TRUE — the LLM can rationalize
a memory-safety story about almost any indexed access it sees. So a raw positive
tells us almost nothing about which hypotheses are worth the expensive next steps
(input synthesis / PoV adjudication). We can't afford to chase every ``is_bug``.

The observation that unlocks a fix: a bare ``is_bug=True`` is weak, but the
STRENGTH of a finding lives in HOW it was reached — signals ALREADY captured in
the :class:`~zeroverse.agentic.AgentResult`:

  * did the adversarial skeptic (``verify_finding``) try to REFUTE it and fail?
  * did a PROVING tool (``arg_provenance`` / ``buffer_size`` /
    ``find_structs_for_pointer``) actually run on the NAMED sink — i.e. was the
    offset / buffer bound established concretely, not eyeballed?
  * did the behavioral confirm-gate fire and get RESOLVED by proving, rather than
    a bare verdict drifting past it?
  * is the sink on the attacker-INPUT-reachable path, or is it a
    ``no known callers`` libc++ template instantiation nobody can reach?
  * does the explanation cite CONCRETE arithmetic (a specific index vs a specific
    buffer size) or vague "attacker-controlled" hand-waving?

:func:`score_finding` combines these into a transparent 0..1 score + a tier, and
:func:`rank_findings` orders a batch so a caller pursues the HIGH ones first and
drops ``reject``.

HONEST LIMITATION. This is a rule-based heuristic over the trajectory. It
improves *ranking* — it does NOT make a hypothesis TRUE. Only the oracle
(``adjudicate`` / a reproduced crash) confirms a bug. The integrated recall
matrix proved why this matters: a well-reasoned FALSE POSITIVE that ran every
proving tool, survived the skeptic, and cited crisp arithmetic scored 0.94-1.0
on DIVERGENT wrong-sibling sinks. So the *tier* is now oracle-grounded: trajectory
alone tops out at ``medium`` (a strong LEAD), and only a reproduction AT the sink
(``score_finding(..., oracle_confirmed=True)``) earns ``high``; an oracle
divergence caps it at ``low``. The raw ``score`` is unchanged (it still ranks the
leads); the ceiling stops the label from over-claiming. The one hard signal we
trust as a *kill* is an adversarial REFUTATION — the skeptic found a concrete
guard — which floors the score to 0. No LLM and no network here by design (the
whole point is to NOT spend another model call to rank).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .agentic import AgentResult

# Proving tools — the ones that CONCRETELY establish an offset / a true buffer
# size / a struct layout on a specific sink (mirrors ``agentic._PROVING_TOOLS``).
# Running one on the named sink is the difference between a measured bound and an
# eyeballed one.
_PROVING_TOOLS: frozenset[str] = frozenset(
    {"arg_provenance", "buffer_size", "find_structs_for_pointer", "get_struct"}
)

# The "this sink is unreachable" tell emitted by ``ToolBox.callers`` when the
# recovered call graph has no callers for a function (the `_Large_integer_to_chars`
# no-caller-libc++ case: a template instantiation nothing reaches). Substring match
# against a `callers` observation.
_NO_CALLERS_RE = re.compile(r"no known callers of", re.I)

# Entry sources (``AgentResult.entry_source``) that mean the walk started at an
# attacker-input entry point — the sink is input-reachable by construction.
_INPUT_ENTRY_SOURCES: frozenset[str] = frozenset({"input-entry", "provided"})

# Source-string language that names an attacker-input origin (the walk connected
# the sink back to untrusted bytes). Keyed on the vocabulary ``explore`` emits.
_INPUT_SOURCE_RE = re.compile(
    r"attacker|untrusted|fuzz|input|entry|param|caller-(?:controlled|owned)|"
    r"stdin|network|packet|file|user-?(?:controlled|supplied)",
    re.I,
)

# Concrete arithmetic in an explanation: a hex literal, a subscript `[..7..]`, an
# "N-byte / N-element" bound, or a bare number sitting next to size/offset/index
# vocabulary. This is what separates "nSamples[15] read at index nInputs=32" from
# "an attacker-controlled value could overflow the buffer".
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_SUBSCRIPT_NUM_RE = re.compile(r"\[[^\]]*\d[^\]]*\]")
_SIZED_UNIT_RE = re.compile(
    r"\b\d+\s*[-]?\s*(?:byte|bytes|element|elements|word|words|entr(?:y|ies))\b",
    re.I,
)
_NUM_NEAR_KEYWORD_RE = re.compile(
    r"(?:offset|index|size|length|len|bound|count|array|buffer|field|"
    r"capacity|element|stride)\D{0,24}\d"
    r"|\d\D{0,24}(?:offset|index|size|length|len|bound|count|array|buffer|"
    r"field|capacity|element|stride)",
    re.I,
)
# Strip CWE tokens so "CWE-125" alone never reads as concrete arithmetic.
_CWE_TOKEN_RE = re.compile(r"cwe[-\s]?\d+", re.I)


# --- factor weights ---------------------------------------------------------
#
# Weighted-sum model: score = sum(WEIGHTS[f] * factors[f]) with each factor value
# in [0, 1]. Weights sum to 1.0 so a perfect trajectory scores exactly 1.0 and the
# tiers below have a stable meaning. Rationale per factor is in ``score_finding``.
WEIGHTS: dict[str, float] = {
    # The skeptic actively tried to REFUTE and couldn't — the single strongest
    # trajectory signal that the positive isn't a trivially-guarded FP.
    "adversarial_upheld": 0.30,
    # A proving tool established the bound on the NAMED sink — measured, not eyeballed.
    "proving_on_sink": 0.25,
    # The sink is on the attacker-input-reachable path (vs a no-caller dead sink).
    "input_reachable": 0.20,
    # The confirm-gate dynamics resolved into proof rather than a bare verdict.
    "confirm_resolved": 0.15,
    # The explanation cites concrete arithmetic, not hand-waving.
    "concrete_arithmetic": 0.10,
}

# Tier cutoffs on the 0..1 score. ``reject`` is also forced (score 0) on an
# adversarial refutation or a non-positive verdict, independent of the cutoff.
_TIER_HIGH = 0.70
_TIER_MEDIUM = 0.45
_TIER_LOW = 0.20


@dataclass
class FindingConfidence:
    """A transparent, auditable confidence for one :class:`AgentResult`.

    ``score`` is 0..1 (higher = more likely a REAL bug worth pursuing). ``tier`` is
    ``high`` / ``medium`` / ``low`` / ``reject``. ``factors`` maps each factor name
    to its raw value in [0, 1]; multiply by :data:`WEIGHTS` to see its contribution
    (:meth:`breakdown` renders that). ``reason`` is a one-line human summary
    (carries the hard-reject cause when the score was floored)."""

    score: float
    tier: str
    factors: dict[str, float] = field(default_factory=dict)
    reason: str = ""

    def contributions(self) -> dict[str, float]:
        """Per-factor weighted contribution to the score (value * weight)."""
        return {k: round(v * WEIGHTS.get(k, 0.0), 4) for k, v in self.factors.items()}

    def breakdown(self) -> str:
        """Render the score decomposition for a report."""
        lines = [f"confidence {self.score:.2f} [{self.tier}] — {self.reason}"]
        for name in WEIGHTS:
            val = self.factors.get(name, 0.0)
            lines.append(f"  {name}: {val:.2f} x {WEIGHTS[name]:.2f} = {val * WEIGHTS[name]:.3f}")
        return "\n".join(lines)


def _proving_steps(result: AgentResult) -> list[Any]:
    """Trajectory steps that invoked a proving tool."""
    return [s for s in result.steps if getattr(s, "tool", "") in _PROVING_TOOLS]


def _sink_tokens(sink: str) -> set[str]:
    """Identifier-ish tokens in a sink string, e.g. ``"nSamples[nInputs]"`` ->
    ``{"nsamples", "ninputs"}``. Used to check a proving-tool call named THIS sink
    (its variable/callee) in its args, not merely ran somewhere in the walk."""
    return {t.lower() for t in re.findall(r"[A-Za-z_]\w+", sink or "") if len(t) >= 3}


def _factor_adversarial(result: AgentResult) -> float:
    """0.30-weight. The adversarial skeptic (``verify_finding``) re-investigated the
    sink + its callers trying to REFUTE the bug.

      * upheld (skeptic tried, found no covering guard) -> 1.0 (strongest signal)
      * review is None (no skeptic ran / disabled)      -> 0.30 (unverified, weak)
      * refuted -> handled as a HARD reject upstream (never reaches here at >0)

    Rationale: a positive that SURVIVES an adversary actively hunting for a bounds
    check / clamp / early-return is qualitatively stronger than an unchallenged one.
    A missing skeptic is not evidence of strength, hence a low floor, not 0."""
    review = result.review
    if review is None:
        return 0.30
    return 1.0 if review.upheld else 0.0


def _factor_proving_on_sink(result: AgentResult) -> float:
    """0.25-weight. A proving tool (``arg_provenance`` / ``buffer_size`` /
    ``find_structs_for_pointer`` / ``get_struct``) actually RAN, graded by how
    tightly it targeted the named sink:

      * an arg value names a sink token (the sink's var/callee)  -> 1.0
      * else it ran in the finding's function (start/visited)    -> 0.60
      * else a proving tool ran but on neither                   -> 0.40
      * no proving tool ran at all                               -> 0.0

    Rationale: the offset/buffer bound the verdict asserts was CONCRETELY
    established (measured), not eyeballed from the pseudo-C. Graded because
    decompiler temporaries mean the sink text and the proved variable don't always
    share a name — running the prover in the sink's own function is a real, if
    weaker, link."""
    steps = _proving_steps(result)
    if not steps:
        return 0.0
    sink = result.verdict.sink if result.verdict else ""
    tokens = _sink_tokens(sink)
    fn_context = {result.start_function.lower(), *(v.lower() for v in result.visited)}
    best = 0.40
    for s in steps:
        args = getattr(s, "args", {}) or {}
        arg_vals = " ".join(str(v) for v in args.values()).lower()
        if tokens and any(tok in arg_vals for tok in tokens):
            return 1.0
        fn_arg = str(args.get("function", "")).lower()
        if fn_arg and fn_arg in fn_context:
            best = max(best, 0.60)
    return best


def _factor_input_reachable(result: AgentResult) -> float:
    """0.20-weight. Is the sink on the attacker-INPUT-reachable path?

      * a `callers` observation said "no known callers" and nothing else
        established reachability -> 0.0 (STRONG negative: the dead-sink FP, e.g.
        `_Large_integer_to_chars` — a libc++ template nothing reaches)
      * entry_source is an input entry, OR the verdict source names an
        attacker-input origin -> 1.0
      * otherwise (reachability simply unestablished) -> 0.50 (neutral)

    Rationale: a bug the fuzzer/attacker can never drive is not a bug worth
    synthesizing an input for, however clean the arithmetic. A no-caller sink is
    the canonical unreachable-FP shape and is penalized hard."""
    no_callers = any(
        getattr(s, "tool", "") == "callers"
        and _NO_CALLERS_RE.search(getattr(s, "observation", "") or "")
        for s in result.steps
    )
    source = result.verdict.source if result.verdict else ""
    # STRUCTURAL reachability (the walk started at a classified attacker entry) is a
    # hard fact; SOURCE-language reachability is a softer prose signal. The call graph
    # saying "no known callers" outranks prose but not the structural fact.
    structural_reachable = result.entry_source in _INPUT_ENTRY_SOURCES
    source_reachable = bool(_INPUT_SOURCE_RE.search(source))
    if no_callers and not structural_reachable:
        return 0.0
    if structural_reachable or source_reachable:
        return 1.0
    return 0.50


def _factor_confirm_resolved(result: AgentResult) -> float:
    """0.15-weight. The behavioral confirm-gate dynamics (``agentic._drive_loop``).
    The gate fires a ``confirm-gate`` step when a suspicion was flagged-but-unproven
    (or a spatial TRUE ran zero proving tools); it should be RESOLVED by a following
    proving call rather than a bare verdict drifting past it.

      * gate fired AND a proving tool ran after it          -> 1.0
      * no gate fired but a proving tool ran anyway (proactive proof) -> 0.60
      * gate fired but was NOT followed by proving          -> 0.20
      * no gate, no proving                                 -> 0.0

    Rationale: rewards a hypothesis that engaged the proving machinery — either
    because the gate forced it and it complied, or proactively. A gate that fired
    and was ignored is the weakest of the 'proving happened' states."""
    gate_idx = [i for i, s in enumerate(result.steps) if getattr(s, "action", "") == "confirm-gate"]
    proving_idx = [
        i for i, s in enumerate(result.steps) if getattr(s, "tool", "") in _PROVING_TOOLS
    ]
    if gate_idx:
        first_gate = gate_idx[0]
        if any(pi > first_gate for pi in proving_idx):
            return 1.0
        return 0.20
    if proving_idx:
        return 0.60
    return 0.0


def _factor_concrete_arithmetic(result: AgentResult) -> float:
    """0.10-weight. Does the explanation cite CONCRETE arithmetic (a specific
    index/offset vs a specific buffer size) rather than vague hand-waving?

      * a hex literal, a numeric subscript `[..15..]`, an "N-byte/element" bound,
        or a number adjacent to size/offset/index vocabulary -> 1.0
      * only "attacker-controlled / could overflow" prose     -> 0.0

    (CWE tokens like "CWE-125" are stripped first so a bare CWE never counts.)

    Rationale: crisp arithmetic means the LLM actually did the bound comparison;
    prose means it asserted a story. Lowest weight because a fabricated number is
    cheap — this is a tie-breaker, not a pillar."""
    expl = result.verdict.explanation if result.verdict else ""
    if not expl:
        return 0.0
    stripped = _CWE_TOKEN_RE.sub(" ", expl)
    if (
        _HEX_RE.search(stripped)
        or _SUBSCRIPT_NUM_RE.search(stripped)
        or _SIZED_UNIT_RE.search(stripped)
        or _NUM_NEAR_KEYWORD_RE.search(stripped)
    ):
        return 1.0
    return 0.0


# Tier order for ceiling arithmetic (higher index = stronger).
_TIER_ORDER: tuple[str, ...] = ("reject", "low", "medium", "high")


def _tier_for(score: float, *, ceiling: str = "high") -> str:
    """Base tier from the score cutoffs, then CLAMPED to ``ceiling``.

    The ceiling is how oracle grounding enters: a finding that has not been
    reproduced at its sink can never be labeled ``high`` no matter how clean its
    trajectory reads — the ceiling caps it at ``medium`` (a strong lead, not a
    confirmed bug). See :func:`score_finding`."""
    if score >= _TIER_HIGH:
        base = "high"
    elif score >= _TIER_MEDIUM:
        base = "medium"
    elif score >= _TIER_LOW:
        base = "low"
    else:
        base = "reject"
    if _TIER_ORDER.index(base) > _TIER_ORDER.index(ceiling):
        return ceiling
    return base


def score_finding(
    result: AgentResult, *, oracle_confirmed: bool | None = None
) -> FindingConfidence:
    """Rank one agentic finding by how likely it is a REAL bug, from signals ALREADY
    in ``result`` (no extra LLM call). See the module docstring and each
    ``_factor_*`` for the factor rationales; :data:`WEIGHTS` for the weights.

    ORACLE GROUNDING (``oracle_confirmed``) — the honest tier ceiling. The integrated
    recall matrix showed trajectory-only scores of 0.94/1.0 landing on DIVERGENT
    wrong-sibling sinks: the factors measure how well-argued a finding is, NOT whether
    it is the bug an input actually triggers. So the *tier* is now clamped by what the
    ORACLE has said about this finding:

      * ``None``  (no reproduction attempted yet)   -> ceiling ``medium``. A strong
        trajectory is a strong LEAD, never a confirmed bug. This is the default, so a
        pre-synthesis ``rank_findings`` can order leads without ever mislabeling one
        ``high``.
      * ``True``  (a synthesized/real input reproduced the crash AT this sink)
        -> ceiling ``high``. Now the score may read ``high`` — it has been earned.
      * ``False`` (the oracle RAN and diverged / did not reproduce at the sink)
        -> ceiling ``low``. The story was disproven where it counts; keep it visible
        (it may hint at a real nearby bug) but strip its authority. The raw ``score``
        is preserved for audit; only the tier is capped.

    HARD REJECTS (score forced to 0.0, tier ``reject``), independent of the factors
    and the ceiling:

      * ``result.review.upheld is False`` — the adversarial skeptic REFUTED the
        finding (found a concrete guard). We trust a refutation as a kill.
      * no positive verdict (``verdict is None`` or ``is_bug`` is False) — nothing to
        pursue.

    Otherwise: ``score = sum(WEIGHTS[f] * factor_f)`` and ``tier`` from the cutoffs,
    clamped to the oracle ceiling above."""
    # Hard reject: adversarial refutation is a trusted kill.
    if result.review is not None and not result.review.upheld:
        factors = dict.fromkeys(WEIGHTS, 0.0)
        guard = (result.review.checked_guard or "").strip()
        reason = "adversarial skeptic REFUTED the finding" + (f" (guard: {guard})" if guard else "")
        return FindingConfidence(0.0, "reject", factors, reason)

    # Hard reject: nothing positive to pursue.
    if result.verdict is None or not result.verdict.is_bug:
        factors = dict.fromkeys(WEIGHTS, 0.0)
        return FindingConfidence(0.0, "reject", factors, "no positive verdict")

    factors = {
        "adversarial_upheld": _factor_adversarial(result),
        "proving_on_sink": _factor_proving_on_sink(result),
        "input_reachable": _factor_input_reachable(result),
        "confirm_resolved": _factor_confirm_resolved(result),
        "concrete_arithmetic": _factor_concrete_arithmetic(result),
    }
    score = round(sum(WEIGHTS[k] * v for k, v in factors.items()), 4)

    # Oracle-grounded tier ceiling: trajectory alone tops out at ``medium``.
    if oracle_confirmed is True:
        ceiling, ground = "high", "oracle CONFIRMED at sink"
    elif oracle_confirmed is False:
        ceiling, ground = "low", "oracle did NOT reproduce at sink (unconfirmed)"
    else:
        ceiling, ground = "medium", "unconfirmed lead (no reproduction yet)"
    tier = _tier_for(score, ceiling=ceiling)

    traj = "adversarial upheld" if result.review is not None else "no adversarial pass (unverified)"
    return FindingConfidence(score, tier, factors, f"{traj}; {ground}")


def rank_findings(
    results: list[AgentResult],
    oracle: dict[int, bool] | None = None,
) -> list[tuple[AgentResult, FindingConfidence]]:
    """Score every result and return ``(result, confidence)`` pairs sorted by score
    DESCENDING (stable — original order breaks ties).

    ``oracle`` optionally maps a result's index (position in ``results``) to its
    reproduction outcome (``True`` reproduced at sink / ``False`` diverged), threaded
    into :func:`score_finding` as ``oracle_confirmed`` so the TIER reflects the oracle.
    Omit it for the pre-reproduction pass — every finding then tops out at ``medium``
    (a lead), which is exactly what you want when deciding what to synthesize NEXT.
    After adjudication, re-rank with the outcomes so a confirmed finding reads ``high``
    and a divergent one drops to ``low``.

    Contract: this only RANKS; it does not drop anything. A caller pursues the top
    leads first (expensive synthesis/adjudication), then down the list as budget
    allows, and should DROP ``tier == "reject"`` (score 0 — a refutation or a
    non-finding). The ordering is a lead-quality prior over the trajectory; only the
    oracle (via ``oracle``) confirms a finding is real."""
    omap = oracle or {}
    scored = [(r, score_finding(r, oracle_confirmed=omap.get(i))) for i, r in enumerate(results)]
    # Stable sort: Python's sort is stable, so equal scores keep input order.
    scored.sort(key=lambda pair: pair[1].score, reverse=True)
    return scored
