"""Confidence scoring over agentic findings — pure, mock-only unit tests.

The subject (``zeroverse.confidence``) reads signals ALREADY present in an
``AgentResult`` (verdict / adversarial review / trajectory steps / visited) and
produces a 0..1 confidence + a tier. No LLM, no Ghidra, no network — every
``AgentResult`` here is hand-built to exercise one factor combination.

The point of the module is RANKING on a messy corpus where ``is_bug=True`` is
near-always-true; so the tests pin the extremes (refuted -> reject, fully-proven
-> medium lead / high only once the oracle reproduces, unproven+unreachable -> low)
and the ORDER they come out in.
"""

from __future__ import annotations

from zeroverse.agentic import AgentResult, AgentVerdict, TrajStep, VerdictReview
from zeroverse.confidence import (
    WEIGHTS,
    FindingConfidence,
    rank_findings,
    score_finding,
)

# --- builders ---------------------------------------------------------------


def _verdict(
    *,
    is_bug: bool = True,
    cwe: str = "CWE-125",
    sink: str = "nSamples[nInputs]",
    source: str = "attacker-controlled nInputs from fuzz entry",
    explanation: str = "reads nSamples[15] fixed array at index nInputs up to 32 — OOB",
) -> AgentVerdict:
    return AgentVerdict(is_bug=is_bug, cwe=cwe, sink=sink, source=source, explanation=explanation)


def _proving_step(step: int, tool: str = "arg_provenance", **args: object) -> TrajStep:
    return TrajStep(step, "prove the offset", "call", tool, dict(args), "traced")


def _gate_step(step: int) -> TrajStep:
    return TrajStep(step, "flagged unproven", "confirm-gate", observation="[prove it]")


def _callers_step(step: int, obs: str) -> TrajStep:
    return TrajStep(step, "who calls this", "call", "callers", {"name": "sink"}, obs)


def _result(
    *,
    verdict: AgentVerdict | None,
    review: VerdictReview | None = None,
    steps: list[TrajStep] | None = None,
    start_function: str = "WriteCLUT",
    entry_source: str = "input-entry",
    visited: list[str] | None = None,
) -> AgentResult:
    return AgentResult(
        start_function=start_function,
        steps=steps or [],
        verdict=verdict,
        stop_reason="verdict",
        entry_source=entry_source,
        visited=visited if visited is not None else ["WriteCLUT"],
        review=review,
    )


# --- weights sanity ---------------------------------------------------------


def test_weights_sum_to_one() -> None:
    # A perfect trajectory must be able to reach exactly 1.0.
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


# --- hard rejects -----------------------------------------------------------


def test_adversarial_refuted_scores_zero_and_rejects() -> None:
    # The skeptic found a concrete guard: trusted kill regardless of everything else.
    res = _result(
        verdict=_verdict(is_bug=False),  # already downgraded upstream
        review=VerdictReview(upheld=False, reason="clamped", checked_guard="if (i < 15)"),
        steps=[_proving_step(0, "buffer_size", function="WriteCLUT", pointer_var="nSamples")],
    )
    conf = score_finding(res)
    assert conf.score == 0.0
    assert conf.tier == "reject"
    assert "REFUTED" in conf.reason
    # Even present proving/reachability do NOT rescue a refutation.
    assert all(v == 0.0 for v in conf.factors.values())


def test_no_positive_verdict_rejects() -> None:
    assert score_finding(_result(verdict=None)).tier == "reject"
    assert score_finding(_result(verdict=_verdict(is_bug=False))).tier == "reject"
    assert score_finding(_result(verdict=None)).score == 0.0


# --- the strong finding: upheld + proving-on-sink + reachable + concrete ----


def _perfect_trajectory() -> AgentResult:
    """A finding whose every trajectory factor fires at full strength (score 1.0)."""
    return _result(
        verdict=_verdict(),  # concrete arithmetic + attacker source by default
        review=VerdictReview(upheld=True, reason="no guard covers the read"),
        steps=[
            _gate_step(0),
            # arg_provenance whose sink_call names the sink token 'nSamples' -> targeted.
            _proving_step(
                1,
                "arg_provenance",
                function="WriteCLUT",
                sink_call="nSamples",
                arg_index=0,
            ),
        ],
        entry_source="input-entry",
    )


def test_perfect_trajectory_caps_at_medium_without_oracle() -> None:
    """The honest ceiling: a flawless trajectory is a strong LEAD, not a confirmed
    bug. Score is a perfect 1.0 but the TIER tops out at ``medium`` until the oracle
    reproduces it (this is what stopped the 0.94/1.0 DIVERGENT mislabels)."""
    conf = score_finding(_perfect_trajectory())
    assert conf.score == 1.0  # raw score unchanged — every factor at full strength
    assert conf.tier == "medium"  # ...but capped: no reproduction yet
    assert "no reproduction yet" in conf.reason
    # Every factor still fired at full strength.
    assert conf.factors["adversarial_upheld"] == 1.0
    assert conf.factors["proving_on_sink"] == 1.0
    assert conf.factors["input_reachable"] == 1.0
    assert conf.factors["confirm_resolved"] == 1.0  # gate fired then proving ran
    assert conf.factors["concrete_arithmetic"] == 1.0


def test_oracle_confirmed_lifts_to_high() -> None:
    """A reproduction AT the sink earns ``high`` — the tier the trajectory alone can
    no longer claim."""
    conf = score_finding(_perfect_trajectory(), oracle_confirmed=True)
    assert conf.tier == "high"
    assert conf.score == 1.0
    assert "CONFIRMED at sink" in conf.reason


def test_oracle_divergent_caps_at_low() -> None:
    """The exact integrated-recall failure: a 1.0-trajectory finding whose oracle did
    NOT reproduce at the sink is capped at ``low`` — visible, but stripped of
    authority. The raw score is preserved for audit."""
    conf = score_finding(_perfect_trajectory(), oracle_confirmed=False)
    assert conf.score == 1.0  # audit trail intact
    assert conf.tier == "low"  # ...but the story was disproven where it counts
    assert "did NOT reproduce" in conf.reason


# --- the weak finding: upheld but no proving + vague + no-caller sink --------


def test_upheld_but_unproven_vague_unreachable_is_low() -> None:
    res = _result(
        verdict=_verdict(
            source="internal helper — no attacker path established",
            explanation="an attacker-controlled value could overflow the buffer",
        ),
        review=VerdictReview(upheld=True, reason="skeptic found no guard"),
        steps=[
            _callers_step(0, "no known callers of 'sink' in the recovered call graph"),
        ],
        entry_source="fallback-ranked",
    )
    conf = score_finding(res)
    assert conf.tier == "low"
    # Only the upheld skeptic contributes (0.30); nothing else.
    assert conf.factors["adversarial_upheld"] == 1.0
    assert conf.factors["proving_on_sink"] == 0.0
    assert conf.factors["input_reachable"] == 0.0  # no-caller strong negative
    assert conf.factors["confirm_resolved"] == 0.0
    assert conf.factors["concrete_arithmetic"] == 0.0
    assert conf.score == WEIGHTS["adversarial_upheld"]
    assert 0.20 <= conf.score < 0.45


# --- individual factor behavior --------------------------------------------


def test_proving_targets_sink_by_token_vs_only_function_context() -> None:
    # Token match on the sink -> 1.0.
    hit = _result(
        verdict=_verdict(sink="memcpy len"),
        review=VerdictReview(upheld=True, reason="ok"),
        steps=[
            _proving_step(0, "arg_provenance", function="parse", sink_call="memcpy", arg_index=2)
        ],
    )
    assert score_finding(hit).factors["proving_on_sink"] == 1.0

    # No token match, but the prover ran in the finding's own function -> 0.60.
    ctx = _result(
        verdict=_verdict(sink="cVar2[uVar5]"),
        review=VerdictReview(upheld=True, reason="ok"),
        steps=[_proving_step(0, "buffer_size", function="WriteCLUT", pointer_var="pStack_10")],
        start_function="WriteCLUT",
    )
    assert score_finding(ctx).factors["proving_on_sink"] == 0.60

    # Proving ran, but not on the sink and not in-context -> 0.40 floor.
    loose = _result(
        verdict=_verdict(sink="cVar2[uVar5]"),
        review=VerdictReview(upheld=True, reason="ok"),
        steps=[_proving_step(0, "buffer_size", function="elsewhere", pointer_var="pStack_10")],
        start_function="WriteCLUT",
        visited=["WriteCLUT"],
    )
    assert score_finding(loose).factors["proving_on_sink"] == 0.40


def test_confirm_gate_fired_but_ignored_scores_weak() -> None:
    # Gate fired, verdict followed, but NO proving after it -> 0.20.
    res = _result(
        verdict=_verdict(),
        review=VerdictReview(upheld=True, reason="ok"),
        steps=[_gate_step(0), TrajStep(1, "conclude", "verdict")],
    )
    assert score_finding(res).factors["confirm_resolved"] == 0.20


def test_proactive_proving_without_gate_scores_mid() -> None:
    res = _result(
        verdict=_verdict(),
        review=VerdictReview(upheld=True, reason="ok"),
        steps=[
            _proving_step(
                0, "arg_provenance", function="WriteCLUT", sink_call="nSamples", arg_index=0
            )
        ],
    )
    assert score_finding(res).factors["confirm_resolved"] == 0.60


def test_missing_adversarial_pass_is_weak_not_zero() -> None:
    res = _result(verdict=_verdict(), review=None)
    conf = score_finding(res)
    assert conf.factors["adversarial_upheld"] == 0.30
    assert "unverified" in conf.reason


def test_reachable_via_source_language_without_input_entry() -> None:
    res = _result(
        verdict=_verdict(source="derived from untrusted network packet"),
        review=VerdictReview(upheld=True, reason="ok"),
        entry_source="",  # entry not classified as an input entry
        steps=[],
    )
    assert score_finding(res).factors["input_reachable"] == 1.0


def test_reachability_unknown_is_neutral_half() -> None:
    res = _result(
        verdict=_verdict(source="unclear origin"),
        review=VerdictReview(upheld=True, reason="ok"),
        entry_source="",
        steps=[],  # no no-callers observation, no input source
    )
    assert score_finding(res).factors["input_reachable"] == 0.50


def test_concrete_arithmetic_detects_hex_and_ignores_bare_cwe() -> None:
    hexy = _result(
        verdict=_verdict(explanation="writes 0x40 bytes into a 0x20-byte stack slot"),
        review=VerdictReview(upheld=True, reason="ok"),
    )
    assert score_finding(hexy).factors["concrete_arithmetic"] == 1.0

    bare = _result(
        verdict=_verdict(explanation="CWE-125 out-of-bounds read, attacker controlled"),
        review=VerdictReview(upheld=True, reason="ok"),
    )
    assert score_finding(bare).factors["concrete_arithmetic"] == 0.0


# --- ranking ----------------------------------------------------------------


def test_rank_orders_high_over_low_over_reject() -> None:
    high = _result(
        verdict=_verdict(),
        review=VerdictReview(upheld=True, reason="no guard"),
        steps=[
            _gate_step(0),
            _proving_step(
                1, "arg_provenance", function="WriteCLUT", sink_call="nSamples", arg_index=0
            ),
        ],
    )
    low = _result(
        verdict=_verdict(
            source="internal helper — no attacker path",
            explanation="an attacker-controlled value could overflow the buffer",
        ),
        review=VerdictReview(upheld=True, reason="no guard"),
        steps=[_callers_step(0, "no known callers of 'sink' in the recovered call graph")],
        entry_source="fallback-ranked",
    )
    reject = _result(
        verdict=_verdict(is_bug=False),
        review=VerdictReview(upheld=False, reason="clamped", checked_guard="if (i<15)"),
    )

    ranked = rank_findings([low, reject, high])
    tiers = [conf.tier for _res, conf in ranked]
    # Pre-oracle: the strong lead tops out at ``medium`` (not ``high``) — ordering by
    # score is unchanged, only the label is honest about not-yet-reproduced.
    assert tiers == ["medium", "low", "reject"]
    # The strongest lead is still returned first for a caller to pursue.
    assert ranked[0][0] is high
    # Scores are monotonically non-increasing.
    scores = [conf.score for _res, conf in ranked]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] > scores[1] > scores[2] == 0.0


def test_rank_threads_oracle_outcomes_into_tiers() -> None:
    """After adjudication, re-ranking with the oracle map lifts a reproduced finding
    to ``high`` and drops a divergent one to ``low`` — the score order is unchanged,
    the tiers now tell the truth."""
    a = _perfect_trajectory()  # index 0 — will be CONFIRMED
    b = _perfect_trajectory()  # index 1 — will be DIVERGENT
    ranked = rank_findings([a, b], oracle={0: True, 1: False})
    by_res = {id(res): conf for res, conf in ranked}
    assert by_res[id(a)].tier == "high"
    assert by_res[id(b)].tier == "low"
    # Same raw score — only the oracle-grounded tier differs.
    assert by_res[id(a)].score == by_res[id(b)].score == 1.0


def test_rank_is_stable_on_equal_scores() -> None:
    a = _result(verdict=_verdict(), review=None, steps=[])
    b = _result(verdict=_verdict(), review=None, steps=[])
    ranked = rank_findings([a, b])
    # Equal score -> original input order preserved (stable sort).
    assert ranked[0][1].score == ranked[1][1].score
    assert ranked[0][0] is a and ranked[1][0] is b


def test_confidence_breakdown_renders_every_factor() -> None:
    conf = score_finding(
        _result(verdict=_verdict(), review=VerdictReview(upheld=True, reason="ok"))
    )
    assert isinstance(conf, FindingConfidence)
    text = conf.breakdown()
    for name in WEIGHTS:
        assert name in text
    # Contributions sum to the score.
    assert abs(sum(conf.contributions().values()) - conf.score) < 1e-9
