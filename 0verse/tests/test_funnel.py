"""#4 cheap→expensive triage funnel + variant-analysis framing (deterministic)."""

from zeroverse.agent import (
    MockLLM,
    RankedHypothesis,
    TriageAgent,
    TriageFunnel,
    _variant_framing,
    cheap_score,
)
from zeroverse.analyze import Finding


def _f(source: str, sink: str, **kw: object) -> Finding:
    return Finding(source=source, sink=sink, function="main",
                   source_addr=0x10, sink_addr=0x20, path_len=4, **kw)  # type: ignore[arg-type]


def test_cheap_score_orders_by_danger() -> None:
    dangerous = cheap_score(_f("getenv", "system"))
    benign = cheap_score(_f("foxguard", "memcmp"))
    assert 0.0 <= benign < dangerous <= 1.0


def test_cheap_score_is_deterministic() -> None:
    assert cheap_score(_f("read", "strcpy")) == cheap_score(_f("read", "strcpy"))


def test_funnel_escalates_top_only() -> None:
    # one dangerous slice + many benign ones; only the top few should escalate.
    findings = [_f("getenv", "system")] + [_f("foxguard", "x", origin="foxguard")
                                           for _ in range(12)]
    funnel = TriageFunnel(MockLLM(), escalate_top=3, escalate_threshold=0.45)
    ranked = funnel.run(findings, lambda f: "ctx")
    assert len(ranked) == len(findings)
    escalated = [r for r in ranked if r.escalated]
    # the dangerous getenv->system must escalate and be ranked first
    assert ranked[0].finding.sink == "system"
    assert ranked[0].escalated is True
    assert ranked[0].verdict.is_real is True
    # low-score foxguard hits stay below the cutoff (cheap-verdict, not escalated)
    assert all(not r.escalated for r in ranked if r.finding.origin == "foxguard")
    assert len(escalated) <= 3


def test_funnel_returns_ranked_hypotheses() -> None:
    ranked = TriageFunnel(MockLLM()).run([_f("read", "strcpy")], lambda f: "ctx")
    assert isinstance(ranked[0], RankedHypothesis)
    assert ranked[0].score > 0.5


def test_variant_framing_seeds_system_prompt() -> None:
    txt = _variant_framing("CWE-120 buffer overflow")
    assert "VARIANT ANALYSIS" in txt and "CWE-120 buffer overflow" in txt


def test_agent_seed_bug_class_is_propagated() -> None:
    captured: dict[str, str] = {}

    class _SpyLLM:
        def complete_json(self, system: str, prompt: str, schema: object) -> dict[str, object]:
            captured["system"] = system
            return {"is_real": False, "bug_class": "x", "severity": "info",
                    "explanation": "", "input_example": ""}

    TriageAgent(_SpyLLM(), seed_bug_class="CWE-787").triage(_f("read", "memcpy"), "code")
    assert "VARIANT ANALYSIS" in captured["system"] and "CWE-787" in captured["system"]
