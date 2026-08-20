"""G1 structural-grounding gate — unit + end-to-end tests.

Proves the gate binds to the recovered call graph and enforces the G1 severity
contract: REFUTED load-bearing premise floors severity; UNKNOWN load-bearing caps
it at low; GROUNDED keeps it. The oracle is 0verse's own ``meta.callgraph``.
"""

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import zeroverse.pipeline as pipeline
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.grounding import (
    CallGraph,
    Claim,
    ClaimVerdict,
    _is_free_name,
    adjudicate,
    callgraph_from_meta,
    gate,
    ground_verdict,
    grounding_enabled,
    parse_claims,
)
from zeroverse.pipeline import run


@dataclass
class _Meta:
    callgraph: dict
    imports: list
    exports: list


def _cg():
    # export -> handler -> helper -> {strcpy, free}
    return CallGraph(
        callees={
            "AfdDispatch": {"AfdReceive"},
            "AfdReceive": {"copy_helper"},
            "copy_helper": {"strcpy"},
            "free_helper": {"free"},
            "orphan": {"memcpy"},
        },
        exports={"AfdDispatch"},
        free_primitives={"free"},
    )


# --- oracle construction ---------------------------------------------------


def test_callgraph_from_meta_derives_free_primitives():
    meta = _Meta(
        callgraph={"f": ["kfree", "printf"]},
        imports=["ExFreePoolWithTag", "printf"],
        exports=["f"],
    )
    cg = callgraph_from_meta(meta)
    assert cg.callees == {"f": {"kfree", "printf"}}
    assert "ExFreePoolWithTag" in cg.free_primitives   # from imports
    assert "kfree" in cg.free_primitives               # from callees
    assert "printf" not in cg.free_primitives


def test_free_name_detection_rejects_getters_and_accounting_terms():
    assert _is_free_name("IoFreeMdl")
    assert _is_free_name("AfdFreePollInfo")
    assert _is_free_name("object_free")
    for name in (
        "AfdGetFreeConnection", "GetFreeSpace", "free_space", "free_count",
        "DeallocationCount", "ExReleaseRundownProtection",
    ):
        assert not _is_free_name(name)


def test_grounding_flag_rejects_explicit_false_values(monkeypatch):
    for value in ("", "0", "false", "FALSE", "no", " No "):
        monkeypatch.setenv("ZEROVERSE_GROUND", value)
        assert grounding_enabled() is False
    monkeypatch.setenv("ZEROVERSE_GROUND", "1")
    assert grounding_enabled() is True


# --- call_edge adjudication ------------------------------------------------


def test_call_edge_grounded_refuted_unknown():
    cg = _cg()
    def v(caller, callee):
        return adjudicate(Claim("call_edge", {"caller": caller, "callee": callee}), cg).verdict
    assert v("copy_helper", "strcpy") is ClaimVerdict.GROUNDED
    # caller known, edge absent -> the pseudo-C-vs-disassembly FP
    assert v("AfdReceive", "strcpy") is ClaimVerdict.REFUTED
    # caller not analysed -> cannot say
    assert v("ghost", "strcpy") is ClaimVerdict.UNKNOWN


# --- reachability + free_site ----------------------------------------------


def test_reachability_export_and_free_site():
    cg = _cg()
    def reach(target):
        return adjudicate(Claim("reachability_export", {"target": target}), cg).verdict
    def freesite(func):
        return adjudicate(Claim("free_site", {"func": func}), cg).verdict
    # copy_helper is reachable from the export via the real call graph
    assert reach("copy_helper") is ClaimVerdict.GROUNDED
    # orphan is in the graph but no export reaches it -> partial graph, cap (UNKNOWN)
    assert reach("orphan") is ClaimVerdict.UNKNOWN
    # free_site: free_helper reaches a free primitive; copy_helper does not
    assert freesite("free_helper") is ClaimVerdict.GROUNDED
    assert freesite("copy_helper") is ClaimVerdict.REFUTED


def test_self_reachability_is_grounded():
    cg = CallGraph(callees={"sink": set()})
    result = adjudicate(Claim("reachability", {"from": "sink", "to": "sink"}), cg)
    assert result.verdict is ClaimVerdict.GROUNDED
    assert result.fact == "path: sink"


def test_unresolved_callers_make_negative_facts_unknown():
    meta = SimpleNamespace(
        callgraph={"entry": ["helper"], "helper": []},
        imports=[], exports=["entry"],
        unresolved_edges=[{"func": "helper", "op": "CALLIND", "addr": "0x10"}],
    )
    cg = callgraph_from_meta(meta)
    assert cg.has_edge("helper", "sink") is None
    assert cg.reaches("entry", "sink") == (None, None)
    assert cg.reaches_any_free("entry") == (None, None, None)
    assert cg.reaches_from_any_export("sink") == (None, None)


def test_unresolved_callers_still_ground_positive_facts():
    cg = CallGraph(
        callees={"entry": {"sink"}},
        incomplete_callers={"entry"},
    )
    assert cg.has_edge("entry", "sink") is True
    assert cg.reaches("entry", "sink") == (True, ["entry", "sink"])


# --- the severity gate -----------------------------------------------------


def test_gate_refuted_load_bearing_floors_to_info():
    cg = _cg()
    claims = [Claim("call_edge", {"caller": "AfdReceive", "callee": "strcpy"}, load_bearing=True)]
    res = gate("high", claims, cg)
    assert res.status == "refuted"
    assert res.final_severity == "info"
    assert res.reprompt  # the real fact is returned for re-prompt


def test_gate_unknown_load_bearing_caps_at_low():
    cg = _cg()
    claims = [Claim("offset_field", {"func": "x", "claimed_offset": 0xC0}, load_bearing=True)]
    res = gate("critical", claims, cg)
    assert res.status == "capped"
    assert res.final_severity == "low"


def test_gate_grounded_keeps_severity():
    cg = _cg()
    claims = [Claim("call_edge", {"caller": "copy_helper", "callee": "strcpy"}, load_bearing=True)]
    res = gate("high", claims, cg)
    assert res.status == "grounded"
    assert res.final_severity == "high"


def test_non_load_bearing_unknown_does_not_cap():
    cg = _cg()
    claims = [Claim("offset_field", {"func": "x", "claimed_offset": 0xC0}, load_bearing=False)]
    res = gate("high", claims, cg)
    assert res.final_severity == "high"


# --- @claim parsing --------------------------------------------------------


def test_parse_claims_typed_and_malformed():
    text = (
        "The function frees the object.\n"
        "@claim call_edge caller=A callee=B load_bearing=true\n"
        "@claim reachability from=X to=Y\n"
        "@claim call_edge caller=OnlyOne\n"   # malformed -> dropped
    )
    claims = parse_claims(text)
    assert len(claims) == 2
    assert claims[0].claim_type == "call_edge"
    assert claims[0].operands == {"caller": "A", "callee": "B"}
    assert claims[1].claim_type == "reachability"


def test_parse_claims_drops_invalid_integer_without_crashing():
    claims = parse_claims(
        "@claim offset_field func=parse claimed_offset=not-an-integer\n"
        "@claim call_edge caller=A callee=B"
    )
    assert len(claims) == 1
    assert claims[0].claim_type == "call_edge"


# --- end-to-end: a finding's severity is grounded --------------------------


def test_ground_verdict_refutes_unreachable_sink():
    cg = _cg()
    # LLM rates a strcpy overflow HIGH in free_helper, but free_helper's modeled
    # calls ({free}) never reach strcpy -> the reachability premise is REFUTED.
    f = Finding("recv", "strcpy", "free_helper", 0x1000, 0x2000, 3)
    v = Verdict(True, "CWE-121", "high", "stack overflow via strcpy", "AAAA")
    res = ground_verdict(f, v, cg)
    assert res.status == "refuted"
    assert res.final_severity == "info"


def test_ground_verdict_grounded_direct_edge_kept():
    cg = _cg()
    f = Finding("recv", "strcpy", "copy_helper", 0x1000, 0x2000, 3)
    v = Verdict(True, "CWE-121", "high", "stack overflow via strcpy", "AAAA")
    res = ground_verdict(f, v, cg)
    assert res.status == "grounded"
    assert res.final_severity == "high"


def test_reachability_to_unknown_symbol_is_unknown_not_refuted():
    # A reachability claim whose TARGET is not a real symbol anywhere in the graph
    # (a synthetic bug-class label an escalated LLM parroted into an @claim) must
    # be UNKNOWN (cap), never REFUTED (floor) — the oracle can't decide it.
    cg = _cg()
    v = adjudicate(Claim("reachability", {"from": "copy_helper", "to": "loop-writer"}), cg).verdict
    assert v is ClaimVerdict.UNKNOWN
    # but a real symbol that is genuinely unreachable is still REFUTED
    v2 = adjudicate(Claim("reachability", {"from": "free_helper", "to": "strcpy"}), cg).verdict
    assert v2 is ClaimVerdict.REFUTED


def test_llm_unknown_symbol_claim_caps_without_false_refutation():
    # An escalated LLM emits @claim lines naming bug-class labels as functions.
    # Those targets are not symbols, so the oracle returns UNKNOWN and enforces
    # the documented cap. Dropping them would let model noise evade grounding.
    cg = _cg()
    f = Finding("recv", "strcpy", "copy_helper", 0, 0, 1)  # slice, real reachable sink
    noise = ("stack overflow\n"
             "@claim reachability from=copy_helper to=loop-writer\n"
             "@claim call_edge caller=copy_helper callee=off-by-one\n")
    v = Verdict(True, "CWE-121", "high", noise, "")
    res = ground_verdict(f, v, cg)
    assert res.status == "capped"
    assert res.final_severity == "low"


def test_bugclass_lens_synthetic_sink_not_refuted():
    # A bugclass-lens finding carries a SYNTHETIC sink label ("off-by-one:...")
    # that is not a call target — the reachability premise must be SKIPPED, not
    # refuted, or every such finding would be wrongly floored.
    cg = _cg()
    f = Finding("recv", "off-by-one:off-by-one", "copy_helper", 0, 0, 1, origin="bugclass")
    v = Verdict(True, "CWE-193 off-by-one", "high", "off by one", "")
    res = ground_verdict(f, v, cg)
    assert res.status != "refuted"
    assert res.final_severity == "high"


def test_ground_verdict_grounded_transitive_not_overblocked():
    # The amdxdna case: the sink is reached over several hops. A direct-edge check
    # would wrongly refute it; the reachability premise correctly GROUNDS it.
    cg = CallGraph(callees={
        "amdxdna_sched_job_run": {"amdxdna_cmd_set_state", "aie2_hwctx_status"},
        "amdxdna_cmd_set_state": {"amdxdna_gem_vmap"},
        "amdxdna_gem_vmap": {"to_gobj"},
    })
    f = Finding("ioctl", "to_gobj", "amdxdna_sched_job_run", 0x10, 0x20, 5)
    v = Verdict(True, "CWE-476 NULL deref", "high", "null deref via cmd_bo", "")
    res = ground_verdict(f, v, cg)
    assert res.status == "grounded"          # transitive path grounds it
    assert res.final_severity == "high"      # real TP not floored


# --- end-to-end pipeline wiring (opt-in flag) ------------------------------


def _install_finding_with_callgraph(monkeypatch, finding, callgraph):
    from zeroverse.backends import contract

    adapter = SimpleNamespace(
        _backend="ghidra",
        meta=SimpleNamespace(decompiled_c={finding.function: "void f(){}"},
                             callgraph=callgraph, imports=[], exports=[]),
        all_insts=lambda: [],
    )
    monkeypatch.setattr(contract, "select", lambda requested=None: SimpleNamespace(name="ghidra"))
    monkeypatch.setattr(pipeline, "_try_ghidra", lambda path, **kwargs: adapter)
    monkeypatch.setattr(pipeline, "scan", lambda *a, **k: [finding])
    monkeypatch.setattr(pipeline, "foxguard_union", lambda fs, d: (fs, ""))
    monkeypatch.setattr(pipeline, "prime_bugclasses", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "filter_findings", lambda fs, m: (fs, ""))
    monkeypatch.setattr(pipeline, "angr_available", lambda: False)


def test_pipeline_grounding_floors_phantom_edge_when_enabled(monkeypatch):
    pe = Path(__file__).parent / "fixtures" / "pe_overflow_x64.exe"
    finding = Finding("fread", "strcpy", "parse", 0x1000, 0x1100, 1)
    # MockLLM rates a strcpy sink HIGH, but the real call graph shows parse's
    # modeled calls ({helper}) never reach strcpy (which is a real symbol, called
    # by other()) -> the reachability premise is REFUTED (and no PoV reproduces on
    # the static-only PE path), so it floors.
    _install_finding_with_callgraph(monkeypatch, finding,
                                    {"parse": ["helper"], "other": ["strcpy"]})
    monkeypatch.setenv("ZEROVERSE_GROUND", "1")

    result = run(pe)
    tf = result.findings[0]
    assert "grounding" in result.stages_run
    assert tf.grounding["status"] == "refuted"
    assert tf.verdict.severity == "info"      # floored from high


def test_pipeline_grounding_noop_when_disabled(monkeypatch):
    pe = Path(__file__).parent / "fixtures" / "pe_overflow_x64.exe"
    finding = Finding("fread", "strcpy", "parse", 0x1000, 0x1100, 1)
    _install_finding_with_callgraph(monkeypatch, finding, {"parse": ["helper"]})
    monkeypatch.setenv("ZEROVERSE_GROUND", "0")

    result = run(pe)
    tf = result.findings[0]
    assert "grounding" not in result.stages_run
    assert tf.grounding is None
    assert tf.verdict.severity == "high"      # untouched


def test_pov_overrides_grounding_restores_severity():
    # A finding the gate floored to info, but the crash oracle then reproduced a
    # PoV: execution truth wins, severity restored, evidence re-stamped honestly.
    from zeroverse.pipeline import TriagedFinding, _pov_overrides_grounding
    from zeroverse.report import PoV

    v = Verdict(True, "CWE-121", "info", "floored", "")  # already floored by gate
    grounding = {"status": "refuted", "proposed_severity": "high",
                 "final_severity": "info", "claims": [], "reprompt": []}
    tf = TriagedFinding(finding=Finding("recv", "strcpy", "f", 0, 0, 1), verdict=v,
                        pov=PoV(reproduced=True), grounding=grounding)
    _pov_overrides_grounding([tf])
    assert tf.verdict.severity == "high"                       # restored
    assert tf.grounding["status"].startswith("overridden_by_pov")


def test_pov_override_leaves_unconfirmed_floored():
    from zeroverse.pipeline import TriagedFinding, _pov_overrides_grounding

    v = Verdict(True, "CWE-121", "info", "floored", "")
    grounding = {"status": "refuted", "proposed_severity": "high",
                 "final_severity": "info", "claims": [], "reprompt": []}
    tf = TriagedFinding(finding=Finding("recv", "strcpy", "f", 0, 0, 1), verdict=v,
                        pov=None, grounding=grounding)
    _pov_overrides_grounding([tf])
    assert tf.verdict.severity == "info"                       # no PoV -> stays floored
    assert tf.grounding["status"] == "refuted"


# --- @claim emission prompt (opt-in) ---------------------------------------


def test_claim_emission_prompt_only_when_enabled(monkeypatch):
    from zeroverse.agent import MockLLM, TriageAgent

    captured = {}

    class _Spy(MockLLM):
        def complete_json(self, system, prompt, schema):
            captured["system"] = system
            return super().complete_json(system, prompt, schema)

    agent = TriageAgent(_Spy())
    f = Finding("recv", "strcpy", "parse", 0x1000, 0x2000, 3)

    monkeypatch.setenv("ZEROVERSE_GROUND", "0")
    agent.triage(f, "void parse(){}")
    assert "@claim" not in captured["system"]

    monkeypatch.setenv("ZEROVERSE_GROUND", "1")
    agent.triage(f, "void parse(){}")
    assert "@claim call_edge" in captured["system"]


# --- prospective-precision benchmark (locks the measured numbers) ----------


def test_precision_benchmark_no_overblock_and_100pct():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "measure_precision",
        Path(__file__).resolve().parents[1] / "benchmarks" / "grounding" / "measure_precision.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    m = mod.compute()

    assert m["over_blocked"] == []                       # no real finding demoted
    assert m["fp_block"][0] == m["fp_block"][1]          # 100% FP-block
    assert m["tp_preserve"][0] == m["tp_preserve"][1]    # 100% TP-preservation
    assert m["precision_on"] > m["precision_off"]        # precision improves
    assert m["precision_on"] == 1.0
