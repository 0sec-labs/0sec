"""M7 #43 — the PoV-dataset flywheel: preseeded 5-layer memory, RAG-priming, the
cost-router, capture/loop-closure, the MCP recall tool, and the primed-vs-cold
proof with an un-similar control. No network; deterministic.

The load-bearing invariant under test: **memory PRIMES, the oracle CONFIRMS.** The
flywheel re-orders / re-frames / re-budgets a run but can never manufacture a
confirmation (PoV-is-truth), so it can never create a false positive.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from zeroverse import dataset, flywheel, mcp, seedcatalog
from zeroverse.agent import MockLLM, TriageFunnel, Verdict
from zeroverse.analyze import Finding
from zeroverse.concolic import AngrVerdict
from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.report import PoV

# --- preseed (NOT empty-consolidate) ---------------------------------------

def test_preseed_loads_the_90_archetypes() -> None:
    fw = flywheel.Flywheel()
    n = len(seedcatalog.load_archetypes())
    assert n == 90
    c = fw.counts()
    # one principle + one procedural per archetype; semantic only for mapped lenses.
    assert c[flywheel.PRINCIPLE] == n
    assert c[flywheel.PROCEDURAL] >= n
    assert c[flywheel.SEMANTIC] >= 1
    assert c["total"] >= 2 * n


def test_preseed_is_full_not_empty() -> None:
    # The decisive lesson: the store ships FULL from the registry, with NO corpus —
    # the opposite of the empty-store-and-consolidate attempt that fizzled.
    fw = flywheel.Flywheel()
    assert fw.episodic_loaded == 0
    assert fw.counts()["total"] > 100
    # every layer except the two corpus-fed ones is populated purely from archetypes.
    c = fw.counts()
    assert c[flywheel.PRINCIPLE] and c[flywheel.SEMANTIC] and c[flywheel.PROCEDURAL]
    assert c[flywheel.EPISODIC] == 0 and c[flywheel.ANALOGICAL] == 0


def test_class_tokens_bridge_cwe_and_lens_spellings() -> None:
    # the cross-corpus join key: a record's "CWE-78 OS command injection" and an
    # archetype's "cmdi" lens must meet on a shared token.
    a = flywheel.class_tokens("CWE-78 OS command injection")
    b = flywheel.class_tokens("cmdi")
    assert "cwe-78" in a and "cmdi" in a and "cmdi" in b
    assert a & b


# --- recall ranks a similar PoV above an unrelated one ----------------------

def test_recall_ranks_similar_pov_above_unrelated() -> None:
    fw = flywheel.Flywheel()
    fw.remember([flywheel._confirmed_pov_record()])  # one confirmed cmdi PoV

    cmdi_q = flywheel.TargetQuery.from_features(
        {"format": "ELF", "arch": "x86-64", "bits": 64},
        bug_class="CWE-78 OS command injection", sinks=["doSystem"], sources=["getenv"],
    )
    uaf_q = flywheel.TargetQuery.from_features(
        {"format": "ELF", "arch": "x86-64", "bits": 64},
        bug_class="CWE-416 use-after-free", sinks=["free"], sources=["read"],
    )
    cmdi_recalls = fw.recall(cmdi_q, k=8)
    uaf_recalls = fw.recall(uaf_q, k=8)
    assert cmdi_recalls

    def cmdi_best(recalls: list[flywheel.Recall]) -> float:
        scs = [r.score for r in recalls if "cmdi" in r.memory.class_tokens]
        return max(scs) if scs else 0.0

    # the cmdi knowledge ranks far higher for the cmdi target than for the uaf one,
    # and the very top recall for the cmdi query is itself cmdi knowledge.
    assert "cmdi" in cmdi_recalls[0].memory.class_tokens
    assert cmdi_best(cmdi_recalls) > cmdi_best(uaf_recalls)


# --- capture writes a valid #32 record + closes the loop --------------------

def test_remember_emits_valid_dataset_record(tmp_path) -> None:  # type: ignore[no-untyped-def]
    fw = flywheel.Flywheel()
    out = tmp_path / "corpus.ndjson"
    n = fw.remember([flywheel._confirmed_pov_record()], emit_path=out)
    assert n == 1
    rows = list(dataset.iter_records(out))  # iter_records re-validates every row
    assert len(rows) == 1
    assert rows[0]["verdict"] == "confirmed" and rows[0]["pov"]["path"]
    # the record also landed in the in-memory EPISODIC + PROCEDURAL layers.
    assert any(m.layer == flywheel.EPISODIC and m.confirmed for m in fw.memories)
    assert any(m.layer == flywheel.PROCEDURAL and m.confirmed for m in fw.memories)


def test_capture_closes_the_loop(tmp_path) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "corpus.ndjson"
    flywheel.Flywheel().remember([flywheel._confirmed_pov_record()], emit_path=out)
    # a fresh flywheel preseeds from archetypes AND reads back the captured corpus.
    fw2 = flywheel.Flywheel(dataset_path=out)
    assert fw2.episodic_loaded == 1
    assert fw2.counts()[flywheel.EPISODIC] == 1


def _learning_run(pov_path: str = "/private/povs/confirmed.py") -> RunResult:
    triage = Triage(
        path="/bin/learning", fmt="ELF", arch="x86-64", bits=64,
        endian="little", kind="EXEC",
    )
    confirmed = TriagedFinding(
        finding=Finding("read", "strcpy", "confirmed_fn", 0x1000, 0x1100, 4),
        verdict=Verdict(True, "CWE-120", "high", "confirmed", ""),
        pov=PoV(reproduced=True, pov_script=pov_path),
    )
    refuted = TriagedFinding(
        finding=Finding("recv", "memcpy", "refuted_fn", 0x2000, 0x2100, 4),
        verdict=Verdict(True, "CWE-120", "medium", "refuted", ""),
        angr=AngrVerdict(outcome="unsat", note="path contradiction"),
    )
    unresolved = TriagedFinding(
        finding=Finding("getenv", "system", "hypothesis_fn", 0x3000, 0x3100, 4),
        verdict=Verdict(True, "CWE-78", "high", "unresolved", ""),
    )
    return RunResult(
        triage=triage,
        stages_run=["ingest", "decompile", "reason", "concolic", "dynamic", "poc"],
        findings=[confirmed, refuted, unresolved],
    )


def test_completed_run_remembers_only_verified_and_refuted(
    tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "learning.ndjson"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(out))
    monkeypatch.delenv("ZEROVERSE_DATASET_PATH", raising=False)
    monkeypatch.delenv("ZEROVERSE_EVALUATION", raising=False)
    pov = tmp_path / "confirmed.py"
    pov.write_text("print('replay')\n", encoding="utf-8")

    assert flywheel.remember_completed_run(
        _learning_run(str(pov)), binary="/bin/learning", backend="ghidra"
    ) == 2
    rows = list(dataset.iter_records(out))
    assert {row["verdict"] for row in rows} == {"confirmed", "pruned"}
    assert "hypothesis" not in {row["verdict"] for row in rows}
    confirmed = next(row for row in rows if row["verdict"] == "confirmed")
    assert confirmed["pov"]["path"] == str(pov.resolve())
    assert len(confirmed["pov"]["sha256"]) == 64
    # Retrying the same completed run is idempotent.
    assert flywheel.remember_completed_run(
        _learning_run(str(pov)), binary="/bin/learning", backend="ghidra"
    ) == 0
    assert len(list(dataset.iter_records(out))) == 2


def test_completed_run_rejects_missing_or_symlinked_pov(tmp_path, monkeypatch) -> None:
    out = tmp_path / "learning.ndjson"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(out))
    missing = tmp_path / "missing.py"
    assert flywheel.remember_completed_run(
        _learning_run(str(missing)), binary="/bin/learning", backend="ghidra"
    ) == 1
    assert {row["verdict"] for row in dataset.iter_records(out)} == {"pruned"}

    real = tmp_path / "real.py"
    real.write_text("print('replay')\n", encoding="utf-8")
    link = tmp_path / "linked.py"
    link.symlink_to(real)
    assert flywheel.remember_completed_run(
        _learning_run(str(link)), binary="/bin/learning", backend="ghidra"
    ) == 0


def test_completed_run_concurrent_retries_are_idempotent(tmp_path, monkeypatch) -> None:
    out = tmp_path / "learning.ndjson"
    pov = tmp_path / "confirmed.py"
    pov.write_text("print('replay')\n", encoding="utf-8")
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(out))
    run = _learning_run(str(pov))

    def retain(_attempt: int) -> int:
        return flywheel.remember_completed_run(
            run, binary="/bin/learning", backend="ghidra"
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        retained = list(pool.map(retain, range(8)))
    assert sum(retained) == 2
    assert len(list(dataset.iter_records(out))) == 2


def test_learning_cannot_write_into_live_evaluation_corpus(
    tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "frozen-eval.ndjson"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(out))
    monkeypatch.setenv("ZEROVERSE_DATASET_PATH", str(out))
    assert flywheel.remember_completed_run(
        _learning_run(), binary="/bin/learning", backend="ghidra"
    ) == 0
    assert not out.exists()

    monkeypatch.delenv("ZEROVERSE_DATASET_PATH")
    monkeypatch.setenv("ZEROVERSE_EVALUATION", "1")
    assert flywheel.remember_completed_run(
        _learning_run(), binary="/bin/learning", backend="ghidra"
    ) == 0
    assert not out.exists()


def test_refuted_memory_demotes_exact_path_without_deciding_truth() -> None:
    confirmed = flywheel._confirmed_pov_record()
    refuted = dataset.DatasetRecord(
        **{
            **confirmed.__dict__,
            "record_id": "refuted-do-system",
            "verdict": "pruned",
            "oracle": "angr-reachability(UNSAT)",
            "pov_path": "",
            "repro_cmd": "",
        }
    )
    fw = flywheel.Flywheel()
    fw.remember([refuted])
    exact = Finding("getenv", "doSystem", "apply_cfg", 0x4000, 0x401320, 4)
    sibling = Finding("getenv", "doSystem", "sibling", 0x4000, 0x401320, 4)
    priming = fw.prime(
        flywheel.query_from_findings(
            {"format": "ELF", "arch": "x86-64"}, [exact, sibling]
        )
    )
    exact_bonus = priming.rank_bonus(exact)
    assert exact_bonus < 0
    # Other recalled knowledge may still boost the shared source/sink pair, but
    # this refutation must not demote a different function/site.
    sibling_bonus = priming.rank_bonus(sibling)
    assert sibling_bonus >= 0
    assert sibling_bonus > exact_bonus
    assert any(r.memory.outcome == "refuted" for r in priming.recalls)


def test_fleet_records_become_analogical_links(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # a #42 fleet row (explanation starts "variant-of[...]") folds into ANALOGICAL.
    rec = flywheel._confirmed_pov_record()
    fleet_rec = dataset.DatasetRecord(
        **{**rec.__dict__, "explanation": "variant-of[bugclass:cmdi] fleet sweep; member=router_b"}
    )
    fw = flywheel.Flywheel()
    fw.remember([fleet_rec])
    assert any(m.layer == flywheel.ANALOGICAL for m in fw.memories)


# --- the MCP recall interface ----------------------------------------------

def test_mcp_recall_tool_opt_in(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("ZEROVERSE_FLYWHEEL", raising=False)
    assert "recall_similar" not in {t["name"] for t in mcp.active_tools()}
    # the base four are always present and unchanged.
    assert {t["name"] for t in mcp.TOOLS} == {
        "scan_binary", "list_findings", "get_pov", "get_report"}
    monkeypatch.setenv("ZEROVERSE_FLYWHEEL", "1")
    assert "recall_similar" in {t["name"] for t in mcp.active_tools()}


def test_mcp_recall_dispatch_returns_memory_and_cost_route() -> None:
    eng = mcp.Engine()
    out = json.loads(mcp.dispatch(eng, "recall_similar", {
        "format": "ELF", "arch": "x86-64", "bug_class": "CWE-78",
        "sinks": ["system", "doSystem"], "sources": ["getenv"],
    }))
    assert out["counts"]["principle"] == len(seedcatalog.load_archetypes())
    assert out["cost_route"] in ("cheap", "full")
    assert out["recalls"]
    # a cmdi-shaped query recalls cmdi knowledge near the top.
    assert any("cmdi" in r["key"] or "78" in r["text"] for r in out["recalls"][:3])


# --- the PROOF: primed vs cold + the un-similar control ---------------------

def test_prove_priming_helps_with_unsimilar_control() -> None:
    rep = flywheel.prove_priming()
    # (1) priming LOCATES the known-fruitful bug with fewer escalations on B.
    assert rep.locate_delta > 0
    # (2) the un-similar control B' gets NO spurious lift (rank unchanged).
    assert rep.control_delta == 0
    # (3) recall discriminates: the similar target recalls more than the control.
    assert rep.similar_recall_top > rep.control_recall_top
    # (4) the cost-router skips the LLM on the no-signal control, not on the match.
    assert rep.similar_cost_route == "full"
    assert rep.control_cost_route == "cheap"
    # (5) memory primes only — no confirmation is created or changed.
    assert rep.confirmations_changed is False


# --- memory NEVER flips a hypothesis to confirmed ---------------------------

def test_rank_bonus_escalates_known_finding_without_confirming() -> None:
    fw = flywheel.Flywheel()
    fw.remember([flywheel._confirmed_pov_record()])
    sim = flywheel._similar_scenario()
    prm = fw.prime(flywheel.query_from_findings(sim.features, sim.findings))
    assert prm.active

    def escalated(rows: list, fn: str) -> bool:  # type: ignore[type-arg]
        return next(rh.escalated for rh in rows if rh.finding.function == fn)

    cold = TriageFunnel(MockLLM(), escalate_top=2).run(sim.findings, lambda f: "")
    primed = TriageFunnel(MockLLM(), escalate_top=2, rank_bonus=prm.rank_bonus).run(
        sim.findings, lambda f: "")
    # the known-fruitful site reaches the expensive triage under priming, not cold.
    assert escalated(primed, "handle_set") and not escalated(cold, "handle_set")


def test_memory_cannot_manufacture_a_confirmation() -> None:
    # The Priming surface exposes framing / context / rank_bonus / cost_route — and
    # NO verdict/confirmed field. The flywheel structurally cannot confirm.
    prm = flywheel.Flywheel().prime(
        flywheel.TargetQuery.from_features({"format": "ELF"}, bug_class="cmdi", sinks=["system"]))
    for forbidden in ("confirmed", "verdict", "is_real", "pov"):
        assert not hasattr(prm, forbidden)
    # the cost-router only ever returns a budget hint, never a truth value.
    route, _reason = flywheel.Flywheel().cost_route(
        flywheel.TargetQuery.from_features({"format": "ELF"}))
    assert route in ("cheap", "full")


def test_cold_funnel_unchanged_without_bonus() -> None:
    # regression guard: with no rank_bonus the funnel ordering/escalation is identical
    # to before the flywheel existed (the cold path must be untouched).
    sim = flywheel._similar_scenario()
    a = TriageFunnel(MockLLM(), escalate_top=3).run(sim.findings, lambda f: "")
    b = TriageFunnel(MockLLM(), escalate_top=3, rank_bonus=None).run(sim.findings, lambda f: "")
    assert [r.finding.function for r in a] == [r.finding.function for r in b]
    assert [r.escalated for r in a] == [r.escalated for r in b]


def test_flywheel_enabled_flag(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("ZEROVERSE_FLYWHEEL", raising=False)
    assert flywheel.flywheel_enabled() is False
    monkeypatch.setenv("ZEROVERSE_FLYWHEEL", "0")
    assert flywheel.flywheel_enabled() is False
    monkeypatch.setenv("ZEROVERSE_FLYWHEEL", "1")
    assert flywheel.flywheel_enabled() is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
