#!/usr/bin/env python3
"""Prospective-precision measurement for the G1 structural-grounding gate.

Runs the gate over corpus.json (findings + REAL captured call graphs + hidden
ground-truth labels) and reports the numbers that decide default-on:

  (A) FP-BLOCK        — of the hallucinated-premise findings reported actionable
                        (medium+) with the gate OFF, what fraction the gate demotes.
  (B) TP-PRESERVATION — of the genuinely-real findings reported actionable OFF,
                        what fraction stay actionable with the gate ON (no over-block).
  (C) PRECISION DELTA — precision of actionable findings (real / all-actionable),
                        gate OFF vs ON.

Run: python3 benchmarks/grounding/measure_precision.py
The gate never sees the label; over-blocking a real finding fails the run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from zeroverse.grounding import CallGraph, ground_verdict

ACTIONABLE = {"medium", "high", "critical"}
CORPUS = Path(__file__).with_name("corpus.json")


def _gate(case: dict, oracles: dict) -> tuple[str, str, str]:
    """Return (proposed_severity, gated_severity, status) for one case."""
    o = oracles[case["oracle"]]
    cg = CallGraph(
        callees={k: set(v) for k, v in o["callees"].items()},
        exports=set(o.get("exports", [])),
        free_primitives=set(),  # derived below via callgraph_from_meta semantics
    )
    # match callgraph_from_meta: free primitives from imports + callees
    from zeroverse.grounding import _is_free_name

    all_callees = set().union(*cg.callees.values()) if cg.callees else set()
    cg.free_primitives = {n for n in (set(o.get("imports", [])) | all_callees) if _is_free_name(n)}

    finding = SimpleNamespace(function=case["function"], sink=case["sink"])
    verdict = SimpleNamespace(severity=case["proposed_severity"],
                              bug_class=case["bug_class"],
                              explanation=case.get("explanation", ""))
    gr = ground_verdict(finding, verdict, cg)
    final, status = gr.final_severity, gr.status
    # PoV override: execution truth beats a static refutation (pipeline reconciliation).
    if case.get("pov_confirmed") and status in ("refuted", "capped"):
        final = gr.proposed_severity
        status = f"overridden_by_pov (was {status})"
    return gr.proposed_severity, final, status


def compute(corpus_path: Path = CORPUS) -> dict:
    """Run the gate over the corpus and return the (A)/(B)/(C) metrics + rows."""
    data = json.loads(corpus_path.read_text())
    oracles, cases = data["oracles"], data["cases"]
    rows = []
    over_blocked = []
    for c in cases:
        proposed, gated, status = _gate(c, oracles)
        off_act, on_act = proposed in ACTIONABLE, gated in ACTIONABLE
        rows.append((c["id"], c["label"], proposed, gated, status, off_act, on_act))
        if c["label"] == "real" and off_act and not on_act:
            over_blocked.append(c["id"])

    fps = [r for r in rows if r[1] == "fp"]
    tps = [r for r in rows if r[1] == "real"]
    fp_off = [r for r in fps if r[5]]
    fp_blocked = [r for r in fp_off if not r[6]]
    tp_off = [r for r in tps if r[5]]
    tp_kept = [r for r in tp_off if r[6]]
    tp_on = sum(1 for r in rows if r[1] == "real" and r[6])
    fp_on = sum(1 for r in rows if r[1] == "fp" and r[6])
    tp_offa = sum(1 for r in rows if r[1] == "real" and r[5])
    fp_offa = sum(1 for r in rows if r[1] == "fp" and r[5])
    return {
        "rows": rows,
        "n": len(cases), "n_real": len(tps), "n_fp": len(fps),
        "fp_block": (len(fp_blocked), len(fp_off)),
        "tp_preserve": (len(tp_kept), len(tp_off)),
        "precision_off": tp_offa / (tp_offa + fp_offa) if (tp_offa + fp_offa) else 0.0,
        "precision_on": tp_on / (tp_on + fp_on) if (tp_on + fp_on) else 0.0,
        "over_blocked": over_blocked,
    }


def main() -> int:
    m = compute()
    rows = m["rows"]
    over_blocked = m["over_blocked"]

    print(f"\n{'case':<34} {'label':<5} {'off':<8} {'on':<8} status")
    print("-" * 92)
    for cid, label, proposed, gated, status, _, _ in rows:
        flag = "  <-- demoted" if proposed != gated else ""
        print(f"{cid:<34} {label:<5} {proposed:<8} {gated:<8} {status}{flag}")

    fb_n, fb_d = m["fp_block"]
    tp_n, tp_d = m["tp_preserve"]
    p_off, p_on = m["precision_off"], m["precision_on"]
    a = fb_n / fb_d if fb_d else 0.0
    b = tp_n / tp_d if tp_d else 0.0
    print("\n" + "=" * 60)
    print(f"corpus: {m['n']} findings ({m['n_real']} real, {m['n_fp']} fp)")
    print(f"(A) FP-BLOCK        {fb_n}/{fb_d} hallucinated-premise "
          f"actionable findings demoted = {a*100:.0f}%")
    print(f"(B) TP-PRESERVATION {tp_n}/{tp_d} real actionable findings "
          f"kept = {b*100:.0f}%")
    print(f"(C) PRECISION       actionable-precision {p_off*100:.0f}% (gate OFF) -> "
          f"{p_on*100:.0f}% (gate ON)   delta +{(p_on-p_off)*100:.0f}pts")
    print("=" * 60)

    if over_blocked:
        print(f"\nOVER-BLOCK (gate bug): real findings demoted below actionable: {over_blocked}")
        return 1
    print("\nno over-block: every real finding preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
