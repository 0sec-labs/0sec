---
title: Dynamic Triage Routing — v0 Implementation
description: Per-finding learned layer selection. v0 ships a rule-based router with a seam for a learned classifier; this page documents what shipped, the four decision rules, the routing-trace dataset shape, and the planned upgrade path.
---

> **Status:** v0 (rule-based) shipped behind `PWNKIT_FEATURE_DYNAMIC_TRIAGE`. The learned classifier described in the [design doc](/research/dynamic-routing-design/) lands in a follow-up PR. Tracking: [pwnkit#113](https://github.com/0sec-labs/0sec/issues/113).

## What shipped in v0

A new module at `packages/core/src/triage/router/` that, for every finding, decides which subset of the 11 triage layers should run. The decision is gated behind the feature flag `PWNKIT_FEATURE_DYNAMIC_TRIAGE`; default OFF preserves the existing static-layer behavior verbatim.

The router is structured around a small interface that lets a learned classifier swap in later without touching the dispatch site:

```ts
interface RouterModel {
  readonly id: string;
  predict(finding: Finding, features: RoutingFeatures): RoutingDecision;
}

interface RoutingDecision {
  layers_to_invoke: LayerId[];
  confidence: number;
  reasoning?: string;
  matchedRule?: string;
}
```

v0 ships `RuleBasedRouter`. A follow-up PR ships `XGBoostRouter` (or a VulnBERT-style hybrid head) consuming the same input contract.

## The four decision rules (v0)

The rules are evaluated in priority order. The first match wins.

### Rule 1 — high-confidence SQLi with error-based signal → skip `debate`

```
IF finding.category == "sql-injection"
AND finding.confidence >= 0.8
AND finding.evidence.response matches a SQL-error regex
THEN invoke the default static layer set MINUS `debate`
```

Motivation: the [pwnkit#72 ablation](https://github.com/0sec-labs/0sec/issues/72#issuecomment-4229254355) showed `adversarial_debate` removes real findings on the high-confidence error-based SQLi slice. The oracle is deterministic, free, and sufficient on this shape — debate adds cost and removes signal.

### Rule 2 — ambiguous logic bug → invoke `structured_verify` + `pov_gate`

```
IF finding.category in {missing-validation, security-misconfiguration,
                       information-disclosure, cors, tool-misuse,
                       output-manipulation}
AND finding.confidence in [0.3, 0.55]
THEN invoke FREE_LAYER_SET + {structured_verify, pov_gate}
```

Motivation: per the ablation, the mid-confidence logic-bug band is where the structured 4-step verify and the PoV gate carry their weight. For high-confidence or rejected findings these layers are dead weight; for the ambiguous middle they're the only signal that moves the verdict.

### Rule 3 — strong FP-pattern match → empty layer set (auto-reject)

```
IF triageMemories has a match with score >= 0.85
AND matched_category == finding.category
AND finding.confidence < 0.6
THEN invoke {}   // auto-reject; scanner marks the finding as false-positive
```

**Risk note — this rule is intentionally conservative.** The token-overlap heuristic in `triage/memories.ts` is coarse, and a single fuzzy match dropping a real finding is the regression mode we worry about. The rule only triggers when:

- the match score is **strong** (>= 0.85, not just "above the matcher's floor"), AND
- the category matches **exactly** (a memory about XSS cannot auto-reject an SQLi finding), AND
- the agent's confidence is **low** (< 0.6) — a high-confidence finding overrides the memory match

These thresholds were picked conservatively. Promote them down (looser thresholds → more auto-rejects) only after measured A/B testing on npm-bench, where this rule has the most leverage.

### Rule 4 — default → static layer set

```
ELSE invoke DEFAULT_STATIC_LAYER_SET
```

The router falls through to today's static behavior. Any finding that doesn't match a rule sees no change from the pre-v113 pipeline.

## The routing-trace dataset

At the end of every scan with `PWNKIT_FEATURE_DYNAMIC_TRIAGE=1`, the scanner writes one JSONL record per finding to `<journal-sidecar-dir>/routing-trace.jsonl`. This is the dataset the phase-2 learned router trains on.

**Record shape (one example):**

```json
{
  "scan_id": "scan-2026-05-23-abc",
  "finding_id": "f-7",
  "category": "sql-injection",
  "subsystem": "web",
  "features": [200, 1, 1, 1, 1, 1, 0, 0, 0, 482, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 1, 0, 1, 12,
                3, 0.9, 1, 1, 0, 1, 0, 0,
                34, 0, 0, 0, 0, 0, 0, 1, 1, 1,
                1, 2.7, 0.43, 0.83,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "feature_names": ["resp_http_status", "resp_sql_error", "..."],
  "decided_layers": ["holding_it_wrong", "evidence_gate",
                     "reachability", "multi_modal", "oracle",
                     "pov_gate"],
  "matched_rule": "rule-1-sqli-error-based",
  "router_confidence": 0.9,
  "actual_verdict_per_layer": {
    "oracle": {
      "layer": "oracle",
      "verdict": "pass",
      "confidence": 0.95,
      "reason": "verified: HTTP 500 + SQL error string",
      "durationMs": 4203,
      "costUsd": 0
    },
    "holding_it_wrong": {
      "layer": "holding_it_wrong",
      "verdict": "pass",
      "reason": "no holding-it-wrong pattern matched",
      "durationMs": 1,
      "costUsd": 0
    }
  },
  "ground_truth": "true_positive",
  "decided_at": 1716427200000
}
```

The 55-element `features` vector is the same vector the joint-paper dataset ([pwnkit#67](https://github.com/0sec-labs/0sec/issues/67)) trains on — extracted by `extractFeatures()` in `packages/core/src/triage/feature-extractor.ts`. The `ground_truth` field is left undefined for in-flight scans; the offline collector backfills it from flag extraction (XBOW / Cybench) or package verdict (npm-bench).

## The planned learned-classifier upgrade

Phase 2 of pwnkit#113 (separate PR) replaces `RuleBasedRouter` with `XGBoostRouter`:

1. Train an XGBoost multi-label classifier on `(features, decided_layers, ground_truth)` tuples accumulated by the v0 trace emitter.
2. The target is "which subset of layers would have produced the same final verdict at minimum total cost". This is the cost-saved-per-recall-lost objective from the design doc.
3. Inference must remain sub-millisecond — same constraint as the TP/FP scoring model that ships today as `triage/learned-router.ts`. The XGBoost tree evaluator at `learned-router.ts` is the reference implementation; the routing classifier reuses the same loader pattern.
4. The learned model lands as `class XGBoostRouter implements RouterModel`. Switching from `RuleBasedRouter` to `XGBoostRouter` requires a single line at module load:

```ts
import { setRouterModel } from "@pwnkit/core";
import { XGBoostRouter } from "./xgboost-router.js";
setRouterModel(new XGBoostRouter(loadModelFromDisk()));
```

No changes at the `agentic-scanner.ts` dispatch site.

## Minimum dataset size

The v0 rule set encodes three rules. A learned router that **beats** the rules needs enough data to:

1. Discover those three rules statistically (no extra data — they're high-base-rate patterns that show up in the first hundred findings).
2. Discover NEW per-finding patterns the rules miss. This is where dataset size matters.

The joint-paper reference: VulnBERT achieves 92% recall / 1.2% FPR with ~10k labeled findings on web vulns. We don't need to match that for the routing decision (a coarser task than TP/FP), but the per-category covariate means we need samples per `(subsystem, decision)` cell.

**Rough estimate:** 2,500–5,000 labeled findings with `layerVerdicts` populated should suffice to train a router that strictly beats the v0 rules on every benchmark slice. The current corpus (~1,514 rows in `triage-dataset-v2.jsonl`) is below that floor for routing — it works for the TP/FP head because that's a single binary decision per finding, but the per-layer decision is effectively 6+ binary decisions and needs more data per cell.

Plan: collect routing traces from the next ~10 benchmark dispatches (xbow-bench at 200 challenges × 5 runs = 1000 findings, npm-bench at 81 packages × 3 runs ≈ 250 findings, with v0 routing on). At that point the dataset is large enough to attempt the trained model.

## How to enable

```bash
PWNKIT_FEATURE_DYNAMIC_TRIAGE=1 pwnkit scan ./your-target
```

The routing decision for every finding is recorded in:
- the SQLite event log (`stage:verify event_type:dynamic_triage_routing`), and
- `~/.pwnkit/runs/<scan-id>/routing-trace.jsonl` at scan teardown.

The existing static feature flags (`PWNKIT_FEATURE_HOLDING_IT_WRONG`, `PWNKIT_FEATURE_POV_GATE`, etc.) still gate whether a layer **can** run; the router decides which of the available layers actually runs per finding. The router can never invoke a layer the operator explicitly disabled via the env var.

## Related work

- [pwnkit#113](https://github.com/0sec-labs/0sec/issues/113) — issue tracking this work
- [pwnkit#112](https://github.com/0sec-labs/0sec/issues/112) — per-layer telemetry (prerequisite, already shipped)
- [pwnkit#67](https://github.com/0sec-labs/0sec/issues/67) — joint paper plan
- [pwnkit#72](https://github.com/0sec-labs/0sec/issues/72) — the ablation that motivated this
- [Dynamic Routing Design Doc](/research/dynamic-routing-design/) — full design discussion
