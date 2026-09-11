---
title: Dynamic Triage Routing — v0 Implementation
description: Rule-based layer selection, routing traces, and the planned learned classifier.
---

> **Status:** Rule-based v0 is gated by `0SEC_FEATURE_DYNAMIC_TRIAGE`. The learned classifier remains planned in the [design](/research/dynamic-routing-design/) and [0sec#113](https://github.com/0sec-labs/0sec/issues/113).

## What shipped in v0

`packages/core/src/triage/router/` selects from 11 layers per finding.
`0SEC_FEATURE_DYNAMIC_TRIAGE` defaults off. The interface below allows a future
classifier to reuse the dispatch contract:

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

The [0sec#72 ablation](https://github.com/0sec-labs/0sec/issues/72#issuecomment-4229254355) found that `adversarial_debate` removed real findings on this SQLi slice. The deterministic oracle required no model call.

### Rule 2 — ambiguous logic bug → invoke `structured_verify` + `pov_gate`

```
IF finding.category in {missing-validation, security-misconfiguration,
                       information-disclosure, cors, tool-misuse,
                       output-manipulation}
AND finding.confidence in [0.3, 0.55]
THEN invoke FREE_LAYER_SET + {structured_verify, pov_gate}
```

The ablation motivated structured verification and PoV generation for mid-confidence logic findings.

### Rule 3 — strong FP-pattern match → empty layer set (auto-reject)

```
IF triageMemories has a match with score >= 0.85
AND matched_category == finding.category
AND finding.confidence < 0.6
THEN invoke {}   // auto-reject; scanner marks the finding as false-positive
```

Coarse token overlap can reject a real finding. This rule requires all three conditions:

- Match score >= 0.85.
- Exact category match.
- Agent confidence < 0.6.

Measure recall and false positives before loosening these thresholds.

### Rule 4 — default → static layer set

```
ELSE invoke DEFAULT_STATIC_LAYER_SET
```

The router falls through to today's static behavior. Any finding that doesn't match a rule sees no change from the pre-v113 pipeline.

## The routing-trace dataset

At the end of every scan with `0SEC_FEATURE_DYNAMIC_TRIAGE=1`, the scanner writes one JSONL record per finding to `<journal-sidecar-dir>/routing-trace.jsonl`. This is the dataset the phase-2 learned router trains on.

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

The 55-element `features` vector is the same vector the joint-paper dataset ([0sec#67](https://github.com/0sec-labs/0sec/issues/67)) trains on — extracted by `extractFeatures()` in `packages/core/src/triage/feature-extractor.ts`. The `ground_truth` field is left undefined for in-flight scans; the offline collector backfills it from flag extraction (XBOW / Cybench) or package verdict (npm-bench).

## The planned learned-classifier upgrade

Phase 2 of 0sec#113 (separate PR) replaces `RuleBasedRouter` with `XGBoostRouter`:

1. Train an XGBoost multi-label classifier on `(features, decided_layers, ground_truth)` tuples accumulated by the v0 trace emitter.
2. The target is "which subset of layers would have produced the same final verdict at minimum total cost". This is the cost-saved-per-recall-lost objective from the design doc.
3. Inference must remain sub-millisecond — same constraint as the TP/FP scoring model that ships today as `triage/learned-router.ts`. The XGBoost tree evaluator at `learned-router.ts` is the reference implementation; the routing classifier reuses the same loader pattern.
4. The learned model lands as `class XGBoostRouter implements RouterModel`. Switching from `RuleBasedRouter` to `XGBoostRouter` requires a single line at module load:

```ts
import { setRouterModel } from "@0sec/core";
import { XGBoostRouter } from "./xgboost-router.js";
setRouterModel(new XGBoostRouter(loadModelFromDisk()));
```

No changes at the `agentic-scanner.ts` dispatch site.

## Minimum dataset size

Training needs examples for each `(subsystem, decision)` cell and patterns beyond
the existing rules. The planning estimate is **2,500–5,000 labeled findings**
with `layerVerdicts`. The recorded corpus has about **1,514 rows**.
These estimates establish a collection target; superiority to the rules requires
evaluation across every benchmark slice.

Plan: collect routing traces from the next ~10 benchmark dispatches (xbow-bench at 200 challenges × 5 runs = 1000 findings, npm-bench at 81 packages × 3 runs ≈ 250 findings, with v0 routing on). At that point the dataset is large enough to attempt the trained model.

## How to enable

```bash
env 0SEC_FEATURE_DYNAMIC_TRIAGE=1 0sec scan ./your-target
```

The routing decision for every finding is recorded in:
- the SQLite event log (`stage:verify event_type:dynamic_triage_routing`), and
- `~/.0sec/runs/<scan-id>/routing-trace.jsonl` at scan teardown.

The existing static feature flags (`0SEC_FEATURE_HOLDING_IT_WRONG`, `0SEC_FEATURE_POV_GATE`, etc.) still gate whether a layer **can** run; the router decides which of the available layers actually runs per finding. The router can never invoke a layer the operator explicitly disabled via the env var.

## Related work

- [0sec#113](https://github.com/0sec-labs/0sec/issues/113) — issue tracking this work
- [0sec#112](https://github.com/0sec-labs/0sec/issues/112) — per-layer telemetry (prerequisite, already shipped)
- [0sec#67](https://github.com/0sec-labs/0sec/issues/67) — joint paper plan
- [0sec#72](https://github.com/0sec-labs/0sec/issues/72) — the ablation that motivated this
- [Dynamic Routing Design Doc](/research/dynamic-routing-design/) — full design discussion
