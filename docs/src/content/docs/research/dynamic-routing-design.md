---
title: Dynamic Triage Routing — Design Doc
description: A learned per-finding classifier that picks which subset of pwnkit's triage layers to run, motivated by the 2026-04-11 ablation finding that no static policy wins on all three benchmark slices.
---

> **Status:** Design doc, open for review. Tracking issue [pwnkit#113](https://github.com/0sec-labs/0sec/issues/113). Nothing is implemented yet; this page describes what we're going to build and why.

## The problem in one paragraph

The 2026-04-11 ablation ([writeup](/research/2026-04-11-ablation/), [full data](/research/fp-reduction-moat/)) measured pwnkit's 11-layer FP reduction moat on three benchmark slices. No single static triage policy wins on all three. `no-triage` wins XBOW white-box by flag count. `moat` strictly dominates on XBOW black-box. `none` wins npm-bench on FPR. The single-feature isolation found that `reachability` is the best individual layer on stubborn-14 (+3 flags at $1.61/flag) while `egats` is the only one that regresses (−1 flag at $15.93/flag). Different layers help different findings, and a static scan-level feature-flag system can't pick the right subset per finding. A learned router can.

## Design goals

1. **Per-finding layer selection.** The router sees a finding and emits a subset of triage layers to invoke. The scan-level `PWNKIT_FEATURE_*` flags stay as escape hatches, but they're no longer the right granularity for production.
2. **Beat the best static profile on every slice simultaneously.** The bar to clear is: at least match `no-triage` on XBOW white-box, at least match `moat` on XBOW black-box, at least match `none` on npm-bench. Any learned policy that doesn't do better than the best static policy on its own home turf is worse than just picking the right static policy per slice by hand.
3. **Sub-millisecond inference.** The router runs on every finding before the expensive triage layers execute. It cannot become a bottleneck. 45-feature vector + small MLP head, no network calls, no GPU.
4. **Interpretable enough to debug.** When the router skips a layer for a finding, an operator should be able to understand why. This rules out big opaque transformers and pushes toward additive feature importance.
5. **Feature-flag-gated for A/B testing.** Every pwnkit behavior change lands behind a flag so we can measure its effect. The router ships as `PWNKIT_FEATURE_LEARNED_ROUTER` default OFF, A/B tested against the existing static profiles in CI, and promoted to default ON only after measured gains on all three slices.

## What the router sees

Two classes of inputs:

**Per-finding inputs** (from the attack agent output):
- The 45-element handcrafted feature vector from [`feature-extractor.ts`](/research/feature-extractor/) — same vector VulnBERT-style hybrid architectures consume
- Encoded category (`sql-injection`, `xss`, `ssrf`, `information-disclosure`, etc. — one-hot over ~20 categories)
- Severity ordinal
- Agent-assigned confidence (0.0–1.0)
- Presence of CWE/CVE references
- Evidence completeness score (derived from the feature vector)

**Per-scan inputs** (constant across a scan):
- Mode (`white-box` / `black-box` / `mcp` / `web`)
- Target type (`web-app` / `url` / `npm-package` / `source-code` / `oci-image`)
- Benchmark slice when applicable (`xbow` / `npm-bench` / `production` / `unknown`)

The mode and target-type inputs are first-order predictors per the ablation — `moat` is good on black-box and bad on white-box, `none` is good on npm-bench, etc. A router that doesn't see these will underperform static profiles; a router that does see them should strictly improve on any static per-slice choice.

## What the router outputs

A multi-label verdict over the 10 triage layers (the 6 triage-stage layers covered by [pwnkit#112](https://github.com/0sec-labs/0sec/issues/112)'s telemetry plus the 4 verify-stage layers that ship to telemetry in v2):

```ts
interface RouterOutput {
  // Primary output: which layers should run for this finding
  runLayers: TriageLayerName[];
  skipLayers: TriageLayerName[];

  // TP/FP probability — same head as a standalone triage classifier
  // would use. Bypasses the layers entirely when confidence is extreme.
  tpProbability: number;

  // Decision shortcuts
  autoAccept: boolean;  // tpProbability > accept_threshold → skip all layers, mark accepted
  autoReject: boolean;  // tpProbability < reject_threshold → skip all layers, mark FP

  // For debugging / interpretability
  reason: string;       // short human-readable explanation
  featureImportances?: Record<string, number>;
}
```

The `autoAccept` / `autoReject` shortcut paths are where the TP/FP head provides the most value — if the classifier is confident either way, no layer needs to run at all, and that's a pure cost win. The multi-label `runLayers` output is where the router earns its keep on the middle 60-80% of findings where no single static profile is right.

## Training signal

Every layer verdict entry logged by [pwnkit#112](https://github.com/0sec-labs/0sec/issues/112) is a training example. A finding that accumulates `layerVerdicts` of the form:

```json
[
  { "layer": "holding_it_wrong", "verdict": "pass", "durationMs": 0.3, "costUsd": 0 },
  { "layer": "evidence_gate", "verdict": "pass", "confidence": 0.83, "durationMs": 0.1, "costUsd": 0 },
  { "layer": "oracle", "verdict": "downgrade", "confidence": 0.4, "reason": "only 1/3 sqli signals fired", "durationMs": 4231, "costUsd": 0 }
]
```

is a labeled example of "which layers mattered for this finding." The router is trained to predict, for each layer independently:

1. **Would the layer change the final verdict if we ran it?** If the answer is "no, it would just pass or be skipped," the router learns to skip it. If "yes, it would reject or downgrade," the router learns to run it.
2. **Was the layer worth the cost?** `layerVerdicts[i].costUsd` and `layerVerdicts[i].durationMs` let us compute a "cost saved per verdict change" ratio per layer type. Layers with near-zero cost (holding_it_wrong, evidence_gate, reachability, oracles — all regex/grep/deterministic) should essentially always run. Layers with real LLM cost (structured_verify, consensus, adversarial_debate) should only run when the router predicts they're likely to flip the verdict.

The ground-truth final verdict comes from:
- Flag extraction for XBOW rows (flag found = true positive)
- Package verdict for npm-bench rows (malicious/vulnerable = true positive; safe = false positive)
- Blind verify status for local scan DB rows

See the [Triage Dataset](/research/triage-dataset/) page for the full JSONL schema and [pwnkit#114](https://github.com/0sec-labs/0sec/issues/114) for `triage-dataset-v1.jsonl` (969 rows from the 21 ablation runs, with `layer_verdicts` populated on rows from commits post-[`6f1a889`](https://github.com/0sec-labs/0sec/commit/6f1a889)).

## Model class

Three candidates, in order of preference:

### Option A: XGBoost multi-label head on the 45-feature vector

- **Pros:** Sub-millisecond inference on CPU, feature importances fall out of the model for free, small enough to ship in the npm package, trains in minutes on 1k-10k labeled rows.
- **Cons:** Can't leverage the finding text directly — only the 45 handcrafted features. The cross-attention fusion that makes VulnBERT hit 92% recall / 1.2% FPR doesn't have an analogue here.
- **When it wins:** If the 45 handcrafted features carry most of the signal (which the VulnBERT ablation on kernel commits suggests — features alone get 76.8% recall). On a dataset our size (1k–10k rows), a gradient-boosted tree is likely to outperform a small neural net anyway.

### Option B: Small MLP head on fused (features, CodeBERT embedding)

- **Pros:** Matches VulnBERT's architecture — handcrafted features linearly projected, fused with a neural text embedding via cross-attention, classification head on top. The winning numbers on kernel commits are 92.2% recall / 1.2% FPR with this exact shape. We have the feature half shipped; CodeBERT is off-the-shelf at `microsoft/codebert-base`.
- **Cons:** Inference cost is higher (CodeBERT forward pass is ~10ms on CPU, ~1ms on GPU — not sub-millisecond). Training needs a GPU for any reasonable turnaround. The model weights are ~125M parameters, too big to ship in the npm package; we'd need a separate model distribution mechanism (HuggingFace Hub at inference time, or a local cache directory).
- **When it wins:** If Option A plateaus below the "beat every static profile" bar, and if we're willing to pay the inference cost for a measurable accuracy gain. This is the option most directly aligned with VulnBERT's published architecture (Guanni Qu, Pebblebed Research Residency).

### Option C: Knowledge distillation from a larger LLM

- **Pros:** Could leverage larger text encoders for richer embeddings. Fine-tune GPT-5.4-mini on the routing labels, distill into a small student model for inference.
- **Cons:** Highest training cost, most complex pipeline, slowest iteration.
- **When it wins:** If Options A and B both plateau and we're ready to commit a sprint to a real ML pipeline.

**Recommendation:** Ship Option A first. It's the simplest thing that could clear the bar. If XGBoost-on-features beats every static profile on every slice, that's a complete paper in itself and we don't need a neural model. If it doesn't, we know exactly how much headroom Option B needs to justify its cost.

### Phase 3 results (2026-04-12): Option A trained and evaluated

XGBoost (100 trees, depth 5, focal-loss-style `scale_pos_weight`) trained on `triage-dataset-v2.jsonl` (1514 rows). Model at `packages/benchmark/results/triage-router-v1.json`.

**Aggregate 5-fold CV:** F1=0.944, precision=0.969, recall=0.920, AUC=0.886.

**Leave-one-slice-out (the generalization test):**

| Held-out | F1 | TP recall | FP recall |
|---|---:|---:|---:|
| npm-bench | **0.664** | 50% | 84% |
| xbow-bb | 0.859 | 78% | 33% |
| xbow-wb | 0.900 | 93% | 12% |

**Cross-slice generalization is poor.** A model trained on xbow catches only 50% of npm-bench TPs. Adding slice-type indicators (+3 features) improved npm-bench to 0.705 — marginal.

**Per-slice classifiers (Path B) are the clear winner:**

| Slice | Within-slice F1 |
|---|---:|
| npm-bench | **0.930** ± 0.025 |
| xbow-wb | **0.914** ± 0.023 |
| xbow-bb | 0.721 ± 0.363 (n=115) |

**Feature importance is completely different per slice:**
- npm-bench: `text_description_length` (50%) — longer descriptions predict TP
- xbow-bb: `cross_response_request_length_ratio` (53%) — bigger response ratio predicts TP
- xbow-wb: `req_path_traversal` (12%), `req_param_count` (12%), `resp_error_message` (7%) — actual exploit indicators

**Decision:** Per-slice classifiers (Path B) are the deployment target. The scanner knows its mode + target-type at scan start — dispatch to the right classifier. Each runs sub-millisecond on CPU. The augmented single-model approach (Path A) does not clear the bar for npm-bench generalization.

**Deployment options (ordered by shipping speed):**
1. **Hand-coded thresholds** from the model's learned splits — ships today in TypeScript, zero deps
2. **JS XGBoost loader** — npm package that reads the JSON model, moderate accuracy
3. **ONNX runtime** — export to ONNX, load via `onnxruntime-node`, highest accuracy, adds native dep

## Training objective

For the multi-label routing head (one binary classifier per layer):

$$\mathcal{L}_{\text{route}} = \sum_{l \in \text{layers}} w_l \cdot \text{BCE}(\hat{y}_l, y_l)$$

where $y_l = 1$ if the layer changed the final verdict on this finding's ground truth, $0$ otherwise, and $w_l$ is a per-layer weight that penalizes false negatives more on expensive layers (we'd rather accidentally run a cheap layer than accidentally skip an expensive one when it would have caught a FP).

For the TP/FP head (binary classification):

$$\mathcal{L}_{\text{tp}} = \alpha \cdot \text{BCE}(\hat{p}, y)$$

where $y \in \{0, 1\}$ is the final verdict (flag found / package verdict / blind verify status) and $\alpha$ balances the head against the routing loss.

Combined: $\mathcal{L} = \mathcal{L}_{\text{route}} + \lambda \cdot \mathcal{L}_{\text{tp}}$, with $\lambda$ swept over $\{0.1, 0.5, 1.0, 2.0\}$ in the ablation.

Focal loss on both heads to handle the class imbalance (the v1 dataset is 884 TP / 85 FP = 91.2% TP, which is heavy). VulnBERT uses focal loss for exactly this reason and it's the obvious choice.

## Evaluation

Three metrics, one per benchmark slice:

1. **XBOW white-box flag count at limit=50.** Bar to clear: `no-triage` (44/50). The router should pick layer subsets that match or exceed this on white-box findings, while still getting 63% finding-count reduction (matching `moat` on that axis).
2. **XBOW black-box flag count at limit=50.** Bar to clear: `moat` (19/25 at limit=25, extrapolates to ~38/50). The router should match or exceed.
3. **npm-bench F1 on the 81-package set.** Bar to clear: `none` (F1 0.973, FPR 0.11). The router should match or exceed.

Plus a cost metric: **dollars spent per flag on each slice**. A router that matches flag count but costs 2× is not shipping.

And a recall metric: **per-category recall breakdown**. No category should lose more than 5% recall vs the per-slice baseline. If a router fails, say, SQLi findings badly while winning on aggregate, that's a ship blocker.

## Rollout plan

1. **Phase 1: design doc (this page).** Gather feedback on [pwnkit#113](https://github.com/0sec-labs/0sec/issues/113). Target: ~1 week.
2. **Phase 2: training data v2.** Re-run the 21-profile ablation matrix against a commit that has [pwnkit#112](https://github.com/0sec-labs/0sec/issues/112)'s `layerVerdicts` populated across the board. This produces `triage-dataset-v2.jsonl` with per-layer supervision on every row. Target: ~3 days.
3. **Phase 3: Option A XGBoost baseline.** Train, evaluate against the three bars above, report results publicly. Target: ~1 week.
4. **Phase 4: decision.** If Option A clears the bar, ship it behind `PWNKIT_FEATURE_LEARNED_ROUTER=1`, A/B test in CI, promote to default when stable. If Option A plateaus, proceed to Phase 5.
5. **Phase 5 (contingent): Option B cross-attention model.** Fine-tune CodeBERT + feature projection + routing head on v2 dataset. Target: ~3-4 weeks (requires GPU, distribution pipeline, inference integration). This is the option most aligned with the [VulnBERT](https://pebblebed.com/blog/kernel-bugs) hybrid architecture.
6. **Phase 6: paper.** Submit to a security venue (IEEE S&P, USENIX Security, CCS). Scope: "Learned dynamic triage routing for LLM-agent vulnerability scanners." First half of the empirical section is the [2026-04-11 ablation results log](/research/2026-04-11-ablation/); second half is the router's measured improvement over the best static profile per slice.

## Open questions

- **How do we handle the imbalance on the v1 dataset?** 91.2% TP is way outside the range the VulnBERT paper's focal-loss tuning was validated on. We may need to undersample TP rows during training, or move to a more TP/FP-balanced dataset (possibly by running pwnkit against more benign npm packages to generate more FPs).
- **Does the router get to see the attack agent's conversation history?** Right now the 45 features only see the finding itself. The agent's reasoning trail (which strategies it tried, what signals it followed, what it gave up on) might contain useful signal for the router. But including it risks making the router effectively a full LLM call, which defeats the sub-millisecond goal.
- **Can the router bypass layers the agent already implicitly covered?** For example, if the attack agent successfully exploited an SQLi and captured a flag, the oracle layer would re-attempt the exploit and presumably succeed. Running it is redundant. The router could learn "if the finding has a flag-shaped response, skip all oracles."
- **How do we avoid benchmark overfitting?** XBOW is 104 challenges. npm-bench is 81 packages. If the router learns the specific finding shapes of these two benchmarks, it won't generalize to production targets. We need a held-out slice that isn't in any training set — possibly a fresh sweep against production bug bounty programs with manual ground-truth labeling.
- **What's the right interaction with [pwnkit#116](https://github.com/0sec-labs/0sec/issues/116) (egats disable)?** Should the router learn when egats *would* help (and opt it in for those findings)? Or should we treat the layer as permanently off until we rewrite it against the MAPTA scoring function? Currently leaning toward the latter — a broken layer shouldn't be in the router's action space.

## Related

- [2026-04-11 Ablation writeup](/research/2026-04-11-ablation/) — the measurement that motivates this design
- [FP Reduction Moat](/research/fp-reduction-moat/) — the static triage stack this design replaces
- [Finding Triage ML](/research/finding-triage-ml/) — the original hybrid ML design doc, this page supersedes its routing section
- [Triage Dataset](/research/triage-dataset/) — the JSONL schema the router trains on
- [Feature Extractor](/research/feature-extractor/) — the 45 handcrafted features
- [pwnkit#72](https://github.com/0sec-labs/0sec/issues/72) — the ablation data, with run IDs and per-comment result tables
- [pwnkit#112](https://github.com/0sec-labs/0sec/issues/112) — per-finding `layerVerdicts` telemetry (prerequisite, shipped 2026-04-11)
- [pwnkit#113](https://github.com/0sec-labs/0sec/issues/113) — this tracking issue
- [pwnkit#114](https://github.com/0sec-labs/0sec/issues/114) — `triage-dataset-v1.jsonl` (first training data, shipped 2026-04-11)
- [pwnkit#116](https://github.com/0sec-labs/0sec/issues/116) — disable `egatsTreeSearch` by default (done 2026-04-11)
- [VulnBERT — Guanni Qu, Pebblebed Research Residency](https://pebblebed.com/blog/kernel-bugs) — the hybrid classifier architecture this design is modeled on (91.4% recall / 5.9% FPR on Linux kernel commits)
