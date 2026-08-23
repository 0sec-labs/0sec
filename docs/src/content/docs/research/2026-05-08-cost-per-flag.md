---
title: "2026-05-08 Cost per Flag: A Missing Axis in Autonomous-Pentest Reporting"
description: "Most autonomous-pentest agents publish a percentage. Few publish a dollar amount. The percentage answers whether the agent CAN find the bug; the cost answers whether you can afford to run it. 0sec publishes both — at $0.48 per scan run and $5.20 per flag on XBOW — and argues that $/flag is the most-disclosable, most-comparable cost axis the field has."
---

> **Historical research log (2026-05-08).** A dated lab note kept for transparency. Dollar figures reflect the benchmark ledger at the time; see the [Benchmarks](/benchmark/) page for current numbers.

*Published 2026-05-08. Numbers come from the canonical [benchmark ledger](https://github.com/0sec-labs/0sec/blob/main/packages/benchmark/results/benchmark-ledger.json) and are recomputed on every CI consolidation run.*

## Lead

Most autonomous-pentest agents publish a percentage. Few publish a dollar amount. The percentage answers "did the agent find the bug." The dollar answers "can you afford to run this on every pull request." Both matter; only one is widely shared. This post argues that the cost axis should not be optional, that `$/flag` is the right shape for it, and shows 0sec's number on XBOW under the same methodology that drives the headline percentages.

## The cost-axis design space

There are four candidate cost denominators an evaluator can publish, and they are not interchangeable.

**`$/run`.** The average cost of one attempt at one challenge. Honest, but it varies wildly with retry policy and turn budget. A 40-turn attempt with three retries against a hard challenge costs more than a 10-turn attempt against an easy one, and `$/run` averages those into a single number that hides which challenge ran how often. Useful as a denominator, not as a headline.

**`$/finding`.** Total spend divided by the number of findings the agent surfaced. This number gets *better* the noisier the scanner is — a tool that emits 50 false-positive findings per real bug looks ten times "cheaper per finding" than one that emits five clean findings. Any cost metric that rewards false-positive volume is a bad metric. Skip it.

**`$/flag`.** Total spend on the benchmark divided by the number of *verified* solves. The flag is the unforgeable artifact: a regex match against `flag{...}` (or `FLAG{...}`) on a benchmark whose ground truth is fixed. The denominator is uncontested. A scanner that hallucinates findings does not get cheaper-per-flag because hallucinations do not produce flags. This is the metric we lead with.

**Total $ for a benchmark sweep.** Useful for budget planning, but only honest if the sweep size is disclosed alongside it. "$540 for XBOW" means nothing without "104 challenges, single-config, single-shot." It is a derived number; `$/flag × flags-found` reproduces it.

`$/flag` is the most-disclosable, most-comparable axis because the flag is the only outcome the evaluator cannot massage. Single-config single-shot `$/flag` is a defensible reference number. Best-of-N `$/flag` is also a fine number — but the report has to disclose N, otherwise the reader has no way to convert it back into per-attempt economics.

## 0sec's number

On the XBOW benchmark, single-config (Azure gpt-5.4), single-shot, with three retries per challenge ceiling-capped at $5.00:

> **gpt-5.4 model-specific cohort: 93 / 95 = 97.9% — $0.48 / run, $5.20 / flag.**
>
> Total spend across the 95 attempted challenges in the consolidation window: **$483.75**.

That is the load-bearing claim from the [benchmark page](/benchmark/). It is computed from the canonical [`packages/benchmark/results/benchmark-ledger.json`](https://github.com/0sec-labs/0sec/blob/main/packages/benchmark/results/benchmark-ledger.json), specifically the `xbow.retainedArtifactBacked.perModel` section:

```json
"gpt-5.4": {
  "label": "Model-specific stable cohort (load-bearing claim)",
  "solved": 93,
  "attempted": 95,
  "ratePct": 97.9,
  "totalCostUsd": 483.75,
  "costPerRunUsd": 0.478,
  "costPerFlagUsd": 5.2
}
```

The pipeline that produces this is straightforward: every scan run logs token counts (input, output, cached-input separately) into its result JSON. `packages/core/src/agent/cost.ts` applies provider-specific per-1M-token rates from a hard-coded pricing table (gpt-5.4 input $2.50/1M, output $10.00/1M; with comparable rows for the Anthropic, Google, DeepSeek, Meta, Mistral, and Z.AI models 0sec also runs). `packages/benchmark/src/scripts/consolidate-xbow.ts` walks every retained `xbow-results-*` GitHub Actions artifact, groups results by model, and the ledger aggregates total spend, divides by attempt count for `$/run`, and divides by solve count for `$/flag`.

The consolidate script's per-model summary line on every CI consolidation run reads:

```
gpt-5.4: 93/95 (97.9%) — $0.48/run, $5.20/flag
```

This number is reproducible. It is recomputed on every CI sweep that lands artifacts in the 200-run lookback window. It is not a one-time disclosure.

## What "cost-aware" means in practice

Three concrete contexts make `$/flag` more than a vanity metric.

**CI gates.** A pre-merge security scan that costs more than a developer hour ($50ish loaded cost per PR) is not economical at the margin. At $5.20 per flag, a scan that turns up 10 verified findings on a real codebase costs about $52 — comparable to the developer time it would take to triage them. At $52/flag (a 10× regression), the same scan costs $520, and the calculus stops working. The cost number tells you whether the gate is a budget item or a procurement decision.

**Bug-bounty economics.** If the agent costs $X to find a bug worth $Y, scaling makes sense only when $Y substantially exceeds $X plus the human-review cost. HackerOne medium-severity bounties typically land in the $300-$1500 range; high-severity averages run higher but are rarer. At $5.20 per submission-grade flag the unit economics work. At $52 per flag they shrink toward zero. Any honest discussion of "AI-driven bounty hunting at scale" has to start with the cost number, because the answer depends on it.

**Research budgets.** A 104-challenge XBOW sweep at $5.20 per flag is roughly $540 for a stabilized agent — affordable as a one-time academic comparison, and small enough that re-running for sensitivity analysis is feasible. At undisclosed cost, the same sweep is not reproducible by an outside party. If the goal is comparable benchmark numbers across research groups, cost has to be one of the disclosed parameters.

## Why most agents do not publish

Cost numbers are missing from most autonomous-pentest reports, and the reasons are structural, not malicious.

**Cost is a dependent variable.** The same agent on Sonnet 4.6 vs gpt-5.4 vs DeepSeek R1 has very different `$/flag`, because the per-1M-token rates and the steady-state token counts both differ. A single number with no disclosed model is not very useful. Multiple numbers (one per model) is more useful but also more disclosure work.

**Best-of-N inflates `$/flag`.** Running each challenge under K configurations for a best-of-N aggregate multiplies total spend by roughly K, while the solved-count denominator only goes up if the additional configurations actually pick up new flags. The harder the unsolved tail, the worse the marginal `$/flag` for the last few percentage points. An evaluator who only publishes the aggregate percentage gets to leave that fact off the table.

**Honest accounting is real work.** A correct cost number requires per-call token counts, provider-specific rates kept current as pricing changes, separate handling of cached-input rates where the provider exposes them (Anthropic does, OpenAI does not in the same way), and aggregation across runs. Not zero work; not the kind of thing that fits in a press release.

**Some pricing is contractual.** Self-hosted models, enterprise pricing tiers, and reserved-capacity arrangements make `$/flag` comparison hard. An evaluator running on private discount pricing cannot publish a number that another lab can reproduce without disclosing the pricing.

None of these are bad reasons. But they do not argue against publishing — they argue for disclosing the *methodology* alongside the number, so a reader can reason about what shifts when the substrate changes.

## What 0sec does that makes this work

The cost number falls out of the benchmark pipeline because cost tracking is built into the agent runtime, not bolted on later.

- Per-token cost tracking lives in `packages/core/src/agent/cost.ts`. Every model the agent runs has an input/output/cached-input rate. Unknown models fall back to a conservative default and emit a log line.
- Per-model breakdown is computed by `packages/benchmark/src/scripts/consolidate-xbow.ts`, which walks the retained CI artifacts and groups results by the `model` field in each run. The ledger then derives `totalCostUsd`, `costPerRunUsd`, and `costPerFlagUsd` per cohort.
- The [methodology page](/methodology/#why-flag-is-a-useful-comparison-axis-when-published) explains the axis in plain prose. This post is the long-form version.

Roadmap-wise, [issue #231](https://github.com/0sec-labs/0sec/issues/231) tracks adding `cost_usd`, `cost_breakdown` (by provider/model), and `cost_per_flag` to the `scan_completed` event payload. Today, reconstructing per-PR cost requires reading the run JSON; once #231 lands, a CI step can emit the cost line directly from the event stream and a budget gate can short-circuit a scan that exceeds policy. The cost-aware-CI story is half-built; this is the half that finishes it.

## What is still missing

A few honest gaps remain.

**Cross-model `$/flag` is not a clean comparison.** The published `$5.20/flag` is gpt-5.4 only. Running the same protocol on Sonnet 4.6 or DeepSeek R1 would produce different numbers — possibly meaningfully different, given the per-token-rate spread (DeepSeek input is ~10× cheaper than gpt-5.4 input; Sonnet output is ~50% more expensive). We have not yet published the side-by-side. The methodology supports it; the engineering time to run a clean cross-model sweep does not yet exist.

**XBOW Docker challenges are small.** A real-world repository or a 50K-LOC monorepo will run 5-20× the per-scan token cost, because the agent burns more turns on enumeration. The XBOW number is a lower bound for "how cheap can this get on a tight target," not a forecast for "what will my repo cost." Anyone using the published number for budget planning should derate accordingly.

**`$/wrong-flag` is not yet published.** The honest counterpoint to `$/flag` is `$/false-positive-the-agent-claimed-was-a-flag` — the cost of the bug-shaped-but-not-real findings the system surfaces. Ground truth on hallucinated flags is harder than ground truth on missed flags, because the negative class is open-ended. A reasonable proxy is "findings the verifier rejected after the agent claimed success," which the triage stack already tracks. We will publish this when the methodology is solid.

## Closer

If you publish autonomous-agent benchmark results without a dollar number, you have published half the result. The percentage tells me whether the agent *can* find the bug. The cost tells me whether I can afford to run it. Either number alone tells a partial story; together they describe a scanner that is or is not deployable.

0sec publishes both. The norm we want to see in the field is that everybody else does too — not because the percentages should be smaller, but because comparison without a cost denominator is comparison without a unit.

## Related

- [Methodology](/methodology/) — the per-attempt success rate, Wilson CI, and single-config-vs-aggregate framing
- [Benchmark](/benchmark/) — current XBOW, Cybench, AutoPenBench, HarmBench, and npm-bench numbers with cost disclosed
- [Competitive Landscape](/research/competitive-landscape) — how the headline percentages stack up; cost numbers are notably absent from competitor reports
