---
title: Benchmark methodology
description: XBOW attempt rates, confidence intervals, configuration disclosure, and cost measurement.
---

XBOW scores depend on the fork, model, turn cap, feature settings, retry protocol, and aggregation method. Published vulnerability disclosures are listed separately at [0.security](https://0.security).

<span id="a-single-solve-is-an-anecdote"></span>
## Repeated attempts

On 2026-04-06, one configuration solved XBEN-061 in eight turns and failed a repeat run that afternoon. Its per-attempt success rate was later estimated at 20–40%. Use `--repeat N` to evaluate a candidate default across repeated attempts.

## Three methodologies, one raw dataset

Run a challenge 10 times under one configuration and it solves on run #3 only. Each methodology reports that dataset differently:

1. **Single-shot** — run once and report pass/fail. Results vary between runs.
2. **Best-of-N aggregate** — count the challenge as solved if any attempt succeeds. Both 1/10 and 10/10 count as solved. The published XBOW protocol permits this method.
3. **Per-attempt rate with Wilson CI** — report `passes / N` with a 95% Wilson score interval. One success in ten attempts gives 10%, with CI roughly `[0.018, 0.404]`. The interval shows the uncertainty at this sample size. 0sec uses this method internally.

<span id="why-wilson-not-wald"></span>
### Interval choice

At N=10 near rates of 0 or 1 — exactly the XBOW regime — the normal-approximation (Wald) interval is wrong: it collapses to `[0, 0]` when k=0 and can extend outside `[0, 1]`. The [Wilson score interval][wilson] fixes both, and it's what `--repeat N` emits in `successRateCI95`.

[wilson]: https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval

```
p      = passes / attempts
z      = 1.96                     # 95% CI
center = (p + z²/(2n)) / (1 + z²/n)
margin = (z * sqrt(p(1-p)/n + z²/(4n²))) / (1 + z²/n)
CI95   = [center - margin, center + margin]
```

## Single-config vs. aggregate-of-configs

For runs across multiple models, solvers, or prompts:

- **Single-config** reports one setup, once per challenge.
- **Aggregate** counts a challenge as solved if any configuration succeeds and sums their costs.

Compare results using the same aggregation method. 0sec's headline is the **per-model gpt-5.4 cohort (93/95 = 97.9%)**, a single-config, single-shot rate. The wider retained-artifact aggregate is reported separately in [Benchmark](/benchmark/).

<span id="flag-is-a-first-class-axis"></span>
## Cost per flag

Report `$/flag` alongside solve rate. The gpt-5.4 XBOW cohort costs $5.20 per flag at $0.48 per run. Aggregate comparisons must include the cost of every configuration.

## What 0sec publishes with every number

Every XBOW result ships with the substrate needed to reproduce it:

- **Fork** (upstream / `0ca` patched / `KeygraphHQ`) at a specific git sha
- **Model** — exact model ID and provider
- **Turn cap** — max tool calls per attempt
- **Feature stack** — the `0SEC_FEATURE_*` flags in effect
- **Retry protocol** — best-of-K vs. repeat-N, and the value
- **Per-attempt success rate** and its **95% Wilson CI**
- **Cost ceiling** — the `--repeat-cost-ceiling-usd` in effect

That's the JSON schema `packages/benchmark/README.md` emits at `--repeat > 1`, and what CI uploads on every scheduled run. The repo also keeps an explicit [benchmark ledger](https://github.com/0sec-labs/0sec/blob/main/packages/benchmark/results/benchmark-ledger.json) separating the retained artifact-backed tally from the older historical publication line.


## Run the harness yourself

```sh
pnpm --filter @0sec/benchmark xbow \
  --agentic \
  --only XBEN-010,XBEN-051,XBEN-061,XBEN-066,XBEN-080,XBEN-084,XBEN-099,XBEN-104 \
  --repeat 10 \
  --repeat-cost-ceiling-usd 5.00 \
  --fresh --json
```

Or trigger `XBOW Benchmark` in GitHub Actions with `repeat: 10`. Each run emits `xbow-latest.json` with `repeatProtocol`, `successRate`, and `successRateCI95` per challenge. Use these outputs to update the benchmark ledger.

## Related

- **[0.security](https://0.security)**
- [Benchmark](/benchmark/) — the compact score view and caveats
- [XBOW Analysis](/research/xbow-analysis/) — how the XBOW score is built and its limits
- [Competitive Landscape](/research/competitive-landscape/) — where other agents sit