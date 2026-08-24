---
title: Benchmark methodology
description: How 0sec measures itself on XBOW — what "percent solved" actually means, why a single solve is not a benchmark, and why the honest number matters.
---

Benchmarks are a secondary signal for 0sec; the real proof is disclosed CVEs at
**[0.security](https://0.security)**. But if we quote a benchmark number, it should
be measured honestly — so this page documents exactly how a raw pile of XBOW
attempts becomes a headline, and which choices move that headline by several points.

"We solved 96% of XBOW" sounds like a property of the agent. It isn't. It's a
property of the agent *plus* the substrate (which XBOW fork), the model, the turn
cap, the feature stack, the retry protocol, and the methodology used to turn
attempts into a number. Change any one and the number moves.

## A single solve is an anecdote

On 2026-04-06 a 0sec sweep solved XBEN-061 in 8 turns and we nearly promoted that
config to a recommended default. The same afternoon a regression run of the same
config against the same challenge *failed*; the true per-attempt rate was later
estimated at 20–40%. One solve, one failure. Single-shot results cannot be promoted
to defaults — which is why 0sec measures with a `--repeat N` harness rather than a
single lucky run.

## Three methodologies, one raw dataset

Imagine you ran a challenge 10 times under one configuration and it solved on run #3
only. Each methodology reports that same dataset differently:

1. **Single-shot** — run once, report pass/fail. The number you publish is a coin
   flip on noise; two labs running the identical agent can report wildly different
   headlines. This is what most "we solved X%" press releases do.
2. **Best-of-N aggregate** — run N times, report "solved" if *any* run found the
   flag. XBEN-061 counts as solved. A 1/10 lucky run scores the same as 10/10
   reproducible; best-of-N conflates "the agent can do this" with "the agent
   sometimes accidentally does this." The published XBOW protocol permits it.
3. **Per-attempt rate with Wilson CI** *(what 0sec uses internally)* — run N times,
   report `passes / N` with a 95% Wilson score interval. XBEN-061 becomes a 10%
   rate, CI roughly `[0.018, 0.404]`. The wide interval is the point: at N=10 a 10%
   observed rate is compatible with anything from "rarely" to "~40% of the time," so
   you don't ship a default off it. This is the only number that answers "would this
   work next Tuesday against a customer's real app?"

### Why Wilson, not Wald

At N=10 near rates of 0 or 1 — exactly the XBOW regime — the normal-approximation
(Wald) interval is wrong: it collapses to `[0, 0]` when k=0 and can extend outside
`[0, 1]`. The [Wilson score interval][wilson] fixes both, and it's what `--repeat N`
emits in `successRateCI95`.

[wilson]: https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval

```
p      = passes / attempts
z      = 1.96                     # 95% CI
center = (p + z²/(2n)) / (1 + z²/n)
margin = (z * sqrt(p(1-p)/n + z²/(4n²))) / (1 + z²/n)
CI95   = [center - margin, center + margin]
```

## Single-config vs. aggregate-of-configs

There's a second axis once you run the same benchmark under *multiple*
configurations (different models, solvers, prompts):

- **Single-config** — one setup, once per challenge. Answers "what can I expect from
  this exact setup on a fresh run?" — usually what a buyer is actually asking.
- **Aggregate (best-of-N union over configs)** — run K configs and count a challenge
  solved if any config ever flagged it; cost sums across configs. Answers "what's the
  ceiling of this whole stack?" — the more impressive headline.

Both are honest, but a single-config 80% and an aggregate 97% are **not comparable**;
treating them as if they were is the trap. For XBOW, 0sec publishes both and labels
them: the headline is the **per-model gpt-5.4 cohort (93/95 = 97.9%)** — a
single-config single-shot solve rate — and a wider retained-artifact aggregate is
disclosed separately as a ceiling claim (see [Benchmark](/benchmark/) for the exact
distinction).

## $/flag is a first-class axis

A solve rate with no cost attached invites "how much compute did that take?" An
agent that hits 95% at $50/run is a different product from one that hits 95% at
$0.50/run. `$/flag` ties the score to cost: it turns a percentage into a budget, and
shows when an aggregate buys its extra points by spending 10× the compute. 0sec
publishes `$/flag` (currently $5.20 at $0.48/run on the gpt-5.4 XBOW cohort) as a
first-class comparison axis, and encourages other evaluators to do the same.

## What 0sec publishes with every number

Every XBOW result we quote ships with the substrate needed to reproduce it:

- **Fork** (upstream / `0ca` patched / `KeygraphHQ`) at a specific git sha
- **Model** — exact model ID and provider
- **Turn cap** — max tool calls per attempt
- **Feature stack** — the `0SEC_FEATURE_*` flags in effect
- **Retry protocol** — best-of-K vs. repeat-N, and the value
- **Per-attempt success rate** and its **95% Wilson CI**
- **Cost ceiling** — the `--repeat-cost-ceiling-usd` in effect

That's the JSON schema `packages/benchmark/README.md` emits at `--repeat > 1`, and
what CI uploads on every scheduled run. The repo also keeps an explicit
[benchmark ledger](https://github.com/0sec-labs/0sec/blob/main/packages/benchmark/results/benchmark-ledger.json)
separating the retained artifact-backed tally from the older historical publication
line.

Most competitor reports omit most of this — not because anyone is lying (the XBOW
protocol allows best-of-N, and everyone knows single-shot is noisy) but because the
headline is the product. 0sec's bet is simpler: it's cheaper to publish the real
number now than to explain the inflated one later.

## Run the harness yourself

```sh
pnpm --filter @0sec/benchmark xbow \
  --agentic \
  --only XBEN-010,XBEN-051,XBEN-061,XBEN-066,XBEN-080,XBEN-084,XBEN-099,XBEN-104 \
  --repeat 10 \
  --repeat-cost-ceiling-usd 5.00 \
  --fresh --json
```

Or trigger `XBOW Benchmark` under GitHub Actions with `repeat: 10`. Either way the
run emits `xbow-latest.json` with `repeatProtocol`, `successRate`, and
`successRateCI95` per challenge — treat those raw outputs as inputs to the ledger,
not a second hand-maintained source of truth.

## Related

- **[0.security](https://0.security)**
- [Benchmark](/benchmark/) — the compact score view and caveats
- [XBOW Analysis](/research/xbow-analysis/) — how the XBOW score is built and its limits
- [Competitive Landscape](/research/competitive-landscape/) — where other agents sit
