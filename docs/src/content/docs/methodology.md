---
title: Benchmark methodology
description: How pwnkit measures itself on XBOW — what "percent solved" actually means, why a single solve is not a benchmark, and why methodology disclosure is the moat.
---

If you read enough pentesting-agent press releases you will notice that
"we solved 96% of XBOW" is made to sound like a property of the agent.
It is not. It is a property of the agent, the substrate (which XBOW
fork), the model, the turn cap, the feature stack, the retry protocol,
*and* the methodology used to turn raw attempts into a headline number.
Change any one of those and the number moves several points.

This page documents the three methodologies you can apply to the same
raw data, why pwnkit defaults to the harshest one internally, and why
we publish the rest of the substrate alongside it.

## A worked example: XBEN-061

On 2026-04-06 a pwnkit v1 sweep solved XBEN-061 in 8 turns with a
`handoff,no-hiw,no-evidence` feature combo. We promoted that solve to
a "winning configuration" recommendation, shipped it in a blog post,
and pinned it on the public roadmap as the lean-scaffolding default.

The same afternoon, a regression test ran the same combo against the
same challenge with a fresh workspace. It failed in 10 turns. A
subsequent investigation estimated the true per-attempt success rate
for that combo on that challenge at somewhere in the **20–40%** range.

One solve. One failure. And a recommendation that had already shipped.

The lesson: **a single XBOW solve is an anecdote, not a benchmark.**
Single-shot results cannot be promoted to defaults. That is what the
`--repeat N` harness ([issue #81]) exists to prevent.

[issue #81]: # <!-- github.com/0sec-labs/0sec/issues/81 — repo archived -->

## Three methodologies, one raw dataset

Imagine you ran XBEN-061 ten times under the same configuration and
the agent solved it on run #3 only. That is a fixed 10-attempt dataset
with one flag found. Here is how each methodology reports it.

### 1. Single-shot (what you usually see in headlines)

Run each challenge **once**. Report `passed` or `failed`. Tally the
pass count and divide by the number of challenges. Done.

- **Under this methodology**, the result for XBEN-061 depends entirely
  on which run you picked. On runs 1, 2, 4, 5, 6, 7, 8, 9, 10 you
  publish "failed." On run 3 you publish "96.15% (+1)."
- **The problem:** the number you publish is a coin flip on noise.
  Two labs can run the exact same agent against the exact same fork
  and get wildly different headline numbers.
- **Who uses it:** almost every "we solved X% of the benchmark" press
  release. It is the cheapest method to run and the easiest to spin.

### 2. Best-of-N aggregate (what the published XBOW protocol allows)

Run each challenge **N times**. Report "solved" if the agent ever
found the flag in any of the N runs.

- **Under this methodology**, XBEN-061 is reported as **solved**,
  because run #3 found the flag. A 1/10 lucky run counts the same as
  10/10 reproducible runs. The report has no way to distinguish them.
- **The problem:** best-of-N conflates "the agent can do this"
  with "the agent sometimes accidentally does this." In a pentest
  that distinction is the whole game: a 10% solve rate means you pay
  9 wasted context windows for every flag, and you have no idea
  whether the one that worked was skill or luck.
- **Who uses it:** most competitor reports that bother to run
  multiple attempts at all. The published XBOW protocol permits this,
  so nobody is cheating — they are just reporting the number that
  makes them look best.

### 3. Per-attempt success rate with Wilson CI (what pwnkit measures internally)

Run each challenge **N times**. Report **passes / N** as the per-attempt
success rate, along with a 95% Wilson score confidence interval.

- **Under this methodology**, XBEN-061 gets a **10% success rate**
  with a 95% CI of roughly `[0.018, 0.404]`. The CI is wide — that is
  the point. It tells you plainly that at N=10 a 10% observed rate is
  compatible with anything from "occasionally works" to "about 40% of
  the time." You do not ship a lean-scaffolding default off a 1/10
  data point, and the CI is what stops you.
- **The problem:** the headline number drops. A lot. "We get 30% of
  XBOW per attempt, confidence interval wide" does not fit on a
  billboard the way "96% solved" does.
- **Who uses it:** this is the number the pwnkit team uses internally
  to decide whether a feature combo ships. It is the only number that
  answers "would this work next Tuesday against a customer's real
  app?"

### Why Wilson and not Wald

At N=10 with rates near 0 or 1 — which is exactly the XBOW regime —
the normal-approximation ("Wald") interval is wrong in two obvious
ways. It produces `[0, 0]` when k=0 (implying zero uncertainty about
a rate we have barely measured), and it can extend outside `[0, 1]`
for rates near the boundaries. The [Wilson score interval][wilson]
fixes both. It is the right CI to publish alongside a small-N
binomial rate, and it is what `--repeat N` emits in `successRateCI95`.

[wilson]: https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval

The Wilson formula, for the record:

```
p      = passes / attempts
z      = 1.96                     # 95% CI
center = (p + z²/(2n)) / (1 + z²/n)
margin = (z * sqrt(p(1-p)/n + z²/(4n²))) / (1 + z²/n)
CI95   = [center - margin, center + margin]
```

## Single-config vs aggregate-of-configs

The three methodologies above all assume one configuration — same model,
same solver, same feature stack — applied to each challenge. There is a
second axis that matters once an evaluator runs the same benchmark under
*multiple* configurations (different models, different solver
strategies, different prompt variants) and wants to roll those
attempts up into a single headline number.

There are two natural ways to do that:

- **Single-config** — pick one configuration, run it once per challenge,
  report the result. Whatever number comes out is the score for *that
  configuration*. If you change models, you get a different cohort and
  a different number.
- **Aggregate (best-of-N union over configs)** — run the benchmark under
  K different configurations (often dozens of traces per challenge in
  total) and count a challenge as solved if *any* configuration ever
  flagged it. The headline is the union; per-attempt cost is summed
  across configs.

Both are honest measurements. They answer different questions:

- "What can I expect out of this single setup on a fresh run?" — that's
  the single-config number, and it's what most buyers are actually
  asking.
- "What is the ceiling of what this stack of agents and models, taken
  together, can solve?" — that's the aggregate number, and it is the
  more impressive headline.

A single-config 80% and an aggregate 97% are not comparable; they answer
different questions on the same benchmark. Treating them as if they
were is the trap.

### Why pwnkit reports two numbers on the same benchmark

For XBOW, pwnkit publishes both:

- A **per-model cohort** number: 93/95 = 97.9% on the gpt-5.4 cohort —
  the single-config single-shot solve rate for the model we currently
  run in CI. This is the number that answers "how does pwnkit perform
  next Tuesday on this exact model."
- A **retained artifact-backed aggregate** number: 103/104 = 99.0% — the
  union of every flag that has been independently re-verified from a
  retained CI artifact within the live retention window. This is the
  ceiling claim, and the one we can re-prove from disk.

The two numbers exist because they are answering different questions
about the same raw data. We surface both so a reader picking the lower
one for a head-to-head comparison can do so without needing to ask.

### Why $/flag is a useful comparison axis when published

A solve-rate number with no cost attached invites the reasonable
question "how much compute did that take?" — an agent that hits 95% at
$50 a run is not the same product as an agent that hits 95% at $0.50 a
run, even when the percentages match.

`$/flag` (or equivalently, average `$/run` divided by the per-run solve
rate) is the most useful single-number cost axis for an autonomous
pentest agent because:

- It is normalized to outcomes, not effort. Two configs that spend the
  same average compute but solve at different rates have different
  `$/flag`.
- It lets a buyer convert a benchmark percentage into a budget. A
  100-target external scan at `$X/flag` has a knowable expected cost.
- It is the natural denominator when comparing best-of-N aggregates: an
  aggregate that hits 99% by spending 10× the compute of a single-config
  97% has a worse `$/flag`, and that fact only shows up when cost is
  reported.

pwnkit publishes `$/flag` (currently $5.20/flag at $0.48/run on the
gpt-5.4 XBOW cohort) on the [benchmark page](/benchmark/) alongside the
solve-rate numbers, and treats it as a first-class comparison axis. We
encourage other evaluators to do the same; benchmark numbers without a
cost denominator are difficult to compare across stacks.

## What pwnkit publishes

pwnkit publishes the **per-attempt success rate** with its 95% Wilson
CI for every feature-combo evaluation. We also publish the substrate
you need to reproduce the number.

Specifically, every XBOW result we quote comes with:

- **Fork**: which XBOW repo (upstream / `0ca/xbow-validation-benchmarks-patched` /
  `KeygraphHQ/xbow-validation-benchmarks`), at which git sha
- **Model**: exact model ID and provider (Azure `gpt-4o-2024-08-06`,
  Anthropic `claude-sonnet-4.6`, etc.)
- **Turn cap**: the maximum number of tool calls per attempt
- **Feature stack**: the full set of `PWNKIT_FEATURE_*` flags in effect
  (`handoff`, `no-hiw`, `no-evidence`, etc.)
- **Retry protocol**: best-of-K vs. repeat-N, and the value of K or N
- **Per-attempt success rate**: `passes / attempts` as a float
- **95% Wilson CI**: `[lower, upper]` on that success rate
- **Cost ceiling**: the `--repeat-cost-ceiling-usd` value in effect
  (and whether any cell hit it)

That is what the JSON schema in
`packages/benchmark/README.md`
emits when you run with `--repeat > 1`, and it is what the CI workflow
uploads as a build artifact on every scheduled run. The repo now also keeps
an explicit benchmark ledger at
[`packages/benchmark/results/benchmark-ledger.json`](https://github.com/0sec-labs/0sec/blob/main/packages/benchmark/results/benchmark-ledger.json)
to separate the **retained artifact-backed tally** from the older
**historical mixed local+CI publication** line.

## Methodology disclosure as a moat

Here is the uncomfortable part. Most competitor reports omit most of
the above. You will see "96.15% XBOW solved" without the fork, without
the turn cap, without the retry protocol, and with zero mention of
confidence intervals or per-attempt rates. Not because anybody is
lying — the published XBOW protocol allows best-of-N aggregation, and
everybody knows single-shot numbers are noisy — but because the
headline number is the product and nobody wants to bring a sharper
knife to a marketing fight.

pwnkit's bet is that eventually the people who actually buy pentesting
tools start asking the hard questions, and the lab whose readme
already has the answers wins. The n=10 harness exists so that when
someone asks "did that number hold up under repeated evaluation," we
can answer yes with a Wilson CI and a JSON artifact, instead of
shrugging.

It is cheaper to publish the real number now than to explain the fake
one later.

## How to run the harness yourself

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --agentic \
  --only XBEN-010,XBEN-051,XBEN-061,XBEN-066,XBEN-080,XBEN-084,XBEN-099,XBEN-104 \
  --repeat 10 \
  --repeat-cost-ceiling-usd 5.00 \
  --fresh --json
```

Or, via GitHub Actions, trigger `XBOW Benchmark` under the Actions tab
and set the `repeat` input to `10`. The workflow will emit a full
`xbow-latest.json` with `repeatProtocol`, `successRate`, and
`successRateCI95` fields populated per challenge. The public benchmark page
should treat those raw outputs as inputs to the ledger, not as a second
hand-maintained source of truth.

## Related

- [Benchmark](/benchmark) — runner overview and CI wiring
- [XBOW Analysis](/research/xbow-analysis) — what makes XBOW a meaningful substrate
- [Competitive Landscape](/research/competitive-landscape) — how the 96%-headline numbers stack up against each other
- [Roadmap](/roadmap) — where the n=10 harness sits in the release plan
