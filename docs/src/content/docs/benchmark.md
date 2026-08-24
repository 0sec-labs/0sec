---
title: Benchmark
description: How 0sec scores on public security benchmarks — a secondary, condition-specific signal.
---

**We care about real vulnerabilities, not leaderboards.** 0sec's proof is the
running, verified track record of real bugs disclosed in the Linux kernel and
widely-used open source, with maintainer review — that lives at
**[0.security](https://0.security)**, not on this page.

Public CTF benchmarks are a *secondary* signal. They tell you the core pipeline
isn't broken; they don't tell you the agent finds real CVEs. CTF challenges are
far smaller than real repos, and cross-project scores are protocol-sensitive
(different fork, model, turn cap, retry protocol), so treat every number below as
specific to its test conditions, not a like-for-like leaderboard.

## Where 0sec stands (honest, condition-specific)

| Benchmark | Score | Conditions & caveats |
|-----------|-------|----------------------|
| [XBOW](https://github.com/xbow-engineering/validation-benchmarks) web CTFs | **93 / 95 = 97.9%** black-box | gpt-5.4 model-specific cohort — per-model single-shot solve rate, not a best-of-N union. ~$0.48/run, **$5.20/flag**. |
| [Cybench](https://github.com/andyzorigin/cybench) | **36 / 40 = 90.0%** | First full-suite run, single-config (Azure gpt-5.4), single-shot, 3 retries. BoxPwnr's 40/40 is best-of-N across ~10 configs — not directly comparable. |
| npm audit (81 packages) | **F1 = 0.973** | `none` profile, 100% TPR, FPR 0.11. Self-published ground-truth set; see the [ablation log](/research/2026-04-11-ablation/). |
| AI/LLM suite (10 challenges) | 10 / 10 | Self-authored regression suite, not an independent benchmark. |
| [AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench) / [HarmBench](https://www.harmbench.org/) | Not scored yet | Harness built; no published score. |

**Read the numbers honestly.** The XBOW figure we lead with is the per-model
gpt-5.4 cohort (93/95), because it is a stable single-model solve rate rather than
a union over an aging artifact-retention window. A wider retained-artifact
aggregate exists but is rotation-volatile and is not the headline. Benchmarks here
are single-model, single-config; cross-model cost isn't published; and the 10/10
AI suite is self-authored. For the full measurement discipline — per-attempt rate,
Wilson confidence intervals, and why a single solve is an anecdote — see
[Methodology](/methodology/).

## Running the benchmarks

```bash
pnpm --filter @0sec/benchmark xbow --agentic          # XBOW web CTFs (Docker)
pnpm --filter @0sec/benchmark cybench                 # Cybench, all 40 (Docker)
pnpm --filter @0sec/benchmark npm-bench               # npm audit ground-truth set
pnpm --filter @0sec/benchmark autopenbench            # AutoPenBench (Linux Docker)
pnpm --filter @0sec/benchmark harmbench --target <url># HarmBench LLM safety
```

XBOW, Cybench, and AutoPenBench use Docker-based targets; HarmBench and npm-bench
are lighter-weight and don't require Docker. Scoring is a binary flag check: a
challenge passes when the agent extracts the planted `FLAG{...}`, so there is no
subjective severity scoring.

## Related

- **[0.security](https://0.security)**
- [Methodology](/methodology/) — per-attempt rate, Wilson CI, single-model caveats
- [XBOW Analysis](/research/xbow-analysis/) — how the XBOW score is built, and its limits
- [Competitive Landscape](/research/competitive-landscape/) — where other agents sit, briefly
