---
title: XBOW Analysis
description: Where 0sec's XBOW score comes from, its caveats, and what the benchmark does and doesn't tell you.
---

XBOW is a useful web-CTF substrate, but a benchmark score is not the product. The
proof we care about is real, disclosed CVEs — see **[0.security](https://0.security)**.
This page explains how 0sec's XBOW number is built and where its limits are, so the
figure can be read honestly rather than as a leaderboard trophy.

## How 0sec scores on XBOW, and the caveats

**Headline: 93 / 95 = 97.9% black-box on the gpt-5.4 model-specific cohort.**
Across the 95 XBOW challenges where 0sec has a retained gpt-5.4 attempt within the
live CI window, 93 are solved, at ~$0.48/run and $5.20/flag. We lead with the
per-model number because it is a stable single-model solve rate, not a best-of-N
union over an aging artifact window.

Caveats to keep attached to that number:

- **Single model, single-shot.** The cohort is one model (Azure gpt-5.4) with a
  fixed feature stack and targeted retries, not a multi-model ensemble.
- **A wider retained-artifact aggregate exists but is rotation-volatile.** GitHub
  Actions retains only a 90-day window of run artifacts, so older "unknown"-model
  proofs age out as new sweeps land. The aggregate is real but should not be the
  headline; the per-model cohort is the defensible surface.
- **CTF ≠ real repo.** XBOW challenges are small, single-vuln web apps with a
  planted flag. Solving them says the pipeline works; it says nothing about
  finding a novel bug in a million-line kernel tree.
- **Cross-project scores aren't matched-conditions.** Fork, turn cap, and retry
  protocol all move the number by several points. See [Methodology](/methodology/).

The exact retained-artifact vs. historical-publication distinction and the
challenge-set mismatch live on the [Benchmark](/benchmark/) page and in the
benchmark ledger.

## Where the remaining gaps are

At the retained-artifact layer the unsolved set is small, and clusters into a few
recurring problem types rather than a single systemic weakness:

| Class | Why it's still hard |
|-------|---------------------|
| Hard XSS | Browser-oracle usage still lags the best specialized agents. |
| Blind SSTI / deep exploit chains | Evidence is weak early, so budget gets spent proving exploitability. |
| Complex stateful auth workflows | Multi-step auth chains still degrade reliability. |
| Long-horizon exploit planning | Remaining tasks punish retries that don't materially pivot. |

## Design decisions the benchmark validated

Working against XBOW informed several parts of the harness that also carry over to
real-target scanning:

- **Shell-first.** A `bash` tool plus a tiny result/save interface outperforms
  structured HTTP wrappers — the agent uses curl, python3, and real tools directly.
- **Plan then execute, with reflection checkpoints.** The agent writes a brief
  attack plan before touching the target and is prompted to reassess at ~60% of its
  turn budget rather than repeating a failing approach.
- **Turn budget.** Deep mode runs 40 tool calls with LLM-based context compaction
  (effectively more via re-compaction), in line with published findings that ~40
  calls is the practical sweet spot.
- **Concurrent subagents.** 0sec now ships `spawn_agents`: the lead agent can fan
  out focused children concurrently (bounded fan-out, default concurrency 4) and a
  child can coordinate with its parent. This is a real capability the harness uses.
- **White-box mode.** `--repo <path>` gives the agent source alongside `bash`, which
  lifts the ceiling on challenges with no web-facing vector (e.g. credentials
  hardcoded in source). CI runs black-box and white-box independently.

## Framework vs. model

Much of the score comes from getting the framework out of the model's way — a small
tool surface, a lean prompt, and letting the model's training do the work. But the
framework is doing real load-bearing work too: scope enforcement, context
compaction, loop detection, concurrent subagent fan-out, retry/handoff, and the
separate blind-verify step that decides which findings survive. The scaffolding is
where reliability, safety, and reproducibility come from — the parts that matter far
more on a real target than on a CTF flag hunt.

## Other benchmarks in scope

Beyond XBOW, these are relevant to 0sec's capabilities and are wired or planned:

| Benchmark | Domain | Scale | 0sec relevance |
|-----------|--------|-------|----------------|
| [Cybench](https://github.com/andyzorigin/cybench) | Broad CTF (web/crypto/pwn/rev) | 40 challenges | Scored: 36/40 = 90.0% single-config |
| [AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench) | Network / CVE pentesting | 33 Docker tasks | Harness built; shell-first maps to its `execute_bash` |
| [HarmBench](https://github.com/centerforaisafety/HarmBench) | LLM red-teaming | 510 behaviors | Lightweight `sendPrompt()` harness |
| npm audit (self-published) | Package auditing | 81 packages | F1 = 0.973; see [ablation log](/research/2026-04-11-ablation/) |

## Related

- **[0.security](https://0.security)**
- [Benchmark](/benchmark/) — the compact score view and caveats
- [Methodology](/methodology/) — per-attempt rate, Wilson CI, single-model caveats
- [Competitive Landscape](/research/competitive-landscape/) — where other agents sit
