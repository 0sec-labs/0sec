---
title: Project comparison
description: Comparison of 0sec with BoxPwnr, Shannon, KinoSec, and other autonomous pentesting agents on XBOW scores, approach, and cost.
---

Cross-project XBOW scores are each project's public self-reports, run under
different forks, models, turn caps, and retry protocols. They are
protocol-sensitive and should not be read as a matched-conditions ranking.

## Where the agents sit on XBOW

| Agent | Score | Model | Approach | Cost |
|-------|-------|-------|----------|------|
| [BoxPwnr](https://github.com/0ca/BoxPwnr) | 97.1% (101/104) | Claude / GPT-5 / others | Shell-first, **best-of-N across ~10 configs** (best single model 81.7%) | Unknown |
| [Shannon](https://github.com/KeygraphHQ/shannon) | 96.15% (100/104) | Claude 3-tier | **White-box** (reads source), 13-agent | ~$50/scan |
| [KinoSec](https://kinosec.ai) | 92.3% (96/104) | Claude Sonnet 4.6 | Black-box, 50-turn cap | Unknown (proprietary) |
| [Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent) | 84.62% (88/104) | Not disclosed | Single meta-agent, self-rewriting prompts | Unknown |
| [deadend-cli](https://github.com/xoxruns/deadend-cli) | 77.55% (~76/98) | Kimi K2.5 | Single-agent CLI (tested 98/104) | $122 / 104 |
| [MAPTA](https://arxiv.org/abs/2508.20816) | 76.9% (80/104) | GPT-5 | 3-role multi-agent | $21.38 total |
| **0sec** | **93/95 = 97.9%** black-box | Azure gpt-5.4 | Shell-first, single-model single-shot cohort | ~$0.48/run, **$5.20/flag** |

Two distinctions:

- **Best-of-N ≠ single-config.** BoxPwnr's 97.1% is a union over ~10 model+solver
  configs (~5 attempts/challenge); its best *single* model scores 81.7%. 0sec's
  headline is a single-model single-shot solve rate. See [Methodology](/methodology/).
- **White-box ≠ black-box.** Shannon reads source, which lifts the
  ceiling on challenges with no web-facing vector. Not directly comparable to black-box-only runs.

<span id="what-actually-differentiates-0sec"></span>
## Implementation differences

- **Blind verification:** an independent agent re-exercises candidates on the
  verification path. Other workflows retain their own evidence states.
- **Reachability:** `packages/core/src/triage/reachability.ts` uses patterns to
  assess whether a sink is callable.
- **Scanner agreement:** the optional [foxguard](https://github.com/0sec-labs/foxguard)
  check compares the same tree (`packages/core/src/triage/multi-modal.ts`).
- **Reported cost:** the gpt-5.4 XBOW cohort costs $5.20 per flag at $0.48 per run.

<span id="the-one-durable-finding"></span>
## Architecture comparison

These results use different models, tools, memory, search strategies, and agent
counts. They do not isolate agent count as a cause. 0sec uses shell tools and
supports concurrent `spawn_agents` for parallel strategies.

## Related

- **[0.security](https://0.security)**
- [Benchmark](/benchmark/)
- [XBOW Analysis](/research/xbow-analysis/)
- [Methodology](/methodology/)
- [Triage ablation](/research/2026-04-11-ablation/) — measured effects of individual gates