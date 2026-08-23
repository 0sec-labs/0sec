---
title: Competitive Landscape
description: How 0sec sits among other autonomous pentesting agents — brief, factual context, with real disclosed CVEs as the actual proof.
---

**We don't chase vendor benchmarks.** 0sec's proof is real, disclosed CVEs in the
Linux kernel and widely-used open source, with maintainer review — the running,
verified track record lives at **[0.security](https://0.security)**. The XBOW
leaderboard is condition-specific context, not the scoreboard we're playing on.

Cross-project XBOW scores are each project's public self-reports, run under
different forks, models, turn caps, and retry protocols, so they are
protocol-sensitive and should not be read as a matched-conditions ranking. With
that caveat, here is the brief factual landscape (as of May 2026).

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

Two things worth keeping straight when reading that table:

- **Best-of-N ≠ single-config.** BoxPwnr's 97.1% is a union over ~10 model+solver
  configs (~5 attempts/challenge); its best *single* model scores 81.7%. 0sec's
  headline is a single-model single-shot solve rate — the two answer different
  questions. See [Methodology](/methodology/).
- **White-box ≠ black-box.** Shannon reads source, which lifts the ceiling on
  challenges with no web-facing vector. Not directly comparable to black-box-only runs.

## What actually differentiates 0sec

The parts that carry over from CTFs to real targets — not the leaderboard number:

- **Reproduce before trust.** A separate blind-verify agent re-exploits each finding
  seeing only the PoC; unreproduced findings are dropped rather than shipped as "low
  confidence." This is the discipline behind the [0.security](https://0.security)
  disclosures.
- **Open-source reachability gate.** `packages/core/src/triage/reachability.ts` is a
  zero-dependency grep/pattern first pass that suppresses findings whose sink isn't
  callable from an entry point — the open analogue of Endor Labs' proprietary "Code
  API" moat, and the best-performing FP-reduction layer in the
  [2026-04-11 ablation](/research/2026-04-11-ablation/).
- **Second-scanner cross-validation.** For every finding, run
  [foxguard](https://github.com/0sec-labs/foxguard) (a Rust pattern scanner) against
  the same tree and require agreement (`packages/core/src/triage/multi-modal.ts`).
- **Cost transparency.** 0sec publishes `$/flag` ($5.20 at $0.48/run on the gpt-5.4
  XBOW cohort). A solve rate with no cost denominator is hard to compare across stacks.

## The one durable finding

Across the field, architecture (agent count) matters less than **tool quality,
memory, and search breadth**. Shannon's 13-agent system, deadend-cli's single agent,
and MAPTA's 3-role system all cluster by how good their tools and context handling
are, not by how many agents they run. That is the basis for 0sec's shell-first
design — a terminal plus real security tools, with deterministic guardrails around
it — and 0sec now also fans out concurrent subagents (`spawn_agents`) when a target
warrants parallel strategies.

## Related

- **[0.security](https://0.security)** — the real, disclosed-CVE track record (the proof)
- [Benchmark](/benchmark/) — 0sec's own compact score view and caveats
- [XBOW Analysis](/research/xbow-analysis/) — how the XBOW number is built and its limits
- [Methodology](/methodology/) — why single-config and best-of-N aren't comparable
