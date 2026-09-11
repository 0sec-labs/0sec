---
title: Research
description: Design decisions, experiments, and technical rationale behind the 0sec engine.
---

Design decisions, experiments, and technical rationale for the 0sec engine. Real
disclosed CVEs at [0.security](https://0.security). Most experiments run against
the [XBOW benchmark](https://github.com/xbow-engineering/validation-benchmarks)
(104 Docker CTF challenges) as a reproducible harness.

For benchmark scores, methodology, and competitor comparisons, see
[Benchmarks](/benchmark/). For mechanism docs (agent loop, triage, verification),
see [Architecture](/architecture/).

**Looking for practical workflows?** Start with
[Research Workflows](/research-workflows/) — variant hunting, deep review,
specification checks, fuzzing, kernel evidence, binary analysis, and the
distinction between live execution and imported evidence. The pages below
document design rationale and experiment history.

## Essays & rationale

Design decisions and shipped techniques.

### [Shell-First Rationale](/research/shell-first/)

Why the agent uses bash over structured tools, with A/B test data on prompt length, reasoning effort, tool routing, concurrent subagents, and multi-checkpoint budgets.

### [Agent Techniques](/research/agent-techniques/)

Shipped agent loop features: early-stop retry, exploit templates, loop detection, context compaction, dynamic playbooks, attack-tree search, strategy racing, and progress handoff.

### [Model Comparison](/research/model-comparison/)

Head-to-head testing of gpt-5.4, Kimi K2.5, Qwen3 Coder, DeepSeek, GLM, and free OpenRouter models. Cost, speed, and flag extraction across XBOW challenges.

### [FP Reduction Moat](/research/fp-reduction-moat/)

False-positive reduction stack, measured effects per benchmark slice, layer ordering rationale, and how the dataset and feature foundation supports the shipped runtime layers.

### [TypeScript/Rust Boundary](/research/typescript-rust-boundary/)

Why 0sec uses TypeScript for orchestration while moving deterministic engines such as FoxGuard into Rust behind stable contracts.

## Self-evolving harnesses

The engineering target is not merely a growing tool list. It is an agent that
can author and select alternative implementations, activate them during a task,
retain useful learned skills, and recover when an experiment fails. See
[Improvement Plane](/improvement-plane/) for implementation status and
[Architecture](/architecture/#plugin-first-self-evolution) for runtime boundaries.

These sources address complementary mechanisms; they are not interchangeable
proofs that 0sec improves autonomously:

| Source | What informs the design | What it does not establish |
| --- | --- | --- |
| [A Programming Paradigm for Spatiotemporal Composability](https://arxiv.org/abs/2608.25512) and [Cordis](https://github.com/cordiverse/cordis) | Reversible component effects, reactive dependencies, configuration reconciliation, and hot replacement | A security-quality benchmark, automatic compensation for external effects, or durable campaign recovery |
| [Self-Harness, v3](https://arxiv.org/abs/2606.09498v3) | Same-model weakness mining, diverse targeted code proposals, and held-in/held-out regression-gated selection | Open-ended self-improvement, live hot swapping, multi-day recovery, or security-quality gains in 0sec |
| [Evo-Harness, v2](https://arxiv.org/abs/2608.15071v2) | Failure-grounded natural-language skill curation, separate general/topic guidance, and bounded retrieval for a frozen solver | Executable self-rewriting, multi-agent validation, universal solver transfer, or measured gains in 0sec |
| [DeepSeek Harness architecture](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/architecture.md) | Replaceable agent-loop, tool, model, and session services rather than only fixed tool extension points | Live reload in its shipped headless/SDK profiles or first-class Python plugin hosting |
| [Hermes Python plugins](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins) | Python-native tools, hooks, commands, bundled skills, and memory/context provider interfaces | A language-neutral live-generation implementation for 0sec |
| [Voyager's skill manager](https://github.com/MineDojo/Voyager/blob/main/voyager/agents/skill.py) | Retaining executable skill code and retrieving reusable programs by description | General-purpose harness replacement or evidence of cybersecurity effectiveness |
| [Darwin Gödel Machine](https://arxiv.org/abs/2505.22954) | Evaluated agent-code changes and alternative implementations | Guaranteed monotonic improvement or a substitute for independent evaluation |
| [Chord's lifecycle plan](https://github.com/earendil-works/pi/blob/main/packages/chord/PLANNING.md) | Explicit dependency ordering, stable service handles, and resource ownership | Graph-transactional reload or post-cutover rollback; its plan explicitly excludes both for shape-preserving replacement |

**Cordis and Chord are different projects.** Cordis's formal context discipline
and Chord's application-neutral service host should not be cited as the same
implementation. Upstream implementation plans and APIs can change.

**Evo-Harness complements code evolution; it does not implement it.** Its
natural-language-only learning loop turns failed or negatively reviewed executions
into candidates carrying a lesson, trigger, evidence, and scope hint. A curator
chooses ADD, MERGE, REVISE, or SKIP rather than appending every memory; later tasks
receive bounded relevant guidance. General cross-task lessons remain distinct
from topic-specific procedures. For 0sec, this informs curation within the existing
skills and [revision-aware hunt memory](/improvement-plane/#revision-aware-codebase-learning),
not another registry or a claim that this curator is already implemented.
Retain provenance and scope, invalidate stale codebase knowledge, and evaluate
future-task usefulness separately from successful memory writes. The paper reports
three-run averages, including Opus 4.6 on TerminalBench2 improving from 62.92% to
73.03%; self-generated judgment instead regressed CL-Bench from 29.54% to 27.96%
and SWE-bench Lite from 63.67% to 61.67%. External feedback matters, richer
diagnostics are not uniformly better, and solver/evolver pairings can regress.
Neither these aggregate results nor individual retained skills establish causal
gains in 0sec, executable-code safety, or a free evolution allowance.

For a long-horizon experiment, report the task and harness versions, measured
outcomes, model/tool cost, generation transitions, retained capabilities, and
recovery behavior. A successful import or one lifecycle smoke is not evidence
that a self-evolving agent performed better across an extended task.

## Triage ML

Learned triage pipeline design and reference material.

### [Finding Triage ML](/research/finding-triage-ml/)

Implementation notes: reachability, consensus verify, PoV generation, memories, adversarial debate, and multi-modal agreement with foxguard.

### [Dynamic Routing Design](/research/dynamic-routing-design/)

A learned per-finding classifier that picks which subset of triage layers to run, motivated by the finding that no static policy wins on all benchmark slices.

### [Dynamic Triage Routing (v0)](/research/dynamic-triage-routing/)

The shipped v0 rule-based router, its four decision rules, the routing-trace dataset shape, and the upgrade path to a learned classifier.

### [Triage Dataset](/research/triage-dataset/)

How benchmark runs and verified findings are converted into labeled JSONL for triage-model training.

### [Feature Extractor](/research/feature-extractor/)

The 45 handcrafted features exposed by `extractFeatures()` and how they fit into the hybrid triage direction.

### [Journal + Orchestrator Design](/research/journal-orchestrator-design/)

Design for an append-only execution journal and an orchestrator that separates what to do next from what has been done.

## Experiment logs

Dated, archival records of specific experiments. Kept for transparency and
auditability — not necessarily current guidance.

### [2026-05-09 Control Flow, Not Prompts](/research/2026-05-09-control-flow-not-prompts/)

Audit of the agent loop against the "agents need control flow, not more prompts"
thesis, and the five deterministic-chokepoint fixes it produced.

### [2026-05-08 Cost per Flag](/research/2026-05-08-cost-per-flag/)

Why autonomous-pentest reporting should publish a dollar-per-flag axis alongside the solve percentage, and how 0sec computes its number.

### [2026-05-06 HackerOne Program Audit](/research/2026-05-06-h1-ai-readiness/)

Aggregate analysis of 590 HackerOne programs scored on automation policy, scope shape, and Safe Harbor status — where AI pentest agents can actually operate under the May 2026 CoC update.

### [2026-04-11 Triage Ablation Results](/research/2026-04-11-ablation/)

The 21-profile triage ablation with batch-1 and batch-2 numbers, methodology notes, and links to raw run artifacts.

### [XBEN-099 Investigation](/research/xben-099-investigation/)

Root-cause investigation into why XBEN-099 failed on the patched fork and the proposed fix.

### [Unsolved Eight Investigation](/research/unsolved-eight-investigation/)

Source-level investigation into an earlier 8-challenge XBOW holdout set. Useful for exploit-path reasoning, but not the canonical current unsolved list.


