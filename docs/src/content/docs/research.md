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


