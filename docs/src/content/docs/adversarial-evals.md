---
title: Adversarial evals
description: Attack-driven evaluation of AI systems, with scoped execution and replayable evidence.
---

0sec evaluates AI systems by attempting scoped attacks and recording evidence.

## What's shipped

The benchmark package ships concrete adversarial-eval harnesses:

- **Tool misuse**: attacker-controlled tool parameters (`packages/benchmark/src/adversarial-tool-misuse-*`).
- **Indirect prompt injection**: untrusted tool output (`packages/benchmark/src/adversarial-indirect-prompt-injection-*`).

`agent-assure` drives an agent endpoint, an MCP endpoint, and an oracle under a scoped policy, then writes a replayable evidence bundle.

For endpoint prerequisites, scope, invocation, and result meanings, see [Agent-action assurance](/research-workflows/#agent-action-assurance-agent-assure). All three endpoints must be authorized; an observed prohibited action and an inconclusive run are different outcomes.

The synthetic, deterministic harnesses provide repeatable checks for agent-control failures.

<span id="why-it-matters"></span>
## Evaluation goals

Measure whether attacks trigger unsafe or unauthorized behavior.

## Target classes

- LLM / agent HTTP APIs
- MCP servers
- tool-using agent backends
- authenticated staging apps with AI features enabled

<span id="what-makes-it-different-from-generic-evals"></span>
## Verification

- Confirm failures through demonstrable re-exploitation.
- Repeat attacks to measure recurrence.
- Check security and control boundaries.

<span id="building-on-the-wedge"></span>
## Planned extensions

A dedicated adversarial-eval mode needs an AI-system target model, a report format covering evidence and recurrence, and attack-specific success criteria.

<span id="report-differences-from-a-pentest"></span>
## Report fields

A vuln report covers exploitability and severity. An adversarial-eval report should also capture:

- target class and environment
- attack objective
- recurrence across runs
- whether the failure is specific to agent/tool composition
- whether it's an authorization, tool-use, or instruction-hijack failure

<span id="relationship-to-0sec-cloud"></span>
## Product scope

Run local evaluations through `0sec`. Managed testing belongs to **0cloud**; recurring adversarial evaluation remains planned. **0sec Cloud** is the optional inference service. These products have separate access and billing.