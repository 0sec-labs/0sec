---
title: Adversarial evals
description: How 0sec extends its pentest wedge into attack-driven adversarial evaluation for AI systems.
---

0sec already behaves like an adversarial evaluator: it attacks systems, attempts
exploitation, and reports only what it can back with evidence. This page makes
that category explicit.

## What's shipped

This isn't hypothetical. The benchmark package ships concrete, deterministic
adversarial-eval harnesses:

- **Tool misuse** through attacker-controlled tool parameters
  (`packages/benchmark/src/adversarial-tool-misuse-*`).
- **Indirect prompt injection** through untrusted tool output
  (`packages/benchmark/src/adversarial-indirect-prompt-injection-*`).

The `agent-assure` CLI command runs the shipped primitive end-to-end: it drives
an agent endpoint, an MCP endpoint, and an oracle under a scoped policy, then
writes a replayable evidence bundle. It's the building block behind agent-action
assurance: a scoped action, run and observed from outside the system.

The harnesses are synthetic and deterministic on purpose — a repeatable way to
score whether the scanner catches realistic agent-control failures before they
reach production.

## Why it matters

Most AI eval tooling asks: did the model produce the expected output? Did a judge
score it well? Did the trace stay within policy? Useful — but not enough for
high-stakes systems. The harder question:

> Can this system be pushed into unsafe or unauthorized behavior under realistic
> pressure?

That's the question an attack-driven evaluator is built to answer.

## Target classes

- LLM / agent HTTP APIs
- MCP servers
- tool-using agent backends
- authenticated staging apps with AI features enabled

## What makes it different from generic evals

- attack-driven, not judge-driven
- exploit- and evidence-based
- built for repeated pressure, not one-shot scoring
- finds real security and control-boundary failures

## Building on the wedge

A dedicated adversarial-eval mode builds on the existing pentest engine. It still
needs a few things: a target model for AI systems, a report format focused on
evidence and recurrence, and attack classes with success criteria tuned for
agentic systems.

## Report differences from a pentest

A vuln report centers on exploitability and severity. An adversarial-eval report
should also capture:

- target class and environment
- attack objective
- recurrence across runs
- whether the failure is specific to agent/tool composition
- whether it's an authorization, tool-use, or instruction-hijack failure

## Relationship to 0sec cloud

0sec is the public, self-run tool; 0sec cloud is the managed service for
orchestration and recurring runs. Adversarial evals should work on both — locally
and in CI through `0sec`, and as a managed recurring product through `0sec cloud`.
