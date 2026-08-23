---
title: Budget Management
description: How 0sec manages turn budgets, reflection checkpoints, and depth-based resource allocation across agent scans.
---

Agentic scanning is expensive. Too few turns and the agent misses real bugs; too
many and it loops on dead ends. 0sec balances the two with turn limits,
reflection checkpoints, and depth presets.

## Turn budgets

A turn is one LLM round-trip: the model responds (usually a tool call), the tool
runs, the result feeds the next turn. A multi-step exploit chain might take
8–15 turns; a header check takes 2. Every run has a max turn count — at the
limit the loop stops and all findings so far are saved.

`--depth` sets the attack-stage budget:

| Depth | Max turns | Typical wall time | Use case |
|-------|-----------|-------------------|----------|
| `quick` | 20 | ~1 min | CI, smoke tests, sanity checks |
| `default` | 40 | ~3 min | Standard day-to-day scanning |
| `deep` | 100 | ~10 min | Thorough assessments, pre-launch audits |

Discovery and verification stages use smaller fixed budgets since their
objectives are narrower.

## Why 40 turns

The default comes from MAPTA (a research pentest framework that scored 76.9% on
XBOW), which found ~40 tool calls is the sweet spot — enough for recon, auth,
escalation, and extraction, but past it returns diminish sharply. 0sec's own
data agrees: most successful exploits finish in 10–20 turns, and challenges that
fail at 40 rarely succeed at 60. They need a different model, source access, or
browser automation — not more turns. Complex multi-class challenges are the
exception and benefit from deep mode's 100 turns.

## Reflection checkpoints

Turn limits stop runaway cost but not a subtler failure: burning 35 turns on a
dead end. At four budget percentages, when the agent produces a text-only
response, 0sec injects a budget-awareness prompt (inspired by Cyber-AutoAgent):

| Budget consumed | Checkpoint | Prompt behavior |
|-----------------|------------|-----------------|
| 30% | Status check | Summarize what you've learned; state your top hypothesis. |
| 50% | Halfway review | List every approach and its result; focus on the most promising untested vector. |
| 70% | Urgency | If the current approach isn't working, switch technique now. |
| 85% | Final push | Highest-confidence exploit path only — exploit, don't explore. |

In practice this keeps agents productive through more of their budget instead of
stalling early on a repeating approach. It improves consistency; it does not
crack challenges that need stronger reasoning or a capability the agent lacks.

## When budget runs out

If the agent hits max turns without calling `done`, the loop ends with "Agent
reached max turns (N) without completing." All findings so far are persisted and
the scan continues to verification and reporting. A budget-exhausted scan is
incomplete, not failed — three findings from 38 turns still get verified and
reported.

Session state is also saved every 2 turns to SQLite, so crashed or interrupted
scans resume with `--resume` (separate from budget exhaustion).

## Choosing a depth

- **Quick (20)** — CI gates and smoke tests. Probes obvious misconfigs and
  common patterns; won't find multi-step chains.
- **Default (40)** — standard scanning. Recon, hypotheses, multiple vectors,
  follow-ups. Most scans should use this.
- **Deep (100)** — completeness over speed: pre-launch audits, compliance
  reviews, formal pentests. Costs ~2.5× the tokens of default. Benchmarks
  (XBOW) run deep to measure the capability ceiling.

## Non-determinism and retries

LLM agents are non-deterministic — the same target scanned twice can differ. On
XBOW this shows as challenges that pass on some runs and fail on others. The
benchmark harness mitigates with `--retries`, counting a challenge passed if any
attempt succeeds; for production, running 2–3 times and merging findings is
reasonable when thoroughness matters. A single failed scan does not prove a
target is secure — only that this run found nothing.
