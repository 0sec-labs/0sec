---
title: Budget Management
description: How 0sec manages turn budgets, reflection checkpoints, and depth-based resource allocation across agent scans.
---

Use depth presets to set turn limits. Reflection checkpoints prompt the agent to review progress during a scan.

## Turn budgets

A turn is one LLM round-trip: the model responds (usually a tool call), the tool runs, and the result feeds the next turn. A multi-step exploit chain might take 8–15 turns; a header check takes 2. Every run has a max turn count — at the limit the loop stops and all findings so far are saved.

`--depth` sets the attack-stage budget:

| Depth | Max turns | Typical wall time | Use case |
|-------|-----------|-------------------|----------|
| `quick` | 20 | ~1 min | CI, smoke tests, sanity checks |
| `default` | 40 | ~3 min | Standard day-to-day scanning |
| `deep` | 100 | ~10 min | Thorough assessments, pre-launch audits |

Discovery and verification stages use smaller fixed budgets since their objectives are narrower.

<span id="why-40-turns"></span>
## Turn-limit rationale

The 40-turn default follows MAPTA's reported results (76.9% on XBOW). In 0sec's observations, most successful exploits finish in 10–20 turns; failures at 40 rarely succeed at 60. Check model capability, source access, and browser availability before increasing the limit. Deep mode allows 100 turns for longer tasks.

## Reflection checkpoints

At four budget checkpoints, a text-only response triggers a budget-awareness prompt inspired by Cyber-AutoAgent:

| Budget consumed | Checkpoint | Prompt behavior |
|-----------------|------------|-----------------|
| 30% | Status check | Summarize what you've learned; state your top hypothesis. |
| 50% | Halfway review | List every approach and its result; focus on the most promising untested vector. |
| 70% | Urgency | If the current approach isn't working, switch technique now. |
| 85% | Final push | Highest-confidence exploit path only — exploit, don't explore. |


## When budget runs out

If the agent hits max turns without calling `done`, the loop ends with "Agent reached max turns (N) without completing." All findings so far are persisted and the scan continues to verification and reporting. A budget-exhausted scan is incomplete; three findings from 38 turns still get verified and reported.

Scan state is checkpointed to SQLite every two turns. [Scan Workflows](/scan-workflows/) describes supported resume paths and their state requirements.

## Choosing a depth

- **Quick (20)** — CI gates and smoke tests. Probes obvious misconfigs and common patterns; won't find multi-step chains.
- **Default (40)** — standard scanning. Recon, hypotheses, multiple vectors, follow-ups. Most scans should use this.
- **Deep (100)** — longer assessments, at roughly 2.5× the default token budget. XBOW benchmarks use this preset.

## Non-determinism and retries

LLM agents are non-deterministic — the same target scanned twice can differ. On XBOW this shows as challenges that pass on some runs and fail on others. The benchmark harness mitigates with `--retries`, counting a challenge passed if any attempt succeeds; for production, running 2–3 times and merging findings is reasonable when thoroughness matters. A single failed scan does not prove a target is secure — only that this run found nothing.