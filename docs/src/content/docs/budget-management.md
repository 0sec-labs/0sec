---
title: Budget Management
description: How pwnkit manages turn budgets, reflection checkpoints, and depth-based resource allocation across agent scans.
---

Agentic security scanning is expensive. Every turn costs tokens, time, and API dollars. Spend too few turns and the agent misses real vulnerabilities. Spend too many and it loops on dead ends, burning budget without results. pwnkit's budget system balances thoroughness against efficiency using turn limits, graduated reflection checkpoints, and depth presets tuned to empirical data.

## Turn budgets

A "turn" is one round-trip with the LLM: the model receives context, produces a response (typically including a tool call), the tool executes, and the result feeds back into the next turn. A multi-step exploit chain -- login, extract a cookie, probe an authenticated endpoint, escalate privileges, exfiltrate data -- might consume 8-15 turns. A simple header check might take 2.

pwnkit caps every agent run with a maximum turn count. When the agent reaches that limit, the loop terminates and all findings discovered so far are saved. The turn budget is the primary mechanism that prevents runaway scans.

The `--depth` flag maps directly to turn budgets for the attack stage:

| Depth | Max turns | Typical wall time | Use case |
|-------|-----------|-------------------|----------|
| `quick` | 20 | ~1 min | CI pipelines, smoke tests, sanity checks |
| `default` | 40 | ~3 min | Standard day-to-day scanning |
| `deep` | 100 | ~10 min | Thorough assessments, pre-launch audits |

Discovery and verification stages use smaller, fixed budgets (8-12 turns for discovery, up to 15 for verification) since they have narrower objectives.

## Why 40 turns is the default

The default budget of 40 turns is not arbitrary. It comes from MAPTA (Multi-Agent Penetration Testing Agent), an academic framework that achieved 76.9% on the XBOW benchmark. Their research showed that 40 tool calls is the sweet spot for autonomous pentesting agents: enough to complete multi-step exploit chains that require reconnaissance, authentication, privilege escalation, and data extraction, but not so many that the agent wastes tokens revisiting failed approaches.

Beyond roughly 40 calls, returns diminish sharply. The agent has typically exhausted its best hypotheses and begins cycling through low-probability variants. The exceptions are complex challenges that require deep exploration across multiple vulnerability classes -- those benefit from the 100-turn deep budget, which gives the agent room to try fundamentally different strategies after the first few fail.

pwnkit's own benchmark data confirms this pattern. Most successful exploits complete in 10-20 turns. Challenges that fail at 40 turns rarely succeed at 60 -- they need either a different model, source code access, or browser automation, not more turns of the same approach.

## Reflection checkpoints

Raw turn limits prevent runaway costs, but they do not prevent a subtler problem: the agent spending 35 turns on a dead-end approach and only realizing too late that it should have pivoted. pwnkit addresses this with graduated reflection checkpoints, inspired by Cyber-AutoAgent's phased plan evaluation.

At four points during a scan, the agent receives a budget-awareness prompt that forces it to reassess:

| Budget consumed | Checkpoint | Prompt behavior |
|-----------------|------------|-----------------|
| 30% | Status check | Summarize what you have learned. What is your top hypothesis? |
| 50% | Halfway review | List every approach tried and its result. What is the most promising untested vector? Focus there. |
| 70% | Urgency signal | If current approach is not working, switch now to a completely different technique. |
| 85% | Final push | Go for the highest-confidence exploit path only. No more exploration -- exploit what you found. |

These checkpoints are injected as user-role messages when the agent produces a text-only response (no tool calls) at the corresponding budget percentage. They serve as forcing functions: the 30% checkpoint encourages hypothesis formation, the 50% checkpoint triggers a strategic review, the 70% checkpoint demands a pivot if progress has stalled, and the 85% checkpoint narrows focus to exploitation over exploration.

In practice, the multi-checkpoint system keeps agents active longer. Before this was implemented, agents with a single 60% reflection prompt would often stall early, repeating the same failing approach. With graduated checkpoints, agents stay productive through more of their budget. That said, the checkpoints improve consistency -- they do not crack challenges that require stronger model reasoning or capabilities the agent lacks (like browser automation).

## What happens when budget runs out

When the agent reaches its maximum turn count without calling the `done` tool, the loop terminates with the message: "Agent reached max turns (N) without completing." All findings discovered up to that point are persisted to the database exactly as they were reported. The scan proceeds to the next pipeline stage (verification, then reporting) using whatever findings exist.

This means a budget-exhausted scan is not a failure -- it is an incomplete scan. If the agent found three vulnerabilities in 38 turns but did not finish its planned fourth attack vector, those three findings still get verified and reported. The agent is expected to call `done` with a summary when it believes it has finished. If it never calls `done`, the infrastructure treats the timeout as an implicit completion.

Session state is also saved periodically (every 2 turns) to SQLite, so interrupted scans can be resumed with `--resume`. This is separate from budget exhaustion -- it handles crashes, network failures, and manual interruptions.

## Choosing the right depth

**Quick (20 turns)** is designed for CI pipelines and automated gates. It runs enough turns for the agent to probe obvious misconfigurations, test a handful of common attack patterns, and report what it finds. It will not discover vulnerabilities that require multi-step exploit chains or deep exploration. Use it as a smoke test or regression check.

**Default (40 turns)** is the standard scanning mode. It gives the agent enough budget to run a meaningful reconnaissance phase, form hypotheses, test multiple attack vectors, and follow up on promising leads. Most real-world scans should use this depth. It hits the empirical sweet spot where additional turns stop producing additional findings.

**Deep (100 turns)** is for thorough assessments where completeness matters more than speed. Pre-launch security audits, compliance-driven reviews, and penetration test engagements benefit from the extended budget. The agent can try fundamentally different strategies after initial approaches fail, explore edge cases, and chain complex multi-step exploits. Deep mode costs roughly 2.5 times more in API tokens than default mode.

When running benchmarks, deep mode is the standard. XBOW evaluations use deep mode to give the agent maximum opportunity, since benchmark scores reflect capability ceiling rather than typical usage.

## Non-determinism and retries

LLM-based agents are inherently non-deterministic. The same target scanned twice with identical configuration can produce different results. The agent might choose a different initial reconnaissance strategy, follow a different hunch after the first few turns, or stumble onto (or miss) a key insight due to sampling randomness.

On the XBOW benchmark, this manifests as challenges that pass on some runs and fail on others. A challenge that the agent cracks in 12 turns on one attempt might stall and exhaust its budget on the next. This is not a bug -- it is a fundamental property of probabilistic agents.

Retries are the practical mitigation. The benchmark harness supports a `--retries` flag that runs each challenge multiple times and counts it as passed if any attempt succeeds. This smooths out the variance and gives a more accurate picture of the agent's capability ceiling. For production scans, running the same scan 2-3 times and merging findings is a reasonable strategy when thoroughness matters.

The non-determinism also means that a single failed scan does not prove a target is secure. It means the agent did not find anything in that particular run with that particular sequence of decisions. A different run, a different model, or a different depth setting might produce different results.
