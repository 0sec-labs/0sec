---
title: Blind Verification
description: How 0sec independently re-exploits every finding to kill false positives.
---

Most scanners report what they find. 0sec kills what it can't prove.

Every finding that survives the attack stage enters blind verification: a second
agent tries to reproduce the vulnerability with **zero access to the original
reasoning.** If it can't reproduce it, the finding is killed. This is the biggest
difference between 0sec's output and the noise other tools produce.

## What it is

The verify agent gets exactly two things:

1. **The PoC** — the original payload and response from the attack stage.
2. **The target path** — where to send it.

It never sees the research agent's chain of thought, strategy, or hypothesis.
Same principle as double-blind peer review: judge the work on its merits, not on
who made the claim or why they believe it.

Its job is simple: re-send the payload (or a close variant), observe the
response, decide if the vuln is real. Target complies again → confirmed. Target
refuses, blocks, or behaves differently → killed.

## Why it matters

**Confirmation bias is the root cause of false positives in AI security tools.**
An attack agent that just spent turns building an exploit has every incentive to
read an ambiguous response as a win. The verify agent has none of that context.
If the response is ambiguous, it has no reason to interpret it favorably. Default
disposition: skepticism — better to miss a real finding than confirm a fake one.

This kills a whole class of false positives:

- **Refusal misclassification.** The target echoes the injected instruction while
  explaining why it won't comply. Pattern matching sees the payload in the
  response; the verify agent sees the refusal framing. Killed.
- **Non-deterministic responses.** A response looked vulnerable once. Re-send
  gets something different. Killed.
- **Multi-turn context leakage.** The final payload only worked after 8 turns of
  setup. Sent cold, it fails. Killed.
- **Partial compliance.** The target partly complied but never leaked data or ran
  the injected instruction. Killed.

## How it works

### Finding lifecycle

Every finding starts `discovered` when the attack agent calls `save_finding`. No
finding is reported to the user in this state.

```
discovered -> TRUE_POSITIVE (confirmed) -> in report
discovered -> FALSE_POSITIVE (killed)   -> dropped
```

### Agentic verification (with API key)

With an API key, 0sec spins up a verification agent with its own tools:
`send_prompt` (re-send payloads), `bash` (reproduction scripts), `save_finding`
(confirm with fresh evidence), `done`.

`buildVerifyAgentPrompt` builds a task list from all discovered findings — for
each: template name, category, original payload and response (truncated to 500
chars). The agent works through the list, re-exploits each, and confirms or
skips it.

Turn budget scales with finding count: `max(10, findingCount * 4)`. Three
findings → 12 turns — enough room to retry with variants without burning tokens.

Each finding gets a formal verdict in the database:

```typescript
{
  verdict: "TRUE_POSITIVE" | "FALSE_POSITIVE",
  confidence: 0.7 | 0.8,
  reasoning: string,  // why it confirmed or rejected
  agentRole: "verify",
  model: string
}
```

Confirmed findings become `confirmed`. Unverified findings are dropped from
`ctx.findings` entirely — they don't appear as "unverified" or "low confidence."
They're gone.

### Heuristic fallback (no API key)

Without an API key, 0sec falls back to a statistical heuristic: did multiple
payloads from the same attack template trigger a vulnerable response?

- **2+ payloads succeeded** → confirmed (convergent evidence).
- **Only 1 succeeded** → killed (could be noise).

Weaker than agentic verification, but it still filters flukes. Deterministic
findings from structured checks (web baseline probes, MCP checks) bypass this —
they're validated by direct HTTP response matching and don't need AI.

Deterministic replay fixtures emit a structured
[`verification_result`](/verification-result/) with command records, assertions,
artifact references, and a replay status. That status is an automated proof
signal, not the human triage state — maintainers can still accept, suppress, or
reopen after reviewing the evidence.

## What gets killed

In practice, blind verification kills **30-60% of raw findings** — the ones a
traditional scanner would report and a human would have to triage by hand:

- **Prompt-injection "successes" that are refusals** — the most common LLM false
  positive. The model echoes the instruction while refusing it.
- **One-shot anomalies** — a 500 with a stack trace once, a clean 200 on retry.
- **Context-dependent jailbreaks** — only work after a specific conversation
  setup; the cold payload holds.
- **Overzealous severity** — a real issue called critical when it's info. The
  finding survives, but with accurate severity.

## Comparison

Most tools find-and-report and leave triage to the operator. 0sec inverts this:
a finding is "not real until proven otherwise," and verification is a **required
stage**, not optional post-processing.

| Approach | What happens to a finding |
|----------|--------------------------|
| Traditional scanner | Found → Reported → Human triages |
| 0sec | Found → Blind re-exploitation → Confirmed or killed → Only confirmed reported |

The cost is time: another agent loop, more API calls, more latency (a scan with
5 vulns spends ~15-20 extra turns). Worth it — every reported finding has been
independently reproduced, not left as a maybe to sort through.
