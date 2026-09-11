---
title: Blind Verification
description: How independent agent verification filters findings, and how it differs from deterministic replay and discovery leads.
---

Blind verification uses a separate agent to re-exercise a finding without the research agent's original reasoning. See [Scan Workflows](/scan-workflows/#verification-and-evidence) for choosing a verifier and interpreting evidence.

## What it is

The verify agent gets exactly two things:

1. The **PoC** — the original payload and response from the attack stage.
2. The **target path** — where to send it.

The verifier receives no research-agent reasoning, strategy, or hypothesis. It re-sends the payload or a close variant and checks the response.

<span id="why-it-matters"></span>
## Confirmation bias

A separate verifier checks ambiguous responses and common false-positive patterns:

- **Refusal misclassification:** the target echoes an instruction while refusing it.
- **Non-deterministic responses:** the apparent failure disappears on retry.
- **Context-dependent payloads:** an attack fails without its earlier conversation setup.
- **Partial compliance:** the response contains no claimed data leak or executed action.

## How it works

### Finding lifecycle

`save_finding` produces `discovered` findings on the attack/verify path. The verification stage filters report candidates:

```
discovered -> TRUE_POSITIVE (confirmed) -> in report
discovered -> FALSE_POSITIVE (killed)   -> dropped
```

Persisted discovery records and other workflow outputs have separate lifecycle rules.

### Agentic verification (with API key)

With an API key, 0sec spins up a verification agent with its own tools: `send_prompt` (re-send payloads), `bash` (reproduction scripts), `save_finding` (confirm with fresh evidence), `done`.

`buildVerifyAgentPrompt` builds a task list from all discovered findings — for each: template name, category, original payload and response (truncated to 500 chars). The agent works through the list, re-exploits each, and confirms or skips it.

Turn budget scales with finding count: `max(10, findingCount * 4)`. Three findings → 12 turns — room to retry with variants.

Each finding gets a formal verdict:

```typescript
{
  verdict: "TRUE_POSITIVE" | "FALSE_POSITIVE",
  confidence: 0.7 | 0.8,
  reasoning: string,  // why it confirmed or rejected
  agentRole: "verify",
  model: string
}
```

Confirmed findings become `confirmed`; unverified candidates leave this stage's `ctx.findings`. Stored records and other research outputs retain their own lifecycle rules.

### Heuristic fallback (no API key)

Without an API key, 0sec falls back to a statistical heuristic: did multiple payloads from the same attack template trigger a vulnerable response?

- **2+ payloads succeeded** → confirmed (convergent evidence).
- **Only 1 succeeded** → killed (likely noise).

This heuristic filters isolated responses with weaker evidence than agentic verification. Structured web and MCP checks use direct HTTP response matching.

Deterministic replay emits [`verification_result`](/verification-result/) with commands, assertions, artifacts, and replay status. Human acceptance, suppression, and reopening remain separate triage decisions.

## What gets killed

Reported filtering rates are **30–60% of raw findings**, covering cases such as:

- **Prompt-injection "successes" that are refusals** — the most common LLM false positive. The model echoes the instruction while refusing it.
- **One-shot anomalies** — a 500 with a stack trace once, a clean 200 on retry.
- **Context-dependent jailbreaks** — work only after specific conversation setup; the cold payload fails.
- **Overzealous severity** — a real issue called critical when it's info. The finding survives with accurate severity.

## Comparison

| Approach | What happens to a finding |
|----------|--------------------------|
| Traditional scanner | Found → Reported → Human triages |
| Blind agent verification path | Found → Independent re-exercise → Confirmed or rejected for this stage |
| Research discovery path | Candidate → Additional reachability, verification, and novelty work required |
| Deterministic replay | Executable contract → Observations and assertions → Mode-specific result |

Verification adds runtime and model cost. Inspect the actual result and retained evidence; neither a successful command exit nor a human acceptance decision substitutes for reproduction.