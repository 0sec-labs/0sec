---
title: Blind Verification
description: How 0sec independently re-exploits every finding to kill false positives.
---

Most security scanners report what they find. 0sec kills what it cannot prove.

Every finding that survives the attack stage enters blind verification -- a second agent independently attempts to reproduce the vulnerability with zero access to the original reasoning. If it cannot reproduce it, the finding is killed. This is the single biggest difference between 0sec's output and the noise that other tools produce.

## What blind verification is

The verify agent receives only two things:

1. **The PoC** -- the original payload and response from the attack stage
2. **The target path** -- where to send it

It never sees the research agent's chain of thought, attack strategy, hypothesis, or reasoning about why the vulnerability exists. It gets the exploit artifact and the target. Nothing else.

This is the same principle as double-blind peer review. The reviewer doesn't know who wrote the paper or why they think it's important. They evaluate the work on its own merits.

The verify agent's job is simple: re-send the payload (or a close variant), observe the response, and decide whether the vulnerability is real. If the target complies with the attack again, the finding is confirmed. If the target refuses, blocks, or behaves differently, the finding is killed.

## Why it matters

**Confirmation bias is the root cause of false positives in AI security tools.** When an attack agent finds something that looks like a vulnerability, it has every incentive to interpret ambiguous responses as confirmation. It spent turns building up to this exploit. It has context about why this should work. It sees what it wants to see.

The verify agent has none of this context. It sees a payload and a target. If the response is ambiguous, it has no reason to interpret it favorably. The default disposition is skepticism -- it is better to miss a real finding than to confirm a false positive.

This design kills an entire class of false positives:

- **Refusal misclassification.** The attack agent sends a prompt injection. The target responds with a long message that includes the injected content in a "I cannot do that because..." refusal. The attack agent sees its payload in the response and calls it a hit. The verify agent re-sends the payload, sees the refusal framing, and kills it.
- **Non-deterministic responses.** The target happened to produce a response that looked vulnerable on one attempt. The verify agent re-sends and gets a different response. Killed.
- **Context leakage from multi-turn.** The attack agent built up a multi-turn conversation that gradually weakened the target's defenses. The final payload only worked because of 8 previous turns of context. The verify agent sends the payload cold. It fails. Killed.
- **Partial compliance.** The target partially complied with an attack but didn't actually leak data or execute the injected instruction. The attack agent's pattern matching flagged it. The verify agent sees that the response doesn't actually demonstrate the vulnerability. Killed.

## How it works technically

### Finding lifecycle

Every finding starts in the `discovered` state when the attack agent calls `save_finding`. No finding is ever reported to the user in this state.

```
discovered -> TRUE_POSITIVE (confirmed) -> included in report
discovered -> FALSE_POSITIVE (killed)   -> excluded from report
```

### Agentic verification (with API key)

When an API key is available, 0sec spins up a full verification agent with its own tool set. The verify agent gets:

- `send_prompt` -- to re-send payloads to the target
- `bash` -- to run reproduction scripts
- `save_finding` -- to confirm findings with fresh evidence
- `done` -- to signal completion

The verification system prompt (`buildVerifyAgentPrompt`) constructs a task list from all discovered findings. For each finding, it includes the template name, category, the original payload (truncated to 500 chars), and the original response (truncated to 500 chars). The agent iterates through this list, re-exploits each one, and either confirms or skips it.

The turn budget scales with finding count: `max(10, findingCount * 4)` turns. A scan with 3 findings gets 12 turns for verification. This gives the agent enough room to retry with variants without burning tokens on dead ends.

After the agent completes, 0sec records a formal verdict for each finding in the database:

```typescript
{
  verdict: "TRUE_POSITIVE" | "FALSE_POSITIVE",
  confidence: 0.7 | 0.8,
  reasoning: string,  // why the agent confirmed or rejected
  agentRole: "verify",
  model: string       // which model ran verification
}
```

Confirmed findings have their status set to `confirmed`. Unverified findings are dropped from `ctx.findings` entirely -- they don't appear in the report as "unverified" or "low confidence." They are gone.

### Heuristic fallback (no API key)

When no API key is available, 0sec falls back to a statistical heuristic. Instead of an agent re-exploiting the finding, it checks whether multiple payloads from the same attack template triggered a vulnerable response.

- If 2+ payloads from the same template succeeded: confirmed (convergent evidence)
- If only 1 payload succeeded: killed (could be noise)

This is a weaker signal than agentic verification, but it still filters out one-off flukes. Deterministic findings from structured checks (web baseline probes, MCP security checks) bypass this heuristic -- they are validated by direct HTTP response matching and don't need AI verification.

Deterministic replay fixtures emit a structured
[`verification_result`](/verification-result/) with command records, assertion
results, artifact references, and a replay status. That status is an automated
proof signal, not the human triage state for the finding. Maintainers can still
accept, suppress, or reopen findings after reviewing the replay evidence.

## What gets killed

In practice, blind verification kills 30-60% of raw findings from the attack stage. These are findings that a traditional scanner would report and a human would have to triage manually.

**Prompt injection "successes" that are actually refusals.** The most common false positive in LLM security scanning. The model echoes back the injected instruction in the process of explaining why it won't do it. Pattern matching sees the payload in the response. The verify agent sees the refusal.

**One-shot anomalies.** A web endpoint returned a 500 error with a stack trace on one request but works fine on retry. The attack agent logged it as information disclosure. The verify agent hits the same endpoint, gets a 200, and kills it.

**Context-dependent jailbreaks.** A multi-turn jailbreak that only works after a specific conversation setup. The verify agent sends the final payload without the preceding turns. The target's defenses hold. Killed.

**Overzealous severity classification.** The attack agent found a real issue but called it critical when it's informational. The verify agent reproduces it but with lower-impact evidence. The finding survives but with accurate severity.

## Comparison with other tools

Most security scanning tools operate on a find-and-report model. They run checks, collect results, and present everything they found. The operator is responsible for triaging false positives.

0sec inverts this. The default state of a finding is "not real until proven otherwise." The verification stage is not optional post-processing -- it is a required pipeline stage that every finding must survive.

| Approach | What happens to a finding |
|----------|--------------------------|
| Traditional scanner | Found -> Reported -> Human triages |
| 0sec | Found -> Blind re-exploitation -> Confirmed or killed -> Only confirmed reported |

The cost is time. Verification adds another agent loop, which means more API calls and more latency. A scan that finds 5 vulnerabilities will spend an additional 15-20 turns verifying them. The tradeoff is worth it: operators get a report where every finding has been independently reproduced, not a list of maybes to sort through.
