---
title: "We took the control-flow audit seriously — here are the 5 fixes"
date: "2026-05-09"
description: "A bear-blog post argued that agents need deterministic code at chokepoints, not 'MUST' prompts. We audited pwnkit's agent loop, found 5 places we were doing it wrong, and shipped fixes in 24 hours. Here's the diff."
---

*Published 2026-05-09. PRs #287–#291 land the fixes; closes [#280](https://github.com/0sec-labs/0sec/issues/280).*

## The post that started it

On 2026-05-07, [bsuh's "Agents need control flow, not more prompts"](https://bsuh.bearblog.dev/agents-need-control-flow-not-more-prompts/) hit the HN front page. The thesis is one sentence: agent reliability comes from deterministic code at chokepoints, not from prompts that escalate to "MUST" or "MANDATORY" when the model misbehaves. If the model has to re-derive a constraint on every turn, the constraint will fail on some non-trivial fraction of turns. Encode it once, in code, at the spot where a single bad output corrupts the rest of the run.

We took it seriously. This post is what we changed and what we deliberately didn't.

## What we audited

We grepped `MANDATORY` / `MUST` / `EVERY` / `EACH` / `CRITICAL` across `packages/core/src/agent/prompts.ts`, `analysis-prompts.ts`, and the review/audit pipelines. Each hit got traced to the chokepoint downstream: is there a code gate enforcing this, or is the prompt the only thing standing between the model and a bad outcome? Six patterns came up where the prompt was load-bearing. Five turned out to be real failures; one was a false positive on second-pass review. Eleven other "MUST"s already had deterministic gates and stayed untouched.

## 5 PRs, 5 chokepoints, 5 deterministic gates

### #287 — empty-PoC gate at save time

**What the prompt enforced.** `prompts.ts` and `analysis-prompts.ts` told the agent to "include concrete proof — actual code, request/response, or PoC steps" on every `save_finding` call. The disclose layer already refused empty PoCs at render time via `EmptyPocError` in `disclose/template.ts`, but that was downstream — the agent could still spend turns producing findings that would be silently dropped later as `_dropped/` rows.

**Why prompts failed at it.** The model would emit `evidence_request: ""`, `evidence_response: ""`, `poc_steps: undefined` on a finding it was halfway sure about, count it as progress, and move on. The transcript said "5 findings"; disclose said "1 advisory."

**Where the gate now lives.** `packages/core/src/agent/tools.ts:2360` — the first thing `saveFinding` does is check that at least one of `evidence_request`, `evidence_response`, or `poc_steps` is non-empty:

```ts
const requestEmpty = typeof requestRaw !== "string" || !requestRaw.trim();
const responseEmpty = typeof responseRaw !== "string" || !responseRaw.trim();
const pocStepsEmpty = !args.poc_steps
  || (Array.isArray(args.poc_steps) && args.poc_steps.length === 0)
  || (typeof args.poc_steps === "string" && !args.poc_steps.trim());
if (requestEmpty && responseEmpty && pocStepsEmpty) {
  return {
    success: false,
    output: null,
    error:
      "save_finding requires non-empty evidence_request, evidence_response, or poc_steps. " +
      "Re-run the exploit and capture the request/response or step graph.",
  };
}
```

The retry-friendly shape mirrors `flag-validator.ts` at `markDone`: rejected once with a specific hint, accepted on retry. The model sees its own bad output rejected with concrete guidance instead of inferring from a downstream artifact it never reads.

### #288 — fuzzy-title dedup at save time

**What the prompt enforced.** `prompts.ts:134` told the agent to "query existing findings to avoid duplicate work." The agent was supposed to call `query_findings` before each `save_finding`.

**Why prompts failed at it.** Same SQLi got saved 2–4 times across attack and verify stages. The disclose bundle then rendered N advisories from one bug. We were already running post-hoc dedup logic in `consolidate-xbow.ts` to clean up benchmark output, which is a tell — if you need post-hoc dedup, the ingest didn't dedup.

**Where the gate now lives.** `packages/core/src/agent/tools.ts:2467`. Before pushing a new finding, `saveFinding` builds a similarity key from `(category, normalizedTitle, evidenceRequestPrefix)` and walks `this.ctx.findings` for an existing match. Exact match on normalized title merges. Fuzzy match — Levenshtein ≤ 5 on normalized title plus identical evidence-request prefix — also merges:

```ts
const newNormTitle = normalizeFindingTitle(finding.title);
const newEvidencePrefix = evidenceRequestPrefix(finding.evidence.request);
const existing = this.ctx.findings.find((f) => {
  if (f.category !== finding.category) return false;
  const existingNormTitle = normalizeFindingTitle(f.title);
  if (existingNormTitle === newNormTitle) return true;
  const existingEvidencePrefix = evidenceRequestPrefix(f.evidence.request);
  if (existingEvidencePrefix !== newEvidencePrefix) return false;
  return levenshtein(existingNormTitle, newNormTitle) <= FUZZY_TITLE_DISTANCE_THRESHOLD;
});
```

The `FUZZY_TITLE_DISTANCE_THRESHOLD = 5` (in `tools-helpers.ts:77`) tolerates `"SQL injection in /users"` vs `"SQL Injection in /users.php"` after normalization, but the same-prefix evidence guard prevents `/admin/users` vs `/admin/orders` from collapsing. First-write-wins: re-running with stronger evidence requires the explicit `update_finding` path.

### #289 — path-existence validation at parse time

**What the prompt enforced.** `prompts.ts:514` told the agent to "Read the file… verify independently" before citing a `file:line` reference. The H1 disclosure CoC explicitly punishes hallucinated function/file/endpoint references in reports — it's tripwire #1.

**Why prompts failed at it.** `findings-parser.ts parseStructuredBlocks` accepted whatever `file:` line the agent emitted. There was a real path-existence check in `disclose/canary.ts:93 verifyAgainstRef`, but it only ran when `--repo` was passed at disclose time, and most pipelines didn't reach it. Hallucinated `file:line` references would slip through to advisories.

**Where the gate now lives.** `packages/core/src/findings-parser.ts:39 validateFileRef`. Mirrors the canary check but runs at parse time:

```ts
export function validateFileRef(fileRef, scopePath) {
  if (!scopePath) return { valid: true }; // can't validate, accept
  const path = fileRef.trim().split(":")[0];
  const scopeAbs = resolve(scopePath);
  if (isAbsolute(path)) return { valid: false, reason: `fabricated path: ${path}` };
  const abs = resolve(scopeAbs, path);
  if (abs !== scopeAbs && !abs.startsWith(scopeAbs + "/")) {
    return { valid: false, reason: `fabricated path: ${path}` };
  }
  if (!existsSync(abs)) return { valid: false, reason: `fabricated path: ${path}` };
  return { valid: true };
}
```

Called from both parse strategies (`parseJsonOutput` at `findings-parser.ts:108`, `parseStructuredBlocks` at `:182`). Path traversal that escapes scope is treated as fabricated; absolute paths are rejected on the same grounds. Failure mode is "drop a finding," not "raise on a real one" — false-negative-safe by design.

### #290 — auth injection at bash time

**What the prompt enforced.** `prompts.ts:33–39` told the agent: "Authentication (CRITICAL) — You MUST use them with EVERY HTTP request. … When using curl, include the appropriate -H flag." Structured tools (`http_request`, `crawl`, `submit_form`, `browser`) auto-injected via `buildAuthHeaders`; the bash tool only exposed `$AUTH_HEADER` / `$AUTH_VALUE` / `$AUTH_CURL_FLAG` env vars and asked the agent to interpolate them.

**Why prompts failed at it.** Shell-first mode is the highest-throughput attack path on XBOW BB and on most H1 engagements. After conversation compaction in long bash chains, the agent forgot the env-var affordance and sent unauthenticated curls for 5+ turns. The failure was silent — 200 anonymous responses look fine — and the engagement effectively pivoted back to discovery from zero.

**Where the gate now lives.** `packages/core/src/agent/tools.ts:856 injectAuthIntoBashCommand`, called from the `bash` tool at `tools.ts:2038`:

```ts
if (this.ctx.authConfig && this.ctx.scope) {
  const verdict = injectAuthIntoBashCommand(command, this.ctx.scope);
  if (verdict.kind === "refuse") {
    return { success: false, output: null, error: `bash refused: ${verdict.reason}` };
  }
  if (verdict.kind === "rewrite") {
    command = verdict.command;
  }
}
```

The rewriter splits on top-level pipes and `&&`/`||`/`;`, then for each curl/wget segment whose URL is in scope and which doesn't already carry explicit auth, splices `$AUTH_CURL_FLAG` in front of the URL. Python `requests` invocations without explicit auth are refused with a hint pointing at `http_request`. Auth-aware in code, not prompt.

### #291 — per-item orchestration loops

**What the prompt enforced.** `prompts.ts:457` told the verify agent: "For each finding: 1. Replay the original attack…" and the verify orchestrator passed every finding into a single `runNativeAgentLoop` with `maxTurns: Math.min(findings.length * 3, 15)`. Same shape on `audit.ts collectSourceFiles` and the research path: "For EACH file that handles untrusted input…" inside one shared session.

**Why prompts failed at it.** With ≥6 findings the agent couldn't actually do 3 turns each in a 15-turn budget. It skipped, deduped (informally, in-context), or condensed. Skipped findings stayed `discovered` and contaminated the disclose bundle. On the audit/research path, dumping 50 source files into one prompt produced a skim, not a per-file walk.

**Where the gate now lives.** Three sites, same shape — replace one big prompt with an outer `for` loop in code.

`agentic-scanner.ts:2552 runNativeVerify` runs one session per finding with a fixed `VERIFY_TURNS_PER_FINDING = 5`:

```ts
for (const finding of findings) {
  await runNativeAgentLoop({
    config: {
      role: "verify",
      systemPrompt: verifyPromptSingleFinding(config.target, finding, config.auth),
      maxTurns: VERIFY_TURNS_PER_FINDING,
      // ...
    },
    // ...
  });
}
```

`unified-pipeline.ts:915 runPerFileResearch` and `audit.ts:668 runPerFileAudit` mirror the shape for research and npm/PyPI/cargo/OCI audits — one agent session per source file, focused per-file system prompt, deterministic outer loop. The reference implementation already lived in the repo: `triage/pov-gate.ts buildPovSystemPrompt` was doing this years ago for evidence-judge agents. We just generalized the pattern.

Feature-flagged via `PWNKIT_FEATURE_PER_ITEM_ORCHESTRATION` (default on) — set to `0` if you need to revert to the shared-session shape for cost-bounded benchmarks. Default-on because per-item is the correct shape; the flag exists to let benchmark sweeps measure the delta.

## The 11 patterns we didn't change

The audit also enumerated 11 "MUST"-shaped prompts that already had deterministic gates behind them. We didn't touch these because they were already doing what bsuh's post advocates:

- `triage/pov-gate.ts:160 CATEGORY_JUDGES` — LLM produces `execution_evidence`, regex oracle decides if it's real exploit proof. Per-category. The textbook narrow-LLM + deterministic-judge pattern.
- `agent/flag-validator.ts validateFlagShape`, called from `tools.ts markDone` — honeypot flags rejected once with a hint, second call passes through. The retry-friendly shape #287 now mirrors.
- `triage/holding-it-wrong.ts isHoldingItWrong` — sink-name blocklist invoked at `agentic-scanner.ts:922`. Findings citing `writeFile` / `compile` / `eval` are downgraded to `info` with a triage note.
- `disclose/template.ts:118 redactSensitiveHeaders` — AWS keys, JWTs, Bearer tokens stripped unconditionally. No prompt asks the LLM to redact.
- `agent/native-loop.ts:1234 LoopDetector` + `earlyStopNoProgress` + budget injections at 30/50/70/85% turn fractions — deterministic loop detection. The "URGENCY: switch now" prompt is fired by code, not by the model self-noticing.
- `agent/tools.ts validateTargetUrl` + scope check at every fetch site + `scope/scanner-binaries.ts detectScannerBinary` — pure code scope enforcement. The "stay within that scope" prompt at `prompts.ts:77` is documentation; the gate is at every URL/shell entry.
- `triage/verify-pipeline.ts:670 parseStepOutput`, `triage/adversarial.ts:218 parseJudgeOutput`, `triage/hybrid-router.ts:130 parseLlmResponse` — markdown-fence-stripping JSON parsers. Fences tolerated; "MUST respond with ONLY a JSON object" is belt-and-suspenders.
- `agentic-scanner.ts:982 evidence-gate` — `evidenceCompleteness <= 0.5` rejects. A code threshold, not "agent should know when evidence is insufficient."

The triage layer in particular is more deterministic than the audit expected to find. The codebase had been growing in the right direction; these five fixes closed the upstream gaps where agent-side ingest still trusted the model.

## What the audit got wrong

The first-pass audit flagged a sixth pattern (H6): verify-pipeline JSON parsing was supposedly fragile because the prompt said "MUST respond with ONLY a JSON object" and we couldn't see fence-stripping in the parser. Second-pass review verified that fences are already stripped at `verify-pipeline.ts:676`, `adversarial.ts:220`, and `hybrid-router.ts:132` — three different parsers, all tolerant of markdown fences and surrounding prose. The "MUST" prompts there are belt-and-suspenders; the parsers handle whatever the model emits.

We closed [issue #284](https://github.com/0sec-labs/0sec/issues/284) on second-pass review and filed [#286](https://github.com/0sec-labs/0sec/issues/286) for path-existence in its place. Honest second pass is the difference between a useful audit and a witch hunt.

## What this is and isn't

This is not a claim that pwnkit's agent loop is now deterministic-everywhere. The agent still has lots of LLM-driven steps — tactical action selection inside the attack stage, finding-content generation, exploit-payload construction, source-file comprehension. Those are search-space exploration and don't deterministically encode. Pwnkit's edge has always been hybrid: code-determined orchestration, LLM-determined tactics.

What did change is that the chokepoints — the spots where one bad model output corrupts everything downstream of it — are now code-gated, not prompt-suggested. Empty PoCs can't be saved. Duplicate findings can't be saved. Fabricated `file:line` references can't be parsed. Unauthenticated curl can't reach in-scope targets when auth is configured. Verify and audit walk per-item instead of asking the model to walk N items inside one session.

Test count went from 1185 to 1204 (19 new tests). All five PRs ship behind file-level changes you can read end-to-end:

- [#287](https://github.com/0sec-labs/0sec/pull/287) — empty-PoC gate at `tools.ts:2360`
- [#288](https://github.com/0sec-labs/0sec/pull/288) — fuzzy-title dedup at `tools.ts:2467` + `tools-helpers.ts:33 levenshtein`
- [#289](https://github.com/0sec-labs/0sec/pull/289) — path-existence validation at `findings-parser.ts:39 validateFileRef`
- [#290](https://github.com/0sec-labs/0sec/pull/290) — bash auth injection at `tools.ts:856 injectAuthIntoBashCommand`
- [#291](https://github.com/0sec-labs/0sec/pull/291) — per-item loops in `agentic-scanner.ts:2552`, `unified-pipeline.ts:915`, `audit.ts:668`

Credit to bsuh for the framing. We didn't invent it; we read a thoughtful post and ran it against our own codebase. The audit found things. The fixes were small. The interesting move was looking — and then doing the second pass on what we found, so the witch-hunt count stayed at zero and the real-fix count was five.
