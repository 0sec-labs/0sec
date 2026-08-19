---
title: Append-only execution journal + Orchestrator — Design Doc
description: The architectural refactor that separates "what to do next" (Orchestrator agent) from "what has been done" (durable on-disk journal). Motivated by Provos / IronCurtain (Apr 2026) and BoxPwnr (97.1% XBOW), both of which validated the same pattern independently.
---

> **Status:** Design doc, open for review. Tracking issue [pwnkit#224](https://github.com/0sec-labs/0sec/issues/224). Nothing is implemented yet; this page describes what we're going to build, why, and how we'll know it worked.

## The problem in one paragraph

pwnkit's agent loop in `packages/core/src/agent/native-loop.ts` carries every tool result, hypothesis, and partial finding in the conversation window until a turn-budget or cost-ceiling fires. When context fills up, a summarizer kicks in and lossy-compresses. This caps the size of investigation we can run, makes recovery from mid-run failures lossy, prevents clean resumption, and makes parallelization hard. Two independent groups have now validated the answer: a durable on-disk journal as source of truth, an Orchestrator agent that routes off the journal and never reads source code directly, and specialist agents that get a fresh context window each dispatch and rehydrate the slice of journal they need. [Provos / IronCurtain](https://www.provos.org/post/finding-zero-days-with-any-model/) (Apr 2026) replicates the 1998 OpenBSD SACK bug on Sonnet 4.6 + Opus 4.6 and finds an autonomous CVE-class issue on GLM 5.1 with this architecture. [BoxPwnr](https://github.com/0ca/boxpwnr) (0ca) reaches 97.1% on XBOW with the same architectural choices: context compaction, loop detection, progress handoff. The technique is settled. The question is what shape it takes inside pwnkit.

## Design goals

1. **Journal is the source of truth.** Every agent decision is reconstructible from the journal. If the runner crashes, a fresh process can rehydrate state and continue. If we want to A/B re-run a step with a different prompt, we replay the journal up to that point and branch. This is what unlocks resumable scans, durable replay, and parallel specialist dispatch.
2. **Orchestrator never reads source code.** It sees a summarized journal view and decides which specialist agent to dispatch next. This is what keeps the strategic loop in a small, cacheable context window even when the investigation is large.
3. **Specialists get fresh context windows.** A recon agent that just finished writes its observations to the journal and exits. The next specialist starts cold and reads only the journal slice it needs. No "summarizer eats the most important detail" failure mode.
4. **Backwards-compatible.** The current loop keeps working. The journal-based loop ships behind `PWNKIT_FEATURE_JOURNAL_LOOP=1`, A/B tested against the existing loop on XBOW, promoted to default only after measured gains on all three slices (BB, WB, npm-bench).
5. **No regression on XBOW BB.** Current state-of-record is 97/104 black-box (93.3%) on retained-artifact-backed runs. Any journal-based replacement must clear that bar on a 30-run pilot before the default flips.

## Journal schema

Plain JSONL under `~/.pwnkit/runs/<run-id>/journal.jsonl`. Append-only, never rewritten in place. Large blobs (full HTTP responses, full file reads, semgrep raw output) are sidecarred to `~/.pwnkit/runs/<run-id>/artifacts/<entry-id>.{ext}` and the journal entry stores a reference + content hash. This keeps the journal grep-able and small enough to feed back into the Orchestrator's window.

Schema versioning: every entry has `schemaVersion: 1`. A migration helper (`packages/core/src/agent/journal/migrate.ts`) runs at load time to upgrade older entries to the current shape.

### Entry types

```ts
type JournalEntry =
  | DispatchEntry      // Orchestrator picks a specialist
  | ToolCallEntry      // Specialist invokes a tool
  | ToolResultEntry    // Tool returns
  | HypothesisEntry    // Specialist asserts a working theory
  | FindingEntry       // Specialist saves a candidate finding
  | HandoffEntry       // Specialist exits, summary back to Orchestrator
  | SystemEntry;       // Schema migration, run start/end, etc.
```

Common fields on every entry: `id` (ULID), `runId`, `parentId` (ULID of the entry that caused this one — gives us a causal DAG), `timestamp` (ISO 8601), `schemaVersion`.

**`DispatchEntry`**

```ts
{
  type: "dispatch",
  specialist: "recon" | "harness-builder" | "exploit-writer" | "validator" | "reporter",
  inputJournalSlice: string[],  // ULIDs of entries the specialist will see
  rationale: string,             // Orchestrator's one-sentence reason
}
```

**`ToolCallEntry` / `ToolResultEntry`**

Mirror what `native-loop.ts` already passes around. The result entry stores small payloads inline; large payloads go to `artifacts/<id>.{json,html,bin}` with a SHA-256 reference.

**`HypothesisEntry`**

```ts
{
  type: "hypothesis",
  text: string,           // "request body deserialization at /api/foo accepts arbitrary classpath"
  status: "open" | "validated" | "refuted",
  confidence: number,     // 0..1
}
```

Specialists update hypothesis status in subsequent entries (by writing a new entry with `parentId` pointing at the original).

**`FindingEntry`** — wraps the existing `Finding` shape, adds `pocVerdict: "pending" | "confirmed" | "could_not_run" | "false_positive"`.

**`HandoffEntry`**

```ts
{
  type: "handoff",
  specialist: "...",
  summary: string,         // 1-3 sentence summary back to the Orchestrator
  recommendedNext: string, // optional hint
}
```

## The Orchestrator–specialist contract

```ts
interface SpecialistInput {
  runId: string;
  journalSlice: JournalEntry[];      // pre-filtered by Orchestrator
  systemPrompt: string;              // role-specific
  toolPolicy: ToolPolicy;            // which tools are allowed
}

interface SpecialistOutput {
  newEntries: JournalEntry[];        // appended in order
  handoff: HandoffEntry;             // mandatory; the last entry the specialist writes
}
```

The contract is one-shot per dispatch. A specialist runs to completion (until it writes its `handoff`), then exits. The Orchestrator decides the next dispatch based on the updated journal.

This is more rigid than a "free agent" loop on purpose. It's what makes context management tractable: the Orchestrator's context is always the journal summary + a small router prompt; the specialist's context is always a fresh window with a curated slice.

## What the Orchestrator actually sees

Not the raw journal — a *summary view*. Built by `summarizeJournal(entries) → string` which:

- Lists the open hypotheses
- Lists findings by status
- Lists the last specialist handoff with its summary
- Lists the count + types of tool calls executed
- Does NOT include raw tool output, raw source code, or sensitive payloads

The specialist *does* see raw output for the entries in its slice. The Orchestrator deliberately does not, so its window stays small even on 100M-token investigations.

## Resume semantics

```bash
pwnkit scan --resume <run-id>
```

Replays the journal from disk, reconstructs in-memory state (open hypotheses, findings, current specialist if mid-dispatch), and continues from the last `handoff` entry. If a `dispatch` exists with no matching handoff, the resume kicks off the specialist again from scratch (specialists are idempotent on re-run by contract — they read the journal slice and append).

A `--branch` flag clones the journal up to a checkpoint and continues from there. Used for A/B prompt testing.

## Backwards compatibility & rollout

Phase 1 — `PWNKIT_FEATURE_JOURNAL_LOOP=0` (default). Existing `native-loop.ts` runs unchanged. New code lands but is gated.

Phase 2 — `PWNKIT_FEATURE_JOURNAL_LOOP=1` shipped, default OFF. We run a 30-run XBOW BB pilot at `limit_runs=30`. Pass criteria: BB flag count within 1 of the current 97/104 record, $/flag within 20% of the current Sonnet 4.6 baseline, no regression on `disclose` advisory render rate.

Phase 3 — promote to default ON for one workflow at a time, starting with `vuln-discovery` (a new workflow with no current baseline) before `web-pentest`.

Phase 4 — once stable, remove the legacy code path. Not before two consecutive benchmark cycles show no regression.

## Risks and mitigations

**Risk: Orchestrator becomes a router that doesn't know enough to make good decisions.** The summary view drops detail by design. If the next-step decision actually needs detail the summary discards, the Orchestrator picks the wrong specialist and the run wastes turns.

*Mitigation:* the summary view is iterated on. We start conservative (more detail, larger Orchestrator window), measure, and trim. The summary is its own module (`summarizeJournal.ts`) with unit tests against canned journal states for the canonical decision points.

**Risk: specialist output is non-deterministic, so resume from journal isn't perfectly reproducible.** Two runs of the same specialist on the same input will not produce identical journals.

*Mitigation:* this is fine. The journal records what *was* decided, not what *would have been* decided. Replay reconstructs state from what was. Branching is the explicit "let's see what would have happened" feature.

**Risk: the journal grows unbounded on long investigations.** A 10M-token Provos-style run could write thousands of entries.

*Mitigation:* the summary view is what the Orchestrator sees, not the journal. Specialists see slices. Long journals are fine on disk. We add a `pwnkit run gc <run-id>` that prunes superseded artifact blobs.

**Risk: schema migrations break replay of old runs.** A future schema change could leave older journals unreadable.

*Mitigation:* every entry has `schemaVersion`. Migration helpers ship with each schema bump. The `migrate.ts` module has a unit test asserting forward-compat for every shipped version.

## What we're explicitly not doing

- **Not a queue or scheduler.** The Orchestrator is one loop, sequential. Parallel specialist dispatch can come later when we have a workload that needs it.
- **Not changing the tools.** `shellExec`, `httpRequest`, `saveFinding` etc. all keep their current signatures. The journal wraps them; it doesn't replace them.
- **Not removing the in-memory state machine.** It still exists for the duration of a single specialist's run. It's just no longer the source of truth across dispatches.
- **Not building #225 here.** This doc is the substrate. YAML-FSM workflows ([#225](https://github.com/0sec-labs/0sec/issues/225)) sit on top.

## Tracking

- Tracking issue: [pwnkit#224](https://github.com/0sec-labs/0sec/issues/224)
- Companion issues: [#225 (YAML FSM workflows)](https://github.com/0sec-labs/0sec/issues/225), [#226 (C/C++ review profile)](https://github.com/0sec-labs/0sec/issues/226), [#227 (cost telemetry)](https://github.com/0sec-labs/0sec/issues/227)
- Prior work referenced: [Provos — Finding Zero-Days with Any Model](https://www.provos.org/post/finding-zero-days-with-any-model/), [BoxPwnr](https://github.com/0ca/boxpwnr) (97.1% XBOW)
