---
title: Append-only execution journal + Orchestrator — Design Doc
description: Historical design for an execution journal, specialist dispatch, replay, and recovery.
---

> Historical proposal tracked in [0sec#224](https://github.com/0sec-labs/0sec/issues/224). The commands and recovery behavior below describe the design.

<span id="the-problem-in-one-paragraph"></span>
## Motivation

`packages/core/src/agent/native-loop.ts` uses a bounded conversation window.
Compaction can lose details needed for later investigation or recovery. This
proposal retains observations in a journal and dispatches specialists with
selected context.

[Provos / IronCurtain](https://www.provos.org/post/finding-zero-days-with-any-model/)
(April 2026) reports the OpenBSD SACK reproduction with Sonnet/Opus 4.6 and a
CVE-class issue with GLM 5.1. [BoxPwnr](https://github.com/0ca/boxpwnr) reports
97.1% on XBOW using compaction, loop detection, and handoffs. These are references
for the design, with different evaluation conditions.

## Design goals

1. Reconstruct decisions from an append-only journal; support explicit replay branches.
2. Let the orchestrator route from a summary while specialists inspect source and raw evidence.
3. Give each specialist a fresh context containing the relevant journal slice.
4. **Backwards-compatible.** The current loop keeps working. The journal-based loop ships behind `0SEC_FEATURE_JOURNAL_LOOP=1`, A/B tested against the existing loop on XBOW, promoted to default only after measured gains on all three slices (BB, WB, npm-bench).
5. **No regression on XBOW BB.** Current state-of-record is 97/104 black-box (93.3%) on retained-artifact-backed runs. Any journal-based replacement must clear that bar on a 30-run pilot before the default flips.

## Journal schema

Plain JSONL under `~/.0sec/runs/<run-id>/journal.jsonl`. Append-only, never rewritten in place. Large blobs (full HTTP responses, full file reads, semgrep raw output) are sidecarred to `~/.0sec/runs/<run-id>/artifacts/<entry-id>.{ext}` and the journal entry stores a reference + content hash. This keeps the journal grep-able and small enough to feed back into the Orchestrator's window.

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

The orchestrator receives a journal summary and routing prompt. Each specialist receives a selected evidence slice.

<span id="what-the-orchestrator-actually-sees"></span>
## Orchestrator context

`summarizeJournal(entries) → string` produces a summary:

- Lists the open hypotheses
- Lists findings by status
- Lists the last specialist handoff with its summary
- Lists the count + types of tool calls executed
- Does NOT include raw tool output, raw source code, or sensitive payloads

Specialists receive raw output from their selected entries.

## Resume semantics

```bash
0sec scan --resume <run-id>
```

Replays the journal from disk, reconstructs in-memory state (open hypotheses, findings, current specialist if mid-dispatch), and continues from the last `handoff` entry. If a `dispatch` exists with no matching handoff, the resume kicks off the specialist again from scratch (specialists are idempotent on re-run by contract — they read the journal slice and append).

A `--branch` flag clones the journal up to a checkpoint and continues from there. Used for A/B prompt testing.

## Backwards compatibility & rollout

Phase 1 — `0SEC_FEATURE_JOURNAL_LOOP=0` (default). Existing `native-loop.ts` runs unchanged. New code lands but is gated.

Phase 2 — `0SEC_FEATURE_JOURNAL_LOOP=1` shipped, default OFF. We run a 30-run XBOW BB pilot at `limit_runs=30`. Pass criteria: BB flag count within 1 of the current 97/104 record, $/flag within 20% of the current Sonnet 4.6 baseline, no regression on `disclose` advisory render rate.

Phase 3 — promote to default ON for one workflow at a time, starting with `vuln-discovery` (a new workflow with no current baseline) before `web-pentest`.

Phase 4 — once stable, remove the legacy code path. Not before two consecutive benchmark cycles show no regression.

## Risks and mitigations

- **Incomplete summaries:** omitted evidence can cause poor dispatch decisions.
  Test `summarizeJournal.ts` against known decision points before reducing detail.
- **Non-deterministic specialists:** replay restores recorded state; branches
  can produce different subsequent decisions.
- **Storage growth:** long investigations need bounded context slices and artifact
  retention. The proposed `0sec run gc <run-id>` prunes superseded blobs.
- **Schema changes:** version entries and test migrations against earlier journals.

<span id="what-were-explicitly-not-doing"></span>
## Scope

The proposed orchestrator dispatches sequentially. Existing tool signatures and
per-specialist in-memory state remain. YAML-FSM workflows are separate work in
[#225](https://github.com/0sec-labs/0sec/issues/225).

## Tracking

- Tracking issue: [0sec#224](https://github.com/0sec-labs/0sec/issues/224)
- Companion issues: [#225 (YAML FSM workflows)](https://github.com/0sec-labs/0sec/issues/225), [#226 (C/C++ review profile)](https://github.com/0sec-labs/0sec/issues/226), [#227 (cost telemetry)](https://github.com/0sec-labs/0sec/issues/227)
- Prior work referenced: [Provos — Finding Zero-Days with Any Model](https://www.provos.org/post/finding-zero-days-with-any-model/), [BoxPwnr](https://github.com/0ca/boxpwnr) (97.1% XBOW)
