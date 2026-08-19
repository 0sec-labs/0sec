/**
 * Orchestrator: summary view + specialist dispatch (#494, slice 3).
 *
 * This is the IronCurtain "central Orchestrator that does NOT read source code
 * — it routes off the append-only execution journal" primitive, ported onto
 * the journal machinery slices 1–2 shipped (`writer.ts`, `rehydrate.ts`,
 * `seed.ts`). It is two pure functions and a contract, deliberately mirroring
 * how `rehydrateContext`/`renderSeedMessages` landed as pure contracts before
 * anything routed off them:
 *
 *   1. `summarizeForOrchestrator(entries)` — collapse a run's journal into a
 *      compact, high-level *summary view*. The router sees dispatches,
 *      findings, decisions, hypothesis status, error counts, and which
 *      specialists have run — it NEVER sees raw tool output or source. Large
 *      blobs live in sidecars (`writer.ts materializeArtifacts`) the router can
 *      choose to hydrate; the summary itself stays bounded regardless of run
 *      length, which is what lets a short-context model orchestrate a long run.
 *   2. `selectNextDispatch(summary)` — given that summary, decide which
 *      specialist to dispatch next (`recon` → `harness-builder` →
 *      `exploit-writer` → `validator`), or stop. Pure and deterministic: the
 *      same summary always routes the same way, so a canned journal state has
 *      one correct dispatch — exactly the property the issue's
 *      "orchestrator picks correct specialist for canned journal states" test
 *      asserts.
 *
 * Both functions are total: malformed / unknown entries are skipped, never
 * thrown, matching `rehydrate.ts`. Nothing in the live loop routes off this
 * yet — wiring `native-loop.ts`'s monolithic prompt into an Orchestrator that
 * dispatches fresh-context specialists is the next slice and lands behind its
 * own flag, the same way slices 1–2 did. Shipping the pure contract first locks
 * the router/reader split so the loop swap is mechanical.
 *
 * See docs/research/agent-execution-journal-design.md §"Strategy/router vs.
 * reader separation".
 */

import type {
  JournalDecisionEntry,
  JournalDispatchEntry,
  JournalDoneEntry,
  JournalEntry,
  JournalFindingEntry,
  JournalHypothesisEntry,
} from "./types.js";

/**
 * The four specialist roles an Orchestrator dispatches, in their natural
 * pipeline order. These are the issue's vocabulary (`recon`, `harness-builder`,
 * `exploit-writer`, `validator`); the live scanner's coarser roles
 * (`discovery`/`attack`/`verify`) map onto these but are intentionally NOT
 * conflated here — the journal records whatever `targetAgent` string a dispatch
 * carried, and the orchestrator routes off the canonical specialist names.
 */
export type SpecialistRole =
  | "recon"
  | "harness-builder"
  | "exploit-writer"
  | "validator";

/** Canonical specialist pipeline order. Index = pipeline stage. */
export const SPECIALIST_PIPELINE: readonly SpecialistRole[] = [
  "recon",
  "harness-builder",
  "exploit-writer",
  "validator",
] as const;

function isSpecialistRole(value: unknown): value is SpecialistRole {
  return (
    typeof value === "string" &&
    (SPECIALIST_PIPELINE as readonly string[]).includes(value)
  );
}

/**
 * The high-level, bounded view of a run the Orchestrator routes off. Carries
 * *no* raw tool output or source — only the strategic kinds. Per-specialist
 * fine-grained traces (`tool_call`/`tool_result`/`note`) are deliberately
 * excluded: a specialist hydrates those via `rehydrateContext` when it runs;
 * the router never needs them.
 */
export interface OrchestratorView {
  runId: string | null;
  /** Highest seq observed; -1 when the journal is empty. */
  lastSeq: number;
  /** Specialist roles that have been dispatched at least once, in first-dispatch order. */
  dispatched: SpecialistRole[];
  /** The most recently dispatched specialist, or null. */
  lastDispatched: SpecialistRole | null;
  /** Count of `finding` entries recorded so far. */
  findingCount: number;
  /** Titles/summaries of findings (bounded strings, never raw payloads). */
  findingTitles: string[];
  /** Strategic decisions committed so far, in order. */
  decisions: string[];
  /** Hypotheses keyed by status, latest status winning (de-duplicated by statement). */
  hypotheses: { open: number; confirmed: number; refuted: number; abandoned: number };
  /** Number of `error` entries — a high count signals a stuck specialist. */
  errorCount: number;
  /** Whether a terminal `done` entry closed the run, and its verdict. */
  done: boolean;
  doneStatus: JournalDoneEntry["status"] | null;
  summary: string;
}

/** Order entries by seq (when present) then original position as tiebreak. */
function orderEntries(entries: JournalEntry[]): JournalEntry[] {
  const seqOf = (entry: JournalEntry): number => {
    const seq = (entry as { seq?: unknown } | null | undefined)?.seq;
    return typeof seq === "number" && Number.isFinite(seq) ? seq : Number.POSITIVE_INFINITY;
  };
  return entries
    .map((entry, index) => ({ entry, index }))
    .sort((a, b) => {
      const sa = seqOf(a.entry);
      const sb = seqOf(b.entry);
      if (sa !== sb) return sa - sb;
      return a.index - b.index;
    })
    .map(({ entry }) => entry);
}

/** Best-effort extraction of a short, safe label from a finding payload. */
function findingTitle(finding: Record<string, unknown>): string {
  const candidate =
    finding.title ?? finding.name ?? finding.summary ?? finding.vulnerability ?? finding.type;
  if (typeof candidate === "string" && candidate.trim()) return candidate.trim().slice(0, 200);
  // Fall back to a compact key set so the router still distinguishes findings
  // without ever embedding a raw exploit/source payload in its view.
  const keys = Object.keys(finding).slice(0, 6).join(", ");
  return keys ? `finding{${keys}}` : "finding";
}

function emptyView(): OrchestratorView {
  return {
    runId: null,
    lastSeq: -1,
    dispatched: [],
    lastDispatched: null,
    findingCount: 0,
    findingTitles: [],
    decisions: [],
    hypotheses: { open: 0, confirmed: 0, refuted: 0, abandoned: 0 },
    errorCount: 0,
    done: false,
    doneStatus: null,
    summary: "",
  };
}

/**
 * Collapse journal entries into the Orchestrator's summary view.
 *
 * Pure and total: malformed / unrecognised entries are skipped, never thrown.
 * Only the strategic high-level kinds contribute; per-step kinds are ignored so
 * the view stays bounded no matter how long the run is.
 */
export function summarizeForOrchestrator(entries: JournalEntry[]): OrchestratorView {
  const view = emptyView();
  if (!Array.isArray(entries) || entries.length === 0) return view;

  const ordered = orderEntries(entries);
  const dispatchedSeen = new Set<SpecialistRole>();
  // Latest status per hypothesis statement, so a confirmed→refuted flip counts once.
  const hypothesisStatus = new Map<string, JournalHypothesisEntry["status"]>();

  for (const entry of ordered) {
    if (!entry || typeof entry !== "object" || typeof entry.kind !== "string") continue;
    if (typeof entry.runId === "string" && view.runId === null) view.runId = entry.runId;
    if (typeof entry.seq === "number" && entry.seq > view.lastSeq) view.lastSeq = entry.seq;

    switch (entry.kind) {
      case "dispatch": {
        const e = entry as JournalDispatchEntry;
        if (isSpecialistRole(e.targetAgent)) {
          if (!dispatchedSeen.has(e.targetAgent)) {
            dispatchedSeen.add(e.targetAgent);
            view.dispatched.push(e.targetAgent);
          }
          view.lastDispatched = e.targetAgent;
        }
        break;
      }
      case "finding": {
        const e = entry as JournalFindingEntry;
        if (e.finding && typeof e.finding === "object" && !Array.isArray(e.finding)) {
          view.findingCount += 1;
          view.findingTitles.push(findingTitle(e.finding));
        }
        break;
      }
      case "decision": {
        const e = entry as JournalDecisionEntry;
        if (typeof e.decision === "string" && e.decision.trim()) view.decisions.push(e.decision);
        break;
      }
      case "hypothesis": {
        const e = entry as JournalHypothesisEntry;
        if (typeof e.statement === "string" && e.statement.trim()) {
          hypothesisStatus.set(e.statement, e.status ?? "open");
        }
        break;
      }
      case "error": {
        view.errorCount += 1;
        break;
      }
      case "done": {
        const e = entry as JournalDoneEntry;
        view.done = true;
        if (e.status === "success" || e.status === "failed" || e.status === "cancelled") {
          view.doneStatus = e.status;
        }
        if (typeof e.summary === "string") view.summary = e.summary;
        break;
      }
      default:
        // observation / tool_call / tool_result / note / unknown carry no
        // router-level signal; skip them. They belong to the specialist trace.
        break;
    }
  }

  for (const status of hypothesisStatus.values()) {
    const key = status ?? "open";
    view.hypotheses[key] += 1;
  }

  return view;
}

/** Why the orchestrator chose to stop dispatching. */
export type StopReason =
  | "done" // a terminal `done` entry already closed the run
  | "validated" // validator confirmed a finding — investigation complete
  | "pipeline-exhausted"; // every specialist has run and produced nothing actionable

/** The orchestrator's routing decision: dispatch a specialist, or stop. */
export type DispatchDecision =
  | {
      action: "dispatch";
      role: SpecialistRole;
      /** Human-readable objective handed to the specialist's role prompt. */
      objective: string;
      /** Why the router picked this specialist (for journaling the decision). */
      rationale: string;
    }
  | { action: "stop"; reason: StopReason; rationale: string };

const OBJECTIVES: Record<SpecialistRole, string> = {
  recon: "Enumerate attack surface and record observations/hypotheses to the journal.",
  "harness-builder": "Build a reproducible harness/test rig for the most promising hypothesis.",
  "exploit-writer": "Develop a working exploit/PoC against the harnessed surface and record findings.",
  validator: "Independently validate recorded findings; confirm or refute each one.",
};

/**
 * Decide the next dispatch from a summary view. Pure and deterministic.
 *
 * Routing policy (intentionally simple and explainable — the router is a state
 * machine over the journal, not an LLM judgement call; the companion
 * YAML-FSM issue formalises this graph):
 *
 *   1. If the run is already `done`, stop.
 *   2. If a finding exists and the validator has NOT yet run, dispatch the
 *      validator — confirming a finding is always the highest-value next step.
 *   3. If the validator has run and findings exist, stop (`validated`):
 *      the investigation reached its goal.
 *   4. Otherwise advance the pipeline: dispatch the first specialist in
 *      `SPECIALIST_PIPELINE` that has not run yet.
 *   5. If every specialist has run and produced no finding, stop
 *      (`pipeline-exhausted`).
 *
 * A persistently erroring specialist (errorCount high relative to progress)
 * does not loop forever: once it has been dispatched, step 4 advances past it
 * to the next stage rather than re-dispatching the same role.
 */
export function selectNextDispatch(view: OrchestratorView): DispatchDecision {
  if (view.done) {
    return {
      action: "stop",
      reason: "done",
      rationale: view.summary
        ? `Run already closed (${view.doneStatus ?? "done"}): ${view.summary}`
        : `Run already closed (${view.doneStatus ?? "done"}).`,
    };
  }

  const hasRun = (role: SpecialistRole): boolean => view.dispatched.includes(role);

  // A finding that hasn't been validated is the top priority: send the validator.
  if (view.findingCount > 0 && !hasRun("validator")) {
    return {
      action: "dispatch",
      role: "validator",
      objective: OBJECTIVES.validator,
      rationale: `${view.findingCount} finding(s) recorded and validator has not run; validate before continuing.`,
    };
  }

  // Validator already ran against existing findings → investigation complete.
  if (view.findingCount > 0 && hasRun("validator")) {
    const confirmed = view.hypotheses.confirmed;
    return {
      action: "stop",
      reason: "validated",
      rationale: `Validator has run against ${view.findingCount} finding(s)` +
        (confirmed > 0 ? `; ${confirmed} hypothesis(es) confirmed.` : "."),
    };
  }

  // Advance the pipeline: first specialist that hasn't run yet.
  for (const role of SPECIALIST_PIPELINE) {
    if (role === "validator") continue; // validator is only dispatched once a finding exists
    if (!hasRun(role)) {
      return {
        action: "dispatch",
        role,
        objective: OBJECTIVES[role],
        rationale: `Pipeline advance: '${role}' has not run yet` +
          (view.lastDispatched ? ` (last dispatched: '${view.lastDispatched}').` : "."),
      };
    }
  }

  // Every productive specialist has run and produced no finding.
  return {
    action: "stop",
    reason: "pipeline-exhausted",
    rationale: "recon, harness-builder and exploit-writer have all run with no finding recorded.",
  };
}

/**
 * The contract a specialist agent fulfils each invocation. The Orchestrator
 * builds this from its dispatch decision plus the journal slice the specialist
 * should hydrate; the runtime (next slice) renders `journalSlice` into a fresh
 * context window via `rehydrateContext`/`renderSeedMessages` and runs the
 * specialist with `rolePrompt`. The specialist's only output side-effect is
 * appending new journal entries — never mutating prior ones.
 */
export interface SpecialistDispatch {
  role: SpecialistRole;
  objective: string;
  /** Role prompt the specialist runs under (set by the caller from its prompt library). */
  rolePrompt?: string;
  /**
   * The journal entries this specialist should rehydrate its fresh context
   * from. Defaults to the whole run; a caller may pass a narrower slice (e.g.
   * only entries after the last validator run) to keep the context tight.
   */
  journalSlice: JournalEntry[];
}

/**
 * Build a `SpecialistDispatch` from a routing decision. Returns null when the
 * decision is to stop. The `journalSlice` defaults to the full ordered run; the
 * caller can post-filter it. Pure: no I/O, no journal append (the caller writes
 * the `dispatch` entry so the append stays on the writer it owns).
 */
export function buildSpecialistDispatch(
  decision: DispatchDecision,
  entries: JournalEntry[],
  options?: { rolePrompt?: string; journalSlice?: JournalEntry[] },
): SpecialistDispatch | null {
  if (decision.action !== "dispatch") return null;
  return {
    role: decision.role,
    objective: decision.objective,
    ...(options?.rolePrompt ? { rolePrompt: options.rolePrompt } : {}),
    journalSlice: options?.journalSlice ?? orderEntries(Array.isArray(entries) ? entries : []),
  };
}
