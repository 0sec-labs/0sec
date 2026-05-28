/**
 * Journal → conversation rehydration (#494).
 *
 * `rehydrateContext` is the *contract* for fresh-context agents: given the
 * append-only journal entries for a run (or a slice of them), it deterministically
 * reconstructs the working state a freshly-spawned agent needs to continue —
 * without ever holding the full transcript in memory. This is the IronCurtain
 * "every agent state begins with a fresh context window and rehydrates from
 * disk" primitive. Nothing routes off it yet (the live loop still carries state
 * in its conversation window); shipping the pure function first locks the
 * contract so the next slice can swap the loop's seed without reshaping data.
 *
 * The function is pure: same entries in → same `ConversationState` out, no I/O,
 * no clock, no randomness. Entries are processed in `seq` order (falling back to
 * array order when `seq` is absent, e.g. legacy journals), and unknown/malformed
 * entries are skipped rather than throwing — a rehydration must never be more
 * fragile than the journal it reads.
 */

import type {
  JournalEntry,
  JournalFindingEntry,
  JournalHypothesisEntry,
  JournalToolCallEntry,
  JournalToolResultEntry,
} from "./types.js";

/** A tool call paired with its result (if one was journaled). */
export interface RehydratedToolStep {
  tool: string;
  arguments?: Record<string, unknown>;
  turn?: number;
  callId?: string;
  result?: {
    ok: boolean;
    output?: unknown;
    error?: string;
  };
}

/** A hypothesis as last seen in the journal (terminal status wins). */
export interface RehydratedHypothesis {
  statement: string;
  rationale?: string;
  confidence?: number;
  status: "open" | "confirmed" | "refuted" | "abandoned";
}

/**
 * The minimal, fresh-context seed a continuing agent needs. Deliberately
 * structural (not a serialized message array): the next slice decides how to
 * render this into a model-specific prompt / message window, so different
 * runtimes (frontier vs. short-context open-weight) can format it differently.
 */
export interface ConversationState {
  runId: string | null;
  /** Highest seq observed; -1 when the journal is empty. */
  lastSeq: number;
  /** Tool steps in chronological order, results joined to their calls by callId. */
  toolSteps: RehydratedToolStep[];
  /** Open + resolved hypotheses, de-duplicated by statement (latest status wins). */
  hypotheses: RehydratedHypothesis[];
  /** Findings recorded so far (raw finding payloads from `finding` entries). */
  findings: Array<Record<string, unknown>>;
  /** Free-form notes in chronological order. */
  notes: string[];
  /** Decisions the agent/orchestrator committed to, in order. */
  decisions: string[];
  /** Whether a terminal `done` entry closed the run, and its summary. */
  done: boolean;
  summary: string;
}

function emptyState(): ConversationState {
  return {
    runId: null,
    lastSeq: -1,
    toolSteps: [],
    hypotheses: [],
    findings: [],
    notes: [],
    decisions: [],
    done: false,
    summary: "",
  };
}

/** Order entries by seq (when present) then by original position as tiebreak. */
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

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Rehydrate a fresh-context `ConversationState` from journal entries.
 *
 * Pure and total: malformed or unrecognised entries are skipped, never thrown.
 */
export function rehydrateContext(entries: JournalEntry[]): ConversationState {
  const state = emptyState();
  if (!Array.isArray(entries) || entries.length === 0) return state;

  const ordered = orderEntries(entries);

  // Tool results are joined to their call by callId when available; otherwise
  // we attach a result to the most recent unresolved call for the same tool.
  const callsByCallId = new Map<string, RehydratedToolStep>();
  const hypothesisByStatement = new Map<string, RehydratedHypothesis>();

  for (const entry of ordered) {
    if (!entry || typeof entry !== "object" || typeof entry.kind !== "string") {
      continue;
    }
    if (typeof entry.runId === "string" && state.runId === null) {
      state.runId = entry.runId;
    }
    if (typeof entry.seq === "number" && entry.seq > state.lastSeq) {
      state.lastSeq = entry.seq;
    }

    switch (entry.kind) {
      case "tool_call": {
        const e = entry as JournalToolCallEntry;
        if (typeof e.tool !== "string") break;
        const step: RehydratedToolStep = {
          tool: e.tool,
          ...(e.arguments !== undefined ? { arguments: e.arguments } : {}),
          ...(typeof e.turn === "number" ? { turn: e.turn } : {}),
          ...(e.callId ? { callId: e.callId } : {}),
        };
        state.toolSteps.push(step);
        if (e.callId) callsByCallId.set(e.callId, step);
        break;
      }
      case "tool_result": {
        const e = entry as JournalToolResultEntry;
        if (typeof e.tool !== "string") break;
        const result = {
          ok: e.ok === true,
          ...(e.output !== undefined ? { output: e.output } : {}),
          ...(typeof e.error === "string" ? { error: e.error } : {}),
        };
        let target: RehydratedToolStep | undefined;
        if (e.callId && callsByCallId.has(e.callId)) {
          target = callsByCallId.get(e.callId);
        } else {
          // Attach to the latest unresolved call for the same tool.
          for (let i = state.toolSteps.length - 1; i >= 0; i -= 1) {
            const candidate = state.toolSteps[i];
            if (candidate.tool === e.tool && candidate.result === undefined) {
              target = candidate;
              break;
            }
          }
        }
        if (target) {
          target.result = result;
        } else {
          // Orphan result (call not journaled): record it as a result-only step
          // so the continuing agent still sees the observation.
          state.toolSteps.push({
            tool: e.tool,
            ...(typeof e.turn === "number" ? { turn: e.turn } : {}),
            ...(e.callId ? { callId: e.callId } : {}),
            result,
          });
        }
        break;
      }
      case "hypothesis": {
        const e = entry as JournalHypothesisEntry;
        if (typeof e.statement !== "string") break;
        const existing = hypothesisByStatement.get(e.statement);
        const merged: RehydratedHypothesis = {
          statement: e.statement,
          ...(e.rationale !== undefined ? { rationale: e.rationale } : existing?.rationale ? { rationale: existing.rationale } : {}),
          ...(typeof e.confidence === "number" ? { confidence: e.confidence } : existing?.confidence !== undefined ? { confidence: existing.confidence } : {}),
          status: e.status ?? existing?.status ?? "open",
        };
        hypothesisByStatement.set(e.statement, merged);
        break;
      }
      case "finding": {
        const e = entry as JournalFindingEntry;
        if (isPlainObject(e.finding)) state.findings.push(e.finding);
        break;
      }
      case "observation": {
        const e = entry as { summary?: unknown };
        if (typeof e.summary === "string" && e.summary.trim()) state.notes.push(e.summary);
        break;
      }
      case "note": {
        const e = entry as { text?: unknown };
        if (typeof e.text === "string" && e.text.trim()) state.notes.push(e.text);
        break;
      }
      case "decision": {
        const e = entry as { decision?: unknown };
        if (typeof e.decision === "string" && e.decision.trim()) state.decisions.push(e.decision);
        break;
      }
      case "done": {
        const e = entry as { summary?: unknown };
        state.done = true;
        if (typeof e.summary === "string") state.summary = e.summary;
        break;
      }
      default:
        // dispatch / error / unknown kinds carry no conversation state for the
        // current seed contract; skip them.
        break;
    }
  }

  // Preserve first-seen order of hypotheses while reflecting final status.
  const seen = new Set<string>();
  for (const entry of ordered) {
    if (entry?.kind !== "hypothesis") continue;
    const statement = (entry as JournalHypothesisEntry).statement;
    if (typeof statement !== "string" || seen.has(statement)) continue;
    seen.add(statement);
    const merged = hypothesisByStatement.get(statement);
    if (merged) state.hypotheses.push(merged);
  }

  return state;
}
