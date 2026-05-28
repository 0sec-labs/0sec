export const JOURNAL_SCHEMA_VERSION = 1;
export const DEFAULT_JOURNAL_SIDECAR_THRESHOLD_BYTES = 32 * 1024;

export type JournalSchemaVersion = typeof JOURNAL_SCHEMA_VERSION;
/**
 * Journal entry kinds.
 *
 * The first six kinds (`dispatch`, `observation`, `finding`, `decision`,
 * `error`, `done`) are the original orchestrator-level vocabulary used by the
 * CVE adaptation loop (`cve/adapt-loop.ts`). The next four — `tool_call`,
 * `tool_result`, `hypothesis`, `note` — are the per-agent-step vocabulary
 * introduced for the execution-journal rearchitecture (#494): one entry per
 * concrete step the in-loop agent takes. Both vocabularies coexist in the
 * same JSONL stream so an orchestrator can route off the high-level kinds
 * while a specialist's fine-grained trace lives alongside it. Adding a kind is
 * a backward-compatible change: readers ignore kinds they do not recognise.
 */
export type JournalEntryKind =
  | "dispatch"
  | "observation"
  | "finding"
  | "decision"
  | "error"
  | "done"
  | "tool_call"
  | "tool_result"
  | "hypothesis"
  | "note";

export interface JournalArtifactInput {
  name?: string;
  ext?: string;
  mediaType?: string;
  content: string | Uint8Array;
  forceSidecar?: boolean;
}

export interface JournalArtifactInline {
  kind: "inline";
  name?: string;
  mediaType?: string;
  content: string;
  encoding: "utf8" | "base64";
  sha256: string;
  size: number;
}

export interface JournalArtifactRef {
  kind: "ref";
  name?: string;
  mediaType?: string;
  ref: string;
  sha256: string;
  size: number;
}

export type JournalArtifact = JournalArtifactInline | JournalArtifactRef;

interface JournalEntryBase {
  schemaVersion: JournalSchemaVersion;
  id: string;
  runId: string;
  /**
   * Monotonic, zero-based sequence number assigned by the writer at append
   * time. Wall-clock `timestamp` is not a reliable ordering key (clock skew,
   * sub-millisecond bursts on a fast loop), so `seq` is the authoritative
   * ordering and de-duplication key. Append order in the file is also
   * authoritative; `seq` makes that order explicit and survives merges of
   * branched journals. Optional on the wire for back-compat with v1 journals
   * written before #494 — readers treat a missing `seq` as "use file order".
   */
  seq?: number;
  timestamp: string;
  actor?: string;
  artifacts?: JournalArtifact[];
}

interface JournalEntryInputBase {
  id?: string;
  /**
   * Optional explicit sequence number. When omitted the writer assigns the
   * next monotonic value. Supplying it is only for replay/branch tooling that
   * needs to preserve a source journal's numbering.
   */
  seq?: number;
  timestamp?: string;
  actor?: string;
  artifacts?: JournalArtifactInput[];
}

export interface JournalDispatchEntry extends JournalEntryBase {
  kind: "dispatch";
  targetAgent: string;
  objective: string;
  context?: Record<string, unknown>;
}

export interface JournalObservationEntry extends JournalEntryBase {
  kind: "observation";
  source: string;
  summary: string;
  data?: Record<string, unknown>;
}

export interface JournalFindingEntry extends JournalEntryBase {
  kind: "finding";
  finding: Record<string, unknown>;
  relatedEntryId?: string;
}

export interface JournalDecisionEntry extends JournalEntryBase {
  kind: "decision";
  decision: string;
  rationale?: string;
  confidence?: number;
}

export interface JournalErrorEntry extends JournalEntryBase {
  kind: "error";
  message: string;
  code?: string;
  stack?: string;
}

export interface JournalDoneEntry extends JournalEntryBase {
  kind: "done";
  status: "success" | "failed" | "cancelled";
  summary: string;
}

// ── Per-step entry kinds (#494) ──
// One entry per concrete step the in-loop agent takes. These are the
// fine-grained vocabulary the rehydrator (`rehydrate.ts`) replays into a
// fresh conversation context.

/** A tool the agent decided to call, with its arguments. */
export interface JournalToolCallEntry extends JournalEntryBase {
  kind: "tool_call";
  tool: string;
  arguments?: Record<string, unknown>;
  /** Turn index in the originating loop, when known. */
  turn?: number;
  /** Stable id linking this call to its `tool_result` entry. */
  callId?: string;
}

/** The observed result of a previously journaled `tool_call`. */
export interface JournalToolResultEntry extends JournalEntryBase {
  kind: "tool_result";
  tool: string;
  ok: boolean;
  /** Result payload (small results inline; large ones sidecarred via `artifacts`). */
  output?: unknown;
  error?: string;
  turn?: number;
  /** Links back to the `tool_call` entry's `callId`. */
  callId?: string;
}

/** A working theory the agent is pursuing, with optional confidence. */
export interface JournalHypothesisEntry extends JournalEntryBase {
  kind: "hypothesis";
  statement: string;
  rationale?: string;
  /** 0..1 self-reported confidence. */
  confidence?: number;
  /** `"open"` while being tested; terminal states close the hypothesis. */
  status?: "open" | "confirmed" | "refuted" | "abandoned";
  turn?: number;
}

/** Free-form narration / scratch note the agent wants persisted. */
export interface JournalNoteEntry extends JournalEntryBase {
  kind: "note";
  text: string;
  turn?: number;
}

export type JournalEntry =
  | JournalDispatchEntry
  | JournalObservationEntry
  | JournalFindingEntry
  | JournalDecisionEntry
  | JournalErrorEntry
  | JournalDoneEntry
  | JournalToolCallEntry
  | JournalToolResultEntry
  | JournalHypothesisEntry
  | JournalNoteEntry;

export type JournalEntryInput =
  | (JournalEntryInputBase & Pick<JournalDispatchEntry, "kind" | "targetAgent" | "objective" | "context">)
  | (JournalEntryInputBase & Pick<JournalObservationEntry, "kind" | "source" | "summary" | "data">)
  | (JournalEntryInputBase & Pick<JournalFindingEntry, "kind" | "finding" | "relatedEntryId">)
  | (JournalEntryInputBase & Pick<JournalDecisionEntry, "kind" | "decision" | "rationale" | "confidence">)
  | (JournalEntryInputBase & Pick<JournalErrorEntry, "kind" | "message" | "code" | "stack">)
  | (JournalEntryInputBase & Pick<JournalDoneEntry, "kind" | "status" | "summary">)
  | (JournalEntryInputBase & Pick<JournalToolCallEntry, "kind" | "tool" | "arguments" | "turn" | "callId">)
  | (JournalEntryInputBase & Pick<JournalToolResultEntry, "kind" | "tool" | "ok" | "output" | "error" | "turn" | "callId">)
  | (JournalEntryInputBase & Pick<JournalHypothesisEntry, "kind" | "statement" | "rationale" | "confidence" | "status" | "turn">)
  | (JournalEntryInputBase & Pick<JournalNoteEntry, "kind" | "text" | "turn">);

export interface JournalPaths {
  runDir: string;
  journalPath: string;
  artifactsDir: string;
}
