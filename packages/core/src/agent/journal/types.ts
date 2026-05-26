export const JOURNAL_SCHEMA_VERSION = 1;
export const DEFAULT_JOURNAL_SIDECAR_THRESHOLD_BYTES = 32 * 1024;

export type JournalSchemaVersion = typeof JOURNAL_SCHEMA_VERSION;
export type JournalEntryKind = "dispatch" | "observation" | "finding" | "decision" | "error" | "done";

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
  timestamp: string;
  actor?: string;
  artifacts?: JournalArtifact[];
}

interface JournalEntryInputBase {
  id?: string;
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

export type JournalEntry =
  | JournalDispatchEntry
  | JournalObservationEntry
  | JournalFindingEntry
  | JournalDecisionEntry
  | JournalErrorEntry
  | JournalDoneEntry;

export type JournalEntryInput =
  | (JournalEntryInputBase & Pick<JournalDispatchEntry, "kind" | "targetAgent" | "objective" | "context">)
  | (JournalEntryInputBase & Pick<JournalObservationEntry, "kind" | "source" | "summary" | "data">)
  | (JournalEntryInputBase & Pick<JournalFindingEntry, "kind" | "finding" | "relatedEntryId">)
  | (JournalEntryInputBase & Pick<JournalDecisionEntry, "kind" | "decision" | "rationale" | "confidence">)
  | (JournalEntryInputBase & Pick<JournalErrorEntry, "kind" | "message" | "code" | "stack">)
  | (JournalEntryInputBase & Pick<JournalDoneEntry, "kind" | "status" | "summary">);

export interface JournalPaths {
  runDir: string;
  journalPath: string;
  artifactsDir: string;
}
