import {
  createTranscriptDocument,
  type PresentationTranscriptDocument,
  type PresentationTranscriptEntry,
} from "@0sec/shared";
import type { SessionState, TranscriptItem } from "./session-state.js";

function projectSessionItem(item: TranscriptItem): PresentationTranscriptEntry {
  const kind = item.kind === "thinking"
    ? "reasoning"
    : item.kind === "error"
      ? "error"
      : item.kind === "user-inject"
        ? "user"
        : "notice";
  const detail = item.actions?.join("\n");

  return {
    id: item.id,
    kind,
    text: item.kind === "tool-group" && item.label
      ? `TOOL ACTIVITY · ${item.text}`
      : item.text,
    turn: item.turn ?? 0,
    ...(detail ? { detail } : {}),
  };
}

/** Adapt the legacy scan-session reducer to the shared transcript document. */
export function createSessionTranscriptDocument(state: SessionState): PresentationTranscriptDocument {
  return createTranscriptDocument(state.transcript.map(projectSessionItem));
}
