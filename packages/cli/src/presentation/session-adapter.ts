import type { PresentationTranscriptEntry } from "@0sec/shared";
import {
  createPresentationEmitter,
  type PresentationEmitter,
} from "./event-bus.js";

export interface SessionPresentationAdapter {
  opened(payload: Record<string, unknown>): void;
  transcriptAppend(entry: PresentationTranscriptEntry): void;
  transcriptReplace(entry: PresentationTranscriptEntry): void;
  sessionEvent(type: string, payload: Record<string, unknown>): void;
  reviewOpened(): void;
  reviewClosed(): void;
  closed(): void;
}

/**
 * Renderer-neutral semantic event adapter for one interactive session. It owns
 * only producer ordering and correlation; screens keep their local focus and
 * layout state.
 */
export function createSessionPresentationAdapter(sessionId: string): SessionPresentationAdapter {
  const emitter: PresentationEmitter = createPresentationEmitter();
  const correlation = { sessionId };

  return {
    opened(payload) {
      emitter.emit("session.opened", payload, correlation);
    },
    transcriptAppend(entry) {
      emitter.emit("session.transcript.append", { entry }, correlation);
    },
    transcriptReplace(entry) {
      emitter.emit("session.transcript.replace", { entry }, correlation);
    },
    sessionEvent(type, payload) {
      emitter.emit(type, payload, correlation);
    },
    reviewOpened() {
      emitter.emit("review.opened", {}, correlation);
    },
    reviewClosed() {
      emitter.emit("review.closed", {}, correlation);
    },
    closed() {
      emitter.emit("session.closed", {}, correlation);
    },
  };
}
