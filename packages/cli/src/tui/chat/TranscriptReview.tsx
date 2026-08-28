/** @jsxImportSource @opentui/react */
import React, { type MutableRefObject, useMemo } from "react";
import type { PresentationTranscriptDocument } from "@0sec/shared";
import type { Theme } from "../theme-context.js";
import {
  compileTranscriptReview,
  type TranscriptReviewDocument,
} from "../transcript-review.js";
import "../transcript-review-renderable.js";
import type { TranscriptReviewRenderable } from "../transcript-review-renderable.js";
import type { TranscriptDetail } from "../transcript-style.js";

export interface TranscriptReviewProps {
  transcript: PresentationTranscriptDocument;
  width: number;
  detail: TranscriptDetail;
  expandedTurns: ReadonlySet<number>;
  theme: Theme;
  renderableRef: MutableRefObject<TranscriptReviewRenderable | null>;
}

export function TranscriptReview({
  transcript,
  width,
  detail,
  expandedTurns,
  theme,
  renderableRef,
}: TranscriptReviewProps) {
  const document = useMemo<TranscriptReviewDocument>(
    () => compileTranscriptReview(transcript, { width, detail, expandedTurns }),
    [detail, expandedTurns, transcript, width],
  );
  const content = document.text
    ? [
        `TRANSCRIPT REVIEW · ${transcript.entries.length} entries`,
        "Esc / Ctrl+O live · PgUp/PgDn scroll · Ctrl+Home/Ctrl+End jump",
        "",
        document.text,
      ].join("\n")
    : "TRANSCRIPT REVIEW\n\nNo transcript entries yet. Esc / Ctrl+O returns to live chat.";

  return (
    <box flexGrow={1} minHeight={0} width="100%" minWidth={0} backgroundColor={theme.PANEL}>
      <transcript-review
        ref={renderableRef}
        content={content}
        fg={theme.TEXT}
        bg={theme.PANEL}
        wrapMode="word"
        selectable
        height="100%"
        width="100%"
      />
    </box>
  );
}
