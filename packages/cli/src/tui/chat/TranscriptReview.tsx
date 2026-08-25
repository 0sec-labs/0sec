/** @jsxImportSource @opentui/react */
import React, { type MutableRefObject, useMemo } from "react";
import type { Theme } from "../theme-context.js";
import {
  compileTranscriptReview,
  type TranscriptReviewDocument,
} from "../transcript-review.js";
import "../transcript-review-renderable.js";
import type { TranscriptReviewRenderable } from "../transcript-review-renderable.js";
import type { TranscriptDetail } from "../transcript-style.js";
import type { ChatEntry } from "./types.js";

export interface TranscriptReviewProps {
  entries: readonly ChatEntry[];
  width: number;
  detail: TranscriptDetail;
  expandedTurns: ReadonlySet<number>;
  theme: Theme;
  renderableRef: MutableRefObject<TranscriptReviewRenderable | null>;
}

export function TranscriptReview({
  entries,
  width,
  detail,
  expandedTurns,
  theme,
  renderableRef,
}: TranscriptReviewProps) {
  const document = useMemo<TranscriptReviewDocument>(
    () => compileTranscriptReview(entries, { width, detail, expandedTurns }),
    [detail, entries, expandedTurns, width],
  );
  const content = document.text
    ? [
        `TRANSCRIPT REVIEW · ${entries.length} entries`,
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
